#!/bin/sh
# Install or upgrade ipssl-dns from a GitHub release.
#
#   sudo sh install.sh                # upgrade the services enabled on this
#                                     # host; on a new host, install a name server
#   sudo sh install.sh v0.4.0         # the same with a specific release
#   sudo sh install.sh --dns          # install and enable the name server
#   sudo sh install.sh --acme-api     # install and enable the DNS-01 challenge API
#   sudo sh install.sh --acme-api v0.4.0
#
# Downloads the static binary for this machine, checks it against the
# release's SHA256SUMS and installs it with a systemd unit per service:
# ipssl-dns.service on a name server, ipssl-acme-api.service on the host
# that runs the challenge API (v0.4.0 and later; it never starts the DNS
# server). Both run the same binary, so every enabled service is checked
# and restarted. A service that is not enabled is enabled only when its
# flag is given, so an upgrade never starts a role this host gave up.
#
# On a first install it also puts the example config at
# /etc/ipssl/config.toml and stops, so the config can be filled in before
# anything starts. An existing config is never changed. Before anything is
# replaced, it is checked with the new binary as an unprivileged user, the
# way the services read it. If a service does not stay up after the
# restart, the previous binary and units are put back.

set -eu

REPO=gonolab/ipssl.cc
BIN=/usr/local/bin/ipssl-dns
UNIT_DIR=/etc/systemd/system
CONFIG_DIR=/etc/ipssl
CONFIG=$CONFIG_DIR/config.toml
LOCK=/run/ipssl-install.lock
ALL_SERVICES="ipssl-dns ipssl-acme-api"

die() {
    echo "install.sh: $*" >&2
    exit 1
}

WANT=""
VERSION=latest
for arg in "$@"; do
    case "$arg" in
        --dns) WANT="$WANT ipssl-dns" ;;
        --acme-api) WANT="$WANT ipssl-acme-api" ;;
        latest | v[0-9]*) VERSION=$arg ;;
        *) die "unexpected argument '$arg' (expected --dns, --acme-api and/or a version such as v0.4.0)" ;;
    esac
done

# True if word $2 is in the space-separated list $1.
has() {
    case " $1 " in
        *" $2 "*) return 0 ;;
    esac
    return 1
}

# The flag that selects service $1.
flag_for() {
    case "$1" in
        ipssl-dns) echo --dns ;;
        ipssl-acme-api) echo --acme-api ;;
    esac
}

# True if files $1 and $2 have the same content.
same_file() {
    [ "$(sha256sum < "$1")" = "$(sha256sum < "$2")" ]
}

# Replaces $3 with a copy of $2 (mode $1) atomically: the copy is written
# next to the target, then renamed over it, so the target is always either
# the old file or the new one, never a partial copy.
put() {
    NEW=$3.ipssl-new
    install -m "$1" "$2" "$NEW"
    mv -f "$NEW" "$3"
    NEW=""
}

# Checks the config with binary $1 the way service $2 runs it, as a
# throwaway unprivileged user like the units' DynamicUser=yes. Run as
# root, a config only root can read would pass, and the restarted
# service would then fail to read it.
check_config() {
    if [ "$2" = ipssl-acme-api ]; then
        set -- "$1" --acme-api -c "$CONFIG" --check
    else
        set -- "$1" -c "$CONFIG" --check
    fi
    systemd-run --quiet --wait --pipe --collect --property=DynamicUser=yes -- "$@" < /dev/null
}

# True if service $1 is active and keeps the same main process for about
# five seconds. With Restart=always, a service that exits is started again
# after RestartSec=2, so a crash in that time shows up as "not active" or
# as a new PID.
healthy() {
    sleep 1
    systemctl is-active --quiet "$1" || return 1
    pid=$(systemctl show --property=MainPID --value "$1")
    for _ in 1 2 3 4; do
        sleep 1
        systemctl is-active --quiet "$1" || return 1
    done
    [ "$(systemctl show --property=MainPID --value "$1")" = "$pid" ]
}

# Puts the previous binary and units back after a failed upgrade, and
# turns off the services this run enabled. With no previous binary (a
# first install), the new files stay for debugging.
rollback() {
    for svc in $SERVICES; do
        if ! has "$ENABLED" "$svc"; then
            systemctl disable --quiet --now "$svc"
        fi
    done
    if [ ! -f "$OLD/ipssl-dns" ]; then
        systemctl daemon-reload
        echo "install.sh: fix the problem above, then run: $RERUN" >&2
        return
    fi
    echo "install.sh: putting back $OLD_VERSION" >&2
    put 755 "$OLD/ipssl-dns" "$BIN"
    for svc in $SERVICES; do
        if [ -f "$OLD/$svc.service" ]; then
            put 644 "$OLD/$svc.service" "$UNIT_DIR/$svc.service"
        else
            rm -f "$UNIT_DIR/$svc.service"
        fi
    done
    systemctl daemon-reload
    for svc in $ENABLED; do
        systemctl restart "$svc"
        if healthy "$svc"; then
            echo "install.sh: $svc is running $OLD_VERSION again" >&2
        else
            echo "install.sh: $svc did not come back either; see journalctl -u $svc" >&2
        fi
    done
}

on_exit() {
    status=$?
    trap - EXIT INT TERM HUP
    set +e
    if [ "$PHASE" = replaced ]; then
        rollback
        status=1
    fi
    [ -z "$NEW" ] || rm -f "$NEW"
    [ -z "$STAGE" ] || rm -rf "$STAGE"
    [ -z "$LOCK_DIR" ] || rmdir "$LOCK_DIR"
    exit "$status"
}

[ "$(id -u)" -eq 0 ] || die "run as root"
for tool in curl sha256sum tar systemctl systemd-run; do
    command -v "$tool" > /dev/null || die "$tool is required"
done

# PHASE is "replaced" while the new files are in place but not yet known
# to work; exiting then, for any reason, rolls back.
PHASE=prepare
NEW=""
STAGE=""
LOCK_DIR=""
SERVICES=""
ENABLED=""
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# One run at a time, so two runs cannot mix files from different releases.
if command -v flock > /dev/null; then
    exec 9> "$LOCK"
    flock -n 9 || die "another install.sh is running (lock $LOCK)"
else
    mkdir "$LOCK.d" 2> /dev/null || die "another install.sh is running (or remove the stale lock $LOCK.d)"
    LOCK_DIR=$LOCK.d
fi

# The roles this host runs are the services that are enabled, not the
# unit files that exist: a role that was given up keeps its unit file.
for svc in $ALL_SERVICES; do
    if systemctl is-enabled --quiet "$svc" 2> /dev/null; then
        ENABLED="$ENABLED $svc"
    fi
done
if [ -z "$WANT$ENABLED" ]; then
    installed=""
    for svc in $ALL_SERVICES; do
        if [ -f "$UNIT_DIR/$svc.service" ]; then
            installed="$installed $svc"
        fi
    done
    if [ -n "$installed" ]; then
        die "no ipssl service is enabled here (installed:$installed). Say which one to check and start: sudo sh install.sh --dns for the name server, or --acme-api for the challenge API"
    fi
    # A new host: install a name server.
    WANT=ipssl-dns
fi
for svc in $ALL_SERVICES; do
    if has "$WANT" "$svc" || has "$ENABLED" "$svc"; then
        SERVICES="$SERVICES $svc"
    fi
done
SERVICES=${SERVICES# }
ENABLED=${ENABLED# }

if [ ! -f "$CONFIG" ] && [ -n "$ENABLED" ]; then
    die "$CONFIG is missing but $ENABLED is enabled; put the config back first"
fi

case "$(uname -m)" in
    x86_64 | amd64) TARGET=x86_64-unknown-linux-musl ;;
    aarch64 | arm64) TARGET=aarch64-unknown-linux-musl ;;
    *) die "no release build for $(uname -m)" ;;
esac

if [ "$VERSION" = latest ]; then
    # GitHub redirects /releases/latest to /releases/tag/<version>.
    url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")
    VERSION=${url##*/}
fi
case "$VERSION" in
    v[0-9]*) ;;
    *) die "unexpected version '$VERSION'" ;;
esac

# How to run this again for the same services and release.
RERUN="sudo sh install.sh"
for svc in $SERVICES; do
    RERUN="$RERUN $(flag_for "$svc")"
done
RERUN="$RERUN $VERSION"

# Stage next to the installed binary rather than in /tmp: the new binary
# runs from here for the config check (/tmp may be mounted noexec), and on
# the same file system the final rename is atomic.
BIN_DIR=${BIN%/*}
[ -d "$BIN_DIR" ] || install -d -m 755 "$BIN_DIR"
STAGE=$(mktemp -d "$BIN_DIR/.ipssl-install.XXXXXX")
# The unprivileged config check must be able to run the new binary.
chmod 755 "$STAGE"

NAME=ipssl-dns-$VERSION-$TARGET
BASE=https://github.com/$REPO/releases/download/$VERSION
PKG=$STAGE/$NAME

echo "Downloading $NAME"
curl -fsSL -o "$STAGE/$NAME.tar.gz" "$BASE/$NAME.tar.gz"
curl -fsSL -o "$STAGE/SHA256SUMS" "$BASE/SHA256SUMS"
(cd "$STAGE" && sha256sum -c --ignore-missing --quiet SHA256SUMS) || die "checksum mismatch"
tar -xzf "$STAGE/$NAME.tar.gz" -C "$STAGE"
for svc in $SERVICES; do
    [ -f "$PKG/$svc.service" ] || die "$VERSION has no $svc.service; the challenge API needs v0.4.0 or later"
done

# Check the new binary against the existing config before replacing
# anything. The untouched example passes the check, but would serve its
# sample records.
if [ -f "$CONFIG" ]; then
    if same_file "$CONFIG" "$PKG/config.example.toml"; then
        die "$CONFIG is still the example config. Nothing was changed. Fill it in, then run: $RERUN"
    fi
    for svc in $SERVICES; do
        echo "Checking $CONFIG for $svc as an unprivileged user"
        check_config "$PKG/ipssl-dns" "$svc" ||
            die "the new binary rejects $CONFIG for $svc (see above). The services run as an unprivileged user, so the file must be readable by everyone (mode 644). Nothing was changed."
    done
fi

# Keep the previous files for a rollback.
OLD=$STAGE/old
mkdir "$OLD"
OLD_VERSION=""
if [ -f "$BIN" ]; then
    cp -p "$BIN" "$OLD/ipssl-dns"
    OLD_VERSION=$("$BIN" --version 2> /dev/null) || OLD_VERSION="the previous binary"
fi
for svc in $SERVICES; do
    if [ -f "$UNIT_DIR/$svc.service" ]; then
        cp -p "$UNIT_DIR/$svc.service" "$OLD/$svc.service"
    fi
done

PHASE=replaced
put 755 "$PKG/ipssl-dns" "$BIN"
for svc in $SERVICES; do
    put 644 "$PKG/$svc.service" "$UNIT_DIR/$svc.service"
done
# Never touch the mode of an existing directory: it may be stricter.
[ -d "$CONFIG_DIR" ] || install -d -m 755 "$CONFIG_DIR"
systemctl daemon-reload
echo "Installed $("$BIN" --version)"

if [ ! -f "$CONFIG" ]; then
    PHASE=finished
    install -m 644 "$PKG/config.example.toml" "$CONFIG"
    if has "$SERVICES" ipssl-acme-api; then
        echo "Wrote $CONFIG from the example. Fill it in, including the [acme] section, then check it and start $SERVICES with:"
    else
        echo "Wrote $CONFIG from the example. Fill it in, then check it and start $SERVICES with:"
    fi
    echo "  $RERUN"
    exit 0
fi

for svc in $SERVICES; do
    if ! has "$ENABLED" "$svc"; then
        systemctl enable --quiet "$svc"
    fi
done
for svc in $SERVICES; do
    echo "Restarting $svc"
    # A failed start shows up in the health check below.
    systemctl restart "$svc" || true
done
failed=""
for svc in $SERVICES; do
    healthy "$svc" || failed="$failed $svc"
done
if [ -n "$failed" ]; then
    for svc in $failed; do
        journalctl -u "$svc" -n 20 --no-pager >&2 || true
    done
    die "${failed# } did not stay up with $VERSION"
fi
PHASE=finished
echo "Running $VERSION: $SERVICES"
