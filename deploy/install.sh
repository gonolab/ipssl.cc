#!/bin/sh
# Install or upgrade ipssl-dns from a GitHub release.
#
#   sudo sh install.sh                      # name server, latest release
#   sudo sh install.sh v0.2.0               # name server, a specific release
#   sudo sh install.sh --acme-api           # DNS-01 challenge API host
#   sudo sh install.sh --acme-api v0.4.0
#
# Downloads the static binary for this machine, checks it against the
# release's SHA256SUMS and installs it with a systemd unit: ipssl-dns.service
# on a name server, or ipssl-acme-api.service with --acme-api (v0.4.0 and
# later), which never starts the DNS server. On a first install it also puts
# the example config at /etc/ipssl/config.toml and stops, so the config can
# be filled in before the service starts. An existing config is never
# touched: it is checked, then the service is (re)started.

set -eu

REPO=gonolab/ipssl.cc
BIN=/usr/local/bin/ipssl-dns
UNIT_DIR=/etc/systemd/system
CONFIG_DIR=/etc/ipssl
CONFIG=$CONFIG_DIR/config.toml

die() {
    echo "install.sh: $*" >&2
    exit 1
}

MODE=dns
VERSION=latest
for arg in "$@"; do
    case "$arg" in
        --acme-api) MODE=api ;;
        latest | v[0-9]*) VERSION=$arg ;;
        *) die "unexpected argument '$arg' (expected --acme-api and/or a version such as v0.4.0)" ;;
    esac
done

if [ "$MODE" = api ]; then
    SERVICE=ipssl-acme-api
    CHECK_HINT="ipssl-dns --acme-api -c $CONFIG --check"
else
    SERVICE=ipssl-dns
    CHECK_HINT="ipssl-dns -c $CONFIG --check"
fi
UNIT=$UNIT_DIR/$SERVICE.service

# Checks the config with binary $1, the way this host's service runs it.
check_config() {
    if [ "$MODE" = api ]; then
        "$1" --acme-api -c "$CONFIG" --check
    else
        "$1" -c "$CONFIG" --check
    fi
}

[ "$(id -u)" -eq 0 ] || die "run as root"
for tool in curl sha256sum tar systemctl; do
    command -v "$tool" > /dev/null || die "$tool is required"
done

# A host that only runs the challenge API must not start the DNS server.
if [ "$MODE" = dns ] && [ -f "$UNIT_DIR/ipssl-acme-api.service" ] && [ ! -f "$UNIT_DIR/ipssl-dns.service" ]; then
    die "this host runs ipssl-acme-api, not the DNS server; upgrade it with: sh install.sh --acme-api"
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

NAME=ipssl-dns-$VERSION-$TARGET
BASE=https://github.com/$REPO/releases/download/$VERSION
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Downloading $NAME"
curl -fsSL -o "$TMP/$NAME.tar.gz" "$BASE/$NAME.tar.gz"
curl -fsSL -o "$TMP/SHA256SUMS" "$BASE/SHA256SUMS"
(cd "$TMP" && sha256sum -c --ignore-missing --quiet SHA256SUMS) || die "checksum mismatch"
tar -xzf "$TMP/$NAME.tar.gz" -C "$TMP"
[ -f "$TMP/$NAME/$SERVICE.service" ] || die "$VERSION has no $SERVICE.service; --acme-api needs v0.4.0 or later"

# Check the new binary against the existing config before replacing anything.
if [ -f "$CONFIG" ]; then
    check_config "$TMP/$NAME/ipssl-dns"
fi

install -m 755 "$TMP/$NAME/ipssl-dns" "$BIN"
install -m 644 "$TMP/$NAME/$SERVICE.service" "$UNIT"
install -d -m 755 "$CONFIG_DIR"
systemctl daemon-reload
echo "Installed $("$BIN" --version)"

if [ ! -f "$CONFIG" ]; then
    install -m 644 "$TMP/$NAME/config.example.toml" "$CONFIG"
    if [ "$MODE" = api ]; then
        echo "Wrote $CONFIG from the example. Fill it in, including the [acme] section, then run:"
    else
        echo "Wrote $CONFIG from the example. Fill it in, then run:"
    fi
    echo "  $CHECK_HINT && systemctl enable --now $SERVICE"
    exit 0
fi

systemctl enable --quiet "$SERVICE"
systemctl restart "$SERVICE"
sleep 1
systemctl is-active --quiet "$SERVICE" || {
    journalctl -u "$SERVICE" -n 20 --no-pager >&2
    die "$SERVICE failed to start"
}
echo "$SERVICE is running"
