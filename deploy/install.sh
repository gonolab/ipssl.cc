#!/bin/sh
# Install or upgrade ipssl-dns from a GitHub release.
#
#   sudo sh install.sh            # latest release
#   sudo sh install.sh v0.2.0     # a specific release
#
# Downloads the static binary for this machine, checks it against the
# release's SHA256SUMS and installs it with the systemd unit. On a first
# install it also puts the example config at /etc/ipssl/config.toml and
# stops, so the config can be filled in before the server starts. An
# existing config is never touched: it is checked, then the service is
# (re)started.

set -eu

REPO=gonolab/ipssl.cc
BIN=/usr/local/bin/ipssl-dns
UNIT=/etc/systemd/system/ipssl-dns.service
CONFIG_DIR=/etc/ipssl
CONFIG=$CONFIG_DIR/config.toml

die() {
    echo "install.sh: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || die "run as root"
for tool in curl sha256sum tar systemctl; do
    command -v "$tool" > /dev/null || die "$tool is required"
done

case "$(uname -m)" in
    x86_64 | amd64) TARGET=x86_64-unknown-linux-musl ;;
    aarch64 | arm64) TARGET=aarch64-unknown-linux-musl ;;
    *) die "no release build for $(uname -m)" ;;
esac

VERSION=${1:-latest}
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

# Check the new binary against the existing config before replacing anything.
if [ -f "$CONFIG" ]; then
    "$TMP/$NAME/ipssl-dns" -c "$CONFIG" --check
fi

install -m 755 "$TMP/$NAME/ipssl-dns" "$BIN"
install -m 644 "$TMP/$NAME/ipssl-dns.service" "$UNIT"
install -d -m 755 "$CONFIG_DIR"
systemctl daemon-reload
echo "Installed $("$BIN" --version)"

if [ ! -f "$CONFIG" ]; then
    install -m 644 "$TMP/$NAME/config.example.toml" "$CONFIG"
    echo "Wrote $CONFIG from the example. Fill it in, then run:"
    echo "  ipssl-dns -c $CONFIG --check && systemctl enable --now ipssl-dns"
    exit 0
fi

systemctl enable --quiet ipssl-dns
systemctl restart ipssl-dns
sleep 1
systemctl is-active --quiet ipssl-dns || {
    journalctl -u ipssl-dns -n 20 --no-pager >&2
    die "ipssl-dns failed to start"
}
echo "ipssl-dns is running"
