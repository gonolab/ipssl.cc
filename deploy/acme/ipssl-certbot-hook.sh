#!/bin/sh
# certbot hooks that publish DNS-01 challenges through the ipssl.cc API,
# for names with private addresses such as 10-0-2-2.ipssl.cc:
#
#   certbot certonly --manual --preferred-challenges dns \
#     --manual-auth-hook "sh /path/to/ipssl-certbot-hook.sh present" \
#     --manual-cleanup-hook "sh /path/to/ipssl-certbot-hook.sh cleanup" \
#     -d 10-0-2-2.ipssl.cc
#
# Set IPSSL_API to use another endpoint (default https://ipssl.cc/acme).

set -eu

api=${IPSSL_API:-https://ipssl.cc/acme}
action=${1:-}
case "$action" in
    present | cleanup) ;;
    *)
        echo "usage: $0 present|cleanup" >&2
        exit 2
        ;;
esac

# certbot passes *.example names without the wildcard label.
domain=${CERTBOT_DOMAIN#\*.}
body=$(printf '{"fqdn":"_acme-challenge.%s","value":"%s"}' "$domain" "$CERTBOT_VALIDATION")

reply=$(curl -sS -m 30 -X POST -H 'Content-Type: application/json' --data "$body" "$api/$action") || {
    echo "ipssl.cc: $action request failed" >&2
    exit 1
}
case "$reply" in
    *'"ok":true'*) ;;
    *)
        echo "ipssl.cc: $action failed: $reply" >&2
        exit 1
        ;;
esac
