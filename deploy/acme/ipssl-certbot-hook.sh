#!/bin/sh
# certbot hooks that publish DNS-01 challenges through the ipssl.cc API,
# for names with private addresses such as 10-0-2-2.ipssl.cc:
#
#   sudo curl -fsSL -o /usr/local/bin/ipssl-certbot-hook.sh https://ipssl.cc/acme/ipssl-certbot-hook.sh
#   sudo certbot certonly --manual --preferred-challenges dns \
#     --manual-auth-hook "sh /usr/local/bin/ipssl-certbot-hook.sh present" \
#     --manual-cleanup-hook "sh /usr/local/bin/ipssl-certbot-hook.sh cleanup" \
#     -d 10-0-2-2.ipssl.cc
#
# Keep the script at a root-owned path: certbot runs it as root on every
# renewal.
#
# IPSSL_API selects another endpoint (default https://ipssl.cc/acme).
# certbot saves the hook commands for renewal but not the environment, so
# set it inside the commands:
#
#   --manual-auth-hook "env IPSSL_API=https://example.net/acme sh /usr/local/bin/ipssl-certbot-hook.sh present"

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

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# The API limits each client network (by default 10 requests a minute,
# with bursts of 20), so an order for many names can hit 429. Retry then,
# waiting as long as Retry-After asks or backing off from 6 seconds, for
# at most 90 seconds in all.
max_wait=90
waited=0
backoff=6
while :; do
    code=$(curl -sS -m 30 -o "$tmp/body" -D "$tmp/headers" -w '%{http_code}' \
        -X POST -H 'Content-Type: application/json' --data "$body" "$api/$action") || {
        echo "ipssl.cc: $action request to $api failed" >&2
        exit 1
    }
    if [ "$code" = 200 ]; then
        exit 0
    fi
    if [ "$code" = 429 ]; then
        delay=$(tr -d '\r' < "$tmp/headers" | tr '[:upper:]' '[:lower:]' |
            sed -n 's/^retry-after:[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' | tail -n 1)
        if [ -z "$delay" ]; then
            delay=$backoff
            backoff=$((backoff * 2))
        fi
        [ "$delay" -ge 1 ] || delay=1
        if [ $((waited + delay)) -le "$max_wait" ]; then
            echo "ipssl.cc: rate limited, retrying $action in ${delay}s" >&2
            sleep "$delay"
            waited=$((waited + delay))
            continue
        fi
    fi
    echo "ipssl.cc: $action failed (HTTP $code): $(cat "$tmp/body")" >&2
    exit 1
done
