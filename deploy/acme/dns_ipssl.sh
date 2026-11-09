#!/usr/bin/env sh
# shellcheck disable=SC2034
dns_ipssl_info='ipssl.cc
 DNS-01 challenges for names with private addresses, such as 10-0-2-2.ipssl.cc.
Site: github.com/gonolab/ipssl.cc
Docs: github.com/gonolab/ipssl.cc#certificates-for-private-addresses
Options:
 IPSSL_API API endpoint. Default "https://ipssl.cc/acme".
'

# acme.sh DNS API for ipssl.cc. Copy this file to ~/.acme.sh/dnsapi/, then:
#
#   acme.sh --issue --dns dns_ipssl -d 10-0-2-2.ipssl.cc

IPSSL_API_DEFAULT="https://ipssl.cc/acme"

# Usage: dns_ipssl_add _acme-challenge.10-0-2-2.ipssl.cc "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_ipssl_add() {
  _ipssl_call present "$1" "$2"
}

# Usage: dns_ipssl_rm _acme-challenge.10-0-2-2.ipssl.cc "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_ipssl_rm() {
  _ipssl_call cleanup "$1" "$2"
}

####################  Private functions below ##################################

_ipssl_call() {
  action="$1"
  fulldomain="$2"
  txtvalue="$3"

  IPSSL_API="${IPSSL_API:-$(_readaccountconf_mutable IPSSL_API)}"
  IPSSL_API="${IPSSL_API:-$IPSSL_API_DEFAULT}"
  if [ "$IPSSL_API" != "$IPSSL_API_DEFAULT" ]; then
    _saveaccountconf_mutable IPSSL_API "$IPSSL_API"
  fi

  body="{\"fqdn\":\"$fulldomain\",\"value\":\"$txtvalue\"}"
  _debug body "$body"
  response="$(_post "$body" "$IPSSL_API/$action" "" "POST" "application/json")"
  _debug response "$response"
  if _contains "$response" '"ok":true'; then
    return 0
  fi
  _err "ipssl.cc $action failed: $response"
  return 1
}
