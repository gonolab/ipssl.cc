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
#   acme.sh --issue --server letsencrypt --dns dns_ipssl -d 10-0-2-2.ipssl.cc
#
# IPSSL_API selects another endpoint. It is saved with the certificate
# (in its domain conf, not account-wide), so renewals of that certificate
# keep using it, and certificates issued without it use the default.

IPSSL_API_DEFAULT="https://ipssl.cc/acme"

# The API limits each client network (by default 10 requests a minute,
# with bursts of 20), so an order for many names can hit 429. Requests are
# retried then for at most this many seconds in all.
IPSSL_MAX_WAIT=90

# Usage: dns_ipssl_add _acme-challenge.10-0-2-2.ipssl.cc "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_ipssl_add() {
  _ipssl_call present "$1" "$2"
}

# Usage: dns_ipssl_rm _acme-challenge.10-0-2-2.ipssl.cc "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_ipssl_rm() {
  _ipssl_call cleanup "$1" "$2"
}

####################  Private functions below ##################################

# Sets IPSSL_API: from the environment, else as saved for this certificate,
# else the default. The saved key is not named IPSSL_API because acme.sh
# sources the domain conf on renewal, which would set IPSSL_API to the
# encoded value. Older versions of this plugin saved the endpoint
# account-wide, where it leaked into every other certificate; that value
# is ignored and removed.
_ipssl_api() {
  _clearaccountconf SAVED_IPSSL_API
  IPSSL_API="${IPSSL_API:-$(_readdomainconf IPSSL_API_SAVED)}"
  IPSSL_API="${IPSSL_API:-$IPSSL_API_DEFAULT}"
  if [ "$IPSSL_API" = "$IPSSL_API_DEFAULT" ]; then
    _cleardomainconf IPSSL_API_SAVED
  else
    # Base64, so quotes in the URL cannot break the conf file.
    _savedomainconf IPSSL_API_SAVED "$IPSSL_API" base64
  fi
}

_ipssl_call() {
  _ipssl_action="$1"
  _ipssl_body="{\"fqdn\":\"$2\",\"value\":\"$3\"}"
  _ipssl_api
  _debug body "$_ipssl_body"

  _ipssl_waited=0
  _ipssl_backoff=6
  while true; do
    _ipssl_response="$(_post "$_ipssl_body" "$IPSSL_API/$_ipssl_action" "" "POST" "application/json")"
    _ipssl_ret="$?"
    _debug response "$_ipssl_response"
    if [ "$_ipssl_ret" != "0" ]; then
      _err "ipssl.cc $_ipssl_action request to $IPSSL_API failed"
      return 1
    fi
    _ipssl_code="$(grep -i '^HTTP' "$HTTP_HEADER" | _tail_n 1 | cut -d ' ' -f 2 | tr -d '\r\n')"
    _debug code "$_ipssl_code"
    if [ "$_ipssl_code" = "200" ]; then
      return 0
    fi
    if [ "$_ipssl_code" = "429" ]; then
      # Wait as long as Retry-After asks, or back off from 6 seconds.
      _ipssl_delay="$(grep -i '^retry-after:' "$HTTP_HEADER" | _tail_n 1 | cut -d ':' -f 2 | tr -d ' \t\r\n')"
      case "$_ipssl_delay" in
        '' | *[!0-9]*)
          _ipssl_delay="$_ipssl_backoff"
          _ipssl_backoff="$(_math "$_ipssl_backoff" \* 2)"
          ;;
      esac
      if [ "$_ipssl_delay" -lt 1 ]; then
        _ipssl_delay=1
      fi
      if [ "$(_math "$_ipssl_waited" + "$_ipssl_delay")" -le "$IPSSL_MAX_WAIT" ]; then
        _info "ipssl.cc rate limit reached, retrying in ${_ipssl_delay}s"
        _sleep "$_ipssl_delay"
        _ipssl_waited="$(_math "$_ipssl_waited" + "$_ipssl_delay")"
        continue
      fi
    fi
    _err "ipssl.cc $_ipssl_action failed (HTTP $_ipssl_code): $_ipssl_response"
    return 1
  done
}
