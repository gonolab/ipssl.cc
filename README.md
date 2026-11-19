# ipssl.cc

[![CI](https://github.com/gonolab/ipssl.cc/actions/workflows/ci.yml/badge.svg)](https://github.com/gonolab/ipssl.cc/actions/workflows/ci.yml)

Wildcard DNS for any IP address, like nip.io and sslip.io: put an IP address in a hostname and it resolves to that address. No hosts file edits, no DNS server of your own.

```
10-0-0-1.ipssl.cc         →  10.0.0.1
app-192-168-1-10.ipssl.cc →  192.168.1.10
2001-db8--1.ipssl.cc      →  2001:db8::1
```

## Supported forms

| Name | Result | Notes |
|---|---|---|
| `10-0-0-1.ipssl.cc` | 10.0.0.1 | **Recommended.** A single label, easiest to get certificates for |
| `app-10-0-0-1.ipssl.cc` | 10.0.0.1 | Words before or after the address, joined with `-` |
| `10-0-0-1-app.ipssl.cc` | 10.0.0.1 | |
| `app.10-0-0-1.ipssl.cc` | 10.0.0.1 | Any number of subdomain levels |
| `10.0.0.1.ipssl.cc` | 10.0.0.1 | Dotted form |
| `app.10.0.0.1.ipssl.cc` | 10.0.0.1 | |
| `0a000001.ipssl.cc` | 10.0.0.1 | Eight hex digits |
| `2001-db8--1.ipssl.cc` | 2001:db8::1 | IPv6: write `:` as `-` and `::` as `--` |
| `app.2001-db8--1.ipssl.cc` | 2001:db8::1 | IPv6 prefixes must be separated with `.` |

Rules:

- When a name contains more than one address, the rightmost one (closest to the zone) wins. A label of eight decimal numbers, such as `10-0-0-1-192-168-1-1`, holds two IPv4 addresses, not one IPv6 address, so it resolves to 192.168.1.1.
- Numbers with leading zeros (such as `010`) are rejected, so nobody has to guess whether they are octal.
- Every name under `ipssl.cc` exists. A name without an address (such as `app.ipssl.cc`), or an AAAA query for an IPv4 name and the other way round, returns NODATA, not NXDOMAIN. Only names whose address is on the operator's blocklist return NXDOMAIN.
- A TXT query for `ip.ipssl.cc` returns the address the query came from (usually your recursive resolver). Handy for debugging.

## HTTPS certificates

Get certificates on your own server, the same way as with nip.io and sslip.io. `203-0-113-10.ipssl.cc` resolves to `203.0.113.10`, so an ACME client running on that server (certbot, acme.sh, Caddy and others) passes HTTP-01 or TLS-ALPN-01 validation as usual. With nothing else on port 80:

```bash
sudo certbot certonly --standalone -d 203-0-113-10.ipssl.cc
```

If nginx already serves port 80, let certbot put the challenge in its document root (use the real one) and reload nginx after each renewal, so it picks up the new certificate:

```bash
sudo certbot certonly --webroot -w /var/www/html -d 203-0-113-10.ipssl.cc \
  --deploy-hook "systemctl reload nginx"
```

Or run `sudo certbot --nginx -d 203-0-113-10.ipssl.cc` to let certbot edit the nginx config itself.

Any ACME CA works: the zone publishes no CAA record that would limit the choice.

This only works for public addresses the CA can reach, and gives no wildcard certificates: a wildcard needs DNS-01, which ipssl.cc offers only for private addresses. Names with private addresses such as `192-168-1-10.ipssl.cc` use DNS-01, see [below](#certificates-for-private-addresses).

Every name under `ipssl.cc` shares the domain's Let's Encrypt rate limit for certificates per registered domain. Let's Encrypt raised that limit for `ipssl.cc` in November 2026, but it is still one limit for every user of the service.

## Certificates for private addresses

A CA cannot reach `10.0.2.2` or `192.168.1.10`, so names with private addresses prove control through DNS instead (DNS-01). Your ACME client publishes the challenge through the ipssl.cc API, and the CA finds it in DNS. This works for every name whose address is private (`10/8`, `172.16/12`, `192.168/16`), shared (`100.64/10`), loopback or link-local, IPv4 or IPv6. Wildcards such as `*.10-0-2-2.ipssl.cc` work too.

The API takes `POST https://ipssl.cc/acme/present` and `POST https://ipssl.cc/acme/cleanup` with a JSON body such as `{"fqdn": "_acme-challenge.10-0-2-2.ipssl.cc", "value": "..."}`. That is the format of lego's `httpreq` provider, so lego and Traefik work as they are. With lego v5 (replace `YOUR_EMAIL`):

```bash
HTTPREQ_ENDPOINT=https://ipssl.cc/acme lego run --dns httpreq --dns.propagation.disable-ans \
  --email YOUR_EMAIL -d 10-0-2-2.ipssl.cc
```

`--dns.propagation.disable-ans` skips lego's own check, which queries the authoritative name servers directly on port 53 and fails on networks that block outbound DNS; the API answers only once every name server holds the value. lego v4 (4.19 or later) takes these flags before `run` and spells this one `--dns.propagation-disable-ans`.

In Traefik, set the environment variable `HTTPREQ_ENDPOINT=https://ipssl.cc/acme` and use `httpreq` as the `dnsChallenge` provider.

certbot, with [`ipssl-certbot-hook.sh`](deploy/acme/ipssl-certbot-hook.sh) saved where only root can change it, since renewals run it as root:

```bash
sudo curl -fsSL -o /usr/local/bin/ipssl-certbot-hook.sh https://ipssl.cc/acme/ipssl-certbot-hook.sh
```

```bash
sudo certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook "sh /usr/local/bin/ipssl-certbot-hook.sh present" \
  --manual-cleanup-hook "sh /usr/local/bin/ipssl-certbot-hook.sh cleanup" \
  -d 10-0-2-2.ipssl.cc
```

The hook takes another endpoint from `IPSSL_API`. certbot saves the hook commands for renewal but not the environment, so set the variable inside both commands, as in `--manual-auth-hook "env IPSSL_API=https://acme.example.net/acme sh /usr/local/bin/ipssl-certbot-hook.sh present"`.

acme.sh, with [`dns_ipssl.sh`](deploy/acme/dns_ipssl.sh) in `~/.acme.sh/dnsapi/` (`--server letsencrypt`, because acme.sh defaults to ZeroSSL):

```bash
curl -fsSL -o ~/.acme.sh/dnsapi/dns_ipssl.sh https://ipssl.cc/acme/dns_ipssl.sh
```

```bash
acme.sh --issue --server letsencrypt --dns dns_ipssl -d 10-0-2-2.ipssl.cc
```

For another endpoint, set `IPSSL_API` when issuing. acme.sh saves it with that certificate, so its renewals keep using it.

Keep in mind:

- The certificate encrypts the connection, but it does not prove whose machine you reached. `10.0.2.2` exists on countless networks, and anyone can get a certificate for the same name.
- Names with public addresses are refused: otherwise anyone could get a certificate for someone else's server. Run the ACME client on that server and use HTTP-01 or TLS-ALPN-01.
- Values must be real DNS-01 digests. They are dropped after 10 minutes.
- A name holds at most 16 pending values, and at most 2 from one client network. Over either cap the API answers 409 and keeps the values it has, so clean up after each order (the hooks and plugins do).
- Only the client network that presented a value can clean it up. A cleanup from another network also answers 200, but removes nothing, since the values are public in DNS anyway.
- If a name server does not take a value, the API answers 502 and takes the value back from the name servers that did, so a retry starts clean.
- Each client network can make 10 requests a minute, with bursts of 20, which is enough for an order of about 20 names. The certbot hook and the acme.sh plugin wait and retry when the API answers 429.
- These certificates count toward the same Let's Encrypt limit as every other name under `ipssl.cc`. Keep a certificate until it is due for renewal, or use another CA such as ZeroSSL or Google Trust Services.

## Shared names

Every name under `ipssl.cc` is open to everyone. That matters for certificates and for the sites you serve under these names:

- **Cookies.** Never set cookies with `Domain=ipssl.cc`. Browsers send such cookies to every name under the domain, other people's included, and other people's names can set them for yours. Use host-only cookies (no `Domain` attribute), preferably named with the `__Host-` prefix, which only the host itself can set.
- **Origins.** The same name on different networks is the same origin to a browser: `https://192-168-1-10.ipssl.cc` at home and at work share cookies, storage and granted permissions, although they are different machines.
- **Revocation.** Anyone who can validate a name can also revoke its certificates. For a name with a private address, that is anyone.
- **Certificate Transparency.** Issued certificates appear in public Certificate Transparency logs, so the names in them, labels and addresses included, can be searched.
- **Duplicate certificates.** Let's Encrypt allows 5 certificates per 7 days for the exact same set of names, and everyone who uses a name shares that limit. Give common private names a label of your own, such as `myname-192-168-1-10.ipssl.cc`.
- **Changing addresses.** After a public IP address changes hands, its previous holder may still hold certificates for its name, and for a while obtain new ones, since CAs reuse recent validations.

## Running locally

```bash
cp config.example.toml config.toml
```

Change `listen` in `config.toml` to a high port (for example `["127.0.0.1:15353"]`), then:

```bash
cargo run -- -c config.toml
```

```bash
dig @127.0.0.1 -p 15353 +short app-10-0-0-1.ipssl.cc
```

To validate the config without starting the server:

```bash
cargo run -- -c config.toml --check
```

## Tests

```bash
cargo test
```

- `src/parse.rs`: parsing rules for every supported name form
- `src/zone.rs`: answer logic (NXDOMAIN, NODATA, REFUSED, apex records, blocklist and more)
- `src/ratelimit.rs`: token buckets, client network grouping, the bounded table
- `src/config.rs`: config parsing and which changes need a restart
- `src/metrics.rs`, `src/http.rs`: metric counting, rendering and the `/metrics` endpoint
- `src/acme.rs`: which addresses count as private, challenge values, the challenge store
- `tests/dns.rs`: starts the server on a local port and sends real queries over UDP and TCP
- `tests/acme.rs`: runs the challenge API and name servers locally and checks values reach DNS

CI runs `cargo fmt --check`, clippy and the tests on every push and pull request, and checks that the code still builds with the minimum Rust version (`rust-version` in `Cargo.toml`).

## Deployment

### 1. Servers

Use at least two VPSes, with different providers in different regions. Each needs a fixed public IPv4 address, ideally IPv6 as well.

Open **UDP 53 and TCP 53** on every server.

### 2. Get the binary

The quickest way is the install script. It downloads the latest release for the machine (x86_64 or aarch64), checks it against `SHA256SUMS`, and installs the binary and the systemd unit (steps 2 and 3 in one go):

```bash
curl -fsSLO https://raw.githubusercontent.com/gonolab/ipssl.cc/main/deploy/install.sh
sudo sh install.sh
```

On a first install it writes the example config to `/etc/ipssl/config.toml` and stops: fill it in, then run the command it prints (`sudo sh install.sh --dns` with the version), which checks the config and starts the service. If a config is already there (for example copied over with `scp` first), the script checks it and starts the service right away. It refuses to start while the config is still the unchanged example, or while any line outside comments and `blocklist` holds a documentation address (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` or `2001:db8::/32`), as the example config of every release does. For a lab that uses those networks on purpose, run it as `sudo env IPSSL_ALLOW_DOC_ADDRESSES=1 sh install.sh` with the usual arguments.

Run the script again to upgrade, optionally with a version such as `v0.4.0`. It upgrades every ipssl service enabled on the host, since they share the binary:

- Before replacing anything, it checks the config with the new binary as an unprivileged user, the way the services read it. Keep the config readable by everyone (mode 644).
- It restarts the services, and puts the previous binary and units back if one does not stay up.
- It enables a service only when asked to: `--dns` for the name server, `--acme-api` for the DNS-01 challenge API (see [step 7](#7-dns-01-challenge-api-optional)). A service that was disabled stays disabled.

To do it by hand, download a static Linux build from [Releases](https://github.com/gonolab/ipssl.cc/releases) and check it:

```bash
url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/gonolab/ipssl.cc/releases/latest)
VERSION=${url##*/}                 # the latest release, or set one such as v0.4.0
TARGET=x86_64-unknown-linux-musl   # or aarch64-unknown-linux-musl
BASE=https://github.com/gonolab/ipssl.cc/releases/download/$VERSION
curl -fLO "$BASE/ipssl-dns-$VERSION-$TARGET.tar.gz" &&
  curl -fLO "$BASE/SHA256SUMS" &&
  sha256sum -c --ignore-missing SHA256SUMS &&
  tar -xzf "ipssl-dns-$VERSION-$TARGET.tar.gz" &&
  cd "ipssl-dns-$VERSION-$TARGET"
```

The archive holds the binary, `config.example.toml`, the units `ipssl-dns.service` and `ipssl-acme-api.service`, the DNS-01 hooks and the nginx snippet in `deploy/acme/`, the README and the license.

Or build it yourself with Rust 1.88 or newer. On the server:

```bash
cargo build --locked --release
```

To cross-compile static Linux binaries on macOS (or any other host), add the musl targets once:

```bash
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
```

Then build with the linker that comes with Rust. The project is pure Rust with no C dependencies, so it needs nothing else:

```bash
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld cargo build --locked --release --target x86_64-unknown-linux-musl
```

```bash
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld cargo build --locked --release --target aarch64-unknown-linux-musl
```

### 3. Install

Copy `config.example.toml` to `config.toml` and fill in your servers' addresses. Then, from the release directory:

```bash
sudo install -m 755 ipssl-dns /usr/local/bin/
sudo mkdir -p /etc/ipssl
sudo install -m 644 config.toml /etc/ipssl/config.toml
sudo install -m 644 ipssl-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ipssl-dns
```

The service runs as an unprivileged user, so keep the config readable by everyone (mode 644).

To upgrade by hand, first check the config with the new binary as a regular user, not root, which also shows whether the service can read it: `./ipssl-dns -c /etc/ipssl/config.toml --check`. Then copy only the binary and the unit into place (the `install` lines for `ipssl-dns` and `ipssl-dns.service` above) and restart the service, since `enable --now` leaves a running one alone:

```bash
sudo systemctl daemon-reload
```

```bash
sudo systemctl restart ipssl-dns
```

On a host that also runs the challenge API, restart `ipssl-acme-api` too: both use the same binary.

From a source checkout, the binary is `target/release/ipssl-dns` (or `target/<target>/release/ipssl-dns` for a cross build) and the units are `deploy/ipssl-dns.service` and `deploy/ipssl-acme-api.service`.

If any listener stops serving, the process exits with an error and systemd restarts it. On a host without IPv6, `[::]:53` in `listen` is skipped with a warning; any other address that cannot be bound stops the start.

On a server with more than one address, list each address in `listen` instead of `0.0.0.0:53` and `[::]:53`, for example `["198.51.100.1:53", "[2001:db8::1]:53"]`. A socket bound to the wildcard address can send a UDP reply from a different address than the one queried, and resolvers ignore such replies.

On Ubuntu, systemd-resolved holds `127.0.0.53:53` by default, which can make binding `0.0.0.0:53` fail. Two ways around it:

- List only the server's public IP in `listen`.
- Or set `DNSStubListener=no` in `/etc/systemd/resolved.conf` and restart systemd-resolved. `/etc/resolv.conf` points at that stub by default, so point it at systemd-resolved's list of upstream servers, or the host can no longer resolve names:

  ```bash
  sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  ```

### 4. Registrar setup

1. If the domain has DNSSEC, note the DS record's TTL (`dig +noall +answer DS ipssl.cc`), remove the DS record at the registrar, and wait at least that long before changing the name servers. This server does not sign the zone, and resolvers that still hold the DS record would reject its answers.
2. Create **glue records** (some registrars call them "child name servers" or host records): `ns1.ipssl.cc` and `ns2.ipssl.cc`, each pointing to one server's IP.
3. Then set the domain's name servers to `ns1.ipssl.cc` and `ns2.ipssl.cc`.
4. Once the change has propagated, check it:

```bash
dig +trace 10-0-0-1.ipssl.cc
```

### 5. Updating the config

Edit `/etc/ipssl/config.toml` (bump `soa.serial` too), check it, then reload:

```bash
sudo ipssl-dns -c /etc/ipssl/config.toml --check
```

```bash
sudo systemctl reload ipssl-dns
```

On reload (SIGHUP) the server re-reads the file and switches to the new records without dropping queries. `systemctl reload` runs the same check first and fails if the config does not pass. The server itself checks the whole file too, including the sections that need a restart: if anything is wrong, it logs the error, counts a failed reload and keeps answering from the running config. Changes to `listen`, `tcp_timeout_secs`, `[rate_limit]`, `[metrics]` and `[acme]` only take effect after a restart. With `[acme]`, restart the name servers one at a time (see [step 7](#7-dns-01-challenge-api-optional)).

### 6. Mail for the domain

To receive mail such as `abuse@ipssl.cc`, add the records your mail server asks for under `[hosts]`. Paste DKIM keys in one piece; values over 255 bytes are split automatically.

`[hosts]` takes A, AAAA, TXT and MX records only. Providers that need CNAME records, such as Amazon SES with Easy DKIM, are not supported: pick a DKIM setup that publishes the key in a TXT record.

```toml
[hosts."@"]
mx = [{ preference = 10, exchange = "mail.example.net" }]
txt = ["v=spf1 mx -all"]

[hosts."202611r._domainkey"]
txt = ["v=DKIM1; k=rsa; h=sha256; p=MIIBIjANBgkq..."]

[hosts._dmarc]
txt = ["v=DMARC1; p=quarantine; rua=mailto:postmaster@ipssl.cc"]
```

### 7. DNS-01 challenge API (optional)

This step enables [certificates for private addresses](#certificates-for-private-addresses). The API runs on one host, here the web server behind `https://ipssl.cc`. It checks each request and sends it to every name server. It reports success only once all of them hold the value, so the CA finds it whichever name server it asks.

1. On every name server, add an `[acme]` section to the config (see `config.example.toml`), with the API host's address in `writers`:

   ```toml
   [acme]
   listen = "0.0.0.0:8053"
   writers = ["198.51.100.10"]
   ```

   Open TCP port 8053 to that address only, then restart `ipssl-dns`. The server also closes connections from other addresses without an answer. The values live in memory only, so a restart drops the challenges in flight: restart the name servers one at a time, and not while a certificate is being issued.

   Do this on all name servers at least the zone's negative TTL (`soa.minimum`, 300 seconds by default) before the first DNS-01 issuance: until then they answer `_acme-challenge` names with an empty answer, which resolvers, the CA's included, may still have cached.

2. On the API host, put the same config at `/etc/ipssl/config.toml` and run the install script with `--acme-api`. It installs `ipssl-acme-api.service`, checks the config and starts the API:

   ```bash
   sudo sh install.sh --acme-api
   ```

   Later runs upgrade it, with or without the flag. The script enables a service only when its flag is given, so it never starts a DNS server on the API host by mistake.

   The config check lists the name server endpoints the API writes to:

   ```bash
   ipssl-dns --acme-api -c /etc/ipssl/config.toml --check
   ```

   By default that is each name server's first address of the family `acme.listen` uses (IPv4 for `0.0.0.0:8053`, IPv6 for `[::]:8053`), on the `acme.listen` port. If a name server has no address of that family, for example one outside the zone, list the endpoints in `acme.nodes`: the API refuses to start without them.

   When the set of name servers changes, update the API host's config too and restart `ipssl-acme-api`: it reads the config only when it starts.

3. Add the two locations from [`deploy/acme/nginx.conf`](deploy/acme/nginx.conf) to the website's `server` block, so the API is reachable over HTTPS at `/acme`, and reload nginx.

## Rate limiting

UDP source addresses are easy to forge, so an open authoritative server can be used to send floods of answers to someone else. The server limits UDP responses per client network (`/24` for IPv4, `/56` for IPv6), by default to 50 a second with bursts of up to 100. Over the limit, every second response is sent truncated and the rest are dropped. A real resolver that gets a truncated response retries over TCP, which cannot be forged and is never limited, so it still gets its answer.

Tune or turn it off in the `[rate_limit]` section of the config.

## Monitoring

With a `[metrics]` section in the config, the server serves Prometheus metrics over plain HTTP, by default at `127.0.0.1:9153`. Keep that address private. An IPv6 address such as `[::1]:9153` accepts IPv6 connections only.

```bash
curl -s http://127.0.0.1:9153/metrics
```

| Metric | Meaning |
|---|---|
| `ipssl_dns_queries_total{protocol, qtype}` | Requests received |
| `ipssl_dns_responses_total{rcode}` | Responses handed to hickory to send |
| `ipssl_dns_send_errors_total` | Responses hickory would not take for sending |
| `ipssl_dns_truncated_total` | UDP answers too large for the client's buffer, sent truncated so it retries over TCP |
| `ipssl_dns_rate_limited_total{action}` | UDP responses dropped (`drop`) or sent truncated (`slip`) by rate limiting |
| `ipssl_rate_limit_tracked_networks` | Client networks the rate limiter is tracking |
| `ipssl_config_reloads_total{result}` | Config reloads that succeeded or failed |
| `ipssl_acme_challenges` | DNS-01 challenge values being served; an expired value drops out at once (with `[acme]` only) |
| `ipssl_acme_writes_total{result}` | Challenge writes: `accepted`, `rejected` (wrong path or method, a body that holds no valid challenge, or a value over a cap) or `forbidden` (a connection from an address not in `writers`, closed before it is read) (with `[acme]` only) |
| `ipssl_zone_serial` | SOA serial being served; compare across servers to check they run the same config |
| `ipssl_build_info{version}` | Version of the running binary |
| `process_start_time_seconds` | When the process started |

What the DNS counters leave out:

- hickory answers some UDP packets it cannot decode with FORMERR itself, before the server sees them. Those replies are not counted as requests or responses, and rate limiting does not apply to them.
- A response counts in `ipssl_dns_responses_total` once it is handed to hickory. If sending a UDP response fails after that, hickory only logs it, so it is not in `ipssl_dns_send_errors_total`.

`forbidden` counts port scanners that reach the write port too, so expect a trickle. When the API host's outgoing address stops matching `writers`, every write from the API lands there instead of in `accepted`, and as `failed` in the API's own metrics below.

The DNS-01 challenge API (`ipssl-dns --acme-api`) serves its own metrics at `[metrics].listen`:

| Metric | Meaning |
|---|---|
| `ipssl_acme_api_requests_total{endpoint, status}` | Responses by endpoint (`present`, `cleanup` or `other`) and status: `200`, `400`, `403` (a name with a public or blocked address), `404`, `405`, `409` (over a cap on pending values), `411`, `413`, `429` (rate limited), `502` (a name server did not take the change), `503` (every connection slot busy) or `other` |
| `ipssl_acme_api_node_writes_total{node, result}` | Changes sent to each name server: `accepted`, `rejected` (over a cap on pending values) or `failed` (down, too slow, or an answer that is not the name server's `{"ok":true}`) |
| `ipssl_rate_limit_tracked_networks` | Client networks the API's rate limiter is tracking |
| `ipssl_build_info{version}` | Version of the running binary |
| `process_start_time_seconds` | When the process started |

On a host that runs both the DNS server and the API, the two cannot share a `[metrics].listen` address, so give the API a config file of its own (and point `ipssl-acme-api.service` at it). With one shared config, whichever starts second cannot listen there: the API then runs without metrics and logs a warning, but the DNS server does not start.

## Website

The landing page at https://ipssl.cc lives in [`site/`](site/): plain HTML, CSS and JavaScript with no build step. Its hostname converter (`site/assets/app.js`) is a port of `src/parse.rs`, so keep the two in step when the naming rules change. Converting a name happens in the browser. The page looks a name up, through Cloudflare's DNS-over-HTTPS API, only when asked to: with the Check button, or Enter once the box holds a name (Enter on an IP address converts it first). For a name with an address, it asks for the name with a random label in front, which resolves the same, so the answer comes from ipssl.cc and not from Cloudflare's cache.

Preview it locally:

```bash
python3 -m http.server 4173 --directory site
```

To publish, copy the contents of `site/` into the web server's document root, following symlinks: `site/acme/` and `site/install.sh` link to the scripts in `deploy/`, so they are also served at `https://ipssl.cc/acme/` and `https://ipssl.cc/install.sh`. On the web server, with the document root at `/var/www/ipssl.cc`:

```bash
sudo cp -RL site/. /var/www/ipssl.cc/
```

Or from another machine:

```bash
rsync -aL site/ web.example.net:/var/www/ipssl.cc/
```

Bump the `?v=` query on the stylesheet and script links in the HTML files so browsers fetch the new versions.

## FAQ

**Private IPs don't resolve?** Many routers (OpenWrt, pfSense, dnsmasq, Fritz!Box and others) have DNS rebinding protection, which drops answers pointing to private addresses. Allowlist this domain there, or use a public resolver.

**Why not hand out a wildcard certificate?** Publishing a private key breaks the CA's subscriber agreement, and anyone holding the key can revoke the certificate. Get a certificate on your own server instead (see [HTTPS certificates](#https-certificates)).

**How do I report abuse?** Email abuse@ipssl.cc or open an issue on GitHub with the name and what it is used for. The server's blocklist takes IP networks, not names, so blocking an address blocks every name that encodes it.

**Why isn't ipssl.cc on the Public Suffix List?** The PSL explicitly excludes services that resolve an IP address encoded in a hostname to that address: the same IP can be assigned to different people over time, so it does not show stable control of a name. DNS resolution does not depend on the PSL, but browsers do: they treat every name under `ipssl.cc` as one site, which is why cookies with `Domain=ipssl.cc` must be avoided (see [Shared names](#shared-names)).

## Releasing

1. Bump `version` in `Cargo.toml`, then run `cargo check` so `Cargo.lock` records the new version too: the release builds use `--locked` and fail otherwise. Commit both files.
2. Tag the commit with the same version and push the tag:

```bash
git tag v0.5.0
git push origin v0.5.0
```

The [release workflow](.github/workflows/release.yml) checks that the tag matches `Cargo.toml`, checks the code with the minimum Rust version, runs the tests on x86_64 and aarch64, and builds static musl binaries. It publishes them with a `SHA256SUMS` file only if the tag still points at the commit it built. Tags with a suffix, such as `v0.3.0-rc.1`, become pre-releases; build metadata after a `+` does not count.

## Roadmap

- [x] v0.1: DNS core (A/AAAA/SOA/NS/CAA/TXT, UDP + TCP, EDNS)
- [x] v0.2: Response rate limiting (RRL), config hot reload, Prometheus metrics
- [x] v0.3: MX records and long TXT values (DKIM keys) for mail on the domain
- [x] v0.4: DNS-01 challenges, so names with private addresses can get certificates
- [x] v0.5: NODATA for names without an address, stricter config checks, a sturdier challenge API and safer upgrades
- [x] Ask Let's Encrypt to raise the rate limit for `ipssl.cc`
- [x] Landing page

## License

Released under the [MIT License](LICENSE).
