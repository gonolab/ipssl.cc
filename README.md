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

- When a name contains more than one address, the rightmost one (closest to the zone) wins.
- Numbers with leading zeros (such as `010`) are rejected, so nobody has to guess whether they are octal.
- An AAAA query for an IPv4 name (and the other way round) returns NODATA, not NXDOMAIN.
- A TXT query for `ip.ipssl.cc` returns the address the query came from (usually your recursive resolver). Handy for debugging.

## HTTPS certificates

Get certificates on your own server, the same way as with nip.io and sslip.io. `203-0-113-10.ipssl.cc` resolves to `203.0.113.10`, so an ACME client running on that server (certbot, acme.sh, Caddy and others) passes HTTP-01 or TLS-ALPN-01 validation as usual:

```bash
certbot certonly --standalone -d 203-0-113-10.ipssl.cc
```

Any ACME CA works: the zone publishes no CAA record that would limit the choice.

This only works for public addresses the CA can reach. Names with private addresses such as `192-168-1-10.ipssl.cc` use DNS-01 instead, see [below](#certificates-for-private-addresses).

Every name under `ipssl.cc` shares the domain's Let's Encrypt rate limit for certificates per registered domain. The service asks Let's Encrypt to raise that limit for `ipssl.cc`.

## Certificates for private addresses

A CA cannot reach `10.0.2.2` or `192.168.1.10`, so names with private addresses prove control through DNS instead (DNS-01). Your ACME client publishes the challenge through the ipssl.cc API, and the CA finds it in DNS. This works for every name whose address is private (`10/8`, `172.16/12`, `192.168/16`), shared (`100.64/10`), loopback or link-local, IPv4 or IPv6. Wildcards such as `*.10-0-2-2.ipssl.cc` work too.

The API takes `POST https://ipssl.cc/acme/present` and `POST https://ipssl.cc/acme/cleanup` with a JSON body such as `{"fqdn": "_acme-challenge.10-0-2-2.ipssl.cc", "value": "..."}`. That is the format of lego's `httpreq` provider, so lego and Traefik work as they are:

```bash
HTTPREQ_ENDPOINT=https://ipssl.cc/acme lego --email you@example.com --dns httpreq --domains 10-0-2-2.ipssl.cc run
```

In Traefik, set the environment variable `HTTPREQ_ENDPOINT=https://ipssl.cc/acme` and use `httpreq` as the `dnsChallenge` provider.

certbot, with [`ipssl-certbot-hook.sh`](deploy/acme/ipssl-certbot-hook.sh):

```bash
certbot certonly --manual --preferred-challenges dns \
  --manual-auth-hook "sh ipssl-certbot-hook.sh present" \
  --manual-cleanup-hook "sh ipssl-certbot-hook.sh cleanup" \
  -d 10-0-2-2.ipssl.cc
```

acme.sh, with [`dns_ipssl.sh`](deploy/acme/dns_ipssl.sh) copied to `~/.acme.sh/dnsapi/`:

```bash
acme.sh --issue --dns dns_ipssl -d 10-0-2-2.ipssl.cc
```

Keep in mind:

- The certificate encrypts the connection, but it does not prove whose machine you reached. `10.0.2.2` exists on countless networks, and anyone can get a certificate for the same name.
- Names with public addresses are refused: otherwise anyone could get a certificate for someone else's server. Run the ACME client on that server and use HTTP-01 or TLS-ALPN-01.
- Values must be real DNS-01 digests. They are dropped after 10 minutes, and each client network can make 10 requests a minute.
- These certificates count toward the same Let's Encrypt limit as every other name under `ipssl.cc`. Keep a certificate until it is due for renewal, or use another CA such as ZeroSSL or Google Trust Services.

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

On a first install it writes the example config to `/etc/ipssl/config.toml` and stops: fill it in, then start the service as the script says. If a config is already there (for example copied over with `scp` first), the script checks it and starts the service right away.

Run the script again to upgrade, optionally with a version such as `v0.2.0`. It checks the existing config with the new binary before replacing anything, then restarts the service.

To do it by hand, download a static Linux build from [Releases](https://github.com/gonolab/ipssl.cc/releases) and check it:

```bash
VERSION=v0.2.0
TARGET=x86_64-unknown-linux-musl   # or aarch64-unknown-linux-musl
BASE=https://github.com/gonolab/ipssl.cc/releases/download/$VERSION
curl -fLO "$BASE/ipssl-dns-$VERSION-$TARGET.tar.gz"
curl -fLO "$BASE/SHA256SUMS"
sha256sum -c --ignore-missing SHA256SUMS
tar -xzf "ipssl-dns-$VERSION-$TARGET.tar.gz"
cd "ipssl-dns-$VERSION-$TARGET"
```

The archive holds the binary, `config.example.toml`, `ipssl-dns.service`, the README and the license.

Or build it yourself with Rust 1.88 or newer. On the server:

```bash
cargo build --release
```

To cross-compile a static Linux binary on macOS:

```bash
cargo install cargo-zigbuild
```

```bash
rustup target add x86_64-unknown-linux-musl
```

```bash
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

### 3. Install

Copy `config.example.toml` to `config.toml` and fill in your servers' addresses. Then, from the release directory:

```bash
sudo install -m 755 ipssl-dns /usr/local/bin/
sudo install -d /etc/ipssl
sudo install -m 644 config.toml /etc/ipssl/config.toml
sudo install -m 644 ipssl-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ipssl-dns
```

From a source checkout, the binary is `target/release/ipssl-dns` (or `target/x86_64-unknown-linux-musl/release/ipssl-dns`) and the unit file is `deploy/ipssl-dns.service`.

On Ubuntu, systemd-resolved holds `127.0.0.53:53` by default, which can make binding `0.0.0.0:53` fail. Two ways around it:

- List only the server's public IP in `listen`.
- Or set `DNSStubListener=no` in `/etc/systemd/resolved.conf` and restart systemd-resolved.

### 4. Registrar setup

1. Create **glue records** first (some registrars call them "child name servers" or host records): `ns1.ipssl.cc` and `ns2.ipssl.cc`, each pointing to one server's IP.
2. Then set the domain's name servers to `ns1.ipssl.cc` and `ns2.ipssl.cc`.
3. Once the change has propagated, check it:

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

On reload (SIGHUP) the server re-reads the file and switches to the new records without dropping queries. If the file has an error, the server logs it and keeps answering from the running config. Changes to `listen`, `tcp_timeout_secs`, `[rate_limit]`, `[metrics]` and `[acme]` only take effect after a restart.

### 6. Mail for the domain

To receive mail such as `abuse@ipssl.cc`, add the records your mail server asks for under `[hosts]`. Paste DKIM keys in one piece; values over 255 bytes are split automatically.

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

   Open TCP port 8053 to that address only, then restart `ipssl-dns`. The values live in memory only.

2. On the API host, put the same config at `/etc/ipssl/config.toml`, install the binary and `ipssl-acme-api.service`, and start it:

   ```bash
   sudo ipssl-dns --acme-api -c /etc/ipssl/config.toml --check
   ```

   ```bash
   sudo systemctl enable --now ipssl-acme-api
   ```

   The check lists the name server endpoints it will write to: by default, each name server's first address on port 8053.

3. Add the two locations from [`deploy/acme/nginx.conf`](deploy/acme/nginx.conf) to the website's `server` block, so the API is reachable over HTTPS at `/acme`, and reload nginx.

## Rate limiting

UDP source addresses are easy to forge, so an open authoritative server can be used to send floods of answers to someone else. The server limits UDP responses per client network (`/24` for IPv4, `/56` for IPv6), by default to 50 a second with bursts of up to 100. Over the limit, every second response is sent truncated and the rest are dropped. A real resolver that gets a truncated response retries over TCP, which cannot be forged and is never limited, so it still gets its answer.

Tune or turn it off in the `[rate_limit]` section of the config.

## Monitoring

With a `[metrics]` section in the config, the server serves Prometheus metrics over plain HTTP, by default at `127.0.0.1:9153`. Keep that address private.

```bash
curl -s http://127.0.0.1:9153/metrics
```

| Metric | Meaning |
|---|---|
| `ipssl_dns_queries_total{protocol, qtype}` | Requests received |
| `ipssl_dns_responses_total{rcode}` | Responses sent |
| `ipssl_dns_send_errors_total` | Responses that could not be sent |
| `ipssl_dns_truncated_total` | UDP answers too large for the client's buffer, sent truncated so it retries over TCP |
| `ipssl_dns_rate_limited_total{action}` | UDP responses dropped (`drop`) or sent truncated (`slip`) by rate limiting |
| `ipssl_rate_limit_tracked_networks` | Client networks the rate limiter is tracking |
| `ipssl_config_reloads_total{result}` | Config reloads that succeeded or failed |
| `ipssl_acme_challenges` | DNS-01 challenge values being served (with `[acme]` only) |
| `ipssl_acme_writes_total{result}` | Challenge writes from the API, `accepted` or `rejected` (with `[acme]` only) |
| `ipssl_zone_serial` | SOA serial being served; compare across servers to check they run the same config |
| `ipssl_build_info{version}` | Version of the running binary |
| `process_start_time_seconds` | When the process started |

## Website

The landing page at https://ipssl.cc lives in [`site/`](site/): plain HTML, CSS and JavaScript with no build step. Its hostname converter (`site/assets/app.js`) is a port of `src/parse.rs`, so keep the two in step when the naming rules change. The "Check live" button looks names up through Cloudflare's DNS-over-HTTPS API, and only when clicked.

Preview it locally:

```bash
python3 -m http.server 4173 --directory site
```

To publish, copy the contents of `site/` into the web server's document root, and bump the `?v=` query on the stylesheet and script links in the HTML files so browsers fetch the new versions.

## FAQ

**Private IPs don't resolve?** Many routers (OpenWrt, pfSense, dnsmasq, Fritz!Box and others) have DNS rebinding protection, which drops answers pointing to private addresses. Allowlist this domain there, or use a public resolver.

**Why not hand out a wildcard certificate?** Publishing a private key breaks the CA's subscriber agreement, and anyone holding the key can revoke the certificate. Get a certificate on your own server instead (see [HTTPS certificates](#https-certificates)).

**How do I report abuse?** Email abuse@ipssl.cc or open an issue on GitHub with the name and what it is used for. Names used for abuse can be put on the server's blocklist.

**Why isn't ipssl.cc on the Public Suffix List?** The PSL explicitly excludes services that resolve an IP address encoded in a hostname to that address: the same IP can be assigned to different people over time, so it does not show stable control of a name. DNS resolution does not depend on the PSL.

## Releasing

1. Bump `version` in `Cargo.toml` and commit.
2. Tag the commit with the same version and push the tag:

```bash
git tag v0.2.0
git push origin v0.2.0
```

The [release workflow](.github/workflows/release.yml) checks that the tag matches `Cargo.toml`, runs the tests on x86_64 and aarch64, builds static musl binaries and publishes them with a `SHA256SUMS` file. Tags with a suffix, such as `v0.3.0-rc.1`, become pre-releases.

## Roadmap

- [x] v0.1: DNS core (A/AAAA/SOA/NS/CAA/TXT, UDP + TCP, EDNS)
- [x] v0.2: Response rate limiting (RRL), config hot reload, Prometheus metrics
- [x] v0.3: MX records and long TXT values (DKIM keys) for mail on the domain
- [x] v0.4: DNS-01 challenges, so names with private addresses can get certificates
- [ ] Ask Let's Encrypt to raise the rate limit for `ipssl.cc`
- [x] Landing page

## License

Released under the [MIT License](LICENSE).
