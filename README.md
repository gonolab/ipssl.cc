# ipssl.cc

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

This only works for public addresses the CA can reach. Private addresses such as `192-168-1-10.ipssl.cc` cannot be validated this way.

Every name under `ipssl.cc` shares the domain's Let's Encrypt rate limit for certificates per registered domain. The service asks Let's Encrypt to raise that limit for `ipssl.cc`.

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
- `tests/dns.rs`: starts the server on a local port and sends real queries over UDP and TCP

## Deployment

### 1. Servers

Use at least two VPSes, with different providers in different regions. Each needs a fixed public IPv4 address, ideally IPv6 as well.

Open **UDP 53 and TCP 53** on every server.

### 2. Build

Building on the server itself is simplest:

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

```bash
sudo install -m 755 target/release/ipssl-dns /usr/local/bin/
sudo install -d /etc/ipssl
sudo install -m 644 config.toml /etc/ipssl/config.toml
sudo install -m 644 deploy/ipssl-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ipssl-dns
```

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

## FAQ

**Private IPs don't resolve?** Many routers (OpenWrt, pfSense, dnsmasq, Fritz!Box and others) have DNS rebinding protection, which drops answers pointing to private addresses. Allowlist this domain there, or use a public resolver.

**Why not hand out a wildcard certificate?** Publishing a private key breaks the CA's subscriber agreement, and anyone holding the key can revoke the certificate. Get a certificate on your own server instead (see [HTTPS certificates](#https-certificates)).

**Why isn't ipssl.cc on the Public Suffix List?** The PSL explicitly excludes services that resolve an IP address encoded in a hostname to that address: the same IP can be assigned to different people over time, so it does not show stable control of a name. DNS resolution does not depend on the PSL.

## Roadmap

- [x] v0.1: DNS core (A/AAAA/SOA/NS/CAA/TXT, UDP + TCP, EDNS)
- [ ] v0.2: Response rate limiting (RRL), blocklist hot reload, Prometheus metrics
- [ ] Ask Let's Encrypt to raise the rate limit for `ipssl.cc`
- [ ] Landing page

## License

Released under the [MIT License](LICENSE).
