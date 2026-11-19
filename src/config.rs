//! TOML configuration. See `config.example.toml` for a documented example.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail, ensure};
use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, HEXLOWER_PERMISSIVE};
use ipnet::IpNet;
use serde::{Deserialize, Deserializer};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The zone this server is authoritative for, e.g. `ipssl.cc`.
    pub domain: String,

    /// Addresses to serve DNS on, both UDP and TCP. See [`Config::validate`]
    /// for what is allowed.
    #[serde(default = "default_listen")]
    pub listen: Vec<SocketAddr>,

    /// Idle timeout for TCP connections, in seconds.
    #[serde(default = "default_tcp_timeout")]
    pub tcp_timeout_secs: u64,

    /// Authoritative name servers for the zone (at least two in production).
    pub nameservers: Vec<NameServer>,

    pub soa: SoaConfig,

    #[serde(default)]
    pub ttl: TtlConfig,

    /// CAs allowed to issue certificates for the zone (CAA `issue` at the apex).
    #[serde(default)]
    pub caa_issuers: Vec<String>,

    /// Fixed records. Keys are relative to `domain`; `@` is the apex.
    #[serde(default)]
    pub hosts: BTreeMap<String, HostConfig>,

    /// Embedded addresses in these networks get NXDOMAIN.
    #[serde(default)]
    pub blocklist: Vec<IpNet>,

    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Prometheus metrics over HTTP; off when the section is missing.
    pub metrics: Option<MetricsConfig>,

    /// DNS-01 challenges for names with private addresses, see
    /// [`crate::acme`]; off when the section is missing.
    pub acme: Option<AcmeConfig>,
}

/// DNS-01 challenge API. The same section serves both sides: name servers
/// read `listen` and `writers`, `ipssl-dns --acme-api` reads the rest.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    /// Name servers accept challenge writes on this address (plain HTTP).
    #[serde(default = "default_acme_listen")]
    pub listen: SocketAddr,
    /// Addresses allowed to write challenges to a name server: the hosts
    /// running the API. Everyone else is refused.
    #[serde(default)]
    pub writers: Vec<IpAddr>,
    /// Where the API listens. Keep it on loopback behind a TLS reverse
    /// proxy that sets `X-Real-IP`.
    #[serde(default = "default_acme_api_listen")]
    pub api_listen: SocketAddr,
    /// Name server write endpoints the API sends every challenge to. Empty
    /// means each name server's first address of the `listen` family on
    /// the `listen` port, see [`AcmeConfig::node_addrs`]. When set, it
    /// must list an endpoint for every name server, see
    /// [`Config::validate_acme_api`].
    #[serde(default)]
    pub nodes: Vec<SocketAddr>,
    /// API requests per minute for each client network.
    #[serde(default = "default_acme_requests_per_minute")]
    pub requests_per_minute: u32,
    /// API requests a client network may make at once.
    #[serde(default = "default_acme_burst")]
    pub burst: u32,
    /// Shared secret that signs every write from the API to the name
    /// servers and every answer to it, see [`crate::acme`]. With a key, a
    /// name server takes only signed writes, and the API trusts only
    /// signed answers (but see `allow_unsigned_nodes`).
    #[serde(default)]
    pub key: Option<AcmeKey>,
    /// API only, while `key` is being rolled out: also trust unsigned
    /// answers, from name servers that do not have the key yet. A wrongly
    /// signed answer is never trusted.
    #[serde(default)]
    pub allow_unsigned_nodes: bool,
}

/// Fewest bytes `acme.key` may have: as many as the SHA-256 output.
pub const MIN_KEY_BYTES: usize = 32;

/// Shortest run of hex or base64 characters that [`redact_keys`] takes
/// for a key: an `acme.key` long enough to use is 43 or more, and half of
/// one in hex is 32.
const KEY_RUN: usize = 32;

/// `text` with every run of [`KEY_RUN`] or more characters that keys in
/// hex or base64 are made of replaced by `<redacted>`. Other long runs
/// (a DKIM key, say) go too, which only makes an error a little vaguer.
fn redact_keys(text: &str) -> String {
    let in_key = |c: char| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_');
    let mut redacted = String::with_capacity(text.len());
    let mut run = String::new();
    let flush = |redacted: &mut String, run: &mut String| {
        if run.len() >= KEY_RUN {
            redacted.push_str("<redacted>");
        } else {
            redacted.push_str(run);
        }
        run.clear();
    };
    for c in text.chars() {
        if in_key(c) {
            run.push(c);
        } else {
            flush(&mut redacted, &mut run);
            redacted.push(c);
        }
    }
    flush(&mut redacted, &mut run);
    redacted
}

/// The secret in `acme.key`, given as hex or base64.
///
/// It is decoded as the config is read, but a bad key is reported only by
/// [`Config::validate`] and [`Config::validate_acme_api`]: a parse error
/// would quote the line it is on. `Debug` never shows it either.
#[derive(Clone, PartialEq, Eq)]
pub struct AcmeKey(std::result::Result<Vec<u8>, KeyProblem>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyProblem {
    Encoding,
    Short(usize),
}

impl AcmeKey {
    /// Decodes `text`: hex if it is hex digits only, otherwise base64,
    /// standard or URL-safe, with or without padding.
    pub fn decode(text: &str) -> Self {
        let text = text.trim().as_bytes();
        let hex = !text.is_empty()
            && text.len().is_multiple_of(2)
            && text.iter().all(u8::is_ascii_hexdigit);
        let bytes = if hex {
            HEXLOWER_PERMISSIVE.decode(text).ok()
        } else {
            [&BASE64, &BASE64_NOPAD, &BASE64URL, &BASE64URL_NOPAD]
                .iter()
                .find_map(|encoding| encoding.decode(text).ok())
        };
        Self(match bytes {
            None => Err(KeyProblem::Encoding),
            Some(bytes) if bytes.len() < MIN_KEY_BYTES => Err(KeyProblem::Short(bytes.len())),
            Some(bytes) => Ok(bytes),
        })
    }

    /// The key's bytes, or why it cannot be used.
    pub fn bytes(&self) -> Result<&[u8]> {
        match &self.0 {
            Ok(bytes) => Ok(bytes),
            Err(KeyProblem::Encoding) => bail!(
                "acme.key must be hex or base64; create one with `openssl rand -hex {MIN_KEY_BYTES}`"
            ),
            Err(KeyProblem::Short(n)) => bail!(
                "acme.key has {n} bytes, but needs at least {MIN_KEY_BYTES}; create one with \
                 `openssl rand -hex {MIN_KEY_BYTES}`"
            ),
        }
    }
}

impl fmt::Debug for AcmeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcmeKey(..)")
    }
}

impl<'de> Deserialize<'de> for AcmeKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(|text| Self::decode(&text))
    }
}

impl AcmeConfig {
    /// Write endpoints of every name server, as the API reaches them, each
    /// once: `nodes` when set, otherwise each name server's first address
    /// on the `listen` port. Name servers that share an address (one host
    /// serving several names) share an endpoint. A name server with a key
    /// takes each signed write once, so the same endpoint twice would fail
    /// every change.
    ///
    /// The address has to be of the family `listen` accepts: IPv6 listeners
    /// are IPv6-only (see [`crate::bind_tcp`]), so `[::]:8053` cannot be
    /// reached over IPv4, nor `0.0.0.0:8053` over IPv6. A name server with no
    /// such address, such as one outside the zone (those never have
    /// addresses here), is an error rather than skipped: the API would
    /// report success without it while the CA may still ask it.
    pub fn node_addrs(&self, nameservers: &[NameServer]) -> Result<Vec<SocketAddr>> {
        if !self.nodes.is_empty() {
            return Ok(unique(self.nodes.iter().copied()));
        }
        let port = self.listen.port();
        let nodes: Result<Vec<_>> = nameservers
            .iter()
            .map(|ns| {
                let ip = if self.listen.is_ipv4() {
                    ns.ipv4.first().map(|ip| IpAddr::V4(*ip))
                } else {
                    ns.ipv6.first().map(|ip| IpAddr::V6(*ip))
                };
                let family = if self.listen.is_ipv4() {
                    "IPv4"
                } else {
                    "IPv6"
                };
                ip.map(|ip| SocketAddr::new(ip, port)).with_context(|| {
                    format!(
                        "name server {} has no {family} address to send challenges to \
                         (acme.listen is {}); list every name server's write endpoint \
                         in acme.nodes",
                        ns.name, self.listen
                    )
                })
            })
            .collect();
        Ok(unique(nodes?))
    }
}

/// `addrs` without repeats, in their order.
fn unique(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut unique = Vec::new();
    for addr in addrs {
        if !unique.contains(&addr) {
            unique.push(addr);
        }
    }
    unique
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Address to serve `/metrics` on. Keep it private: loopback or an
    /// internal network.
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NameServer {
    /// Host name, e.g. `ns1.ipssl.cc`. In-zone names get A/AAAA from the
    /// addresses below.
    pub name: String,
    #[serde(default)]
    pub ipv4: Vec<Ipv4Addr>,
    #[serde(default)]
    pub ipv6: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoaConfig {
    /// Contact address, e.g. `hostmaster@ipssl.cc`.
    pub email: String,
    #[serde(default = "default_serial")]
    pub serial: u32,
    #[serde(default = "default_refresh")]
    pub refresh: i32,
    #[serde(default = "default_retry")]
    pub retry: i32,
    #[serde(default = "default_expire")]
    pub expire: i32,
    /// TTL for negative answers (NXDOMAIN / NODATA), in seconds.
    #[serde(default = "default_negative_ttl")]
    pub minimum: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TtlConfig {
    /// TTL for answers computed from the name. They never change, so this
    /// can be long.
    #[serde(default = "default_ip_ttl")]
    pub ip: u32,
    /// TTL for fixed records: SOA, NS, CAA and `hosts`.
    #[serde(default = "default_records_ttl")]
    pub records: u32,
}

impl Default for TtlConfig {
    fn default() -> Self {
        Self {
            ip: default_ip_ttl(),
            records: default_records_ttl(),
        }
    }
}

/// UDP response rate limiting, see [`crate::ratelimit`].
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// UDP responses per second for each client network; 0 turns limiting off.
    #[serde(default = "default_responses_per_second")]
    pub responses_per_second: u32,
    /// How many responses a client network may get at once before the rate applies.
    #[serde(default = "default_burst")]
    pub burst: u32,
    /// Every `slip`-th limited response is sent truncated, so real resolvers
    /// retry over TCP; the others are dropped. 0 drops them all.
    #[serde(default = "default_slip")]
    pub slip: u32,
    /// Clients in the same IPv4 network of this size share one limit.
    #[serde(default = "default_ipv4_prefix")]
    pub ipv4_prefix: u8,
    /// Clients in the same IPv6 network of this size share one limit.
    #[serde(default = "default_ipv6_prefix")]
    pub ipv6_prefix: u8,
    /// Clients that are never limited, e.g. monitoring.
    #[serde(default)]
    pub exempt: Vec<IpNet>,
    /// Most client networks tracked at once. Bounds memory; when the table
    /// is full, new networks share a single limit. Approximate, since the
    /// table is split into parts that fill up on their own.
    #[serde(default = "default_max_tracked")]
    pub max_tracked: usize,
}

impl RateLimitConfig {
    /// Checks the settings the DNS server's limiter uses. Nothing is
    /// checked while limiting is off (`responses_per_second = 0`).
    pub fn validate(&self) -> Result<()> {
        if self.responses_per_second == 0 {
            return Ok(());
        }
        ensure!(self.burst >= 1, "rate_limit.burst must be at least 1");
        self.validate_networks()
    }

    /// Checks how clients are grouped into networks and how many are
    /// tracked. The API's limiter uses these settings too, even when the
    /// DNS server's limiting is off.
    pub fn validate_networks(&self) -> Result<()> {
        ensure!(
            self.ipv4_prefix <= 32,
            "rate_limit.ipv4_prefix must be 0..=32"
        );
        ensure!(
            self.ipv6_prefix <= 128,
            "rate_limit.ipv6_prefix must be 0..=128"
        );
        ensure!(
            self.max_tracked >= 1,
            "rate_limit.max_tracked must be at least 1"
        );
        Ok(())
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            responses_per_second: default_responses_per_second(),
            burst: default_burst(),
            slip: default_slip(),
            ipv4_prefix: default_ipv4_prefix(),
            ipv6_prefix: default_ipv6_prefix(),
            exempt: Vec::new(),
            max_tracked: default_max_tracked(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    #[serde(default)]
    pub a: Vec<Ipv4Addr>,
    #[serde(default)]
    pub aaaa: Vec<Ipv6Addr>,
    /// One TXT record per entry. Values longer than 255 bytes (such as RSA
    /// DKIM keys) are split into several strings automatically.
    #[serde(default)]
    pub txt: Vec<String>,
    #[serde(default)]
    pub mx: Vec<MxConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MxConfig {
    /// Lower values are tried first.
    pub preference: u16,
    /// Mail server host name, always taken as absolute (`mx.example.net`,
    /// not relative to `domain`). `.` with preference 0 is a null MX
    /// (RFC 7505): the name accepts no mail.
    pub exchange: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        // A parse error quotes the line it is on, and its message may
        // quote a value. Either may be acme.key, mistyped or in the wrong
        // place, which must not end up on the terminal or in the journal.
        toml::from_str(text).map_err(|e| anyhow!(redact_keys(&e.to_string())))
    }

    /// Checks the settings the DNS server would otherwise trip over only
    /// at startup or later. `--check`, startup and reload all run it, so a
    /// config that passes is one the server accepts. The zone's own data
    /// is checked by [`crate::zone::Zone::from_config`].
    pub fn validate(&self) -> Result<()> {
        // With no listener the server would have nothing to do and exit at
        // once, and the service manager would restart it in a loop.
        ensure!(
            !self.listen.is_empty(),
            "listen is empty: give at least one address to serve DNS on"
        );
        for addr in &self.listen {
            // UDP and TCP bind separately, so port 0 would give them two
            // different ports, and TCP fallback after a truncated UDP
            // answer would go nowhere.
            ensure!(
                addr.port() != 0,
                "listen {addr}: port 0 is not allowed, give the port to serve DNS on"
            );
        }
        self.check_tcp_overlaps()?;
        if let Some(acme) = &self.acme
            && let Some(key) = &acme.key
        {
            key.bytes()?;
        }
        self.rate_limit.validate()
    }

    /// Checks the settings `ipssl-dns --acme-api` uses, for both `--check`
    /// and start. The zone is checked when the API builds it.
    pub fn validate_acme_api(&self) -> Result<()> {
        let acme = self
            .acme
            .as_ref()
            .context("the [acme] section is missing")?;
        ensure!(
            acme.requests_per_minute >= 1 && acme.burst >= 1,
            "acme.requests_per_minute and acme.burst must be at least 1"
        );
        if let Some(key) = &acme.key {
            key.bytes()?;
        }
        // The API groups and tracks clients the way the DNS server does.
        self.rate_limit.validate_networks()?;
        let nodes = acme.node_addrs(&self.nameservers)?;
        ensure!(
            !nodes.is_empty(),
            "no name server to send challenges to: set acme.nodes or give the name servers addresses"
        );
        // A CA may ask any name server, so the API must reach all of them
        // before it reports a value as published. Endpoints in `nodes`
        // cannot be matched to name servers, but there must be at least as
        // many as there are hosts; see `acme_api_warnings` for name
        // servers that share one.
        let hosts = name_server_hosts(&self.nameservers);
        ensure!(
            acme.nodes.is_empty() || nodes.len() >= hosts,
            "acme.nodes lists {} write endpoint(s), but the {} name servers run on {hosts} \
             host(s) (name servers that share an address are one host): list every \
             name server's endpoint, or the API would report values as published that \
             some name servers never got",
            nodes.len(),
            self.nameservers.len()
        );
        Ok(())
    }

    /// Settings `ipssl-dns --acme-api` accepts that are probably not what
    /// was meant, as messages for the log.
    pub fn acme_api_warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        let Some(acme) = &self.acme else {
            return warnings;
        };
        if !acme.nodes.is_empty()
            && let Ok(nodes) = acme.node_addrs(&self.nameservers)
            && nodes.len() < self.nameservers.len()
        {
            warnings.push(format!(
                "acme.nodes lists {} write endpoint(s) for {} name servers; that is only \
                 right if the name servers that share an address are one host",
                nodes.len(),
                self.nameservers.len()
            ));
        }
        match (&acme.key, acme.allow_unsigned_nodes) {
            (None, false) => warnings.push(
                "acme.key is not set, so nothing proves that writes to the name servers, \
                 or their answers, are genuine"
                    .to_owned(),
            ),
            (None, true) => {
                warnings.push("acme.allow_unsigned_nodes does nothing without acme.key".to_owned());
            }
            (Some(_), true) => warnings.push(
                "acme.allow_unsigned_nodes is on, so unsigned answers from name servers are \
                 trusted; remove it once every name server has acme.key"
                    .to_owned(),
            ),
            (Some(_), false) => {}
        }
        warnings
    }

    /// Fails when two of the TCP listeners the DNS server opens (every
    /// `listen` address, `[metrics]` and `[acme]`) would need the same port,
    /// since the second one could not be bound.
    fn check_tcp_overlaps(&self) -> Result<()> {
        let mut listeners: Vec<(&str, SocketAddr)> =
            self.listen.iter().map(|addr| ("listen", *addr)).collect();
        if let Some(metrics) = &self.metrics {
            listeners.push(("metrics.listen", metrics.listen));
        }
        if let Some(acme) = &self.acme {
            listeners.push(("acme.listen", acme.listen));
        }
        for (i, &(name_a, a)) in listeners.iter().enumerate() {
            for &(name_b, b) in &listeners[i + 1..] {
                ensure!(
                    !tcp_overlap(a, b),
                    "{name_a} {a} and {name_b} {b} overlap: both need TCP port {} \
                     on the same addresses; use different ports",
                    a.port()
                );
            }
        }
        Ok(())
    }

    /// Names of the settings that differ from `running` but only take
    /// effect after a restart. Everything else is applied on reload.
    pub fn restart_only_changes(&self, running: &Config) -> Vec<&'static str> {
        let mut changed = Vec::new();
        if self.listen != running.listen {
            changed.push("listen");
        }
        if self.tcp_timeout_secs != running.tcp_timeout_secs {
            changed.push("tcp_timeout_secs");
        }
        if self.rate_limit != running.rate_limit {
            changed.push("rate_limit");
        }
        if self.metrics != running.metrics {
            changed.push("metrics");
        }
        if self.acme != running.acme {
            changed.push("acme");
        }
        changed
    }
}

/// How many hosts the name servers run on: name servers that share an
/// address are one host serving several names, with one write endpoint.
/// A name server without addresses (one outside the zone) is a host of
/// its own.
fn name_server_hosts(nameservers: &[NameServer]) -> usize {
    let mut hosts: Vec<Vec<IpAddr>> = Vec::new();
    for ns in nameservers {
        let mut addrs: Vec<IpAddr> = ns.ipv4.iter().map(|&ip| IpAddr::V4(ip)).collect();
        addrs.extend(ns.ipv6.iter().map(|&ip| IpAddr::V6(ip)));
        // Merge every host this name server shares an address with.
        hosts.retain(|host| {
            let shared = host.iter().any(|ip| addrs.contains(ip));
            if shared {
                addrs.extend(host);
            }
            !shared
        });
        hosts.push(addrs);
    }
    hosts.len()
}

/// Whether TCP listeners on `a` and `b` would need the same socket: same
/// port and address family, and the same address or a wildcard on either
/// side. IPv6 listeners are IPv6-only (see [`crate::bind_tcp`]), so
/// `0.0.0.0:53` and `[::]:53` do not overlap. Port 0 picks a free port, so
/// it never clashes.
fn tcp_overlap(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() != 0
        && a.port() == b.port()
        && a.is_ipv4() == b.is_ipv4()
        && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

fn default_acme_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8053))
}

fn default_acme_api_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8054))
}

fn default_acme_requests_per_minute() -> u32 {
    10
}

fn default_acme_burst() -> u32 {
    20
}

fn default_listen() -> Vec<SocketAddr> {
    vec![
        SocketAddr::from(([0, 0, 0, 0], 53)),
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 53)),
    ]
}

fn default_tcp_timeout() -> u64 {
    10
}

fn default_serial() -> u32 {
    1
}

fn default_refresh() -> i32 {
    3600
}

fn default_retry() -> i32 {
    600
}

fn default_expire() -> i32 {
    1_209_600
}

fn default_negative_ttl() -> u32 {
    300
}

fn default_ip_ttl() -> u32 {
    86_400
}

fn default_records_ttl() -> u32 {
    3600
}

fn default_responses_per_second() -> u32 {
    50
}

fn default_burst() -> u32 {
    100
}

fn default_slip() -> u32 {
    2
}

fn default_ipv4_prefix() -> u8 {
    24
}

fn default_ipv6_prefix() -> u8 {
    56
}

fn default_max_tracked() -> usize {
    100_000
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        domain = "ipssl.cc"

        [[nameservers]]
        name = "ns1.ipssl.cc"

        [soa]
        email = "hostmaster@ipssl.cc"
    "#;

    #[test]
    fn example_config_parses() {
        Config::parse(include_str!("../config.example.toml")).unwrap();
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let text = format!("typo = 1\n{MINIMAL}");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn restart_only_changes() {
        let running = Config::parse(MINIMAL).unwrap();
        let mut next = running.clone();
        next.soa.serial += 1;
        next.blocklist.push("203.0.113.0/24".parse().unwrap());
        assert!(next.restart_only_changes(&running).is_empty());

        next.listen = vec!["127.0.0.1:5353".parse().unwrap()];
        next.tcp_timeout_secs = 30;
        next.rate_limit.burst += 1;
        next.metrics = Some(MetricsConfig {
            listen: "127.0.0.1:9153".parse().unwrap(),
        });
        next.acme = Config::parse(&format!("{MINIMAL}\n[acme]\n")).unwrap().acme;
        assert_eq!(
            next.restart_only_changes(&running),
            [
                "listen",
                "tcp_timeout_secs",
                "rate_limit",
                "metrics",
                "acme"
            ]
        );
    }

    fn err(result: Result<()>) -> String {
        format!("{:#}", result.unwrap_err())
    }

    #[test]
    fn example_config_is_valid() {
        let config = Config::parse(include_str!("../config.example.toml")).unwrap();
        config.validate().unwrap();
        let api = format!("{}\n[acme]\n", include_str!("../config.example.toml"));
        Config::parse(&api).unwrap().validate_acme_api().unwrap();
    }

    #[test]
    fn listen_must_not_be_empty() {
        let config = Config::parse(&format!("listen = []\n{MINIMAL}")).unwrap();
        assert!(err(config.validate()).contains("listen is empty"));
    }

    #[test]
    fn listen_port_zero_is_rejected() {
        let config = Config::parse(&format!("listen = [\"127.0.0.1:0\"]\n{MINIMAL}")).unwrap();
        assert!(err(config.validate()).contains("port 0"));
    }

    #[test]
    fn overlapping_tcp_listeners_are_rejected() {
        let check = |listen: &str, sections: &str| {
            let text = format!("listen = [{listen}]\n{MINIMAL}\n{sections}");
            Config::parse(&text).unwrap().validate()
        };
        let metrics = |addr: &str| format!("[metrics]\nlisten = \"{addr}\"\n");
        let acme = |addr: &str| format!("[acme]\nlisten = \"{addr}\"\n");

        // Same address and port.
        assert!(err(check("\"127.0.0.1:53\"", &metrics("127.0.0.1:53"))).contains("overlap"));
        // A wildcard covers every specific address of its family.
        assert!(check("\"0.0.0.0:9153\"", &metrics("127.0.0.1:9153")).is_err());
        assert!(check("\"[::]:8053\"", &acme("[2001:db8::1]:8053")).is_err());
        assert!(
            check(
                "\"[::]:53\"",
                &format!("{}{}", metrics("[::1]:9000"), acme("[::]:9000"))
            )
            .is_err()
        );
        // Twice in `listen`.
        assert!(check("\"0.0.0.0:53\", \"198.51.100.1:53\"", "").is_err());

        // Another port, another address or another family is fine.
        check("\"0.0.0.0:53\", \"[::]:53\"", "").unwrap();
        check("\"127.0.0.1:53\"", &metrics("127.0.0.2:53")).unwrap();
        check("\"0.0.0.0:8053\"", &acme("[::]:8053")).unwrap();
        check(
            "\"0.0.0.0:53\"",
            &format!("{}{}", metrics("127.0.0.1:9153"), acme("0.0.0.0:8053")),
        )
        .unwrap();
    }

    #[test]
    fn rate_limit_is_checked_only_when_on() {
        let config = |settings: &str| {
            Config::parse(&format!("{MINIMAL}\n[rate_limit]\n{settings}\n")).unwrap()
        };
        assert!(err(config("burst = 0").validate()).contains("burst"));
        assert!(config("ipv4_prefix = 33").validate().is_err());
        assert!(config("ipv6_prefix = 129").validate().is_err());
        assert!(config("max_tracked = 0").validate().is_err());
        config("responses_per_second = 0\nburst = 0\nmax_tracked = 0")
            .validate()
            .unwrap();
    }

    #[test]
    fn acme_api_checks_its_rate_limit() {
        let config = |settings: &str| {
            let text = format!(
                "{MINIMAL}\n[rate_limit]\n{settings}\n[acme]\nnodes = [\"127.0.0.1:8053\"]\n"
            );
            Config::parse(&text).unwrap()
        };
        config("").validate_acme_api().unwrap();
        // The API groups clients even when the DNS server's limit is off.
        for bad in ["max_tracked = 0", "ipv4_prefix = 33", "ipv6_prefix = 129"] {
            let settings = format!("responses_per_second = 0\n{bad}");
            assert!(config(&settings).validate_acme_api().is_err(), "{bad}");
        }
        let text = format!("{MINIMAL}\n[acme]\nnodes = [\"127.0.0.1:8053\"]\nburst = 0\n");
        assert!(Config::parse(&text).unwrap().validate_acme_api().is_err());
        assert!(err(Config::parse(MINIMAL).unwrap().validate_acme_api()).contains("[acme]"));
    }

    const TWO_NAME_SERVERS: &str = r#"
        domain = "ipssl.cc"

        [[nameservers]]
        name = "ns1.ipssl.cc"
        ipv4 = ["198.51.100.1"]
        ipv6 = ["2001:db8::1"]

        [[nameservers]]
        name = "ns2.ipssl.cc"
        ipv6 = ["2001:db8::2"]

        [soa]
        email = "hostmaster@ipssl.cc"
    "#;

    /// The warnings about `acme.nodes`.
    fn node_warnings(config: &Config) -> Vec<String> {
        let mut warnings = config.acme_api_warnings();
        warnings.retain(|w| w.contains("acme.nodes"));
        warnings
    }

    fn nodes(config: &Config) -> Result<Vec<String>> {
        let acme = config.acme.as_ref().unwrap();
        let addrs = acme.node_addrs(&config.nameservers)?;
        Ok(addrs.iter().map(ToString::to_string).collect())
    }

    #[test]
    fn acme_nodes_use_the_family_of_the_listener() {
        // An IPv6 listener is IPv6-only: use the IPv6 addresses even though
        // ns1 has an IPv4 one.
        let text = format!("{TWO_NAME_SERVERS}\n[acme]\nlisten = \"[::]:8053\"\n");
        let config = Config::parse(&text).unwrap();
        assert_eq!(
            nodes(&config).unwrap(),
            ["[2001:db8::1]:8053", "[2001:db8::2]:8053"]
        );
        config.validate_acme_api().unwrap();

        let text = format!("{TWO_NAME_SERVERS}\n[acme]\nlisten = \"0.0.0.0:8053\"\n");
        let config = Config::parse(&text).unwrap();
        let error = format!("{:#}", nodes(&config).unwrap_err());
        assert!(
            error.contains("ns2.ipssl.cc has no IPv4 address"),
            "{error}"
        );
        assert!(config.validate_acme_api().is_err());

        // Explicit nodes are taken as they are, each once.
        let text = format!(
            "{TWO_NAME_SERVERS}\n[acme]\nlisten = \"0.0.0.0:8053\"\n\
             nodes = [\"127.0.0.1:9000\", \"127.0.0.1:9001\", \"127.0.0.1:9000\"]\n"
        );
        let config = Config::parse(&text).unwrap();
        assert_eq!(
            nodes(&config).unwrap(),
            ["127.0.0.1:9000", "127.0.0.1:9001"]
        );
        config.validate_acme_api().unwrap();
        assert!(node_warnings(&config).is_empty());
    }

    #[test]
    fn explicit_acme_nodes_cover_every_name_server() {
        let config = |name_servers: &str, nodes: &str| {
            let text = format!(
                "domain = \"ipssl.cc\"\n{name_servers}\n[soa]\nemail = \"hostmaster@ipssl.cc\"\n\
                 [acme]\nnodes = [{nodes}]\n"
            );
            Config::parse(&text).unwrap()
        };
        let ns = |name: &str, ipv4: &str| {
            format!("[[nameservers]]\nname = \"{name}\"\nipv4 = [\"{ipv4}\"]\n")
        };
        let two = format!(
            "{}{}",
            ns("ns1.ipssl.cc", "198.51.100.1"),
            ns("ns2.ipssl.cc", "198.51.100.2")
        );

        // One endpoint for two name servers on two hosts: the API would
        // report success while the CA may ask the one it never wrote to.
        let one_node = config(&two, "\"198.51.100.1:8053\"");
        let error = err(one_node.validate_acme_api());
        assert!(
            error.contains("1 write endpoint(s), but the 2 name servers run on 2 host(s)"),
            "{error}"
        );
        // Listing the same endpoint twice does not help.
        let twice = config(&two, "\"198.51.100.1:8053\", \"198.51.100.1:8053\"");
        assert!(twice.validate_acme_api().is_err());

        let both = config(&two, "\"198.51.100.1:8053\", \"198.51.100.2:8053\"");
        both.validate_acme_api().unwrap();
        assert!(node_warnings(&both).is_empty());

        // Two names served by one host share its endpoint: allowed, with a
        // warning in case the shared address is a typo.
        let shared = format!(
            "{}{}{}",
            ns("ns1.ipssl.cc", "198.51.100.1"),
            ns("ns2.ipssl.cc", "198.51.100.1"),
            ns("ns3.ipssl.cc", "198.51.100.3"),
        );
        let config_shared = config(&shared, "\"198.51.100.1:8053\", \"198.51.100.3:8053\"");
        config_shared.validate_acme_api().unwrap();
        let warnings = node_warnings(&config_shared);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("2 write endpoint(s) for 3 name servers"));
        assert!(
            config(&shared, "\"198.51.100.1:8053\"")
                .validate_acme_api()
                .is_err()
        );

        // Name servers outside the zone have no addresses; each is a host.
        let outside = format!(
            "{}[[nameservers]]\nname = \"ns.example.net\"\n[[nameservers]]\nname = \"ns.example.org\"\n",
            ns("ns1.ipssl.cc", "198.51.100.1")
        );
        let two_nodes = config(&outside, "\"198.51.100.1:8053\", \"192.0.2.1:8053\"");
        assert!(two_nodes.validate_acme_api().is_err());

        // The derived list needs no check: it has an endpoint for every
        // name server, one for each host.
        let derived = Config::parse(&format!(
            "domain = \"ipssl.cc\"\n{shared}\n[soa]\nemail = \"hostmaster@ipssl.cc\"\n[acme]\n"
        ))
        .unwrap();
        assert_eq!(
            nodes(&derived).unwrap(),
            ["198.51.100.1:8053", "198.51.100.3:8053"]
        );
        derived.validate_acme_api().unwrap();
        assert!(node_warnings(&derived).is_empty());
    }

    #[test]
    fn acme_nodes_need_every_name_server() {
        // Out-of-zone name servers have no addresses in the config, so the
        // API cannot find their write endpoint on its own.
        let text = format!(
            "{TWO_NAME_SERVERS}\n[[nameservers]]\nname = \"ns.example.net\"\n\n[acme]\nlisten = \"[::]:8053\"\n"
        );
        let config = Config::parse(&text).unwrap();
        let error = err(config.validate_acme_api());
        assert!(error.contains("ns.example.net"), "{error}");
        assert!(error.contains("acme.nodes"), "{error}");
    }

    const HEX_KEY: &str = "4f1c0e5b9a7d3e2f6a8b1c4d7e0f2a3b5c6d8e9f0a1b2c3d4e5f60718293a4b5";

    fn with_key(key: &str, extra: &str) -> Config {
        let text =
            format!("{MINIMAL}\n[acme]\nnodes = [\"127.0.0.1:8053\"]\nkey = \"{key}\"\n{extra}");
        Config::parse(&text).unwrap()
    }

    #[test]
    fn acme_key_is_hex_or_base64() {
        let bytes = HEXLOWER_PERMISSIVE.decode(HEX_KEY.as_bytes()).unwrap();
        for text in [
            HEX_KEY.to_owned(),
            HEX_KEY.to_ascii_uppercase(),
            BASE64.encode(&bytes),
            BASE64_NOPAD.encode(&bytes),
            BASE64URL.encode(&bytes),
            format!(" {} ", BASE64.encode(&bytes)),
        ] {
            assert_eq!(AcmeKey::decode(&text).bytes().unwrap(), bytes, "{text}");
            let config = with_key(&text, "");
            config.validate().unwrap();
            config.validate_acme_api().unwrap();
        }
        // 48 random bytes in base64 are 64 characters: base64, not hex.
        let long = BASE64.encode(&[0xfb; 48]);
        assert_eq!(AcmeKey::decode(&long).bytes().unwrap(), [0xfb; 48]);
    }

    #[test]
    fn bad_acme_keys_are_reported_without_the_key() {
        let short = &HEX_KEY[..62];
        let bad = "not a key at all, not hex and not base64!";
        for (key, problem) in [
            (short, "has 31 bytes"),
            (bad, "hex or base64"),
            ("", "has 0 bytes"),
        ] {
            // Parsing works, so the parser cannot quote the line.
            let config = with_key(key, "");
            for error in [err(config.validate()), err(config.validate_acme_api())] {
                assert!(error.contains(problem), "{error}");
                assert!(key.is_empty() || !error.contains(key), "{error}");
            }
        }
        let debug = format!("{:?}", with_key(HEX_KEY, "").acme);
        assert!(
            !debug.contains(HEX_KEY) && !debug.contains("79, 28"),
            "{debug}"
        );
        assert!(debug.contains("AcmeKey(..)"), "{debug}");
    }

    #[test]
    fn acme_api_warns_about_its_key_settings() {
        let warnings = |config: &Config| {
            let mut warnings = config.acme_api_warnings();
            warnings.retain(|w| w.contains("acme.key") || w.contains("allow_unsigned"));
            warnings
        };
        let keyless = Config::parse(&format!(
            "{MINIMAL}\n[acme]\nnodes = [\"127.0.0.1:8053\"]\n"
        ))
        .unwrap();
        assert!(warnings(&keyless)[0].contains("acme.key is not set"));
        assert!(warnings(&with_key(HEX_KEY, "")).is_empty());
        let rollout = with_key(HEX_KEY, "allow_unsigned_nodes = true\n");
        assert!(warnings(&rollout)[0].contains("remove it once every name server has acme.key"));
    }

    #[test]
    fn parse_errors_never_show_the_key() {
        let base64 = BASE64.encode(&HEXLOWER_PERMISSIVE.decode(HEX_KEY.as_bytes()).unwrap());
        for (extra, problem) in [
            (format!("kye = \"{HEX_KEY}\""), "unknown field `kye`"),
            (format!("key = {HEX_KEY}"), "line 11"),
            (format!("key = {base64}"), "line 11"),
            (
                format!("key = \"{HEX_KEY}\"\nkey = \"{HEX_KEY}\""),
                "duplicate key",
            ),
            (format!("burst = \"{HEX_KEY}\""), "expected u32"),
            (format!("key = \"{HEX_KEY}"), "line 11"),
        ] {
            let text = format!("{MINIMAL}\n[acme]\n{extra}\n");
            let error = format!("{:#}", Config::parse(&text).unwrap_err());
            // Still says what is wrong and where.
            assert!(error.contains(problem), "{extra}: {error}");
            assert!(error.contains("<redacted>"), "{extra}: {error}");
            for secret in [&HEX_KEY[..16], &HEX_KEY[48..], &base64[..16]] {
                assert!(!error.contains(secret), "{extra}: {error}");
            }
        }
        // Errors without a key are left as they are.
        let typo = format!("{MINIMAL}\n[acme]\nnodez = []\n");
        let error = format!("{:#}", Config::parse(&typo).unwrap_err());
        assert!(
            error.contains("unknown field `nodez`") && !error.contains("redacted"),
            "{error}"
        );
    }
}
