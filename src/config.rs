//! TOML configuration. See `config.example.toml` for a documented example.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The zone this server is authoritative for, e.g. `ipssl.cc`.
    pub domain: String,

    /// Addresses to serve DNS on, both UDP and TCP.
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
    /// means each name server's first address on the `listen` port.
    #[serde(default)]
    pub nodes: Vec<SocketAddr>,
    /// API requests per minute for each client network.
    #[serde(default = "default_acme_requests_per_minute")]
    pub requests_per_minute: u32,
    /// API requests a client network may make at once.
    #[serde(default = "default_acme_burst")]
    pub burst: u32,
}

impl AcmeConfig {
    /// Write endpoints of every name server, as the API reaches them.
    pub fn node_addrs(&self, nameservers: &[NameServer]) -> Vec<SocketAddr> {
        if !self.nodes.is_empty() {
            return self.nodes.clone();
        }
        let port = self.listen.port();
        nameservers
            .iter()
            .filter_map(|ns| {
                let ip = ns.ipv4.first().map(|ip| IpAddr::V4(*ip));
                ip.or_else(|| ns.ipv6.first().map(|ip| IpAddr::V6(*ip)))
            })
            .map(|ip| SocketAddr::new(ip, port))
            .collect()
    }
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
    /// is full, new networks share a single limit.
    #[serde(default = "default_max_tracked")]
    pub max_tracked: usize,
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
        Ok(toml::from_str(text)?)
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

    #[test]
    fn acme_nodes_default_to_name_servers() {
        let text = r#"
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

            [acme]
            listen = "0.0.0.0:8053"
        "#;
        let config = Config::parse(text).unwrap();
        let acme = config.acme.as_ref().unwrap();
        let nodes: Vec<String> = acme
            .node_addrs(&config.nameservers)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(nodes, ["198.51.100.1:8053", "[2001:db8::2]:8053"]);

        let mut explicit = acme.clone();
        explicit.nodes = vec!["127.0.0.1:9000".parse().unwrap()];
        assert_eq!(explicit.node_addrs(&config.nameservers).len(), 1);
    }
}
