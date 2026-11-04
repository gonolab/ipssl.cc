//! TOML configuration. See `config.example.toml` for a documented example.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostConfig {
    #[serde(default)]
    pub a: Vec<Ipv4Addr>,
    #[serde(default)]
    pub aaaa: Vec<Ipv6Addr>,
    #[serde(default)]
    pub txt: Vec<String>,
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
