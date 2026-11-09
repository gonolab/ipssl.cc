//! DNS-01 challenges for names that hold a private address.
//!
//! A CA cannot reach `10-0-2-2.ipssl.cc` to check HTTP-01, so names with
//! private addresses prove control through DNS instead: the ACME client
//! publishes a TXT record at `_acme-challenge.10-0-2-2.ipssl.cc` and the CA
//! looks it up. Two parts make that work:
//!
//! - The API ([`Api`], run as `ipssl-dns --acme-api` behind a TLS proxy)
//!   takes `POST /present` and `POST /cleanup` with a JSON body
//!   `{"fqdn": ..., "value": ...}`, the format of lego's `httpreq`
//!   provider. It checks the request, then sends it to every name server
//!   and reports success only once all of them have the value, so the CA
//!   finds it whichever name server it asks.
//! - Each name server keeps the values in memory for a few minutes
//!   ([`Challenges`]) and takes writes only from the API hosts ([`Node`]).
//!
//! Only names with private addresses qualify ([`Zone::check_challenge`]),
//! and values must look like real challenge digests, so the API cannot be
//! used to publish arbitrary text in the zone.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use hickory_server::proto::rr::LowerName;
use serde::Deserialize;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::warn;

use crate::config::Config;
use crate::handler::Handler;
use crate::http::{Request, Response, post_json};
use crate::ratelimit::{RateLimiter, Verdict};
use crate::zone::{ChallengeError, Zone};

/// First label of every DNS-01 challenge name (RFC 8555 section 8.4).
pub const CHALLENGE_LABEL: &str = "_acme-challenge";

/// How long a published value stays. Validation takes seconds; this
/// leaves room for slow clients and retries.
const LIFETIME: Duration = Duration::from_secs(600);

/// Most challenge names held at once. Bounds memory.
const MAX_NAMES: usize = 10_000;

/// Most values held for one name: a certificate for a name and its
/// wildcard needs two, and retries may add more. The oldest goes first.
const MAX_VALUES: usize = 4;

/// Time the API gives each name server to take a change.
const NODE_TIMEOUT: Duration = Duration::from_secs(5);

const JSON: &str = "application/json";

/// Whether `ip` is an address no public CA can reach: private, shared
/// (CGNAT), loopback or link-local, IPv4 or IPv6.
pub fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => {
            let [a, b, ..] = ip.octets();
            let shared = a == 100 && b & 0xc0 == 64; // 100.64.0.0/10
            ip.is_private() || ip.is_loopback() || ip.is_link_local() || shared
        }
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

/// Whether `value` looks like a DNS-01 TXT value: the unpadded base64url
/// SHA-256 digest of a key authorization, always 43 characters.
pub fn is_valid_value(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Challenge values published on this name server, by name.
#[derive(Default)]
pub struct Challenges {
    names: Mutex<HashMap<LowerName, Vec<Entry>>>,
}

struct Entry {
    value: String,
    expires: Instant,
}

/// No room for another challenge name.
#[derive(Debug, PartialEq, Eq)]
pub struct StoreFull;

impl Challenges {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publishes `value` at `name`, or extends it if it is already there.
    pub fn present(&self, name: LowerName, value: &str) -> Result<(), StoreFull> {
        self.present_at(name, value, Instant::now())
    }

    /// Removes `value` from `name`, if it is there.
    pub fn cleanup(&self, name: &LowerName, value: &str) {
        let mut names = self.lock();
        if let Some(entries) = names.get_mut(name) {
            entries.retain(|e| e.value != value);
            if entries.is_empty() {
                names.remove(name);
            }
        }
    }

    /// The values currently published at `name`.
    pub fn values(&self, name: &LowerName) -> Vec<String> {
        self.values_at(name, Instant::now())
    }

    /// Forgets expired values.
    pub fn purge(&self) {
        purge(&mut self.lock(), Instant::now());
    }

    /// Number of values held, expired ones included until the next purge.
    pub fn len(&self) -> usize {
        self.lock().values().map(Vec::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn present_at(&self, name: LowerName, value: &str, now: Instant) -> Result<(), StoreFull> {
        let mut names = self.lock();
        if !names.contains_key(&name) && names.len() >= MAX_NAMES {
            purge(&mut names, now);
            if names.len() >= MAX_NAMES {
                return Err(StoreFull);
            }
        }
        let entries = names.entry(name).or_default();
        entries.retain(|e| e.expires > now);
        let expires = now + LIFETIME;
        if let Some(entry) = entries.iter_mut().find(|e| e.value == value) {
            entry.expires = expires;
            return Ok(());
        }
        if entries.len() >= MAX_VALUES
            && let Some(oldest) = (0..entries.len()).min_by_key(|&i| entries[i].expires)
        {
            entries.remove(oldest);
        }
        entries.push(Entry {
            value: value.to_owned(),
            expires,
        });
        Ok(())
    }

    fn values_at(&self, name: &LowerName, now: Instant) -> Vec<String> {
        self.lock()
            .get(name)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.expires > now)
                    .map(|e| e.value.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<LowerName, Vec<Entry>>> {
        // A map left half-updated by a panic is still consistent enough.
        self.names.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn purge(names: &mut HashMap<LowerName, Vec<Entry>>, now: Instant) {
    names.retain(|_, entries| {
        entries.retain(|e| e.expires > now);
        !entries.is_empty()
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Present,
    Cleanup,
}

impl Action {
    fn path(self) -> &'static str {
        match self {
            Self::Present => "/present",
            Self::Cleanup => "/cleanup",
        }
    }
}

/// The request body, as lego's `httpreq` provider sends it.
#[derive(Deserialize)]
struct Body {
    fqdn: String,
    value: String,
}

fn route(req: &Request) -> Result<Action, Response> {
    let action = match req.path.as_str() {
        "/present" => Action::Present,
        "/cleanup" => Action::Cleanup,
        _ => return Err(error(404, "not found; use /present or /cleanup")),
    };
    if req.method != "POST" {
        return Err(error(405, "use POST"));
    }
    Ok(action)
}

/// Checks the request body against `zone` and returns the challenge name
/// and value.
fn parse(req: &Request, zone: &Zone) -> Result<(LowerName, String), Response> {
    let body: Body = serde_json::from_slice(&req.body).map_err(|_| {
        error(
            400,
            r#"expected a JSON body {"fqdn": "...", "value": "..."}"#,
        )
    })?;
    let name = zone.challenge_name(&body.fqdn).map_err(|e| {
        let status = match e {
            ChallengeError::PublicAddress | ChallengeError::Blocked => 403,
            _ => 400,
        };
        error(status, e.message())
    })?;
    if !is_valid_value(&body.value) {
        return Err(error(
            400,
            "value must be a DNS-01 digest (43 base64url characters)",
        ));
    }
    Ok((name, body.value))
}

fn ok() -> Response {
    Response::new(200, JSON, r#"{"ok":true}"#)
}

fn error(status: u16, message: &str) -> Response {
    let body = serde_json::json!({ "ok": false, "error": message });
    Response::new(status, JSON, body.to_string())
}

/// The challenge write endpoint on a name server.
pub struct Node {
    handler: Handler,
    store: Arc<Challenges>,
    writers: Vec<IpAddr>,
}

impl Node {
    /// `handler` supplies the current zone and the metrics; `store` must
    /// be the one `handler` answers from.
    pub fn new(handler: Handler, store: Arc<Challenges>, writers: &[IpAddr]) -> Self {
        Self {
            handler,
            store,
            writers: writers.iter().map(|ip| ip.to_canonical()).collect(),
        }
    }

    pub async fn handle(&self, req: Request) -> Response {
        self.try_handle(req).unwrap_or_else(|response| response)
    }

    fn try_handle(&self, req: Request) -> Result<Response, Response> {
        if !self.writers.contains(&req.peer.ip().to_canonical()) {
            return Err(error(403, "not allowed to write challenges"));
        }
        let action = route(&req)?;
        let zone = self.handler.zone();
        let (name, value) = parse(&req, &zone).inspect_err(|_| {
            self.handler.metrics().acme_write(false);
        })?;
        match action {
            Action::Present => {
                if self.store.present(name, &value).is_err() {
                    self.handler.metrics().acme_write(false);
                    return Err(error(503, "too many challenges, try again later"));
                }
            }
            Action::Cleanup => self.store.cleanup(&name, &value),
        }
        self.handler.metrics().acme_write(true);
        Ok(ok())
    }
}

/// The public challenge API.
pub struct Api {
    zone: Zone,
    limiter: RateLimiter,
    nodes: Vec<SocketAddr>,
}

impl Api {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let acme = cfg.acme.as_ref().context("the [acme] section is missing")?;
        ensure!(
            acme.requests_per_minute >= 1 && acme.burst >= 1,
            "acme.requests_per_minute and acme.burst must be at least 1"
        );
        let nodes = acme.node_addrs(&cfg.nameservers);
        ensure!(
            !nodes.is_empty(),
            "no name server to send challenges to: set acme.nodes or give the name servers addresses"
        );
        Ok(Self {
            zone: Zone::from_config(cfg)?,
            limiter: RateLimiter::new(
                f64::from(acme.requests_per_minute) / 60.0,
                acme.burst,
                cfg.rate_limit.ipv4_prefix,
                cfg.rate_limit.ipv6_prefix,
                cfg.rate_limit.max_tracked,
            ),
            nodes,
        })
    }

    /// The name server endpoints every change goes to.
    pub fn nodes(&self) -> &[SocketAddr] {
        &self.nodes
    }

    pub async fn handle(&self, req: Request) -> Response {
        match self.try_handle(req).await {
            Ok(response) | Err(response) => response,
        }
    }

    async fn try_handle(&self, req: Request) -> Result<Response, Response> {
        let action = route(&req)?;
        if self.limiter.check(client_ip(&req)) != Verdict::Allow {
            return Err(error(429, "too many requests, slow down"));
        }
        let (name, value) = parse(&req, &self.zone)?;
        let body = serde_json::json!({ "fqdn": name.to_string(), "value": value }).to_string();

        let mut tasks = JoinSet::new();
        for &addr in &self.nodes {
            let body = body.clone();
            tasks.spawn(async move {
                let result = timeout(NODE_TIMEOUT, post_json(addr, action.path(), &body)).await;
                let problem = match result {
                    Ok(Ok((200, _))) => return None,
                    Ok(Ok((status, _))) => format!("HTTP {status}"),
                    Ok(Err(e)) => e.to_string(),
                    Err(_) => "timed out".to_owned(),
                };
                Some(format!("{addr} ({problem})"))
            });
        }
        let mut failed = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(None) => {}
                Ok(Some(problem)) => failed.push(problem),
                Err(e) => failed.push(format!("task failed: {e}")),
            }
        }
        if failed.is_empty() {
            return Ok(ok());
        }
        failed.sort();
        let failed = failed.join(", ");
        warn!(action = action.path(), %failed, "acme: a name server did not take the change");
        Err(error(
            502,
            &format!("not every name server took the change: {failed}"),
        ))
    }
}

/// The client's address: `X-Real-IP` when the request comes through a
/// proxy on this host, otherwise the peer.
fn client_ip(req: &Request) -> IpAddr {
    let peer = req.peer.ip().to_canonical();
    if peer.is_loopback()
        && let Some(ip) = req
            .header("x-real-ip")
            .and_then(|v| v.parse::<IpAddr>().ok())
    {
        return ip.to_canonical();
    }
    peer
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::rr::Name;

    const VALUE: &str = "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM";

    fn name(s: &str) -> LowerName {
        LowerName::new(&Name::from_ascii(s).unwrap())
    }

    #[test]
    fn private_addresses() {
        for ip in [
            "10.0.2.2",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.10",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_private(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "172.32.0.1",
            "100.128.0.1",
            "203.0.113.10",
            "2001:db8::1",
            "2606:4700::1111",
        ] {
            assert!(!is_private(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn challenge_values() {
        assert!(is_valid_value(VALUE));
        assert!(!is_valid_value(&VALUE[1..]));
        assert!(!is_valid_value(&format!("{}=", &VALUE[1..])));
        assert!(!is_valid_value(&format!("{} ", &VALUE[1..])));
        assert!(!is_valid_value("v=spf1 include:example.net ~all"));
    }

    #[test]
    fn store_publishes_and_expires() {
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let now = Instant::now();
        store.present_at(n.clone(), VALUE, now).unwrap();
        store.present_at(n.clone(), "b", now).unwrap();
        assert_eq!(store.values_at(&n, now), [VALUE, "b"]);

        store.cleanup(&n, "b");
        assert_eq!(store.values_at(&n, now), [VALUE]);
        assert!(store.values_at(&n, now + LIFETIME).is_empty());

        // Presenting again extends the lifetime instead of adding a copy.
        let later = now + LIFETIME / 2;
        store.present_at(n.clone(), VALUE, later).unwrap();
        assert_eq!(store.values_at(&n, now + LIFETIME), [VALUE]);
        assert_eq!(store.len(), 1);

        store.cleanup(&n, VALUE);
        assert!(store.is_empty());
    }

    #[test]
    fn store_keeps_the_newest_values() {
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let now = Instant::now();
        for i in 0..=MAX_VALUES {
            let at = now + Duration::from_secs(i as u64);
            store.present_at(n.clone(), &i.to_string(), at).unwrap();
        }
        assert_eq!(store.values_at(&n, now), ["1", "2", "3", "4"]);
    }

    #[test]
    fn store_is_bounded() {
        let store = Challenges::new();
        let now = Instant::now();
        for i in 0..MAX_NAMES {
            let n = name(&format!("_acme-challenge.{i}.10-0-2-2.ipssl.cc."));
            store.present_at(n, VALUE, now).unwrap();
        }
        let extra = name("_acme-challenge.10-0-2-3.ipssl.cc.");
        assert_eq!(store.present_at(extra.clone(), VALUE, now), Err(StoreFull));
        // Once the others expire there is room again.
        store.present_at(extra, VALUE, now + LIFETIME).unwrap();
        assert_eq!(store.len(), 1);
    }
}
