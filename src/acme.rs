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
//!   A value belongs to the client network that presented it, which the
//!   API sends along; only that network can clean it up.
//!
//! Only names with private addresses qualify ([`Zone::check_challenge`]),
//! and values must look like real challenge digests, so the API cannot be
//! used to publish arbitrary text in the zone.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
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

/// Shortest time between two sweeps of a full store, see
/// [`Challenges::present`].
const PURGE_INTERVAL: Duration = Duration::from_secs(1);

/// Most values held for one name, from all client networks together.
/// Values are never pushed out early, so this is also how many pending
/// values one name can have; 16 TXT records still fit in one 1232-byte
/// UDP answer.
const MAX_VALUES: usize = 16;

/// Most values one client network may hold at one name: a certificate for
/// a name and its wildcard needs two at once.
const MAX_VALUES_PER_OWNER: usize = 2;

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
///
/// 43 characters carry 258 bits for the digest's 256, and a canonical
/// encoding leaves the last two zero (RFC 4648 section 3.5), so the final
/// character is one of the 16 whose value is a multiple of four. Anything
/// else is a client-side encoding mistake that would only show up when
/// the CA fails to validate.
pub fn is_valid_value(value: &str) -> bool {
    const LAST: &[u8] = b"AEIMQUYcgkosw048";
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && value.bytes().last().is_some_and(|b| LAST.contains(&b))
}

/// Challenge values published on this name server, by name.
///
/// Each value belongs to the client network that presented it through the
/// API (the owner), and only that network can clean it up: values are
/// public in DNS while a CA validates them, so knowing one proves nothing.
/// Values are never pushed out before they expire; when a cap is reached,
/// the new value is refused instead.
#[derive(Default)]
pub struct Challenges {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    names: HashMap<LowerName, Vec<Entry>>,
    /// When expired values were last swept out of the whole table.
    last_purge: Option<Instant>,
}

struct Entry {
    value: String,
    /// The client network that presented the value, as the API groups
    /// clients. `None` for writes from an API that sends no owner.
    owner: Option<IpAddr>,
    expires: Instant,
}

/// Why a value could not be published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Full {
    /// No room for another challenge name.
    Store,
    /// The name holds [`MAX_VALUES`] values already.
    Name,
    /// The owner holds [`MAX_VALUES_PER_OWNER`] values at the name already.
    Owner,
}

impl Full {
    /// The name server's answer to the API.
    fn response(self) -> Response {
        match self {
            Self::Store => error(503, "too many challenges, try again later"),
            Self::Name => error(
                409,
                &format!("this name already holds {MAX_VALUES} pending values"),
            ),
            Self::Owner => error(
                409,
                &format!(
                    "this client network already holds {MAX_VALUES_PER_OWNER} pending values at this name"
                ),
            ),
        }
    }
}

impl Challenges {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publishes `value` at `name` for `owner`, or extends it if `owner`
    /// published it there already.
    pub fn present(&self, name: LowerName, value: &str, owner: Option<IpAddr>) -> Result<(), Full> {
        self.present_at(name, value, owner, Instant::now())
    }

    /// Removes `value` from `name` if `owner` published it. Anything else
    /// is left alone, the same value published by another owner included.
    pub fn cleanup(&self, name: &LowerName, value: &str, owner: Option<IpAddr>) {
        let names = &mut self.lock().names;
        if let Some(entries) = names.get_mut(name) {
            entries.retain(|e| e.value != value || e.owner != owner);
            if entries.is_empty() {
                names.remove(name);
            }
        }
    }

    /// The values currently published at `name`, each once.
    pub fn values(&self, name: &LowerName) -> Vec<String> {
        self.values_at(name, Instant::now())
    }

    /// Forgets expired values.
    pub fn purge(&self) {
        self.lock().purge(Instant::now());
    }

    /// Number of values being published. Expired values still waiting for
    /// a purge are left out, as they are from DNS answers.
    pub fn len(&self) -> usize {
        self.len_at(Instant::now())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn present_at(
        &self,
        name: LowerName,
        value: &str,
        owner: Option<IpAddr>,
        now: Instant,
    ) -> Result<(), Full> {
        let mut inner = self.lock();
        if !inner.names.contains_key(&name) && inner.names.len() >= MAX_NAMES {
            // A sweep walks the whole table while TXT lookups wait for the
            // lock, so a store kept full by a flood of new names sweeps at
            // most once a second, however many writes arrive.
            if inner
                .last_purge
                .is_none_or(|last| now.saturating_duration_since(last) >= PURGE_INTERVAL)
            {
                inner.purge(now);
            }
            if inner.names.len() >= MAX_NAMES {
                return Err(Full::Store);
            }
        }
        let entries = inner.names.entry(name).or_default();
        entries.retain(|e| e.expires > now);
        let expires = now + LIFETIME;
        if let Some(entry) = entries
            .iter_mut()
            .find(|e| e.value == value && e.owner == owner)
        {
            entry.expires = expires;
            return Ok(());
        }
        // Writes without an owner cannot be told apart, so only the cap
        // for the whole name applies to them.
        if owner.is_some()
            && entries.iter().filter(|e| e.owner == owner).count() >= MAX_VALUES_PER_OWNER
        {
            return Err(Full::Owner);
        }
        if entries.len() >= MAX_VALUES {
            return Err(Full::Name);
        }
        entries.push(Entry {
            value: value.to_owned(),
            owner,
            expires,
        });
        Ok(())
    }

    fn values_at(&self, name: &LowerName, now: Instant) -> Vec<String> {
        self.lock()
            .names
            .get(name)
            .map(|entries| live(entries, now).map(str::to_owned).collect())
            .unwrap_or_default()
    }

    fn len_at(&self, now: Instant) -> usize {
        self.lock()
            .names
            .values()
            .map(|entries| live(entries, now).count())
            .sum()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // A map left half-updated by a panic is still consistent enough.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Inner {
    fn purge(&mut self, now: Instant) {
        self.names.retain(|_, entries| {
            entries.retain(|e| e.expires > now);
            !entries.is_empty()
        });
        self.last_purge = Some(now);
    }
}

/// The unexpired values in `entries`, each once: two owners may publish
/// the same value, and DNS answers carry it once.
fn live(entries: &[Entry], now: Instant) -> impl Iterator<Item = &str> {
    entries
        .iter()
        .enumerate()
        .filter(move |&(i, e)| {
            e.expires > now
                && !entries[..i]
                    .iter()
                    .any(|seen| seen.expires > now && seen.value == e.value)
        })
        .map(|(_, e)| e.value.as_str())
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

/// What the API adds to the body when it forwards a change to the name
/// servers. Only name servers read it, never the public API.
#[derive(Deserialize)]
struct Forwarded {
    /// The client network the change came from, which owns the value. An
    /// API from before values had owners leaves it out.
    #[serde(default)]
    owner: Option<IpAddr>,
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
    // Taking a value down publishes nothing, so cleanup takes any challenge
    // name in the zone; only present needs one that can take a value now.
    let name = match route(req) {
        Ok(Action::Cleanup) => zone.cleanup_name(&body.fqdn),
        _ => zone.challenge_name(&body.fqdn),
    };
    let name = name.map_err(|e| {
        let status = match e {
            ChallengeError::PublicAddress
            | ChallengeError::FixedAddress
            | ChallengeError::Blocked => 403,
            _ => 400,
        };
        error(status, e.message())
    })?;
    if !is_valid_value(&body.value) {
        return Err(error(
            400,
            "value must be a DNS-01 digest: a SHA-256 hash as 43 base64url characters",
        ));
    }
    Ok((name, body.value))
}

/// The owner the API sent with a change, see [`Forwarded`].
fn owner(req: &Request) -> Result<Option<IpAddr>, Response> {
    serde_json::from_slice::<Forwarded>(&req.body)
        .map(|f| f.owner)
        .map_err(|_| error(400, "owner must be an IP address"))
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
        let owner = owner(&req).inspect_err(|_| {
            self.handler.metrics().acme_write(false);
        })?;
        match action {
            Action::Present => {
                if let Err(full) = self.store.present(name, &value, owner) {
                    self.handler.metrics().acme_write(false);
                    return Err(full.response());
                }
            }
            // Removing nothing (a value this owner never published, or one
            // already gone) still succeeds, so cleanup can be retried.
            Action::Cleanup => self.store.cleanup(&name, &value, owner),
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
        // Rate limiter settings and every name server's write endpoint.
        cfg.validate_acme_api()?;
        let acme = cfg.acme.as_ref().context("the [acme] section is missing")?;
        let nodes = acme.node_addrs(&cfg.nameservers)?;
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
        let client = client_ip(&req);
        if self.limiter.check(client) != Verdict::Allow {
            return Err(error(429, "too many requests, slow down"));
        }
        let (name, value) = parse(&req, &self.zone)?;
        // The value belongs to the client's network, grouped as for rate
        // limiting, so only that network can clean it up again.
        let owner = self.limiter.network(client);
        let body = serde_json::json!({
            "fqdn": name.to_string(),
            "value": value,
            "owner": owner,
        })
        .to_string();

        let mut tasks = JoinSet::new();
        for &addr in &self.nodes {
            let body = body.clone();
            tasks.spawn(async move {
                let result = timeout(NODE_TIMEOUT, post_json(addr, action.path(), &body)).await;
                let problem = match result {
                    Ok(Ok((200, _))) => return Outcome::Accepted,
                    // A cap on pending values: the client's to sort out.
                    Ok(Ok((409, _))) => return Outcome::Rejected,
                    Ok(Ok((status, _))) => format!("HTTP {status}"),
                    Ok(Err(e)) => e.to_string(),
                    Err(_) => "timed out".to_owned(),
                };
                Outcome::Failed(format!("{addr} ({problem})"))
            });
        }
        let mut failed = Vec::new();
        let mut rejected = false;
        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok(Outcome::Accepted) => {}
                Ok(Outcome::Rejected) => rejected = true,
                Ok(Outcome::Failed(problem)) => failed.push(problem),
                Err(e) => failed.push(format!("task failed: {e}")),
            }
        }
        if rejected {
            return Err(error(409, &too_many_values()));
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

/// What one name server did with a change.
enum Outcome {
    Accepted,
    /// Refused because the name holds too many pending values.
    Rejected,
    /// No usable answer; the text says why, for the log.
    Failed(String),
}

/// The API's answer when a name server refuses a value over a cap.
fn too_many_values() -> String {
    format!(
        "this name already holds as many pending values as allowed \
         ({MAX_VALUES_PER_OWNER} per client network, {MAX_VALUES} in all); \
         clean up values you no longer need, or wait up to {} minutes for them to expire",
        LIFETIME.as_secs() / 60
    )
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

    fn owner(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
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

        // Only 16 final characters leave the padding bits zero.
        let stem = &VALUE[..42];
        let last = |c: char| is_valid_value(&format!("{stem}{c}"));
        for c in "AEIMQUYcgkosw048".chars() {
            assert!(last(c), "{c}");
        }
        for c in "BNZdhx19-_".chars() {
            assert!(!last(c), "{c}");
        }
    }

    #[test]
    fn store_publishes_and_expires() {
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let me = owner("192.0.2.0");
        let now = Instant::now();
        store.present_at(n.clone(), VALUE, me, now).unwrap();
        store.present_at(n.clone(), "b", me, now).unwrap();
        assert_eq!(store.values_at(&n, now), [VALUE, "b"]);

        store.cleanup(&n, "b", me);
        assert_eq!(store.values_at(&n, now), [VALUE]);
        assert!(store.values_at(&n, now + LIFETIME).is_empty());

        // Presenting again extends the lifetime instead of adding a copy.
        let later = now + LIFETIME / 2;
        store.present_at(n.clone(), VALUE, me, later).unwrap();
        assert_eq!(store.values_at(&n, now + LIFETIME), [VALUE]);
        assert_eq!(store.len_at(now), 1);

        store.cleanup(&n, VALUE, me);
        assert!(store.is_empty());
    }

    #[test]
    fn only_the_owner_cleans_up() {
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let (me, other) = (owner("192.0.2.0"), owner("198.51.100.0"));
        let now = Instant::now();
        store.present_at(n.clone(), VALUE, me, now).unwrap();

        // Another network, or a write with no owner, removes nothing.
        store.cleanup(&n, VALUE, other);
        store.cleanup(&n, VALUE, None);
        assert_eq!(store.values_at(&n, now), [VALUE]);

        // The same value from two owners is answered once and stays until
        // both have cleaned it up.
        store.present_at(n.clone(), VALUE, other, now).unwrap();
        assert_eq!(store.values_at(&n, now), [VALUE]);
        assert_eq!(store.len_at(now), 1);
        store.cleanup(&n, VALUE, me);
        assert_eq!(store.values_at(&n, now), [VALUE]);
        store.cleanup(&n, VALUE, other);
        assert!(store.values_at(&n, now).is_empty());
    }

    #[test]
    fn writes_without_an_owner_belong_to_nobody_else() {
        // What an API that sends no owner gets: such values are cleaned up
        // by such writes, and only the cap for the whole name applies.
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let now = Instant::now();
        for i in 0..MAX_VALUES {
            store
                .present_at(n.clone(), &i.to_string(), None, now)
                .unwrap();
        }
        assert_eq!(store.present_at(n.clone(), "x", None, now), Err(Full::Name));
        store.cleanup(&n, "0", owner("192.0.2.0"));
        assert_eq!(store.len_at(now), MAX_VALUES);
        store.cleanup(&n, "0", None);
        assert_eq!(store.len_at(now), MAX_VALUES - 1);
    }

    #[test]
    fn live_values_are_never_pushed_out() {
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let me = owner("192.0.2.0");
        let now = Instant::now();
        store.present_at(n.clone(), "a", me, now).unwrap();
        store.present_at(n.clone(), "b", me, now).unwrap();
        // A third value from the same network is refused...
        assert_eq!(store.present_at(n.clone(), "c", me, now), Err(Full::Owner));
        // ...but extending one it holds is fine.
        store.present_at(n.clone(), "a", me, now).unwrap();
        assert_eq!(store.values_at(&n, now), ["a", "b"]);

        // Other networks fill the name up to its cap.
        for i in 1..MAX_VALUES / MAX_VALUES_PER_OWNER {
            let them = owner(&format!("198.51.{i}.0"));
            for v in ["a", "b"] {
                store
                    .present_at(n.clone(), &format!("{v}{i}"), them, now)
                    .unwrap();
            }
        }
        assert_eq!(store.len_at(now), MAX_VALUES);
        let late = owner("203.0.113.0");
        assert_eq!(store.present_at(n.clone(), "z", late, now), Err(Full::Name));
        assert_eq!(store.values_at(&n, now)[..2], ["a", "b"]);

        // Once the first ones expire, there is room again.
        let later = now + LIFETIME;
        store.present_at(n.clone(), "z", late, later).unwrap();
        store.present_at(n.clone(), "c", me, later).unwrap();
        assert_eq!(store.values_at(&n, later), ["z", "c"]);
    }

    #[test]
    fn store_is_bounded() {
        let store = Challenges::new();
        let now = Instant::now();
        for i in 0..MAX_NAMES {
            let n = name(&format!("_acme-challenge.{i}.10-0-2-2.ipssl.cc."));
            store.present_at(n, VALUE, None, now).unwrap();
        }
        let extra = name("_acme-challenge.10-0-2-3.ipssl.cc.");
        assert_eq!(
            store.present_at(extra.clone(), VALUE, None, now),
            Err(Full::Store)
        );
        // Once the others expire there is room again.
        store
            .present_at(extra, VALUE, None, now + LIFETIME)
            .unwrap();
        assert_eq!(store.len_at(now + LIFETIME), 1);
    }

    #[test]
    fn full_store_sweeps_at_most_once_a_second() {
        let store = Challenges::new();
        let now = Instant::now();
        for i in 0..MAX_NAMES {
            let n = name(&format!("_acme-challenge.{i}.10-0-2-2.ipssl.cc."));
            store.present_at(n, VALUE, None, now).unwrap();
        }
        let extra = name("_acme-challenge.10-0-2-3.ipssl.cc.");
        let present = |at| store.present_at(extra.clone(), VALUE, None, at);
        // Just before the others expire: a sweep finds nothing to forget.
        let swept = now + LIFETIME - Duration::from_millis(500);
        assert_eq!(present(swept), Err(Full::Store));
        // They have expired now, but the last sweep was too recent.
        let soon = swept + Duration::from_millis(600);
        assert_eq!(present(soon), Err(Full::Store));
        // A second later the store sweeps again and has room.
        present(swept + PURGE_INTERVAL).unwrap();
        assert_eq!(store.values_at(&extra, soon), [VALUE]);
    }

    #[test]
    fn expired_values_are_not_counted() {
        let store = Challenges::new();
        let now = Instant::now();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        store.present_at(n.clone(), VALUE, None, now).unwrap();
        assert_eq!(store.len_at(now), 1);
        // Gone from the count as soon as DNS stops serving it, before any purge.
        assert_eq!(store.len_at(now + LIFETIME), 0);
        assert!(store.values_at(&n, now + LIFETIME).is_empty());
    }
}
