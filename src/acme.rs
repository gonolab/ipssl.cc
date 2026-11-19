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
//!   A value belongs to the client that presented it, by its IPv4 address
//!   or its IPv6 /64, which the API sends along ([`Origin`]); only that
//!   client can clean it up. The API numbers its changes, and name servers
//!   apply them in that order however they arrive.
//!
//! With a shared key (`acme.key`), the API signs every change, and a name
//! server takes only signed ones (still only from the API hosts) and signs
//! its answers, so someone on the path between them can neither forge a
//! change nor an answer.
//!
//! Only names with private addresses qualify ([`Zone::check_challenge`]),
//! and values must look like real challenge digests, so the API cannot be
//! used to publish arbitrary text in the zone.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use hickory_server::proto::rr::LowerName;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tracing::warn;

use crate::config::{AcmeConfig, Config};
use crate::handler::Handler;
use crate::http::{Reply, Request, Response, Server, post};
use crate::metrics::{AcmeWrite, ApiMetrics, NodeWrite};
use crate::ratelimit::{RateLimiter, Verdict};
use crate::zone::{ChallengeError, Zone};

mod auth;

/// First label of every DNS-01 challenge name (RFC 8555 section 8.4).
pub const CHALLENGE_LABEL: &str = "_acme-challenge";

/// How long a published value stays. Validation takes seconds; this
/// leaves room for slow clients and retries.
const LIFETIME: Duration = Duration::from_secs(600);

/// Most challenge names held at once. Bounds memory.
const MAX_NAMES: usize = 10_000;

/// Most recent cleanups remembered at once, see [`Removal`]. Bounds
/// memory; past it, the oldest are forgotten early.
const MAX_REMOVALS: usize = 10_000;

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
const MAX_VALUES_PER_NETWORK: usize = 2;

/// The IPv6 prefix that owns a value: one host, as far as an address
/// says, since a host usually picks addresses from its whole /64.
const IPV6_OWNER_PREFIX: u32 = 64;

/// Time the API gives each name server to take a change.
const NODE_TIMEOUT: Duration = Duration::from_secs(5);

/// Time the API gives a name server to drop a value again after the
/// change failed elsewhere. Short, so that even with a name server down
/// ([`NODE_TIMEOUT`] and then this) the answer beats the HTTP server's
/// 10-second deadline.
const ROLLBACK_TIMEOUT: Duration = Duration::from_secs(2);

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
/// Each value belongs to the client that presented it through the API
/// (the owner, see [`Origin`]), and only that client can clean it up:
/// values are public in DNS while a CA validates them, so knowing one
/// proves nothing. The caps on pending values count by the client's
/// network. Values are never pushed out before they expire; when a cap is
/// reached, the new value is refused instead.
#[derive(Default)]
pub struct Challenges {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    names: HashMap<LowerName, Vec<Entry>>,
    /// Recent cleanups with a sequence number.
    removals: HashMap<Key, Removal>,
    /// When expired values and removals were last swept out.
    last_purge: Option<Instant>,
}

struct Entry {
    value: String,
    /// Who presented the value.
    origin: Origin,
    /// The API's number for the latest present of it, see [`Sequence`].
    seq: Option<u64>,
    expires: Instant,
}

/// A cleanup the name server remembers for as long as a present sent
/// before it could still be pending, so that such a present, arriving
/// late, cannot bring the value back. Changes reach the name servers
/// independently, so one name server may get a present after the cleanup
/// that followed it while the others got them in order.
///
/// Removals are not values: they are never served and never count toward
/// a cap. When there are too many, the oldest are forgotten early.
struct Removal {
    seq: u64,
    /// When any present sent before the cleanup would have expired.
    expires: Instant,
}

/// Whether a change numbered `seq` is older than the state numbered
/// `current`, and so must not undo it. Changes without a number (from an
/// API on v0.5.0) are applied as they come.
fn superseded(seq: Option<u64>, current: Option<u64>) -> bool {
    matches!((seq, current), (Some(seq), Some(current)) if seq <= current)
}

impl Entry {
    /// Whether a cleanup from `origin` takes this value down.
    fn owned_by(&self, origin: &Origin) -> bool {
        self.origin.owner == origin.owner
            // Presented through an API from v0.5.0, which sent the client's
            // network as the owner: the network cleans it up, as it could
            // then. Only for values from before the API's upgrade.
            || (self.origin.network.is_none()
                && origin.network.is_some()
                && self.origin.owner == origin.network)
    }
}

/// Who presented a value or cleans it up, as the API sends it along with
/// each change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Origin {
    /// The client: its IPv4 address, or its IPv6 /64. Only the same
    /// owner can clean a value up. `None` for writes from an
    /// API that sends no owner; those belong to nobody else.
    pub owner: Option<IpAddr>,
    /// The client's network, as the API groups clients for rate limiting.
    /// The caps on pending values count by it. An API from v0.5.0 sends
    /// the network as the owner and leaves this out.
    pub network: Option<IpAddr>,
}

impl Origin {
    /// What the caps on pending values count by.
    fn network(&self) -> Option<IpAddr> {
        self.network.or(self.owner)
    }
}

/// Why a value could not be published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Full {
    /// No room for another challenge name.
    Store,
    /// The name holds as many values as it may (16).
    Name,
    /// The client network holds as many values at the name as it may (2).
    Network,
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
            Self::Network => error(
                409,
                &format!(
                    "this client network already holds {MAX_VALUES_PER_NETWORK} pending values at this name"
                ),
            ),
        }
    }
}

impl Challenges {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publishes `value` at `name` for the owner in `origin`, or extends
    /// it if that owner published it there already.
    ///
    /// `seq` is the API's number for the change. A present older than the
    /// latest present or cleanup of the same value by the same owner
    /// changes nothing and still succeeds: the later change wins.
    pub fn present(
        &self,
        name: LowerName,
        value: &str,
        origin: Origin,
        seq: Option<u64>,
    ) -> Result<(), Full> {
        self.present_at(name, value, origin, seq, Instant::now())
    }

    /// Removes `value` from `name` if the owner in `origin` published it.
    /// Anything else is left alone, the same value published by another
    /// owner included, and so is a value presented after this cleanup
    /// (by `seq`). With a `seq`, the cleanup is remembered for a while,
    /// so that a present sent before it that arrives late cannot bring the
    /// value back.
    pub fn cleanup(&self, name: &LowerName, value: &str, origin: Origin, seq: Option<u64>) {
        self.cleanup_at(name, value, origin, seq, Instant::now());
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
        origin: Origin,
        seq: Option<u64>,
        now: Instant,
    ) -> Result<(), Full> {
        let mut inner = self.lock();
        let key = (name, value.to_owned(), origin.owner);
        if let Some(removal) = inner.removals.get(&key)
            && removal.expires > now
            && superseded(seq, Some(removal.seq))
        {
            return Ok(());
        }
        inner.present(&key, origin, seq, now)?;
        // The value is back, so the cleanup before it has nothing left to
        // guard. Changes without a number leave removals alone.
        if seq.is_some() {
            inner.removals.remove(&key);
        }
        Ok(())
    }

    fn cleanup_at(
        &self,
        name: &LowerName,
        value: &str,
        origin: Origin,
        seq: Option<u64>,
        now: Instant,
    ) {
        let mut inner = self.lock();
        // Whether this owner presented the value again after this cleanup.
        let mut presented_since = false;
        if let Some(entries) = inner.names.get_mut(name) {
            entries.retain(|e| {
                if e.value != value || !e.owned_by(&origin) {
                    return true;
                }
                let newer = superseded(seq, e.seq);
                presented_since |= newer;
                newer
            });
            if entries.is_empty() {
                inner.names.remove(name);
            }
        }
        if let Some(seq) = seq
            && !presented_since
        {
            let key = (name.clone(), value.to_owned(), origin.owner);
            inner.remember_removal(key, seq, now);
        }
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

/// A challenge name, a value and its owner.
type Key = (LowerName, String, Option<IpAddr>);

impl Inner {
    /// Publishes or extends the value in `key`, see [`Challenges::present`].
    fn present(
        &mut self,
        key: &Key,
        origin: Origin,
        seq: Option<u64>,
        now: Instant,
    ) -> Result<(), Full> {
        let (name, value, owner) = key;
        if !self.names.contains_key(name) && self.names.len() >= MAX_NAMES {
            self.purge_if_due(now);
            if self.names.len() >= MAX_NAMES {
                return Err(Full::Store);
            }
        }
        let entries = self.names.entry(name.clone()).or_default();
        entries.retain(|e| e.expires > now);
        let expires = now + LIFETIME;
        if let Some(entry) = entries
            .iter_mut()
            .find(|e| e.value == *value && e.origin.owner == *owner)
        {
            if !superseded(seq, entry.seq) {
                entry.expires = expires;
                entry.seq = entry.seq.max(seq);
            }
            return Ok(());
        }
        // Writes without an owner cannot be told apart, so only the cap
        // for the whole name applies to them.
        let network = origin.network();
        if network.is_some()
            && entries
                .iter()
                .filter(|e| e.origin.network() == network)
                .count()
                >= MAX_VALUES_PER_NETWORK
        {
            return Err(Full::Network);
        }
        if entries.len() >= MAX_VALUES {
            return Err(Full::Name);
        }
        entries.push(Entry {
            value: value.clone(),
            origin,
            seq,
            expires,
        });
        Ok(())
    }

    fn purge(&mut self, now: Instant) {
        self.names.retain(|_, entries| {
            entries.retain(|e| e.expires > now);
            !entries.is_empty()
        });
        self.removals.retain(|_, removal| removal.expires > now);
        self.last_purge = Some(now);
    }

    /// Purges unless the last purge was less than [`PURGE_INTERVAL`] ago.
    /// A sweep walks both tables while TXT lookups wait for the lock, so a
    /// store kept full by a flood of new names or cleanups sweeps at most
    /// once a second, however many writes arrive.
    fn purge_if_due(&mut self, now: Instant) {
        if self
            .last_purge
            .is_none_or(|last| now.saturating_duration_since(last) >= PURGE_INTERVAL)
        {
            self.purge(now);
        }
    }

    fn remember_removal(&mut self, key: Key, seq: u64, now: Instant) {
        let expires = now + LIFETIME;
        if let Some(removal) = self.removals.get_mut(&key) {
            if seq > removal.seq || removal.expires <= now {
                *removal = Removal { seq, expires };
            }
            return;
        }
        if self.removals.len() >= MAX_REMOVALS {
            self.purge_if_due(now);
        }
        if self.removals.len() >= MAX_REMOVALS {
            // A present sent before a cleanup arrives within seconds, so
            // the oldest removal is the one least likely to be needed. A
            // removal never stands in the way of a new value.
            if let Some(oldest) = self
                .removals
                .iter()
                .min_by_key(|(_, removal)| removal.expires)
                .map(|(key, _)| key.clone())
            {
                self.removals.remove(&oldest);
            }
        }
        self.removals.insert(key, Removal { seq, expires });
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
/// servers, see [`Origin`]. Only name servers read it, never the public
/// API. Unknown fields are ignored, so a name server from v0.5.0 takes
/// changes from a newer API.
#[derive(Deserialize)]
struct Forwarded {
    /// Left out by an API from before values had owners.
    #[serde(default)]
    owner: Option<IpAddr>,
    /// Left out by an API from v0.5.0 or older.
    #[serde(default)]
    network: Option<IpAddr>,
    /// The API's number for the change, see [`Sequence`]. Left out by an
    /// API from v0.5.0 or older.
    #[serde(default)]
    seq: Option<u64>,
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
            | ChallengeError::Blocked
            | ChallengeError::CoversPublicHost => 403,
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

/// Where the API says a change comes from, and its number.
fn forwarded(req: &Request) -> Result<(Origin, Option<u64>), Response> {
    serde_json::from_slice::<Forwarded>(&req.body)
        .map(|f| {
            let origin = Origin {
                owner: f.owner,
                network: f.network,
            };
            (origin, f.seq)
        })
        .map_err(|_| {
            error(
                400,
                "owner and network must be IP addresses, seq a whole number",
            )
        })
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
    /// With a key, writes must be signed with it, and answers are.
    guard: Option<auth::Guard>,
}

impl Node {
    /// `handler` supplies the current zone and the metrics; `store` must
    /// be the one `handler` answers from. Takes unsigned writes from
    /// `writers`; see [`Node::with_key`].
    pub fn new(handler: Handler, store: Arc<Challenges>, writers: &[IpAddr]) -> Self {
        Self {
            handler,
            store,
            writers: writers.iter().map(|ip| ip.to_canonical()).collect(),
            guard: None,
        }
    }

    /// The write endpoint `acme` describes: its writers and, with
    /// `acme.key`, signatures.
    pub fn from_config(
        handler: Handler,
        store: Arc<Challenges>,
        acme: &AcmeConfig,
    ) -> Result<Self> {
        let node = Self::new(handler, store, &acme.writers);
        Ok(match &acme.key {
            Some(key) => node.with_key(key.bytes()?),
            None => node,
        })
    }

    /// Takes only writes signed with `key`, recently and once, from the
    /// writers, and signs every answer to them.
    pub fn with_key(mut self, key: &[u8]) -> Self {
        self.guard = Some(auth::Guard::new(auth::Key::new(key)));
        self
    }

    /// Takes writes on `listener` until the task is dropped. Connections
    /// from anyone but the writers are closed before they are read, so
    /// they cannot hold the slots the API needs.
    pub async fn serve(self, listener: TcpListener) {
        let node = Arc::new(self);
        let filter = node.clone();
        Server::new(listener)
            .allow(move |ip| filter.admits(ip))
            .serve(move |req| {
                let node = node.clone();
                async move { node.handle(req).await }
            })
            .await
    }

    pub async fn handle(&self, req: Request) -> Response {
        // Already checked in `serve`; this is for callers of `handle`.
        if !self.admits(req.peer.ip()) {
            return error(403, "not allowed to write challenges");
        }
        let Some(guard) = &self.guard else {
            return self.try_handle(req).unwrap_or_else(|response| response);
        };
        let mac = match guard.check(&req) {
            Ok(mac) => mac,
            Err(refusal) => {
                warn!(
                    peer = %req.peer.ip(),
                    status = refusal.status,
                    "acme: refused a write that is not properly signed: {}",
                    refusal.body
                );
                self.count(AcmeWrite::Rejected);
                return refusal;
            }
        };
        let response = self.try_handle(req).unwrap_or_else(|response| response);
        guard.key().sign_response(&mac, response)
    }

    /// Whether `ip` may write challenges. Counts those that may not, so a
    /// change of the API's address shows up in the metrics; scanners
    /// knocking on the port do too.
    fn admits(&self, ip: IpAddr) -> bool {
        let admitted = self.writers.contains(&ip.to_canonical());
        if !admitted {
            self.count(AcmeWrite::Forbidden);
        }
        admitted
    }

    fn count(&self, result: AcmeWrite) {
        self.handler.metrics().acme_write(result);
    }

    fn try_handle(&self, req: Request) -> Result<Response, Response> {
        let rejected = |_: &Response| self.count(AcmeWrite::Rejected);
        let action = route(&req).inspect_err(rejected)?;
        let zone = self.handler.zone();
        let (name, value) = parse(&req, &zone).inspect_err(rejected)?;
        let (origin, seq) = forwarded(&req).inspect_err(rejected)?;
        match action {
            Action::Present => {
                if let Err(full) = self.store.present(name, &value, origin, seq) {
                    self.count(AcmeWrite::Rejected);
                    return Err(full.response());
                }
            }
            // Removing nothing (a value this owner never published, or one
            // already gone) still succeeds, so cleanup can be retried.
            Action::Cleanup => self.store.cleanup(&name, &value, origin, seq),
        }
        self.count(AcmeWrite::Accepted);
        Ok(ok())
    }
}

/// The public challenge API.
pub struct Api {
    zone: Zone,
    limiter: RateLimiter,
    nodes: Vec<SocketAddr>,
    metrics: ApiMetrics,
    seq: Sequence,
    /// With `acme.key`: how writes are signed and answers checked.
    signing: Option<Signing>,
}

/// How the API signs its writes and which answers it trusts.
#[derive(Clone)]
struct Signing {
    key: auth::Key,
    /// Whether unsigned answers count, from name servers that do not have
    /// the key yet (`acme.allow_unsigned_nodes`).
    allow_unsigned: bool,
}

impl Api {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        // Rate limiter settings and every name server's write endpoint.
        cfg.validate_acme_api()?;
        for warning in cfg.acme_api_warnings() {
            warn!("{warning}");
        }
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
            metrics: ApiMetrics::new(&nodes),
            nodes,
            seq: Sequence::default(),
            signing: match &acme.key {
                Some(key) => Some(Signing {
                    key: auth::Key::new(key.bytes()?),
                    allow_unsigned: acme.allow_unsigned_nodes,
                }),
                None => None,
            },
        })
    }

    /// The name server endpoints every change goes to.
    pub fn nodes(&self) -> &[SocketAddr] {
        &self.nodes
    }

    /// Serves the API on `listener` until the task is dropped.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) {
        let counter = self.clone();
        Server::new(listener)
            .observe(move |path, status| counter.metrics.request(path, status))
            .serve(move |req| {
                let api = self.clone();
                async move { api.handle(req).await }
            })
            .await
    }

    /// The API's metrics in the Prometheus text format.
    pub fn render_metrics(&self) -> String {
        self.metrics.render(self.limiter.tracked())
    }

    pub async fn handle(self: &Arc<Self>, req: Request) -> Response {
        match self.try_handle(req).await {
            Ok(response) | Err(response) => response,
        }
    }

    async fn try_handle(self: &Arc<Self>, req: Request) -> Result<Response, Response> {
        let action = route(&req)?;
        let client = client_ip(&req);
        if self.limiter.check(client) != Verdict::Allow {
            return Err(error(429, "too many requests, slow down"));
        }
        let (name, value) = parse(&req, &self.zone)?;
        // The value belongs to the client, so only it can clean the value
        // up again; the caps count by its network, grouped as for rate
        // limiting.
        let origin = Origin {
            owner: Some(owner(client)),
            network: Some(self.limiter.network(client)),
        };
        // The change runs in a task of its own, so that it finishes, and
        // takes a failed present back, even if the client's connection is
        // dropped meanwhile.
        let api = self.clone();
        tokio::spawn(async move { api.change(action, name, value, origin).await })
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "acme: a change failed");
                Err(error(500, "internal error, try again later"))
            })
    }

    /// Sends a checked change to every name server and answers the client.
    async fn change(
        &self,
        action: Action,
        name: LowerName,
        value: String,
        origin: Origin,
    ) -> Result<Response, Response> {
        // Each change gets its own number, so every name server ends up
        // with the latest one. A present takes the number of its rollback
        // too, right after its own: a retry that overlaps a present that
        // fails comes after both, so the rollback cannot take the retried
        // value down again.
        let seq = self.seq.take(match action {
            Action::Present => 2,
            Action::Cleanup => 1,
        });
        let change = |seq: u64| {
            // The ASCII form: `to_string` turns Punycode labels into
            // Unicode, which name servers would reject.
            serde_json::json!({
                "fqdn": name.to_ascii(),
                "value": value,
                "owner": origin.owner,
                "network": origin.network,
                "seq": seq,
            })
            .to_string()
        };
        let body = change(seq);

        let all = 0..self.nodes.len();
        let mut rejected = Vec::new();
        let mut failed = Vec::new();
        for (node, outcome) in self.send(all, action, &body, NODE_TIMEOUT).await {
            match outcome {
                Outcome::Accepted => {}
                Outcome::Rejected => rejected.push(node),
                Outcome::Failed(problem) => failed.push(problem),
            }
        }
        if rejected.is_empty() && failed.is_empty() {
            return Ok(ok());
        }
        if !failed.is_empty() {
            failed.sort();
            let failed = failed.join(", ");
            warn!(
                action = action.path(),
                fqdn = %name,
                %failed,
                "acme: a name server did not take the change"
            );
        }
        // The client is told the value was not published, so no name
        // server should keep serving it: not those that took it, and not
        // those that gave no usable answer, which may have stored it and
        // lost the reply. Cleanup succeeds where there is nothing to
        // remove. Only a name server that refused the value over a cap
        // never held it for this client. Waiting for this means a retry
        // right after the error cannot be undone by it.
        if action == Action::Present {
            let others = (0..self.nodes.len()).filter(|node| !rejected.contains(node));
            self.roll_back(others, &change(seq + 1)).await;
        }
        if !rejected.is_empty() {
            return Err(error(409, &too_many_values()));
        }
        // Clients learn how many name servers failed, not which or why:
        // their addresses and errors stay in the log.
        Err(error(
            502,
            &format!(
                "{} of {} name servers did not take the change; try again later",
                failed.len(),
                self.nodes.len()
            ),
        ))
    }

    /// Sends a change to the name servers numbered `nodes`, all at once,
    /// waiting at most `limit` for each, and counts what they did with it.
    async fn send(
        &self,
        nodes: impl IntoIterator<Item = usize>,
        action: Action,
        body: &str,
        limit: Duration,
    ) -> Vec<(usize, Outcome)> {
        let tasks: Vec<_> = nodes
            .into_iter()
            .map(|node| {
                let addr = self.nodes[node];
                let body = body.to_owned();
                let signing = self.signing.clone();
                let task = async move { send(addr, action, &body, limit, signing.as_ref()).await };
                (node, tokio::spawn(task))
            })
            .collect();
        let mut outcomes = Vec::with_capacity(tasks.len());
        for (node, task) in tasks {
            let outcome = task.await.unwrap_or_else(|e| {
                Outcome::Failed(format!("{} (task failed: {e})", self.nodes[node]))
            });
            self.metrics.node_write(node, outcome.kind());
            outcomes.push((node, outcome));
        }
        outcomes
    }

    /// Cleans up a value with `body` on the name servers numbered
    /// `nodes`, as far as they answer in time. Failures are only logged:
    /// the value expires there on its own.
    async fn roll_back(&self, nodes: impl IntoIterator<Item = usize>, body: &str) {
        for (_, outcome) in self
            .send(nodes, Action::Cleanup, body, ROLLBACK_TIMEOUT)
            .await
        {
            if let Outcome::Failed(problem) = outcome {
                warn!(%problem, "acme: could not take back a value after a failed change");
            }
        }
    }
}

/// Numbers the API's changes, so that name servers apply them in the
/// order the API made them, whatever order they arrive in: when a present
/// and a cleanup of the same value overlap, every name server keeps the
/// later one.
///
/// Each number is above the last and at least the wall-clock time in
/// nanoseconds, so numbers keep increasing across restarts of the API as
/// long as its clock does not go back.
#[derive(Default)]
struct Sequence {
    last: AtomicU64,
}

impl Sequence {
    #[cfg(test)]
    fn next(&self) -> u64 {
        self.take(1)
    }

    /// Takes `count` consecutive numbers and returns the first.
    fn take(&self, count: u64) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        let first = |last: u64| now.max(last.saturating_add(1));
        let last = self
            .last
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                Some(first(last).saturating_add(count.saturating_sub(1)))
            })
            .unwrap_or_else(|last| last);
        first(last)
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

impl Outcome {
    fn kind(&self) -> NodeWrite {
        match self {
            Self::Accepted => NodeWrite::Accepted,
            Self::Rejected => NodeWrite::Rejected,
            Self::Failed(_) => NodeWrite::Failed,
        }
    }
}

/// Sends a change to the name server at `addr`, waiting at most `limit`,
/// signed if there is `signing`.
async fn send(
    addr: SocketAddr,
    action: Action,
    body: &str,
    limit: Duration,
    signing: Option<&Signing>,
) -> Outcome {
    let path = action.path();
    let (headers, signed) = match signing {
        Some(signing) => {
            // `post` names `addr` in the Host header, as it is written here.
            let host = addr.to_string();
            let (headers, signed) =
                signing
                    .key
                    .sign_request(&host, auth::now(), "POST", path, body.as_bytes());
            (headers, Some(signed))
        }
        None => (Vec::new(), None),
    };
    let problem = match timeout(limit, post(addr, path, &headers, body)).await {
        Ok(Ok(reply)) => match (reply.status, reply_ok(&reply.body)) {
            // Only a name server's own answer counts, not any 200: a port
            // that serves something else must not acknowledge a value.
            // A refusal over a cap (the client's to sort out) also stops
            // the API from taking the value back there, so both have to
            // be genuine.
            (200, Some(true)) | (409, Some(false)) => match trust(&reply, signing, signed.as_ref())
            {
                Ok(()) if reply.status == 200 => return Outcome::Accepted,
                Ok(()) => return Outcome::Rejected,
                Err(problem) => problem.to_owned(),
            },
            (200, _) => "HTTP 200 without {\"ok\":true}".to_owned(),
            (status, _) => match reply_error(&reply.body) {
                Some(error) => format!("HTTP {status}: {error}"),
                None => format!("HTTP {status}"),
            },
        },
        Ok(Err(e)) => e.to_string(),
        Err(_) => "timed out".to_owned(),
    };
    Outcome::Failed(format!("{addr} ({problem})"))
}

/// Whether `reply`, the answer to the request `signed` with `signing`, is
/// genuine: signed with the key and bound to that request, which names
/// the name server it went to. Without a key every answer counts, as it
/// did before keys.
fn trust(
    reply: &Reply,
    signing: Option<&Signing>,
    signed: Option<&auth::Signed>,
) -> Result<(), &'static str> {
    let (Some(signing), Some(signed)) = (signing, signed) else {
        return Ok(());
    };
    match reply.header(auth::MAC) {
        Some(signature)
            if signing.key.verifies_reply(
                signed,
                reply.status,
                reply.body.as_bytes(),
                signature,
            ) =>
        {
            Ok(())
        }
        Some(_) => Err("answer with a bad signature"),
        None if signing.allow_unsigned => Ok(()),
        None => Err("unsigned answer; does the name server have acme.key?"),
    }
}

/// The `ok` field of a name server's JSON answer, if it is one.
fn reply_ok(reply: &str) -> Option<bool> {
    #[derive(Deserialize)]
    struct Answer {
        ok: bool,
    }
    serde_json::from_str::<Answer>(reply).ok().map(|r| r.ok)
}

/// The `error` field of a name server's JSON answer, for the log: plain
/// ASCII without line breaks, and short.
fn reply_error(reply: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Answer {
        error: String,
    }
    let error = serde_json::from_str::<Answer>(reply).ok()?.error;
    Some(
        error
            .chars()
            .filter(|c| c.is_ascii_graphic() || *c == ' ')
            .take(200)
            .collect(),
    )
}

/// The API's answer when a name server refuses a value over a cap.
fn too_many_values() -> String {
    format!(
        "this name already holds as many pending values as allowed \
         ({MAX_VALUES_PER_NETWORK} per client network, {MAX_VALUES} in all); \
         clean up values you no longer need, or wait up to {} minutes for them to expire",
        LIFETIME.as_secs() / 60
    )
}

/// The owner of the values `client` presents: its IPv4 address, or its
/// IPv6 /64. `client` is canonical, so IPv4-mapped addresses are IPv4.
fn owner(client: IpAddr) -> IpAddr {
    match client {
        IpAddr::V4(_) => client,
        IpAddr::V6(ip) => {
            let mask = u128::MAX << (128 - IPV6_OWNER_PREFIX);
            IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask))
        }
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

    /// A client as the API describes it: its address and its network.
    fn client(owner: &str, network: &str) -> Origin {
        Origin {
            owner: Some(owner.parse().unwrap()),
            network: Some(network.parse().unwrap()),
        }
    }

    /// A client as an API from v0.5.0 describes it: by its network alone.
    fn old_client(network: &str) -> Origin {
        Origin {
            owner: Some(network.parse().unwrap()),
            network: None,
        }
    }

    const NOBODY: Origin = Origin {
        owner: None,
        network: None,
    };

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
    fn owners_are_addresses_or_ipv6_64s() {
        let owner_of = |ip: &str| owner(ip.parse().unwrap()).to_string();
        assert_eq!(owner_of("192.0.2.10"), "192.0.2.10");
        assert_eq!(owner_of("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::");
        assert_eq!(owner_of("2001:db8:1:2::99"), "2001:db8:1:2::");
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
        let me = client("192.0.2.10", "192.0.2.0");
        let now = Instant::now();
        store.present_at(n.clone(), VALUE, me, None, now).unwrap();
        store.present_at(n.clone(), "b", me, None, now).unwrap();
        assert_eq!(store.values_at(&n, now), [VALUE, "b"]);

        store.cleanup(&n, "b", me, None);
        assert_eq!(store.values_at(&n, now), [VALUE]);
        assert!(store.values_at(&n, now + LIFETIME).is_empty());

        // Presenting again extends the lifetime instead of adding a copy.
        let later = now + LIFETIME / 2;
        store.present_at(n.clone(), VALUE, me, None, later).unwrap();
        assert_eq!(store.values_at(&n, now + LIFETIME), [VALUE]);
        assert_eq!(store.len_at(now), 1);

        store.cleanup(&n, VALUE, me, None);
        assert!(store.is_empty());
    }

    #[test]
    fn only_the_owner_cleans_up() {
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let me = client("192.0.2.10", "192.0.2.0");
        let other = client("198.51.100.7", "198.51.100.0");
        let now = Instant::now();
        store.present_at(n.clone(), VALUE, me, None, now).unwrap();

        // A neighbour on the same network, another network, a write with
        // no owner, or one with the network as the owner removes nothing.
        for them in [
            client("192.0.2.99", "192.0.2.0"),
            other,
            NOBODY,
            old_client("192.0.2.0"),
        ] {
            store.cleanup(&n, VALUE, them, None);
        }
        assert_eq!(store.values_at(&n, now), [VALUE]);

        // The same value from two owners is answered once and stays until
        // both have cleaned it up.
        store
            .present_at(n.clone(), VALUE, other, None, now)
            .unwrap();
        assert_eq!(store.values_at(&n, now), [VALUE]);
        assert_eq!(store.len_at(now), 1);
        store.cleanup(&n, VALUE, me, None);
        assert_eq!(store.values_at(&n, now), [VALUE]);
        store.cleanup(&n, VALUE, other, None);
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
                .present_at(n.clone(), &i.to_string(), NOBODY, None, now)
                .unwrap();
        }
        assert_eq!(
            store.present_at(n.clone(), "x", NOBODY, None, now),
            Err(Full::Name)
        );
        store.cleanup(&n, "0", old_client("192.0.2.0"), None);
        store.cleanup(&n, "0", client("192.0.2.10", "192.0.2.0"), None);
        assert_eq!(store.len_at(now), MAX_VALUES);
        store.cleanup(&n, "0", NOBODY, None);
        assert_eq!(store.len_at(now), MAX_VALUES - 1);
    }

    #[test]
    fn values_from_an_old_api_belong_to_the_network() {
        // An API from v0.5.0 sends the client's network as the owner and no
        // network: the caps count by that owner, and its cleanups remove
        // what it presented.
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let now = Instant::now();
        let old = old_client("192.0.2.0");
        store.present_at(n.clone(), "a", old, None, now).unwrap();
        store.present_at(n.clone(), "b", old, None, now).unwrap();
        assert_eq!(
            store.present_at(n.clone(), "c", old, None, now),
            Err(Full::Network)
        );
        // The new API counts that client's network the same way.
        let me = client("192.0.2.10", "192.0.2.0");
        assert_eq!(
            store.present_at(n.clone(), "c", me, None, now),
            Err(Full::Network)
        );

        store.cleanup(&n, "a", old, None);
        assert_eq!(store.values_at(&n, now), ["b"]);
        // Once the API is upgraded, a client on that network can still take
        // down what it presented before: those values never had an address.
        store.cleanup(&n, "b", client("192.0.2.99", "192.0.2.0"), None);
        assert!(store.values_at(&n, now).is_empty());

        // Values the new API presented are not the network's.
        store.present_at(n.clone(), "c", me, None, now).unwrap();
        store.cleanup(&n, "c", old, None);
        assert_eq!(store.values_at(&n, now), ["c"]);
    }

    #[test]
    fn live_values_are_never_pushed_out() {
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let me = client("192.0.2.10", "192.0.2.0");
        let now = Instant::now();
        store.present_at(n.clone(), "a", me, None, now).unwrap();
        store.present_at(n.clone(), "b", me, None, now).unwrap();
        // A third value from the same network is refused, whichever
        // address on it asks...
        assert_eq!(
            store.present_at(n.clone(), "c", me, None, now),
            Err(Full::Network)
        );
        let neighbour = client("192.0.2.99", "192.0.2.0");
        assert_eq!(
            store.present_at(n.clone(), "c", neighbour, None, now),
            Err(Full::Network)
        );
        // ...but extending one it holds is fine.
        store.present_at(n.clone(), "a", me, None, now).unwrap();
        assert_eq!(store.values_at(&n, now), ["a", "b"]);

        // Other networks fill the name up to its cap.
        for i in 1..MAX_VALUES / MAX_VALUES_PER_NETWORK {
            let them = client(&format!("198.51.{i}.1"), &format!("198.51.{i}.0"));
            for v in ["a", "b"] {
                store
                    .present_at(n.clone(), &format!("{v}{i}"), them, None, now)
                    .unwrap();
            }
        }
        assert_eq!(store.len_at(now), MAX_VALUES);
        let late = client("203.0.113.1", "203.0.113.0");
        assert_eq!(
            store.present_at(n.clone(), "z", late, None, now),
            Err(Full::Name)
        );
        assert_eq!(store.values_at(&n, now)[..2], ["a", "b"]);

        // Once the first ones expire, there is room again.
        let later = now + LIFETIME;
        store.present_at(n.clone(), "z", late, None, later).unwrap();
        store.present_at(n.clone(), "c", me, None, later).unwrap();
        assert_eq!(store.values_at(&n, later), ["z", "c"]);
    }

    #[test]
    fn store_is_bounded() {
        let store = Challenges::new();
        let now = Instant::now();
        for i in 0..MAX_NAMES {
            let n = name(&format!("_acme-challenge.{i}.10-0-2-2.ipssl.cc."));
            store.present_at(n, VALUE, NOBODY, None, now).unwrap();
        }
        let extra = name("_acme-challenge.10-0-2-3.ipssl.cc.");
        assert_eq!(
            store.present_at(extra.clone(), VALUE, NOBODY, None, now),
            Err(Full::Store)
        );
        // Once the others expire there is room again.
        store
            .present_at(extra, VALUE, NOBODY, None, now + LIFETIME)
            .unwrap();
        assert_eq!(store.len_at(now + LIFETIME), 1);
    }

    #[test]
    fn full_store_sweeps_at_most_once_a_second() {
        let store = Challenges::new();
        let now = Instant::now();
        for i in 0..MAX_NAMES {
            let n = name(&format!("_acme-challenge.{i}.10-0-2-2.ipssl.cc."));
            store.present_at(n, VALUE, NOBODY, None, now).unwrap();
        }
        let extra = name("_acme-challenge.10-0-2-3.ipssl.cc.");
        let present = |at| store.present_at(extra.clone(), VALUE, NOBODY, None, at);
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
        store
            .present_at(n.clone(), VALUE, NOBODY, None, now)
            .unwrap();
        assert_eq!(store.len_at(now), 1);
        // Gone from the count as soon as DNS stops serving it, before any purge.
        assert_eq!(store.len_at(now + LIFETIME), 0);
        assert!(store.values_at(&n, now + LIFETIME).is_empty());
    }

    #[test]
    fn a_late_present_does_not_undo_a_later_cleanup() {
        // The API presented (1), then cleaned up (2); this name server got
        // the cleanup first.
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let me = client("192.0.2.10", "192.0.2.0");
        let now = Instant::now();
        store.cleanup_at(&n, VALUE, me, Some(2), now);
        store
            .present_at(n.clone(), VALUE, me, Some(1), now)
            .unwrap();
        assert!(store.values_at(&n, now).is_empty());

        // A present after the cleanup does publish the value, and a late
        // copy of the cleanup does not take it down again.
        store
            .present_at(n.clone(), VALUE, me, Some(3), now)
            .unwrap();
        assert_eq!(store.values_at(&n, now), [VALUE]);
        store.cleanup_at(&n, VALUE, me, Some(2), now);
        assert_eq!(store.values_at(&n, now), [VALUE]);
        store.cleanup_at(&n, VALUE, me, Some(4), now);
        assert!(store.values_at(&n, now).is_empty());

        // The cleanup is remembered only as long as a present sent before
        // it could matter.
        let later = now + LIFETIME;
        store
            .present_at(n.clone(), VALUE, me, Some(1), later)
            .unwrap();
        assert_eq!(store.values_at(&n, later), [VALUE]);
    }

    #[test]
    fn a_late_cleanup_does_not_undo_a_later_present() {
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let me = client("192.0.2.10", "192.0.2.0");
        let now = Instant::now();
        store
            .present_at(n.clone(), VALUE, me, Some(5), now)
            .unwrap();
        store.cleanup_at(&n, VALUE, me, Some(4), now);
        assert_eq!(store.values_at(&n, now), [VALUE]);
        // An older present neither adds a copy nor moves the expiry.
        let soon = now + Duration::from_secs(60);
        store
            .present_at(n.clone(), VALUE, me, Some(3), soon)
            .unwrap();
        assert!(store.values_at(&n, now + LIFETIME).is_empty());
        // The same change twice is applied once.
        store
            .present_at(n.clone(), VALUE, me, Some(5), soon)
            .unwrap();
        assert!(store.values_at(&n, now + LIFETIME).is_empty());
        assert_eq!(store.len_at(now), 1);
        assert!(store.lock().removals.is_empty());
    }

    #[test]
    fn changes_without_a_number_apply_as_they_come() {
        // What an API from v0.5.0 sends: no sequence numbers, and nothing
        // is remembered of its cleanups.
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let old = old_client("192.0.2.0");
        let now = Instant::now();
        store.cleanup_at(&n, VALUE, old, None, now);
        assert!(store.lock().removals.is_empty());
        store.present_at(n.clone(), VALUE, old, None, now).unwrap();
        assert_eq!(store.values_at(&n, now), [VALUE]);
        store.cleanup_at(&n, VALUE, old, None, now);
        assert!(store.values_at(&n, now).is_empty());

        // Against numbered changes they are always the newest.
        let me = client("192.0.2.10", "192.0.2.0");
        store
            .present_at(n.clone(), VALUE, me, Some(9), now)
            .unwrap();
        store.cleanup_at(&n, VALUE, me, None, now);
        assert!(store.values_at(&n, now).is_empty());
        store.cleanup_at(&n, VALUE, me, Some(10), now);
        store.present_at(n.clone(), VALUE, me, None, now).unwrap();
        assert_eq!(store.values_at(&n, now), [VALUE]);
    }

    #[test]
    fn removals_count_toward_no_cap() {
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let me = client("192.0.2.10", "192.0.2.0");
        let now = Instant::now();
        // Many cleanups of values never presented, and of two that were.
        for i in 0..MAX_VALUES {
            store.cleanup_at(&n, &i.to_string(), me, Some(1), now);
        }
        store.present_at(n.clone(), "a", me, Some(2), now).unwrap();
        store.present_at(n.clone(), "b", me, Some(3), now).unwrap();
        store.cleanup_at(&n, "a", me, Some(4), now);
        store.cleanup_at(&n, "b", me, Some(5), now);
        assert_eq!(store.len_at(now), 0);
        assert!(store.is_empty());
        // The network still has room for two values, and the name for all.
        store.present_at(n.clone(), "c", me, Some(6), now).unwrap();
        store.present_at(n.clone(), "d", me, Some(7), now).unwrap();
        for i in 1..MAX_VALUES / MAX_VALUES_PER_NETWORK {
            let them = client(&format!("198.51.{i}.1"), &format!("198.51.{i}.0"));
            for v in ["a", "b"] {
                store
                    .present_at(n.clone(), &format!("{v}{i}"), them, Some(8), now)
                    .unwrap();
            }
        }
        assert_eq!(store.len_at(now), MAX_VALUES);
    }

    #[test]
    fn removals_are_bounded() {
        let store = Challenges::new();
        let me = client("192.0.2.10", "192.0.2.0");
        let now = Instant::now();
        let n = |i: usize| name(&format!("_acme-challenge.{i}.10-0-2-2.ipssl.cc."));
        for i in 0..=MAX_REMOVALS {
            let at = now + Duration::from_millis(i as u64);
            store.cleanup_at(&n(i), VALUE, me, Some(1), at);
        }
        assert_eq!(store.lock().removals.len(), MAX_REMOVALS);
        // The oldest was forgotten, so a late present of it gets through;
        // the newest is still guarded.
        let at = now + Duration::from_secs(20);
        store.present_at(n(0), VALUE, me, Some(0), at).unwrap();
        assert_eq!(store.values_at(&n(0), at), [VALUE]);
        store
            .present_at(n(MAX_REMOVALS), VALUE, me, Some(0), at)
            .unwrap();
        assert!(store.values_at(&n(MAX_REMOVALS), at).is_empty());

        // Expired removals are swept with the values.
        store.lock().purge(now + LIFETIME + Duration::from_secs(20));
        assert!(store.lock().removals.is_empty());
    }

    #[test]
    fn sequence_numbers_increase_across_restarts() {
        let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let seq = Sequence::default();
        let first = seq.next();
        assert!(u128::from(first) >= before.as_nanos());
        let mut last = first;
        for _ in 0..1000 {
            let next = seq.next();
            assert!(next > last);
            last = next;
        }
        // A restarted API starts from the clock, past what it sent before
        // unless the clock went back.
        let restarted = Sequence::default();
        std::thread::sleep(Duration::from_millis(2));
        assert!(restarted.next() > first);

        // Ahead of the clock (a clock set back, say), it keeps counting up
        // from the last number it gave.
        let future = first + 3_600_000_000_000;
        let ahead = Sequence {
            last: AtomicU64::new(future),
        };
        assert_eq!(ahead.next(), future + 1);
        assert_eq!(ahead.next(), future + 2);

        // A present takes its rollback's number with its own.
        let present = ahead.take(2);
        assert_eq!(present, future + 3);
        assert_eq!(ahead.next(), present + 2);
    }
}
