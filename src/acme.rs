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
//!   client can clean it up.
//!
//! Only names with private addresses qualify ([`Zone::check_challenge`]),
//! and values must look like real challenge digests, so the API cannot be
//! used to publish arbitrary text in the zone.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use hickory_server::proto::rr::LowerName;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tracing::warn;

use crate::config::Config;
use crate::handler::Handler;
use crate::http::{Request, Response, Server, post_json};
use crate::metrics::{AcmeWrite, ApiMetrics, NodeWrite};
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
    /// When expired values were last swept out of the whole table.
    last_purge: Option<Instant>,
}

struct Entry {
    value: String,
    /// Who presented the value.
    origin: Origin,
    expires: Instant,
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
    /// The client: its IPv4 address, or its IPv6 /64 (see [`owner`]).
    /// Only the same owner can clean a value up. `None` for writes from an
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
    pub fn present(&self, name: LowerName, value: &str, origin: Origin) -> Result<(), Full> {
        self.present_at(name, value, origin, Instant::now())
    }

    /// Removes `value` from `name` if the owner in `origin` published it.
    /// Anything else is left alone, the same value published by another
    /// owner included.
    pub fn cleanup(&self, name: &LowerName, value: &str, origin: Origin) {
        let names = &mut self.lock().names;
        if let Some(entries) = names.get_mut(name) {
            entries.retain(|e| e.value != value || !e.owned_by(&origin));
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
        origin: Origin,
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
            .find(|e| e.value == value && e.origin.owner == origin.owner)
        {
            entry.expires = expires;
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
            value: value.to_owned(),
            origin,
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

/// Where the API says a change comes from, see [`Forwarded`].
fn origin(req: &Request) -> Result<Origin, Response> {
    serde_json::from_slice::<Forwarded>(&req.body)
        .map(|f| Origin {
            owner: f.owner,
            network: f.network,
        })
        .map_err(|_| error(400, "owner and network must be IP addresses"))
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
        self.try_handle(req).unwrap_or_else(|response| response)
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
        // Already checked in `serve`; this is for callers of `handle`.
        if !self.admits(req.peer.ip()) {
            return Err(error(403, "not allowed to write challenges"));
        }
        let rejected = |_: &Response| self.count(AcmeWrite::Rejected);
        let action = route(&req).inspect_err(rejected)?;
        let zone = self.handler.zone();
        let (name, value) = parse(&req, &zone).inspect_err(rejected)?;
        let origin = origin(&req).inspect_err(rejected)?;
        match action {
            Action::Present => {
                if let Err(full) = self.store.present(name, &value, origin) {
                    self.count(AcmeWrite::Rejected);
                    return Err(full.response());
                }
            }
            // Removing nothing (a value this owner never published, or one
            // already gone) still succeeds, so cleanup can be retried.
            Action::Cleanup => self.store.cleanup(&name, &value, origin),
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
        // The value belongs to the client, so only it can clean the value
        // up again; the caps count by its network, grouped as for rate
        // limiting.
        let owner = owner(client);
        let network = self.limiter.network(client);
        // The ASCII form: `to_string` turns Punycode labels into Unicode,
        // which name servers would reject.
        let body = serde_json::json!({
            "fqdn": name.to_ascii(),
            "value": value,
            "owner": owner,
            "network": network,
        })
        .to_string();

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
            self.roll_back(others, &body).await;
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
                (
                    node,
                    tokio::spawn(async move { send(addr, action, &body, limit).await }),
                )
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

    /// Cleans up a value presented with `body` on the name servers
    /// numbered `nodes`, as far as they answer in time. Failures are only
    /// logged: the value expires there on its own.
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

/// Sends a change to the name server at `addr`, waiting at most `limit`.
async fn send(addr: SocketAddr, action: Action, body: &str, limit: Duration) -> Outcome {
    let problem = match timeout(limit, post_json(addr, action.path(), body)).await {
        // Only a name server's own answer counts, not any 200: a port
        // that serves something else must not acknowledge a value.
        Ok(Ok((200, reply))) if reply_ok(&reply) == Some(true) => return Outcome::Accepted,
        Ok(Ok((200, _))) => "HTTP 200 without {\"ok\":true}".to_owned(),
        // A cap on pending values: the client's to sort out.
        Ok(Ok((409, reply))) if reply_ok(&reply) == Some(false) => return Outcome::Rejected,
        Ok(Ok((status, _))) => format!("HTTP {status}"),
        Ok(Err(e)) => e.to_string(),
        Err(_) => "timed out".to_owned(),
    };
    Outcome::Failed(format!("{addr} ({problem})"))
}

/// The `ok` field of a name server's JSON answer, if it is one.
fn reply_ok(reply: &str) -> Option<bool> {
    #[derive(Deserialize)]
    struct Reply {
        ok: bool,
    }
    serde_json::from_str::<Reply>(reply).ok().map(|r| r.ok)
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
        let me = client("192.0.2.10", "192.0.2.0");
        let other = client("198.51.100.7", "198.51.100.0");
        let now = Instant::now();
        store.present_at(n.clone(), VALUE, me, now).unwrap();

        // A neighbour on the same network, another network, a write with
        // no owner, or one with the network as the owner removes nothing.
        for them in [
            client("192.0.2.99", "192.0.2.0"),
            other,
            NOBODY,
            old_client("192.0.2.0"),
        ] {
            store.cleanup(&n, VALUE, them);
        }
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
                .present_at(n.clone(), &i.to_string(), NOBODY, now)
                .unwrap();
        }
        assert_eq!(
            store.present_at(n.clone(), "x", NOBODY, now),
            Err(Full::Name)
        );
        store.cleanup(&n, "0", old_client("192.0.2.0"));
        store.cleanup(&n, "0", client("192.0.2.10", "192.0.2.0"));
        assert_eq!(store.len_at(now), MAX_VALUES);
        store.cleanup(&n, "0", NOBODY);
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
        store.present_at(n.clone(), "a", old, now).unwrap();
        store.present_at(n.clone(), "b", old, now).unwrap();
        assert_eq!(
            store.present_at(n.clone(), "c", old, now),
            Err(Full::Network)
        );
        // The new API counts that client's network the same way.
        let me = client("192.0.2.10", "192.0.2.0");
        assert_eq!(
            store.present_at(n.clone(), "c", me, now),
            Err(Full::Network)
        );

        store.cleanup(&n, "a", old);
        assert_eq!(store.values_at(&n, now), ["b"]);
        // Once the API is upgraded, a client on that network can still take
        // down what it presented before: those values never had an address.
        store.cleanup(&n, "b", client("192.0.2.99", "192.0.2.0"));
        assert!(store.values_at(&n, now).is_empty());

        // Values the new API presented are not the network's.
        store.present_at(n.clone(), "c", me, now).unwrap();
        store.cleanup(&n, "c", old);
        assert_eq!(store.values_at(&n, now), ["c"]);
    }

    #[test]
    fn live_values_are_never_pushed_out() {
        let store = Challenges::new();
        let n = name("_acme-challenge.10-0-2-2.ipssl.cc.");
        let me = client("192.0.2.10", "192.0.2.0");
        let now = Instant::now();
        store.present_at(n.clone(), "a", me, now).unwrap();
        store.present_at(n.clone(), "b", me, now).unwrap();
        // A third value from the same network is refused, whichever
        // address on it asks...
        assert_eq!(
            store.present_at(n.clone(), "c", me, now),
            Err(Full::Network)
        );
        let neighbour = client("192.0.2.99", "192.0.2.0");
        assert_eq!(
            store.present_at(n.clone(), "c", neighbour, now),
            Err(Full::Network)
        );
        // ...but extending one it holds is fine.
        store.present_at(n.clone(), "a", me, now).unwrap();
        assert_eq!(store.values_at(&n, now), ["a", "b"]);

        // Other networks fill the name up to its cap.
        for i in 1..MAX_VALUES / MAX_VALUES_PER_NETWORK {
            let them = client(&format!("198.51.{i}.1"), &format!("198.51.{i}.0"));
            for v in ["a", "b"] {
                store
                    .present_at(n.clone(), &format!("{v}{i}"), them, now)
                    .unwrap();
            }
        }
        assert_eq!(store.len_at(now), MAX_VALUES);
        let late = client("203.0.113.1", "203.0.113.0");
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
            store.present_at(n, VALUE, NOBODY, now).unwrap();
        }
        let extra = name("_acme-challenge.10-0-2-3.ipssl.cc.");
        assert_eq!(
            store.present_at(extra.clone(), VALUE, NOBODY, now),
            Err(Full::Store)
        );
        // Once the others expire there is room again.
        store
            .present_at(extra, VALUE, NOBODY, now + LIFETIME)
            .unwrap();
        assert_eq!(store.len_at(now + LIFETIME), 1);
    }

    #[test]
    fn full_store_sweeps_at_most_once_a_second() {
        let store = Challenges::new();
        let now = Instant::now();
        for i in 0..MAX_NAMES {
            let n = name(&format!("_acme-challenge.{i}.10-0-2-2.ipssl.cc."));
            store.present_at(n, VALUE, NOBODY, now).unwrap();
        }
        let extra = name("_acme-challenge.10-0-2-3.ipssl.cc.");
        let present = |at| store.present_at(extra.clone(), VALUE, NOBODY, at);
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
        store.present_at(n.clone(), VALUE, NOBODY, now).unwrap();
        assert_eq!(store.len_at(now), 1);
        // Gone from the count as soon as DNS stops serving it, before any purge.
        assert_eq!(store.len_at(now + LIFETIME), 0);
        assert!(store.values_at(&n, now + LIFETIME).is_empty());
    }
}
