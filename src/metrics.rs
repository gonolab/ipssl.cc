//! Counters exposed in the Prometheus text format: [`Metrics`] for the DNS
//! server, [`ApiMetrics`] for the DNS-01 challenge API.
//!
//! Plain atomics with fixed label sets: cheap to update on every query,
//! and no label can grow without bound.

use std::fmt::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use hickory_server::net::xfer::Protocol;
use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::RecordType;

/// Query types counted on their own; everything else is `other`.
const QTYPES: [(RecordType, &str); 9] = [
    (RecordType::A, "A"),
    (RecordType::AAAA, "AAAA"),
    (RecordType::HTTPS, "HTTPS"),
    (RecordType::TXT, "TXT"),
    (RecordType::MX, "MX"),
    (RecordType::NS, "NS"),
    (RecordType::SOA, "SOA"),
    (RecordType::CAA, "CAA"),
    (RecordType::ANY, "ANY"),
];
const QTYPE_LABELS: usize = QTYPES.len() + 1;

const PROTOCOLS: [&str; 2] = ["udp", "tcp"];

/// Response codes by their wire value; everything else is `other`.
const RCODES: [(u16, &str); 7] = [
    (0, "NOERROR"),
    (1, "FORMERR"),
    (2, "SERVFAIL"),
    (3, "NXDOMAIN"),
    (4, "NOTIMP"),
    (5, "REFUSED"),
    (16, "BADVERS"),
];
const RCODE_LABELS: usize = RCODES.len() + 1;

/// What rate limiting did with a response.
#[derive(Debug, Clone, Copy)]
pub enum Limited {
    Dropped,
    Slipped,
}

/// What a name server did with a DNS-01 challenge write.
#[derive(Debug, Clone, Copy)]
pub enum AcmeWrite {
    /// Published or cleaned up.
    Accepted,
    /// Refused: wrong path or method, a body that does not hold a
    /// challenge, or no room for the value.
    Rejected,
    /// A connection from an address not in `acme.writers`, closed unread.
    Forbidden,
}

/// Values read at scrape time rather than counted.
pub struct Gauges {
    pub zone_serial: u32,
    /// `None` when rate limiting is off.
    pub rate_limit_tracked: Option<usize>,
    /// DNS-01 challenge values held; `None` when `[acme]` is off.
    pub acme_challenges: Option<usize>,
}

pub struct Metrics {
    started: f64,
    queries: [[AtomicU64; QTYPE_LABELS]; PROTOCOLS.len()],
    responses: [AtomicU64; RCODE_LABELS],
    send_errors: AtomicU64,
    /// UDP answers too large for the client's buffer, sent truncated.
    truncated: AtomicU64,
    /// Dropped, slipped.
    rate_limited: [AtomicU64; 2],
    /// Succeeded, failed.
    reloads: [AtomicU64; 2],
    /// Challenge writes accepted, rejected, forbidden.
    acme_writes: [AtomicU64; 3],
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            started: now(),
            queries: Default::default(),
            responses: Default::default(),
            send_errors: AtomicU64::new(0),
            truncated: AtomicU64::new(0),
            rate_limited: Default::default(),
            reloads: Default::default(),
            acme_writes: Default::default(),
        }
    }

    /// Counts a request. `qtype` is `None` when it has no question.
    pub fn query(&self, protocol: Protocol, qtype: Option<RecordType>) {
        let protocol = usize::from(protocol != Protocol::Udp);
        let qtype = qtype
            .and_then(|t| QTYPES.iter().position(|(known, _)| *known == t))
            .unwrap_or(QTYPES.len());
        inc(&self.queries[protocol][qtype]);
    }

    /// Counts a response that was sent.
    pub fn response(&self, rcode: ResponseCode) {
        let code = u16::from(rcode);
        let index = RCODES
            .iter()
            .position(|(known, _)| *known == code)
            .unwrap_or(RCODES.len());
        inc(&self.responses[index]);
    }

    pub fn send_error(&self) {
        inc(&self.send_errors);
    }

    /// Counts a UDP answer that did not fit and was sent truncated.
    pub fn truncated(&self) {
        inc(&self.truncated);
    }

    pub fn rate_limited(&self, what: Limited) {
        inc(&self.rate_limited[what as usize]);
    }

    pub fn reload(&self, ok: bool) {
        inc(&self.reloads[usize::from(!ok)]);
    }

    /// Counts a challenge write.
    pub fn acme_write(&self, result: AcmeWrite) {
        inc(&self.acme_writes[result as usize]);
    }

    /// The Prometheus text exposition of all metrics.
    pub fn render(&self, gauges: &Gauges) -> String {
        let mut out = String::with_capacity(4096);

        header(
            &mut out,
            "ipssl_dns_queries_total",
            "counter",
            "DNS requests received.",
        );
        for (p, protocol) in PROTOCOLS.iter().enumerate() {
            let labels = QTYPES.iter().map(|(_, l)| *l).chain(["other"]);
            for (t, qtype) in labels.enumerate() {
                let value = load(&self.queries[p][t]);
                writeln!(
                    out,
                    "ipssl_dns_queries_total{{protocol=\"{protocol}\",qtype=\"{qtype}\"}} {value}"
                )
                .unwrap();
            }
        }

        header(
            &mut out,
            "ipssl_dns_responses_total",
            "counter",
            "DNS responses sent, by response code. Includes truncated rate-limit responses.",
        );
        let labels = RCODES.iter().map(|(_, l)| *l).chain(["other"]);
        for (i, rcode) in labels.enumerate() {
            let value = load(&self.responses[i]);
            writeln!(
                out,
                "ipssl_dns_responses_total{{rcode=\"{rcode}\"}} {value}"
            )
            .unwrap();
        }

        header(
            &mut out,
            "ipssl_dns_send_errors_total",
            "counter",
            "DNS responses that could not be sent.",
        );
        writeln!(
            out,
            "ipssl_dns_send_errors_total {}",
            load(&self.send_errors)
        )
        .unwrap();

        header(
            &mut out,
            "ipssl_dns_truncated_total",
            "counter",
            "UDP answers too large for the client's buffer, sent truncated so it retries over TCP.",
        );
        writeln!(out, "ipssl_dns_truncated_total {}", load(&self.truncated)).unwrap();

        header(
            &mut out,
            "ipssl_dns_rate_limited_total",
            "counter",
            "UDP responses held back by rate limiting: dropped, or sent truncated (slip).",
        );
        for (i, action) in ["drop", "slip"].iter().enumerate() {
            let value = load(&self.rate_limited[i]);
            writeln!(
                out,
                "ipssl_dns_rate_limited_total{{action=\"{action}\"}} {value}"
            )
            .unwrap();
        }

        if let Some(tracked) = gauges.rate_limit_tracked {
            header(
                &mut out,
                "ipssl_rate_limit_tracked_networks",
                "gauge",
                "Client networks currently tracked by the rate limiter.",
            );
            writeln!(out, "ipssl_rate_limit_tracked_networks {tracked}").unwrap();
        }

        header(
            &mut out,
            "ipssl_config_reloads_total",
            "counter",
            "Config reloads, by result.",
        );
        for (i, result) in ["success", "failure"].iter().enumerate() {
            let value = load(&self.reloads[i]);
            writeln!(
                out,
                "ipssl_config_reloads_total{{result=\"{result}\"}} {value}"
            )
            .unwrap();
        }

        if let Some(held) = gauges.acme_challenges {
            header(
                &mut out,
                "ipssl_acme_challenges",
                "gauge",
                "DNS-01 challenge values currently published.",
            );
            writeln!(out, "ipssl_acme_challenges {held}").unwrap();

            header(
                &mut out,
                "ipssl_acme_writes_total",
                "counter",
                "DNS-01 challenge writes, by result. rejected includes writes without a valid signature when acme.key is set; forbidden counts connections from addresses not in acme.writers.",
            );
            for (i, result) in ["accepted", "rejected", "forbidden"].iter().enumerate() {
                let value = load(&self.acme_writes[i]);
                writeln!(
                    out,
                    "ipssl_acme_writes_total{{result=\"{result}\"}} {value}"
                )
                .unwrap();
            }
        }

        header(
            &mut out,
            "ipssl_zone_serial",
            "gauge",
            "SOA serial of the zone being served.",
        );
        writeln!(out, "ipssl_zone_serial {}", gauges.zone_serial).unwrap();

        process(&mut out, self.started);
        out
    }
}

/// API endpoints counted on their own; every other path is `other`.
const ENDPOINTS: [(&str, &str); 2] = [("/present", "present"), ("/cleanup", "cleanup")];
const ENDPOINT_LABELS: usize = ENDPOINTS.len() + 1;

/// Statuses the API answers with, counted on their own; anything else is
/// `other`.
const STATUSES: [u16; 11] = [200, 400, 403, 404, 405, 409, 411, 413, 429, 502, 503];
const STATUS_LABELS: usize = STATUSES.len() + 1;

/// What one name server did with a change the API sent it.
#[derive(Debug, Clone, Copy)]
pub enum NodeWrite {
    /// Answered `{"ok":true}`.
    Accepted,
    /// Refused the value over a cap on pending values.
    Rejected,
    /// No usable answer: down, too slow, or some other reply.
    Failed,
}

/// Metrics of the DNS-01 challenge API (`ipssl-dns --acme-api`).
pub struct ApiMetrics {
    started: f64,
    /// By endpoint, then status.
    requests: [[AtomicU64; STATUS_LABELS]; ENDPOINT_LABELS],
    /// For each name server endpoint: accepted, rejected, failed.
    node_writes: Vec<(String, [AtomicU64; 3])>,
}

impl ApiMetrics {
    /// Metrics for an API that sends changes to `nodes`; the name servers
    /// are told apart by their position in it.
    pub fn new(nodes: &[SocketAddr]) -> Self {
        Self {
            started: now(),
            requests: Default::default(),
            node_writes: nodes
                .iter()
                .map(|node| (node.to_string(), Default::default()))
                .collect(),
        }
    }

    /// Counts a response to a request for `path`.
    pub fn request(&self, path: &str, status: u16) {
        let endpoint = ENDPOINTS
            .iter()
            .position(|(known, _)| *known == path)
            .unwrap_or(ENDPOINTS.len());
        let status = STATUSES
            .iter()
            .position(|known| *known == status)
            .unwrap_or(STATUSES.len());
        inc(&self.requests[endpoint][status]);
    }

    /// Counts a change sent to the `node`-th name server.
    pub fn node_write(&self, node: usize, result: NodeWrite) {
        if let Some((_, counts)) = self.node_writes.get(node) {
            inc(&counts[result as usize]);
        }
    }

    /// The Prometheus text exposition. `rate_limit_tracked` is the number
    /// of client networks the API's rate limiter tracks.
    pub fn render(&self, rate_limit_tracked: usize) -> String {
        let mut out = String::with_capacity(4096);

        header(
            &mut out,
            "ipssl_acme_api_requests_total",
            "counter",
            "DNS-01 challenge API responses, by endpoint and status.",
        );
        let endpoints = ENDPOINTS.iter().map(|(_, l)| *l).chain(["other"]);
        for (e, endpoint) in endpoints.enumerate() {
            let statuses = STATUSES.iter().map(u16::to_string).chain(["other".into()]);
            for (s, status) in statuses.enumerate() {
                let value = load(&self.requests[e][s]);
                writeln!(
                    out,
                    "ipssl_acme_api_requests_total{{endpoint=\"{endpoint}\",status=\"{status}\"}} {value}"
                )
                .unwrap();
            }
        }

        header(
            &mut out,
            "ipssl_acme_api_node_writes_total",
            "counter",
            "Changes the API sent to each name server, by result: accepted, rejected over a cap on pending values, or failed.",
        );
        for (node, counts) in &self.node_writes {
            for (i, result) in ["accepted", "rejected", "failed"].iter().enumerate() {
                let value = load(&counts[i]);
                writeln!(
                    out,
                    "ipssl_acme_api_node_writes_total{{node=\"{node}\",result=\"{result}\"}} {value}"
                )
                .unwrap();
            }
        }

        header(
            &mut out,
            "ipssl_rate_limit_tracked_networks",
            "gauge",
            "Client networks currently tracked by the rate limiter.",
        );
        writeln!(
            out,
            "ipssl_rate_limit_tracked_networks {rate_limit_tracked}"
        )
        .unwrap();

        process(&mut out, self.started);
        out
    }
}

/// The series every process exports: version and start time.
fn process(out: &mut String, started: f64) {
    header(
        out,
        "ipssl_build_info",
        "gauge",
        "Always 1; the version is in the label.",
    );
    writeln!(
        out,
        "ipssl_build_info{{version=\"{}\"}} 1",
        env!("CARGO_PKG_VERSION")
    )
    .unwrap();

    header(
        out,
        "process_start_time_seconds",
        "gauge",
        "Start time of the process since the Unix epoch, in seconds.",
    );
    writeln!(out, "process_start_time_seconds {started:.3}").unwrap();
}

/// Seconds since the Unix epoch.
fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

fn inc(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

fn load(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

fn header(out: &mut String, name: &str, kind: &str, help: &str) {
    writeln!(out, "# HELP {name} {help}").unwrap();
    writeln!(out, "# TYPE {name} {kind}").unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAUGES: Gauges = Gauges {
        zone_serial: 2026110501,
        rate_limit_tracked: Some(3),
        acme_challenges: Some(2),
    };

    fn line<'a>(text: &'a str, series: &str) -> &'a str {
        text.lines()
            .find(|l| l.starts_with(series) && l[series.len()..].starts_with(' '))
            .unwrap_or_else(|| panic!("no series {series}"))
    }

    #[test]
    fn counts_and_renders() {
        let m = Metrics::new();
        m.query(Protocol::Udp, Some(RecordType::A));
        m.query(Protocol::Udp, Some(RecordType::A));
        m.query(Protocol::Tcp, Some(RecordType::SRV));
        m.query(Protocol::Udp, None);
        m.response(ResponseCode::NXDomain);
        m.response(ResponseCode::BADVERS);
        m.response(ResponseCode::YXDomain);
        m.rate_limited(Limited::Slipped);
        m.reload(false);
        m.acme_write(AcmeWrite::Accepted);
        m.acme_write(AcmeWrite::Forbidden);
        m.acme_write(AcmeWrite::Forbidden);

        let text = m.render(&GAUGES);
        let value = |series: &str| line(&text, series).rsplit(' ').next().unwrap().to_owned();
        assert_eq!(
            value(r#"ipssl_dns_queries_total{protocol="udp",qtype="A"}"#),
            "2"
        );
        assert_eq!(
            value(r#"ipssl_dns_queries_total{protocol="tcp",qtype="other"}"#),
            "1"
        );
        assert_eq!(
            value(r#"ipssl_dns_queries_total{protocol="udp",qtype="other"}"#),
            "1"
        );
        assert_eq!(
            value(r#"ipssl_dns_queries_total{protocol="tcp",qtype="A"}"#),
            "0"
        );
        assert_eq!(value(r#"ipssl_dns_responses_total{rcode="NXDOMAIN"}"#), "1");
        assert_eq!(value(r#"ipssl_dns_responses_total{rcode="BADVERS"}"#), "1");
        assert_eq!(value(r#"ipssl_dns_responses_total{rcode="other"}"#), "1");
        assert_eq!(value(r#"ipssl_dns_rate_limited_total{action="slip"}"#), "1");
        assert_eq!(value(r#"ipssl_dns_rate_limited_total{action="drop"}"#), "0");
        assert_eq!(
            value(r#"ipssl_config_reloads_total{result="failure"}"#),
            "1"
        );
        assert_eq!(value("ipssl_rate_limit_tracked_networks"), "3");
        assert_eq!(value("ipssl_acme_challenges"), "2");
        assert_eq!(value(r#"ipssl_acme_writes_total{result="accepted"}"#), "1");
        assert_eq!(value(r#"ipssl_acme_writes_total{result="rejected"}"#), "0");
        assert_eq!(value(r#"ipssl_acme_writes_total{result="forbidden"}"#), "2");
        assert_eq!(value("ipssl_zone_serial"), "2026110501");
    }

    #[test]
    fn every_series_has_help_and_type() {
        let text = Metrics::new().render(&GAUGES);
        for sample in text.lines().filter(|l| !l.starts_with('#')) {
            let name = sample.split(['{', ' ']).next().unwrap();
            assert!(text.contains(&format!("# HELP {name} ")), "{name}");
            assert!(text.contains(&format!("# TYPE {name} ")), "{name}");
        }
    }

    #[test]
    fn api_counts_and_renders() {
        let nodes = [
            "198.51.100.1:8053".parse().unwrap(),
            "[2001:db8::2]:8053".parse().unwrap(),
        ];
        let m = ApiMetrics::new(&nodes);
        m.request("/present", 200);
        m.request("/present", 200);
        m.request("/cleanup", 429);
        m.request("/present", 502);
        m.request("/delete", 404);
        m.request("", 418);
        m.node_write(0, NodeWrite::Accepted);
        m.node_write(1, NodeWrite::Failed);
        m.node_write(1, NodeWrite::Failed);
        m.node_write(2, NodeWrite::Failed);

        let text = m.render(5);
        let value = |series: &str| line(&text, series).rsplit(' ').next().unwrap().to_owned();
        let requests = |endpoint: &str, status: &str| {
            value(&format!(
                r#"ipssl_acme_api_requests_total{{endpoint="{endpoint}",status="{status}"}}"#
            ))
        };
        assert_eq!(requests("present", "200"), "2");
        assert_eq!(requests("cleanup", "429"), "1");
        assert_eq!(requests("present", "502"), "1");
        assert_eq!(requests("other", "404"), "1");
        assert_eq!(requests("other", "other"), "1");
        assert_eq!(requests("cleanup", "200"), "0");
        let writes = |node: &str, result: &str| {
            value(&format!(
                r#"ipssl_acme_api_node_writes_total{{node="{node}",result="{result}"}}"#
            ))
        };
        assert_eq!(writes("198.51.100.1:8053", "accepted"), "1");
        assert_eq!(writes("[2001:db8::2]:8053", "failed"), "2");
        assert_eq!(writes("[2001:db8::2]:8053", "rejected"), "0");
        assert_eq!(value("ipssl_rate_limit_tracked_networks"), "5");
        assert!(text.contains("\nipssl_build_info{version="));
        assert!(!text.contains("ipssl_dns_"));

        for sample in text.lines().filter(|l| !l.starts_with('#')) {
            let name = sample.split(['{', ' ']).next().unwrap();
            assert!(text.contains(&format!("# HELP {name} ")), "{name}");
            assert!(text.contains(&format!("# TYPE {name} ")), "{name}");
        }
    }

    #[test]
    fn rate_limit_gauge_is_left_out_when_off() {
        let gauges = Gauges {
            rate_limit_tracked: None,
            acme_challenges: None,
            ..GAUGES
        };
        let text = Metrics::new().render(&gauges);
        assert!(!text.contains("ipssl_rate_limit_tracked_networks"));
        assert!(!text.contains("ipssl_acme_"));
    }
}
