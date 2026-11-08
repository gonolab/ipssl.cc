//! Counters exposed in the Prometheus text format.
//!
//! Plain atomics with fixed label sets: cheap to update on every query,
//! and no label can grow without bound.

use std::fmt::Write;
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

/// Values read at scrape time rather than counted.
pub struct Gauges {
    pub zone_serial: u32,
    /// `None` when rate limiting is off.
    pub rate_limit_tracked: Option<usize>,
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
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        Self {
            started,
            queries: Default::default(),
            responses: Default::default(),
            send_errors: AtomicU64::new(0),
            truncated: AtomicU64::new(0),
            rate_limited: Default::default(),
            reloads: Default::default(),
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

        header(
            &mut out,
            "ipssl_zone_serial",
            "gauge",
            "SOA serial of the zone being served.",
        );
        writeln!(out, "ipssl_zone_serial {}", gauges.zone_serial).unwrap();

        header(
            &mut out,
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
            &mut out,
            "process_start_time_seconds",
            "gauge",
            "Start time of the process since the Unix epoch, in seconds.",
        );
        writeln!(out, "process_start_time_seconds {:.3}", self.started).unwrap();

        out
    }
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
    fn rate_limit_gauge_is_left_out_when_off() {
        let gauges = Gauges {
            rate_limit_tracked: None,
            ..GAUGES
        };
        let text = Metrics::new().render(&gauges);
        assert!(!text.contains("ipssl_rate_limit_tracked_networks"));
    }
}
