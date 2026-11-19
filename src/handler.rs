//! Glue between hickory-server and [`Zone`].

use std::iter;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_server::net::runtime::Time;
use hickory_server::net::xfer::Protocol;
use hickory_server::proto::op::{Edns, Header, HeaderCounts, Metadata, OpCode, ResponseCode};
use hickory_server::proto::rr::{DNSClass, LowerName, Name, Record, RecordType};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::{MessageResponse, MessageResponseBuilder};
use tracing::{debug, warn};

use crate::acme::Challenges;
use crate::metrics::{Gauges, Limited, Metrics};
use crate::ratelimit::{RateLimiter, Verdict};
use crate::zone::{Answer, Zone, message_len};

/// Largest UDP response we send, per the DNS Flag Day 2020 recommendation.
/// Keeps responses below common MTUs, so they are not fragmented.
const MAX_UDP_PAYLOAD: u16 = 1232;

/// Answers DNS requests from the current [`Zone`]. Clones share the same
/// zone, so a clone kept outside the server can swap it at run time.
#[derive(Clone)]
pub struct Handler {
    zone: Arc<ArcSwap<Zone>>,
    /// Limits UDP responses per client network; `None` when turned off.
    limiter: Option<Arc<RateLimiter>>,
    /// Published DNS-01 challenges; `None` when `[acme]` is off.
    challenges: Option<Arc<Challenges>>,
    metrics: Arc<Metrics>,
}

impl Handler {
    pub fn new(zone: Zone) -> Self {
        Self {
            zone: Arc::new(ArcSwap::from_pointee(zone)),
            limiter: None,
            challenges: None,
            metrics: Arc::new(Metrics::new()),
        }
    }

    pub fn with_rate_limiter(mut self, limiter: Option<RateLimiter>) -> Self {
        self.limiter = limiter.map(Arc::new);
        self
    }

    /// Answers TXT queries for challenge names from `store`.
    pub fn with_challenges(mut self, store: Arc<Challenges>) -> Self {
        self.challenges = Some(store);
        self
    }

    /// The zone being served right now.
    pub fn zone(&self) -> Arc<Zone> {
        self.zone.load_full()
    }

    /// Replaces the zone. Requests already being answered finish with the
    /// old one; every later request sees the new one.
    pub fn set_zone(&self, zone: Zone) {
        self.zone.store(Arc::new(zone));
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// All metrics in the Prometheus text format.
    pub fn render_metrics(&self) -> String {
        self.metrics.render(&Gauges {
            zone_serial: self.zone.load().serial(),
            rate_limit_tracked: self.limiter.as_ref().map(|l| l.tracked()),
            acme_challenges: self.challenges.as_ref().map(|c| c.len()),
        })
    }

    /// Looks up a query, answering challenge names from the published
    /// challenges when `[acme]` is on.
    fn resolve(&self, name: &Name, qtype: RecordType, qclass: DNSClass, src: IpAddr) -> Answer {
        let zone = self.zone.load();
        if let Some(store) = &self.challenges
            && matches!(qtype, RecordType::TXT | RecordType::ANY)
            && qclass == DNSClass::IN
            && zone.check_challenge(name).is_ok()
        {
            return zone.challenge_answer(name, store.values(&LowerName::new(name)));
        }
        zone.resolve(name, qtype, qclass, src)
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        let mut metadata = Metadata::response_from_request(&request.metadata);

        let response_edns = request.edns.as_ref().map(|req| {
            let mut edns = Edns::new();
            edns.set_max_payload(req.max_payload().clamp(512, MAX_UDP_PAYLOAD));
            edns.set_version(0);
            // RFC 3225 section 3: copy DO from the query, even though
            // nothing here is signed.
            edns.set_dnssec_ok(req.flags().dnssec_ok);
            edns
        });
        let bad_version = request.edns.as_ref().is_some_and(|e| e.version() > 0);
        let qtype = request.queries.queries().first().map(|q| q.query_type());
        self.metrics.query(request.protocol(), qtype);

        // Only UDP sources can be forged, so only UDP is limited.
        let verdict = match &self.limiter {
            Some(limiter) if request.protocol() == Protocol::Udp => {
                limiter.check(request.src().ip())
            }
            _ => Verdict::Allow,
        };
        match verdict {
            Verdict::Allow => {}
            Verdict::Slip => {
                self.metrics.rate_limited(Limited::Slipped);
                metadata.truncation = true;
                let response =
                    MessageResponseBuilder::new(&request.queries, response_edns.as_ref())
                        .build_no_records(metadata);
                return send(response_handle, response, metadata, &self.metrics).await;
            }
            Verdict::Drop => {
                self.metrics.rate_limited(Limited::Dropped);
                return ResponseInfo::from(Header {
                    metadata,
                    counts: HeaderCounts::default(),
                });
            }
        }

        let answer = if bad_version {
            Answer::error(ResponseCode::BADVERS)
        } else if request.metadata.op_code != OpCode::Query {
            Answer::error(ResponseCode::NotImp)
        } else {
            match request.request_info() {
                Ok(info) => {
                    let q = info.query;
                    debug!(name = %q.name(), qtype = %q.query_type(), "query");
                    self.resolve(
                        q.original().name(),
                        q.query_type(),
                        q.query_class(),
                        info.src.ip(),
                    )
                }
                // Anything but exactly one question.
                Err(_) => Answer::error(ResponseCode::FormErr),
            }
        };

        metadata.authoritative = answer.authoritative;
        metadata.response_code = answer.rcode;

        // When records do not fit, hickory drops them and sets TC but leaves
        // their partly written bytes at the end of the message, which strict
        // parsers reject. So check the size before hickory writes anything.
        let limit = match request.protocol() {
            Protocol::Udp => usize::from(response_edns.as_ref().map_or(512, Edns::max_payload)),
            // TCP frames each message with a 16-bit length.
            _ => usize::from(u16::MAX),
        };
        let fits = |records: &[&Record]| {
            message_len(request.queries.as_bytes(), records, response_edns.as_ref())
                .is_some_and(|len| len <= limit)
        };
        let mut records: Vec<&Record> = answer.answers.iter().chain(&answer.soa).collect();
        // An answer too big for UDP gets a clean truncated response instead
        // (header, question and OPT only), so the client retries over TCP.
        // Over TCP every answer fits; the zone makes sure of that.
        if request.protocol() == Protocol::Udp && !fits(&records) {
            self.metrics.truncated();
            metadata.truncation = true;
            let response = MessageResponseBuilder::new(&request.queries, response_edns.as_ref())
                .build_no_records(metadata);
            return send(response_handle, response, metadata, &self.metrics).await;
        }
        // Additional records only save the client a lookup, so a response
        // goes out complete without the ones that do not fit, never
        // truncated for them. RRsets are added whole, in order.
        let answered = records.len();
        records.extend(&answer.additionals);
        if !answer.additionals.is_empty() && !fits(&records) {
            records.truncate(answered);
            for rrset in answer
                .additionals
                .chunk_by(|a, b| a.name == b.name && a.record_type() == b.record_type())
            {
                records.extend(rrset);
                if !fits(&records) {
                    records.truncate(records.len() - rrset.len());
                    break;
                }
            }
        }

        let response = MessageResponseBuilder::new(&request.queries, response_edns.as_ref()).build(
            metadata,
            answer.answers.iter(),
            iter::empty(),
            answer.soa.iter(),
            records[answered..].iter().copied(),
        );

        send(response_handle, response, metadata, &self.metrics).await
    }
}

/// Sends `response` and counts it. If sending fails, the returned info
/// carries SERVFAIL.
async fn send<'a, R: ResponseHandler>(
    mut response_handle: R,
    response: MessageResponse<
        '_,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    >,
    mut metadata: Metadata,
    metrics: &Metrics,
) -> ResponseInfo {
    match response_handle.send_response(response).await {
        Ok(info) => {
            metrics.response(info.response_code);
            info
        }
        Err(error) => {
            metrics.send_error();
            warn!(%error, "failed to send response");
            metadata.response_code = ResponseCode::ServFail;
            ResponseInfo::from(Header {
                metadata,
                counts: HeaderCounts::default(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use hickory_server::proto::op::{MessageType, Query};
    use hickory_server::proto::serialize::binary::{BinDecoder, BinEncodable, BinEncoder};
    use hickory_server::zone_handler::Queries;

    const BASE: &str = r#"
        domain = "ipssl.cc"

        [[nameservers]]
        name = "ns1.ipssl.cc"
        ipv4 = ["198.51.100.1"]

        [soa]
        email = "hostmaster@ipssl.cc"
    "#;

    /// A zone whose `m.ipssl.cc` has `outside` MX records for names outside
    /// the zone, then `inside` for fixed hosts with two addresses each.
    fn mx_zone(outside: usize, inside: usize) -> Zone {
        let mut config = format!("{BASE}\n[hosts.m]\nmx = [");
        for i in 0..outside {
            config += &format!("{{ preference = 1, exchange = \"q.r{i}.s{i}\" }}, ");
        }
        for i in 0..inside {
            config += &format!("{{ preference = 2, exchange = \"t{i}.ipssl.cc\" }}, ");
        }
        config += "]\n";
        for i in 0..inside {
            config += &format!(
                "[hosts.t{i}]\na = [\"198.51.100.{n}\"]\naaaa = [\"2001:db8::{n}\"]\n",
                n = i + 1
            );
        }
        Zone::from_config(&Config::parse(&config).unwrap()).unwrap()
    }

    /// The size of the message hickory writes for `answer`.
    fn written_len(question: &[u8], answer: &Answer, edns: Option<&Edns>) -> usize {
        let queries = Queries::read(&mut BinDecoder::new(question), 1).unwrap();
        let metadata = Metadata::new(1, MessageType::Response, OpCode::Query);
        let response = MessageResponseBuilder::new(&queries, edns).build(
            metadata,
            answer.answers.iter(),
            iter::empty(),
            answer.soa.iter(),
            answer.additionals.iter(),
        );
        let mut buf = Vec::new();
        response
            .destructive_emit(&mut BinEncoder::new(&mut buf))
            .unwrap();
        buf.len()
    }

    #[test]
    fn size_estimate_matches_what_hickory_writes() {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        // Around the encoder's 64 name compression candidates, and past
        // offset 0x3FFF, from which it stores no more of them.
        let cases = (0..=40)
            .step_by(2)
            .flat_map(|outside| (0..=3).map(move |inside| (outside, inside)))
            .chain([(700, 0), (700, 3)]);
        for (outside, inside) in cases {
            let zone = mx_zone(outside, inside);
            for qname in ["m.ipssl.cc.", "M.IPSSL.cc.", "nothing.ipssl.cc."] {
                let name = Name::from_ascii(qname).unwrap();
                let answer = zone.resolve(
                    &name,
                    RecordType::MX,
                    DNSClass::IN,
                    IpAddr::from([0, 0, 0, 0]),
                );
                let question = Query::query(name, RecordType::MX).to_bytes().unwrap();
                let records: Vec<&Record> = answer
                    .answers
                    .iter()
                    .chain(&answer.soa)
                    .chain(&answer.additionals)
                    .collect();
                for edns in [None, Some(&edns)] {
                    assert_eq!(
                        message_len(&question, &records, edns),
                        Some(written_len(&question, &answer, edns)),
                        "{outside} outside, {inside} inside, {qname}, edns {}",
                        edns.is_some()
                    );
                }
            }
        }
    }
}
