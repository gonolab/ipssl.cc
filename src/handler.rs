//! Glue between hickory-server and [`Zone`].

use std::iter;
use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_server::net::runtime::Time;
use hickory_server::net::xfer::Protocol;
use hickory_server::proto::op::{Edns, Header, HeaderCounts, Metadata, OpCode, ResponseCode};
use hickory_server::proto::rr::Record;
use hickory_server::proto::serialize::binary::{BinEncodable, BinEncoder};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::{MessageResponse, MessageResponseBuilder};
use tracing::{debug, warn};

use crate::metrics::{Gauges, Limited, Metrics};
use crate::ratelimit::{RateLimiter, Verdict};
use crate::zone::{Answer, Zone};

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
    metrics: Arc<Metrics>,
}

impl Handler {
    pub fn new(zone: Zone) -> Self {
        Self {
            zone: Arc::new(ArcSwap::from_pointee(zone)),
            limiter: None,
            metrics: Arc::new(Metrics::new()),
        }
    }

    pub fn with_rate_limiter(mut self, limiter: Option<RateLimiter>) -> Self {
        self.limiter = limiter.map(Arc::new);
        self
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
        })
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
                    self.zone.load().resolve(
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

        // When an answer does not fit, hickory drops the records but leaves
        // their partly written bytes at the end of the message, which strict
        // parsers reject. Send a clean truncated response instead (header,
        // question and OPT only), so the client retries over TCP.
        if request.protocol() == Protocol::Udp {
            let limit = usize::from(response_edns.as_ref().map_or(512, Edns::max_payload));
            let records: Vec<&Record> = answer.answers.iter().chain(&answer.soa).collect();
            let len = encoded_len(request.queries.as_bytes(), &records, response_edns.as_ref());
            if len.is_none_or(|len| len > limit) {
                self.metrics.truncated();
                metadata.truncation = true;
                let response =
                    MessageResponseBuilder::new(&request.queries, response_edns.as_ref())
                        .build_no_records(metadata);
                return send(response_handle, response, metadata, &self.metrics).await;
            }
        }

        let response = MessageResponseBuilder::new(&request.queries, response_edns.as_ref()).build(
            metadata,
            answer.answers.iter(),
            iter::empty(),
            answer.soa.iter(),
            iter::empty(),
        );

        send(response_handle, response, metadata, &self.metrics).await
    }
}

/// Size of the response hickory would send: the header, the question copied
/// as the client sent it, the records and the OPT record. hickory copies the
/// question verbatim, so record names only compress against each other.
/// `None` if a record cannot be encoded at all.
fn encoded_len(question: &[u8], records: &[&Record], edns: Option<&Edns>) -> Option<usize> {
    const HEADER_LEN: usize = 12;
    let mut buf = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut buf);
    encoder.emit_vec(&[0; HEADER_LEN]).ok()?;
    encoder.emit_vec(question).ok()?;
    for record in records {
        record.emit(&mut encoder).ok()?;
    }
    if let Some(edns) = edns {
        Record::from(edns).emit(&mut encoder).ok()?;
    }
    Some(encoder.offset())
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
