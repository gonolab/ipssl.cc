//! Glue between hickory-server and [`Zone`].

use std::iter;
use std::sync::Arc;

use arc_swap::ArcSwap;
use hickory_server::net::runtime::Time;
use hickory_server::proto::op::{Edns, Header, HeaderCounts, Metadata, OpCode, ResponseCode};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use tracing::{debug, warn};

use crate::zone::{Answer, Zone};

/// Largest UDP response we send, per the DNS Flag Day 2020 recommendation.
/// Keeps responses below common MTUs, so they are not fragmented.
const MAX_UDP_PAYLOAD: u16 = 1232;

/// Answers DNS requests from the current [`Zone`]. Clones share the same
/// zone, so a clone kept outside the server can swap it at run time.
#[derive(Clone)]
pub struct Handler {
    zone: Arc<ArcSwap<Zone>>,
}

impl Handler {
    pub fn new(zone: Zone) -> Self {
        Self {
            zone: Arc::new(ArcSwap::from_pointee(zone)),
        }
    }

    /// Replaces the zone. Requests already being answered finish with the
    /// old one; every later request sees the new one.
    pub fn set_zone(&self, zone: Zone) {
        self.zone.store(Arc::new(zone));
    }
}

#[async_trait::async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let mut metadata = Metadata::response_from_request(&request.metadata);

        let response_edns = request.edns.as_ref().map(|req| {
            let mut edns = Edns::new();
            edns.set_max_payload(req.max_payload().clamp(512, MAX_UDP_PAYLOAD));
            edns.set_version(0);
            edns
        });
        let bad_version = request.edns.as_ref().is_some_and(|e| e.version() > 0);

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

        let response = MessageResponseBuilder::new(&request.queries, response_edns.as_ref()).build(
            metadata,
            answer.answers.iter(),
            iter::empty(),
            answer.soa.iter(),
            iter::empty(),
        );

        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(error) => {
                warn!(%error, "failed to send response");
                metadata.response_code = ResponseCode::ServFail;
                ResponseInfo::from(Header {
                    metadata,
                    counts: HeaderCounts::default(),
                })
            }
        }
    }
}
