//! End-to-end tests: start the server on loopback and query it over UDP and TCP.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_server::Server;
use hickory_server::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_server::proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use ipssl::config::Config;
use ipssl::handler::Handler;
use ipssl::ratelimit::RateLimiter;
use ipssl::zone::Zone;

struct TestServer {
    udp: SocketAddr,
    tcp: SocketAddr,
    handler: Handler,
    // Dropping the server stops it.
    _server: Server<Handler>,
}

const EXAMPLE_CONFIG: &str = include_str!("../config.example.toml");

fn start() -> TestServer {
    start_with(Config::parse(EXAMPLE_CONFIG).unwrap())
}

fn start_with(config: Config) -> TestServer {
    let handler = Handler::new(Zone::from_config(&config).unwrap())
        .with_rate_limiter(RateLimiter::from_config(&config.rate_limit).unwrap());
    let udp = ipssl::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    let tcp = ipssl::bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
    TestServer {
        udp: udp.local_addr().unwrap(),
        tcp: tcp.local_addr().unwrap(),
        handler: handler.clone(),
        _server: ipssl::serve(handler, vec![udp], vec![tcp], Duration::from_secs(5)),
    }
}

fn query(name: &str, qtype: RecordType) -> Message {
    let mut msg = Message::query();
    msg.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
    msg
}

async fn over_udp(addr: SocketAddr, msg: &Message) -> Message {
    try_udp(addr, msg, Duration::from_secs(2))
        .await
        .expect("no UDP response")
}

/// Sends `msg` over UDP; `None` if no response arrives within `wait`.
async fn try_udp(addr: SocketAddr, msg: &Message, wait: Duration) -> Option<Message> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&msg.to_vec().unwrap(), addr).await.unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = timeout(wait, socket.recv_from(&mut buf))
        .await
        .ok()?
        .unwrap();
    Some(Message::from_vec(&buf[..n]).unwrap())
}

async fn over_tcp(addr: SocketAddr, msg: &Message) -> Message {
    let bytes = msg.to_vec().unwrap();
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(&(bytes.len() as u16).to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&bytes).await.unwrap();
    let mut len = [0u8; 2];
    timeout(Duration::from_secs(2), stream.read_exact(&mut len))
        .await
        .expect("no TCP response")
        .unwrap();
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut buf).await.unwrap();
    Message::from_vec(&buf).unwrap()
}

fn rdata(msg: &Message) -> Vec<String> {
    msg.answers.iter().map(|r| r.data.to_string()).collect()
}

#[tokio::test]
async fn answers_a_over_udp() {
    let server = start();
    let req = query("app-10-0-0-1.ipssl.cc.", RecordType::A);
    let resp = over_udp(server.udp, &req).await;

    assert_eq!(resp.metadata.id, req.metadata.id);
    assert_eq!(resp.metadata.message_type, MessageType::Response);
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert!(resp.metadata.authoritative);
    assert!(!resp.metadata.recursion_available);
    assert_eq!(rdata(&resp), ["10.0.0.1"]);
}

#[tokio::test]
async fn answers_aaaa_over_tcp() {
    let server = start();
    let resp = over_tcp(
        server.tcp,
        &query("2001-db8--1.ipssl.cc.", RecordType::AAAA),
    )
    .await;
    assert_eq!(rdata(&resp), ["2001:db8::1"]);
}

#[tokio::test]
async fn echoes_question_case() {
    // Resolvers randomise the case of the question (0x20) and check it comes back as sent.
    let server = start();
    let resp = over_udp(server.udp, &query("ApP-10-0-0-1.IpSsL.cC.", RecordType::A)).await;
    assert_eq!(resp.queries[0].name().to_string(), "ApP-10-0-0-1.IpSsL.cC.");
    assert_eq!(rdata(&resp), ["10.0.0.1"]);
}

#[tokio::test]
async fn nxdomain_carries_soa() {
    let server = start();
    let resp = over_udp(server.udp, &query("nothing.ipssl.cc.", RecordType::A)).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    assert!(resp.metadata.authoritative);
    assert_eq!(resp.authorities.len(), 1);
    assert_eq!(resp.authorities[0].record_type(), RecordType::SOA);
    assert_eq!(resp.authorities[0].ttl, 300);
}

#[tokio::test]
async fn refuses_other_zones() {
    let server = start();
    let resp = over_udp(server.udp, &query("example.com.", RecordType::A)).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
    assert!(!resp.metadata.authoritative);
}

#[tokio::test]
async fn edns_is_echoed_and_capped() {
    let server = start();
    let mut req = query("10-0-0-1.ipssl.cc.", RecordType::A);
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    req.set_edns(edns);

    let resp = over_udp(server.udp, &req).await;
    let edns = resp.edns.as_ref().expect("response should carry EDNS");
    assert_eq!(edns.max_payload(), 1232);
    assert_eq!(rdata(&resp), ["10.0.0.1"]);
}

#[tokio::test]
async fn unknown_edns_version_is_badvers() {
    let server = start();
    let mut req = query("10-0-0-1.ipssl.cc.", RecordType::A);
    let mut edns = Edns::new();
    edns.set_version(1);
    req.set_edns(edns);

    let resp = over_udp(server.udp, &req).await;
    // BADVERS and BADSIG share code 16; hickory decodes it as BADSIG.
    assert_eq!(u16::from(resp.metadata.response_code), 16);
    assert!(resp.answers.is_empty());
}

#[tokio::test]
async fn two_questions_is_formerr() {
    let server = start();
    let mut req = query("10-0-0-1.ipssl.cc.", RecordType::A);
    req.add_query(Query::query(
        Name::from_ascii("10-0-0-2.ipssl.cc.").unwrap(),
        RecordType::A,
    ));
    let resp = over_udp(server.udp, &req).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::FormErr);
}

#[tokio::test]
async fn non_query_opcode_is_notimp() {
    let server = start();
    let mut req = Message::new(1234, MessageType::Query, OpCode::Notify);
    req.add_query(Query::query(
        Name::from_ascii("ipssl.cc.").unwrap(),
        RecordType::SOA,
    ));
    let resp = over_udp(server.udp, &req).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NotImp);
}

#[tokio::test]
async fn set_zone_takes_effect_immediately() {
    let server = start();
    let www = query("www.ipssl.cc.", RecordType::A);
    assert_eq!(rdata(&over_udp(server.udp, &www).await), ["198.51.100.10"]);

    let changed = EXAMPLE_CONFIG.replace(
        "[hosts.www]\na = [\"198.51.100.10\"]",
        "[hosts.www]\na = [\"198.51.100.20\"]",
    );
    assert_ne!(changed, EXAMPLE_CONFIG, "example config layout changed");
    let config = Config::parse(&changed).unwrap();
    server.handler.set_zone(Zone::from_config(&config).unwrap());

    assert_eq!(rdata(&over_udp(server.udp, &www).await), ["198.51.100.20"]);
}

#[tokio::test]
async fn udp_is_rate_limited_but_tcp_is_not() {
    let mut config = Config::parse(EXAMPLE_CONFIG).unwrap();
    config.rate_limit.responses_per_second = 1;
    config.rate_limit.burst = 2;
    config.rate_limit.slip = 2;
    let server = start_with(config);
    let req = query("10-0-0-1.ipssl.cc.", RecordType::A);
    let wait = Duration::from_millis(300);

    // The burst is answered as usual.
    for _ in 0..2 {
        let resp = try_udp(server.udp, &req, wait).await.unwrap();
        assert_eq!(rdata(&resp), ["10.0.0.1"]);
    }
    // Then responses alternate between dropped and truncated (slip = 2).
    assert!(try_udp(server.udp, &req, wait).await.is_none());
    let slipped = try_udp(server.udp, &req, wait).await.unwrap();
    assert!(slipped.metadata.truncation);
    assert!(slipped.answers.is_empty());
    assert_eq!(slipped.metadata.id, req.metadata.id);
    assert_eq!(slipped.queries, req.queries);

    // TCP is never limited.
    for _ in 0..5 {
        assert_eq!(rdata(&over_tcp(server.tcp, &req).await), ["10.0.0.1"]);
    }
}
