//! End-to-end tests for DNS-01 challenges: the API, a name server's write
//! endpoint and its DNS answers, all on loopback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_server::Server;
use hickory_server::proto::op::{Message, Query, ResponseCode};
use hickory_server::proto::rr::{Name, RData, RecordType};
use tokio::net::{TcpListener, UdpSocket};
use tokio::time::timeout;

use ipssl::acme::{Api, Challenges, Node};
use ipssl::config::Config;
use ipssl::handler::Handler;
use ipssl::http::post_json;
use ipssl::zone::Zone;

const EXAMPLE_CONFIG: &str = include_str!("../config.example.toml");
const VALUE: &str = "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM";
const NAME: &str = "_acme-challenge.10-0-2-2.ipssl.cc.";

/// A name server with challenges on: DNS on UDP, writes over HTTP.
struct NameServer {
    dns: SocketAddr,
    write: SocketAddr,
    handler: Handler,
    _server: Server<Handler>,
}

async fn name_server(writers: &str) -> NameServer {
    let config = Config::parse(EXAMPLE_CONFIG).unwrap();
    let store = Arc::new(Challenges::new());
    let handler = Handler::new(Zone::from_config(&config).unwrap()).with_challenges(store.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let write = listener.local_addr().unwrap();
    let writers: Vec<_> = writers
        .split_whitespace()
        .map(|w| w.parse().unwrap())
        .collect();
    let node = Arc::new(Node::new(handler.clone(), store, &writers));
    tokio::spawn(ipssl::http::serve(listener, move |req| {
        let node = node.clone();
        async move { node.handle(req).await }
    }));

    let udp = ipssl::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    NameServer {
        dns: udp.local_addr().unwrap(),
        write,
        handler: handler.clone(),
        _server: ipssl::serve(handler, vec![udp], vec![], Duration::from_secs(5)),
    }
}

/// Starts the API, sending changes to `nodes`; returns its address.
async fn api(nodes: &[SocketAddr], extra: &str) -> SocketAddr {
    let nodes: Vec<String> = nodes.iter().map(|n| format!("\"{n}\"")).collect();
    let text = format!(
        "{EXAMPLE_CONFIG}\n[acme]\nnodes = [{}]\n{extra}\n",
        nodes.join(", ")
    );
    let api = Arc::new(Api::from_config(&Config::parse(&text).unwrap()).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(ipssl::http::serve(listener, move |req| {
        let api = api.clone();
        async move { api.handle(req).await }
    }));
    addr
}

fn body(fqdn: &str, value: &str) -> String {
    serde_json::json!({ "fqdn": fqdn, "value": value }).to_string()
}

async fn txt(dns: SocketAddr, name: &str) -> Message {
    let mut msg = Message::query();
    msg.add_query(Query::query(
        Name::from_ascii(name).unwrap(),
        RecordType::TXT,
    ));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&msg.to_vec().unwrap(), dns).await.unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("no DNS response")
        .unwrap();
    Message::from_vec(&buf[..n]).unwrap()
}

fn values(msg: &Message) -> Vec<String> {
    msg.answers
        .iter()
        .map(|r| match &r.data {
            RData::TXT(txt) => String::from_utf8(txt.txt_data.concat()).unwrap(),
            other => panic!("not TXT: {other:?}"),
        })
        .collect()
}

#[tokio::test]
async fn present_reaches_every_name_server_then_cleanup_removes_it() {
    let ns1 = name_server("127.0.0.1").await;
    let ns2 = name_server("127.0.0.1").await;
    let api = api(&[ns1.write, ns2.write], "").await;

    // Before: an authoritative NODATA that nobody caches.
    let before = txt(ns1.dns, NAME).await;
    assert_eq!(before.metadata.response_code, ResponseCode::NoError);
    assert!(before.answers.is_empty());
    assert_eq!(before.authorities[0].ttl, 0);

    // lego's httpreq provider sends the name with a trailing dot.
    let (status, reply) = post_json(api, "/present", &body(NAME, VALUE))
        .await
        .unwrap();
    assert_eq!((status, reply.as_str()), (200, r#"{"ok":true}"#));
    for ns in [&ns1, &ns2] {
        let resp = txt(ns.dns, "_ACME-Challenge.10-0-2-2.ipssl.cc.").await;
        assert!(resp.metadata.authoritative);
        assert_eq!(values(&resp), [VALUE]);
        assert_eq!(resp.answers[0].ttl, 0);
    }

    // acme.sh and certbot send it without one.
    let (status, _) = post_json(api, "/cleanup", &body(NAME.trim_end_matches('.'), VALUE))
        .await
        .unwrap();
    assert_eq!(status, 200);
    for ns in [&ns1, &ns2] {
        assert!(txt(ns.dns, NAME).await.answers.is_empty());
    }

    let metrics = ns1.handler.render_metrics();
    assert!(metrics.contains("\nipssl_acme_challenges 0\n"), "{metrics}");
    assert!(
        metrics.contains("\nipssl_acme_writes_total{result=\"accepted\"} 2\n"),
        "{metrics}"
    );
}

#[tokio::test]
async fn api_rejects_bad_requests() {
    let ns = name_server("127.0.0.1").await;
    let api = api(&[ns.write], "").await;

    for (path, request, status) in [
        (
            "/present",
            body("_acme-challenge.198-51-100-10.ipssl.cc", VALUE),
            403,
        ),
        ("/present", body("10-0-2-2.ipssl.cc", VALUE), 400),
        ("/present", body(NAME, "not a challenge digest"), 400),
        ("/present", "{\"fqdn\": 1}".to_owned(), 400),
        ("/delete", body(NAME, VALUE), 404),
    ] {
        let (got, reply) = post_json(api, path, &request).await.unwrap();
        assert_eq!(got, status, "{path} {request}: {reply}");
        let reply: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].is_string());
    }
    assert!(txt(ns.dns, NAME).await.answers.is_empty());
}

#[tokio::test]
async fn api_reports_a_name_server_that_is_down() {
    let ns = name_server("127.0.0.1").await;
    // Nothing listens here once the listener is dropped.
    let down = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let api = api(&[ns.write, down], "").await;

    let (status, reply) = post_json(api, "/present", &body(NAME, VALUE))
        .await
        .unwrap();
    assert_eq!(status, 502, "{reply}");
    assert!(reply.contains(&down.to_string()), "{reply}");
}

#[tokio::test]
async fn api_is_rate_limited() {
    let ns = name_server("127.0.0.1").await;
    let api = api(&[ns.write], "requests_per_minute = 1\nburst = 2").await;
    let request = body(NAME, VALUE);
    for _ in 0..2 {
        assert_eq!(post_json(api, "/present", &request).await.unwrap().0, 200);
    }
    assert_eq!(post_json(api, "/present", &request).await.unwrap().0, 429);
}

#[tokio::test]
async fn name_server_only_takes_writes_from_writers() {
    let ns = name_server("192.0.2.1").await;
    let (status, _) = post_json(ns.write, "/present", &body(NAME, VALUE))
        .await
        .unwrap();
    assert_eq!(status, 403);
    assert!(txt(ns.dns, NAME).await.answers.is_empty());
}
