//! End-to-end tests for DNS-01 challenges: the API, a name server's write
//! endpoint and its DNS answers, all on loopback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use data_encoding::HEXLOWER;

use hickory_server::Server;
use hickory_server::proto::op::{Message, Query, ResponseCode};
use hickory_server::proto::rr::{Name, RData, RecordType};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;

use ipssl::acme::{Api, Challenges, Node};
use ipssl::config::Config;
use ipssl::handler::Handler;
use ipssl::http::{post, post_json};
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
    name_server_with(writers, "").await
}

/// Like [`name_server`], with more `[acme]` settings, such as a key.
async fn name_server_with(writers: &str, acme: &str) -> NameServer {
    let config = Config::parse(EXAMPLE_CONFIG).unwrap();
    let store = Arc::new(Challenges::new());
    let handler = Handler::new(Zone::from_config(&config).unwrap()).with_challenges(store.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let write = listener.local_addr().unwrap();
    let writers: Vec<String> = writers
        .split_whitespace()
        .map(|w| format!("\"{w}\""))
        .collect();
    let text = format!(
        "{EXAMPLE_CONFIG}\n[acme]\nwriters = [{}]\n{acme}\n",
        writers.join(", ")
    );
    let settings = Config::parse(&text).unwrap().acme.unwrap();
    let node = Node::from_config(handler.clone(), store, &settings).unwrap();
    tokio::spawn(node.serve(listener));

    let udp = ipssl::bind_udp("127.0.0.1:0".parse().unwrap()).unwrap();
    NameServer {
        dns: udp.local_addr().unwrap(),
        write,
        handler: handler.clone(),
        _server: ipssl::serve(handler, vec![udp], vec![], Duration::from_secs(5)),
    }
}

/// A stand-in for a name server's write endpoint that reads each request
/// and answers it with `raw`, as it is.
async fn fake_node(raw: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                // Read the whole request first: closing with unread data
                // would reset the connection instead.
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !complete(&request) {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = stream.write_all(raw.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// A stand-in for the network path to the name server at `target`: it
/// passes each request on and the answer back, except that it drops the
/// answers to requests for `lost`, as a broken connection would after the
/// name server took the change.
async fn lossy_path(target: SocketAddr, lost: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !complete(&request) {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                let mut node = TcpStream::connect(target).await.unwrap();
                node.write_all(&request).await.unwrap();
                let mut answer = Vec::new();
                node.read_to_end(&mut answer).await.unwrap();
                if !request.starts_with(format!("POST {lost} ").as_bytes()) {
                    let _ = stream.write_all(&answer).await;
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// Whether `request` holds a whole request with a `Content-Length` body.
fn complete(request: &[u8]) -> bool {
    let text = String::from_utf8_lossy(request);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return false;
    };
    let length = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().to_owned())
        })
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    body.len() >= length
}

/// Starts the API, sending changes to `nodes`; returns its address.
async fn api(nodes: &[SocketAddr], extra: &str) -> SocketAddr {
    api_with_metrics(nodes, extra).await.0
}

/// Like [`api`], but also returns the API itself for its metrics.
async fn api_with_metrics(nodes: &[SocketAddr], extra: &str) -> (SocketAddr, Arc<Api>) {
    let nodes: Vec<String> = nodes.iter().map(|n| format!("\"{n}\"")).collect();
    let text = format!(
        "{EXAMPLE_CONFIG}\n[acme]\nnodes = [{}]\n{extra}\n",
        nodes.join(", ")
    );
    let mut config = Config::parse(&text).unwrap();
    // One name server per node: the API refuses to start when the nodes
    // leave a name server out.
    config.nameservers.truncate(nodes.len());
    let api = Arc::new(Api::from_config(&config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(api.clone().serve(listener));
    (addr, api)
}

fn body(fqdn: &str, value: &str) -> String {
    serde_json::json!({ "fqdn": fqdn, "value": value }).to_string()
}

/// Another valid challenge value, told apart by its first character.
fn value(first: char) -> String {
    format!("{first}{}", &VALUE[1..])
}

/// Sends `body` to the API the way the TLS proxy in front of it does for
/// a client at `client`; returns the status and the body of the answer.
async fn post_as(api: SocketAddr, client: &str, path: &str, body: &str) -> (u16, String) {
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: ipssl.cc\r\nX-Real-IP: {client}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    raw(api, &request).await
}

/// Sends `request` as it is; returns the status and the body of the answer.
async fn raw(addr: SocketAddr, request: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    (status, body.to_owned())
}

/// The value of one series in `metrics`, which must be there.
fn metric(metrics: &str, series: &str) -> u64 {
    metrics
        .lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' '))
        .unwrap_or_else(|| panic!("no {series} in\n{metrics}"))
        .parse()
        .unwrap()
}

async fn sorted_values(dns: SocketAddr) -> Vec<String> {
    let mut values = values(&txt(dns, NAME).await);
    values.sort();
    values
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
    // How many failed, but not where they are or what went wrong.
    let reply: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let message = reply["error"].as_str().unwrap();
    assert!(message.starts_with("1 of 2 name servers "), "{message}");
    assert!(!message.contains(&down.port().to_string()), "{message}");
    assert!(!message.contains("127.0.0.1"), "{message}");

    // The name server that took the value dropped it again, so it does
    // not serve a value the client was told is not there.
    assert!(txt(ns.dns, NAME).await.answers.is_empty());
}

#[tokio::test]
async fn a_present_whose_answer_was_lost_is_taken_back() {
    // ns1 takes the value, but its answer never reaches the API.
    let ns1 = name_server("127.0.0.1").await;
    let ns2 = name_server("127.0.0.1").await;
    let path = lossy_path(ns1.write, "/present").await;
    let api = api(&[path, ns2.write], "").await;

    let (status, reply) = post_json(api, "/present", &body(NAME, VALUE))
        .await
        .unwrap();
    assert_eq!(status, 502, "{reply}");
    // Both dropped it again, the one that seemed to fail included.
    for ns in [&ns1, &ns2] {
        assert!(txt(ns.dns, NAME).await.answers.is_empty());
    }
}

#[tokio::test]
async fn a_refused_value_is_taken_back_everywhere_else() {
    // One name server is at the cap for this network (another one lost
    // its values in a restart, say), so the change is refused there. The
    // values came from an API from v0.5.0, which sent the network as the
    // owner: the cap counts them for the network all the same.
    let full = name_server("127.0.0.1").await;
    let empty = name_server("127.0.0.1").await;
    for v in ['A', 'B'] {
        let request = serde_json::json!({ "fqdn": NAME, "value": value(v), "owner": "192.0.2.0" });
        let (status, _) = post_json(full.write, "/present", &request.to_string())
            .await
            .unwrap();
        assert_eq!(status, 200);
    }
    let api = api(&[full.write, empty.write], "").await;
    let (status, reply) = post_as(api, "192.0.2.10", "/present", &body(NAME, &value('C'))).await;
    assert_eq!(status, 409, "{reply}");
    assert!(txt(empty.dns, NAME).await.answers.is_empty());
    assert_eq!(sorted_values(full.dns).await, [value('A'), value('B')]);
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
    // Anyone else is cut off before the request is read: no answer at all.
    for _ in 0..40 {
        let result = post_json(ns.write, "/present", &body(NAME, VALUE)).await;
        assert!(result.is_err(), "{result:?}");
    }
    assert!(txt(ns.dns, NAME).await.answers.is_empty());
    // Counted, so an API whose address no longer matches stands out.
    let metrics = ns.handler.render_metrics();
    assert_eq!(
        metric(&metrics, r#"ipssl_acme_writes_total{result="forbidden"}"#),
        40
    );
    assert_eq!(
        metric(&metrics, r#"ipssl_acme_writes_total{result="accepted"}"#),
        0
    );
}

#[tokio::test]
async fn name_server_counts_every_rejected_write() {
    let ns = name_server("127.0.0.1").await;
    let (status, _) = post_json(ns.write, "/delete", &body(NAME, VALUE))
        .await
        .unwrap();
    assert_eq!(status, 404);
    let (status, _) = raw(ns.write, "GET /present HTTP/1.1\r\n\r\n").await;
    assert_eq!(status, 405);
    let (status, _) = post_json(ns.write, "/present", "{").await.unwrap();
    assert_eq!(status, 400);
    let metrics = ns.handler.render_metrics();
    assert_eq!(
        metric(&metrics, r#"ipssl_acme_writes_total{result="rejected"}"#),
        3
    );
}

#[tokio::test]
async fn only_the_presenting_address_cleans_up() {
    let ns = name_server("127.0.0.1").await;
    let api = api(&[ns.write], "").await;
    let request = body(NAME, VALUE);
    assert_eq!(
        post_as(api, "192.0.2.10", "/present", &request).await.0,
        200
    );

    // Values are public in DNS, so knowing one proves nothing: a cleanup
    // from another network, or from a neighbour in the same /24 (which
    // shares a rate limit), succeeds but removes nothing.
    for other in ["198.51.100.7", "192.0.2.99"] {
        let (status, reply) = post_as(api, other, "/cleanup", &request).await;
        assert_eq!((status, reply.as_str()), (200, r#"{"ok":true}"#));
        assert_eq!(values(&txt(ns.dns, NAME).await), [VALUE], "{other}");
    }
    assert_eq!(
        post_as(api, "192.0.2.10", "/cleanup", &request).await.0,
        200
    );
    assert!(txt(ns.dns, NAME).await.answers.is_empty());

    // An IPv6 client owns its /64, where it may pick a new address for
    // each connection; the rest of its /56 does not.
    let present = post_as(api, "2001:db8:0:1::10", "/present", &request).await;
    assert_eq!(present.0, 200);
    post_as(api, "2001:db8:0:2::10", "/cleanup", &request).await;
    assert_eq!(values(&txt(ns.dns, NAME).await), [VALUE]);
    let cleanup = post_as(api, "2001:db8:0:1:aaaa::99", "/cleanup", &request).await;
    assert_eq!(cleanup.0, 200);
    assert!(txt(ns.dns, NAME).await.answers.is_empty());
}

#[tokio::test]
async fn cleanup_works_while_the_address_is_blocked() {
    let ns = name_server("127.0.0.1").await;
    let api = api(&[ns.write], "").await;
    let request = body(NAME, VALUE);
    assert_eq!(post_json(api, "/present", &request).await.unwrap().0, 200);

    // The operator blocks the address while the value is still pending.
    // A present would now be refused, but a cleanup must still go through.
    let blocked = EXAMPLE_CONFIG.replace("blocklist = []", "blocklist = [\"10.0.2.0/24\"]");
    ns.handler
        .set_zone(Zone::from_config(&Config::parse(&blocked).unwrap()).unwrap());
    let (status, reply) = post_json(api, "/cleanup", &request).await.unwrap();
    assert_eq!(status, 200, "{reply}");

    // Lifting the block must not bring the old value back.
    let config = Config::parse(EXAMPLE_CONFIG).unwrap();
    ns.handler.set_zone(Zone::from_config(&config).unwrap());
    assert!(txt(ns.dns, NAME).await.answers.is_empty());
}

#[tokio::test]
async fn api_refuses_values_over_the_caps_without_pushing_any_out() {
    let ns = name_server("127.0.0.1").await;
    let api = api(&[ns.write], "").await;
    for v in ['A', 'B'] {
        let (status, reply) = post_as(api, "192.0.2.10", "/present", &body(NAME, &value(v))).await;
        assert_eq!(status, 200, "{reply}");
    }
    // A third value from the same network: a clear error, not an eviction.
    let (status, reply) = post_as(api, "192.0.2.10", "/present", &body(NAME, &value('C'))).await;
    assert_eq!(status, 409, "{reply}");
    let reply: serde_json::Value = serde_json::from_str(&reply).unwrap();
    let message = reply["error"].as_str().unwrap();
    assert!(message.contains("2 per client network"), "{message}");
    assert_eq!(sorted_values(ns.dns).await, [value('A'), value('B')]);

    // Another network still has room of its own.
    let (status, _) = post_as(api, "198.51.100.7", "/present", &body(NAME, &value('C'))).await;
    assert_eq!(status, 200);
    assert_eq!(
        sorted_values(ns.dns).await,
        [value('A'), value('B'), value('C')]
    );
}

#[tokio::test]
async fn name_server_takes_writes_with_and_without_an_owner() {
    // During an upgrade the name servers may meet an API that sends no
    // owner. Its values belong to no network, so only its own cleanups
    // (which carry no owner either) remove them.
    let ns = name_server("127.0.0.1").await;
    let owned = |owner: &str| {
        serde_json::json!({ "fqdn": NAME, "value": VALUE, "owner": owner }).to_string()
    };
    let write = |path, body: String| async move { post_json(ns.write, path, &body).await.unwrap() };

    assert_eq!(write("/present", body(NAME, VALUE)).await.0, 200);
    assert_eq!(write("/cleanup", owned("192.0.2.0")).await.0, 200);
    assert_eq!(values(&txt(ns.dns, NAME).await), [VALUE]);
    assert_eq!(write("/cleanup", body(NAME, VALUE)).await.0, 200);
    assert!(txt(ns.dns, NAME).await.answers.is_empty());

    assert_eq!(write("/present", owned("192.0.2.0")).await.0, 200);
    assert_eq!(write("/cleanup", body(NAME, VALUE)).await.0, 200);
    assert_eq!(values(&txt(ns.dns, NAME).await), [VALUE]);
    assert_eq!(write("/cleanup", owned("192.0.2.0")).await.0, 200);
    assert!(txt(ns.dns, NAME).await.answers.is_empty());

    assert_eq!(write("/present", owned("nobody")).await.0, 400);
}

#[tokio::test]
async fn name_server_takes_writes_from_old_and_new_apis() {
    // An API from v0.5.0 sends the client's network as the owner; a newer
    // one sends the client's address as the owner, and its network.
    let ns = name_server("127.0.0.1").await;
    let old = serde_json::json!({ "fqdn": NAME, "value": VALUE, "owner": "192.0.2.0" });
    let new = |owner: &str| serde_json::json!({ "fqdn": NAME, "value": VALUE, "owner": owner, "network": "192.0.2.0" });
    let write = |path, body: serde_json::Value| async move {
        post_json(ns.write, path, &body.to_string()).await.unwrap()
    };

    // A value presented before the API's upgrade: a client on the network
    // takes it down after the upgrade, as it could before.
    assert_eq!(write("/present", old.clone()).await.0, 200);
    assert_eq!(write("/cleanup", new("192.0.2.99")).await.0, 200);
    assert!(txt(ns.dns, NAME).await.answers.is_empty());

    // A value presented after it belongs to the address alone.
    assert_eq!(write("/present", new("192.0.2.10")).await.0, 200);
    assert_eq!(write("/cleanup", new("192.0.2.99")).await.0, 200);
    assert_eq!(write("/cleanup", old).await.0, 200);
    assert_eq!(values(&txt(ns.dns, NAME).await), [VALUE]);
    assert_eq!(write("/cleanup", new("192.0.2.10")).await.0, 200);
    assert!(txt(ns.dns, NAME).await.answers.is_empty());

    let bad = serde_json::json!({ "fqdn": NAME, "value": VALUE, "network": "x" });
    assert_eq!(write("/present", bad).await.0, 400);
}

#[tokio::test]
async fn name_server_applies_changes_in_the_api_order() {
    // A present and a cleanup of the same value overlap, and this name
    // server gets them the wrong way round: the later one, by the API's
    // numbers, wins, as it does on the name servers that got them in order.
    let ns = name_server("127.0.0.1").await;
    let change = |seq: u64| {
        serde_json::json!({
            "fqdn": NAME, "value": VALUE,
            "owner": "192.0.2.10", "network": "192.0.2.0", "seq": seq,
        })
        .to_string()
    };
    let write = |path, seq| async move { post_json(ns.write, path, &change(seq)).await.unwrap() };

    assert_eq!(
        write("/cleanup", 200).await,
        (200, r#"{"ok":true}"#.to_owned())
    );
    assert_eq!(write("/present", 100).await.0, 200);
    assert!(txt(ns.dns, NAME).await.answers.is_empty());

    assert_eq!(write("/present", 300).await.0, 200);
    assert_eq!(write("/cleanup", 250).await.0, 200);
    assert_eq!(values(&txt(ns.dns, NAME).await), [VALUE]);
    assert_eq!(write("/cleanup", 400).await.0, 200);
    assert!(txt(ns.dns, NAME).await.answers.is_empty());

    let bad = serde_json::json!({ "fqdn": NAME, "value": VALUE, "seq": -1 });
    assert_eq!(
        post_json(ns.write, "/present", &bad.to_string())
            .await
            .unwrap()
            .0,
        400
    );
}

#[tokio::test]
async fn punycode_names_reach_the_name_servers() {
    let ns = name_server("127.0.0.1").await;
    let api = api(&[ns.write], "").await;
    let name = "_acme-challenge.xn--bcher-kva.10-0-2-2.ipssl.cc.";
    let (status, reply) = post_json(api, "/present", &body(name, VALUE))
        .await
        .unwrap();
    assert_eq!(status, 200, "{reply}");
    assert_eq!(values(&txt(ns.dns, name).await), [VALUE]);
}

#[tokio::test]
async fn api_skips_interim_responses_from_name_servers() {
    let node = fake_node(
        "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n\
         HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n\
         {\"ok\":true}",
    )
    .await;
    let api = api(&[node], "").await;
    let (status, reply) = post_json(api, "/present", &body(NAME, VALUE))
        .await
        .unwrap();
    assert_eq!(status, 200, "{reply}");
}

#[tokio::test]
async fn api_wants_a_name_server_answer_not_just_any_200() {
    // A port that serves a web page instead of a name server's endpoint.
    let page = fake_node(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n\
         <html></html>",
    )
    .await;
    let refused = fake_node(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n\
         {\"ok\":false}",
    )
    .await;
    for node in [page, refused] {
        let api = api(&[node], "").await;
        let (status, reply) = post_json(api, "/present", &body(NAME, VALUE))
            .await
            .unwrap();
        assert_eq!(status, 502, "{reply}");
    }
}

#[tokio::test]
async fn api_counts_requests_and_name_server_writes() {
    let ns = name_server("127.0.0.1").await;
    let down = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let (api, handle) =
        api_with_metrics(&[ns.write, down], "requests_per_minute = 1\nburst = 2").await;
    let request = body(NAME, VALUE);
    assert_eq!(post_json(api, "/present", &request).await.unwrap().0, 502);
    assert_eq!(post_json(api, "/cleanup", &request).await.unwrap().0, 502);
    assert_eq!(post_json(api, "/present", &request).await.unwrap().0, 429);
    assert_eq!(post_json(api, "/delete", &request).await.unwrap().0, 404);

    let metrics = handle.render_metrics();
    let requests = |endpoint: &str, status: u16| {
        let series =
            format!(r#"ipssl_acme_api_requests_total{{endpoint="{endpoint}",status="{status}"}}"#);
        metric(&metrics, &series)
    };
    assert_eq!(requests("present", 502), 1);
    assert_eq!(requests("cleanup", 502), 1);
    assert_eq!(requests("present", 429), 1);
    assert_eq!(requests("other", 404), 1);
    assert_eq!(requests("present", 200), 0);

    let writes = |node: SocketAddr, result: &str| {
        let series =
            format!(r#"ipssl_acme_api_node_writes_total{{node="{node}",result="{result}"}}"#);
        metric(&metrics, &series)
    };
    // The present, taking it back after the other name server failed,
    // and the cleanup; the name server that is down misses all three.
    assert_eq!(writes(ns.write, "accepted"), 3);
    assert_eq!(writes(down, "failed"), 3);
    assert_eq!(writes(down, "accepted"), 0);
    assert_eq!(metric(&metrics, "ipssl_rate_limit_tracked_networks"), 1);
}

const KEY: &str = "4f1c0e5b9a7d3e2f6a8b1c4d7e0f2a3b5c6d8e9f0a1b2c3d4e5f60718293a4b5";
const OTHER_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// The `[acme]` line that sets `key`.
fn key(key: &str) -> String {
    format!("key = \"{key}\"")
}

fn mac(key: &str, message: &str) -> String {
    let key = HEXLOWER.decode(key.as_bytes()).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(message.as_bytes());
    HEXLOWER.encode(&mac.finalize().into_bytes())
}

/// The MAC that signs a request to `host`, as the API makes it.
fn request_mac(key: &str, host: SocketAddr, time: i64, path: &str, body: &str) -> String {
    let message = format!("ipssl-acme-v1 request\n{host}\n{time}\nPOST\n{path}\n{body}");
    mac(key, &message)
}

/// The MAC that signs a name server's answer to a request to `host`
/// with `request`.
fn reply_mac(key: &str, host: SocketAddr, request: &str, status: u16, body: &str) -> String {
    let message = format!("ipssl-acme-v1 reply\n{host}\n{request}\n{status}\n{body}");
    mac(key, &message)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A change as the API sends it to the name servers.
fn change(seq: u64) -> String {
    serde_json::json!({
        "fqdn": NAME, "value": VALUE,
        "owner": "192.0.2.10", "network": "192.0.2.0", "seq": seq,
    })
    .to_string()
}

/// A name server's answer with `status` and `body`, and `extra` headers.
fn answer(status: &str, extra: &str, body: &str) -> &'static str {
    let raw = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}\r\n{body}",
        body.len()
    );
    Box::leak(raw.into_boxed_str())
}

#[tokio::test]
async fn signed_writes_reach_name_servers_with_the_key() {
    let ns1 = name_server_with("127.0.0.1", &key(KEY)).await;
    let ns2 = name_server_with("127.0.0.1", &key(KEY)).await;
    let api = api(&[ns1.write, ns2.write], &key(KEY)).await;

    let (status, reply) = post_json(api, "/present", &body(NAME, VALUE))
        .await
        .unwrap();
    assert_eq!((status, reply.as_str()), (200, r#"{"ok":true}"#));
    for ns in [&ns1, &ns2] {
        assert_eq!(values(&txt(ns.dns, NAME).await), [VALUE]);
    }
    assert_eq!(
        post_json(api, "/cleanup", &body(NAME, VALUE))
            .await
            .unwrap()
            .0,
        200
    );
    for ns in [&ns1, &ns2] {
        assert!(txt(ns.dns, NAME).await.answers.is_empty());
    }
}

#[tokio::test]
async fn name_server_with_a_key_refuses_other_keys_and_unsigned_writes() {
    let ns = name_server_with("127.0.0.1", &key(KEY)).await;
    for settings in [key(OTHER_KEY), String::new()] {
        let api = api(&[ns.write], &settings).await;
        let (status, reply) = post_json(api, "/present", &body(NAME, VALUE))
            .await
            .unwrap();
        assert_eq!(status, 502, "{settings}: {reply}");
        assert!(txt(ns.dns, NAME).await.answers.is_empty());
    }
    // The present and the cleanup after it, from both APIs.
    let metrics = ns.handler.render_metrics();
    assert_eq!(
        metric(&metrics, r#"ipssl_acme_writes_total{result="rejected"}"#),
        4
    );
    assert_eq!(
        metric(&metrics, r#"ipssl_acme_writes_total{result="accepted"}"#),
        0
    );
}

#[tokio::test]
async fn name_server_with_a_key_takes_each_fresh_signed_write_once() {
    let ns = name_server_with("127.0.0.1", &key(KEY)).await;
    let request = change(1);
    let signed = |time: i64, path: &str, mac: String| {
        let headers = vec![("X-Ipssl-Time", time.to_string()), ("X-Ipssl-Mac", mac)];
        let (path, body) = (path.to_owned(), request.clone());
        async move { post(ns.write, &path, &headers, &body).await.unwrap() }
    };

    // No signature at all.
    let (status, reply) = post_json(ns.write, "/present", &request).await.unwrap();
    assert_eq!(status, 401, "{reply}");
    assert!(reply.contains("not signed"), "{reply}");

    // Signed, but too long ago, too far ahead, for another path, for
    // another name server, or with another key.
    let now = unix_now();
    let elsewhere: SocketAddr = "198.51.100.1:8053".parse().unwrap();
    for (time, host, path, key) in [
        (now - 60, ns.write, "/present", KEY),
        (now + 60, ns.write, "/present", KEY),
        (now, ns.write, "/cleanup", KEY),
        (now, elsewhere, "/present", KEY),
        (now, ns.write, "/present", OTHER_KEY),
    ] {
        let mac = request_mac(key, host, time, path, &request);
        let reply = signed(time, "/present", mac).await;
        assert_eq!(reply.status, 401, "{time} {host} {path}: {}", reply.body);
    }
    assert!(txt(ns.dns, NAME).await.answers.is_empty());

    // Signed right: taken, and the answer is signed for this request.
    let mac = request_mac(KEY, ns.write, now, "/present", &request);
    let reply = signed(now, "/present", mac.clone()).await;
    assert_eq!((reply.status, reply.body.as_str()), (200, r#"{"ok":true}"#));
    let expected = reply_mac(KEY, ns.write, &mac, 200, &reply.body);
    assert_eq!(reply.header("x-ipssl-mac"), Some(expected.as_str()));
    assert_eq!(values(&txt(ns.dns, NAME).await), [VALUE]);

    // The same request again, as someone on the path could send it.
    let again = signed(now, "/present", mac).await;
    assert_eq!(again.status, 401, "{}", again.body);
    assert!(again.body.contains("taken already"), "{}", again.body);

    // Refusals for the client are signed too, so the API can trust them.
    let bad = body(NAME, "not a challenge digest");
    let headers = vec![
        ("X-Ipssl-Time", now.to_string()),
        (
            "X-Ipssl-Mac",
            request_mac(KEY, ns.write, now, "/present", &bad),
        ),
    ];
    let reply = post(ns.write, "/present", &headers, &bad).await.unwrap();
    assert_eq!(reply.status, 400);
    let mac = request_mac(KEY, ns.write, now, "/present", &bad);
    let expected = reply_mac(KEY, ns.write, &mac, 400, &reply.body);
    assert_eq!(reply.header("x-ipssl-mac"), Some(expected.as_str()));
}

#[tokio::test]
async fn name_server_without_a_key_takes_signed_writes() {
    // While the key is rolled out, the API has it before the name servers.
    let ns = name_server("127.0.0.1").await;
    let rollout = format!("{}\nallow_unsigned_nodes = true", key(KEY));
    let api_rollout = api(&[ns.write], &rollout).await;
    let request = body(NAME, VALUE);
    assert_eq!(
        post_json(api_rollout, "/present", &request)
            .await
            .unwrap()
            .0,
        200
    );
    assert_eq!(values(&txt(ns.dns, NAME).await), [VALUE]);
    assert_eq!(
        post_json(api_rollout, "/cleanup", &request)
            .await
            .unwrap()
            .0,
        200
    );
    assert!(txt(ns.dns, NAME).await.answers.is_empty());

    // Without allow_unsigned_nodes, an unsigned answer counts for nothing:
    // the API reports a failure and takes the value back.
    let api_strict = api(&[ns.write], &key(KEY)).await;
    let (status, reply) = post_json(api_strict, "/present", &request).await.unwrap();
    assert_eq!(status, 502, "{reply}");
    assert!(txt(ns.dns, NAME).await.answers.is_empty());
}

#[tokio::test]
async fn api_with_a_key_trusts_no_forged_answer() {
    // What someone on the path to a name server could answer instead.
    let ok = r#"{"ok":true}"#;
    let unsigned = answer("200 OK", "", ok);
    let made_up = answer(
        "200 OK",
        &format!("X-Ipssl-Mac: {}\r\n", "00".repeat(32)),
        ok,
    );
    // A genuine signature, from the answer to another request.
    let somewhere: SocketAddr = "198.51.100.1:8053".parse().unwrap();
    let request = request_mac(KEY, somewhere, 1, "/present", "{}");
    let old = reply_mac(KEY, somewhere, &request, 200, ok);
    let replayed = answer("200 OK", &format!("X-Ipssl-Mac: {old}\r\n"), ok);
    let full = answer("409 Conflict", "", r#"{"ok":false,"error":"full"}"#);

    let strict = key(KEY);
    let rollout = format!("{strict}\nallow_unsigned_nodes = true");
    for (raw, settings, expected) in [
        (unsigned, &strict, 502),
        (made_up, &strict, 502),
        (made_up, &rollout, 502),
        (replayed, &strict, 502),
        (replayed, &rollout, 502),
        // A refusal is not believed either: it would stop the API from
        // taking the value back on that name server.
        (full, &strict, 502),
        // While the key is rolled out, an unsigned answer is trusted.
        (unsigned, &rollout, 200),
        (full, &rollout, 409),
    ] {
        let node = fake_node(raw).await;
        let api = api(&[node], settings).await;
        let (status, reply) = post_json(api, "/present", &body(NAME, VALUE))
            .await
            .unwrap();
        assert_eq!(status, expected, "{raw:?} with {settings:?}: {reply}");
    }
}

/// A stand-in for the network path to the name server at `target` that
/// passes requests and answers on, and keeps a copy of each answer in
/// `answers`.
async fn tapped_path(
    target: SocketAddr,
    answers: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let answers = answers.clone();
            tokio::spawn(async move {
                let Some(request) = read_whole_request(&mut stream).await else {
                    return;
                };
                let mut node = TcpStream::connect(target).await.unwrap();
                node.write_all(&request).await.unwrap();
                let mut answer = Vec::new();
                node.read_to_end(&mut answer).await.unwrap();
                let _ = answers.send(answer.clone());
                let _ = stream.write_all(&answer).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// A stand-in for the network path to a name server that never passes a
/// request on, and answers each with the next answer from `answers`: what
/// someone on the path could send back.
async fn substituting_path(answers: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let answers = Arc::new(tokio::sync::Mutex::new(answers));
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let answers = answers.clone();
            tokio::spawn(async move {
                if read_whole_request(&mut stream).await.is_none() {
                    return;
                }
                let Some(answer) = answers.lock().await.recv().await else {
                    return;
                };
                let _ = stream.write_all(&answer).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// Reads one request with its body from `stream`, or `None` if it ends
/// first.
async fn read_whole_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    while !complete(&request) {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => request.extend_from_slice(&chunk[..n]),
        }
    }
    Some(request)
}

/// A stand-in for a second address of the name server at `target`: it
/// relays connections there as they are.
async fn relay(target: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut node = TcpStream::connect(target).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut node).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn api_refuses_one_name_servers_answer_for_another() {
    // Someone on the path to ns2 drops the change and sends back ns1's
    // signed answer to the same change instead.
    let ns1 = name_server_with("127.0.0.1", &key(KEY)).await;
    let ns2 = name_server_with("127.0.0.1", &key(KEY)).await;
    let (tap, answers) = tokio::sync::mpsc::unbounded_channel();
    let path1 = tapped_path(ns1.write, tap).await;
    let path2 = substituting_path(answers).await;
    let api = api(&[path1, path2], &key(KEY)).await;

    let (status, reply) = post_json(api, "/present", &body(NAME, VALUE))
        .await
        .unwrap();
    assert_eq!(status, 502, "{reply}");
    for ns in [&ns1, &ns2] {
        assert!(txt(ns.dns, NAME).await.answers.is_empty());
    }
}

#[tokio::test]
async fn one_name_server_at_two_endpoints_takes_every_change() {
    // One host that serves two NS names on two addresses, or IPv4 and IPv6
    // listed by hand: the API writes to it twice, with and without a key.
    for settings in [String::new(), key(KEY)] {
        let ns = name_server_with("127.0.0.1", &settings).await;
        let second = relay(ns.write).await;
        let api = api(&[ns.write, second], &settings).await;
        for path in ["/present", "/cleanup", "/present"] {
            let (status, reply) = post_json(api, path, &body(NAME, VALUE)).await.unwrap();
            assert_eq!(status, 200, "{path} with {settings:?}: {reply}");
        }
        assert_eq!(values(&txt(ns.dns, NAME).await), [VALUE]);
    }
}
