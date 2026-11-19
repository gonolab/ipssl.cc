//! End-to-end tests: start the server on loopback and query it over UDP and TCP.

use std::net::SocketAddr;
use std::time::Duration;

use hickory_server::Server;
use hickory_server::proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_server::proto::rr::{Name, RData, RecordType};
use hickory_server::proto::serialize::binary::{BinDecodable, BinDecoder};
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
    let limiter = RateLimiter::from_config(&config.rate_limit).unwrap();
    start_with_limiter(config, limiter)
}

/// Starts a server for `config` that limits UDP with `limiter` instead of
/// the one `config` describes.
fn start_with_limiter(config: Config, limiter: Option<RateLimiter>) -> TestServer {
    let handler = Handler::new(Zone::from_config(&config).unwrap()).with_rate_limiter(limiter);
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

/// Sends `msg` over UDP and returns the response exactly as received.
async fn raw_udp(addr: SocketAddr, msg: &Message) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(&msg.to_vec().unwrap(), addr).await.unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("no UDP response")
        .unwrap();
    buf[..n].to_vec()
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
async fn serves_mail_records() {
    // An RSA DKIM key is longer than one 255-byte TXT string, so it has to
    // go out split, and still fit a plain 512-byte UDP response.
    let key = format!("v=DKIM1; k=rsa; p={}", "A".repeat(400));
    let config = format!("{EXAMPLE_CONFIG}\n[hosts.\"s1._domainkey\"]\ntxt = [\"{key}\"]\n");
    let server = start_with(Config::parse(&config).unwrap());

    let mx = over_udp(server.udp, &query("ipssl.cc.", RecordType::MX)).await;
    assert_eq!(rdata(&mx), ["10 mail.example.net."]);

    let dkim = over_udp(
        server.udp,
        &query("s1._domainkey.ipssl.cc.", RecordType::TXT),
    )
    .await;
    assert_eq!(dkim.metadata.response_code, ResponseCode::NoError);
    assert!(!dkim.metadata.truncation);
    let RData::TXT(txt) = &dkim.answers[0].data else {
        panic!("not a TXT record");
    };
    assert_eq!(txt.txt_data.concat(), key.as_bytes());
}

#[tokio::test]
async fn oversized_udp_answer_is_cleanly_truncated() {
    // Too big for 512 bytes even on its own, small enough for 1232.
    let key = format!("v=DKIM1; k=rsa; p={}", "A".repeat(600));
    let config = format!("{EXAMPLE_CONFIG}\n[hosts.\"s1._domainkey\"]\ntxt = [\"{key}\"]\n");
    let server = start_with(Config::parse(&config).unwrap());
    let name = "s1._domainkey.ipssl.cc.";
    // Wire name (one byte longer than the dotted text), then type and class.
    let question_len = name.len() + 1 + 4;
    let with_edns = |payload: u16| {
        let mut msg = query(name, RecordType::TXT);
        let mut edns = Edns::new();
        edns.set_max_payload(payload);
        msg.set_edns(edns);
        msg
    };
    let key_of = |msg: &Message| match &msg.answers[0].data {
        RData::TXT(txt) => txt.txt_data.concat(),
        other => panic!("not TXT: {other:?}"),
    };

    // No EDNS: header and question only, with nothing left over after them.
    let plain = query(name, RecordType::TXT);
    let bytes = raw_udp(server.udp, &plain).await;
    assert_eq!(bytes.len(), 12 + question_len);
    let resp = Message::from_vec(&bytes).unwrap();
    assert!(resp.metadata.truncation);
    assert!(resp.metadata.authoritative);
    assert!(resp.answers.is_empty() && resp.authorities.is_empty());

    // EDNS with a 512-byte buffer: the same plus the OPT record.
    let bytes = raw_udp(server.udp, &with_edns(512)).await;
    assert_eq!(bytes.len(), 12 + question_len + 11);
    assert!(Message::from_vec(&bytes).unwrap().metadata.truncation);

    // A 1232-byte buffer takes the whole record in one go.
    let resp = over_udp(server.udp, &with_edns(1232)).await;
    assert!(!resp.metadata.truncation);
    assert_eq!(key_of(&resp), key.as_bytes());

    // TCP always does.
    let resp = over_tcp(server.tcp, &plain).await;
    assert_eq!(key_of(&resp), key.as_bytes());

    let metrics = server.handler.render_metrics();
    assert!(
        metrics.contains("\nipssl_dns_truncated_total 2\n"),
        "{metrics}"
    );
}

#[tokio::test]
async fn largest_rrset_still_goes_out_over_tcp() {
    // 243 of these TXT records are the most that fit in a 65535-byte
    // message (hickory stops compressing names after 120 of them), so the
    // zone takes 243 and refuses 244.
    let config = |count: usize| {
        let values: Vec<String> = (0..count)
            .map(|i| format!("\"{i:03}{}\"", "A".repeat(247)))
            .collect();
        let text = format!(
            "{EXAMPLE_CONFIG}\n[hosts.big]\ntxt = [{}]\n",
            values.join(", ")
        );
        Config::parse(&text).unwrap()
    };
    assert!(Zone::from_config(&config(244)).is_err());

    let server = start_with(config(243));
    let resp = over_tcp(server.tcp, &query("big.ipssl.cc.", RecordType::TXT)).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert!(!resp.metadata.truncation);
    assert_eq!(resp.answers.len(), 243);
}

/// The additional records as `name type rdata`.
fn additionals(msg: &Message) -> Vec<String> {
    msg.additionals
        .iter()
        .map(|r| format!("{} {} {}", r.name, r.record_type(), r.data))
        .collect()
}

#[tokio::test]
async fn ns_answers_carry_name_server_addresses() {
    let server = start();
    // No EDNS, so the 512-byte limit applies; they fit easily.
    let resp = over_udp(server.udp, &query("ipssl.cc.", RecordType::NS)).await;
    assert!(!resp.metadata.truncation);
    assert_eq!(resp.answers.len(), 2);
    assert_eq!(
        additionals(&resp),
        [
            "ns1.ipssl.cc. A 198.51.100.1",
            "ns1.ipssl.cc. AAAA 2001:db8::1",
            "ns2.ipssl.cc. A 198.51.100.2",
            "ns2.ipssl.cc. AAAA 2001:db8::2",
        ]
    );
    // Over TCP too.
    let resp = over_tcp(server.tcp, &query("ipssl.cc.", RecordType::NS)).await;
    assert_eq!(resp.additionals.len(), 4);
}

#[tokio::test]
async fn mx_answers_carry_target_addresses() {
    let config = format!(
        "{EXAMPLE_CONFIG}\n[hosts.mailer]\nmx = [{{ preference = 10, exchange = \"mx.ipssl.cc\" }}]\n\
         [hosts.mx]\na = [\"198.51.100.25\"]\n"
    );
    let server = start_with(Config::parse(&config).unwrap());
    let resp = over_udp(server.udp, &query("mailer.ipssl.cc.", RecordType::MX)).await;
    assert_eq!(rdata(&resp), ["10 mx.ipssl.cc."]);
    assert_eq!(additionals(&resp), ["mx.ipssl.cc. A 198.51.100.25"]);
    // The domain's own MX is outside the zone, so it has none.
    let resp = over_udp(server.udp, &query("ipssl.cc.", RecordType::MX)).await;
    assert!(resp.additionals.is_empty());
}

#[tokio::test]
async fn additionals_that_do_not_fit_are_left_out() {
    // Ten MX targets with two addresses each: the answer fits in 512
    // bytes, but not with every address.
    let mut config = format!("{EXAMPLE_CONFIG}\n[hosts.mailer]\nmx = [");
    for i in 0..10 {
        config += &format!("{{ preference = {i}, exchange = \"mx{i}.ipssl.cc\" }}, ");
    }
    config += "]\n";
    for i in 0..10 {
        let n = i + 1;
        config += &format!("[hosts.mx{i}]\na = [\"198.51.100.{n}\"]\naaaa = [\"2001:db8::{n}\"]\n");
    }
    let server = start_with(Config::parse(&config).unwrap());
    let req = query("mailer.ipssl.cc.", RecordType::MX);

    // No EDNS: no truncation and nothing left over at the end, with the
    // whole answer and as many whole address RRsets as fit.
    let bytes = raw_udp(server.udp, &req).await;
    assert!(bytes.len() <= 512, "{} bytes", bytes.len());
    let mut decoder = BinDecoder::new(&bytes);
    let resp = Message::read(&mut decoder).unwrap();
    assert!(decoder.is_empty(), "{} bytes left over", decoder.len());
    assert!(!resp.metadata.truncation);
    assert_eq!(resp.answers.len(), 10);
    let some = resp.additionals.len();
    assert!(0 < some && some < 20, "{some} additionals");
    let expected: Vec<String> = (0..10)
        .flat_map(|i| {
            let n = i + 1;
            [
                format!("mx{i}.ipssl.cc. A 198.51.100.{n}"),
                format!("mx{i}.ipssl.cc. AAAA 2001:db8::{n}"),
            ]
        })
        .collect();
    assert_eq!(additionals(&resp), expected[..some]);

    // A bigger buffer takes them all, and so does TCP.
    let mut with_edns = req.clone();
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    with_edns.set_edns(edns);
    let resp = over_udp(server.udp, &with_edns).await;
    assert!(!resp.metadata.truncation);
    assert_eq!(additionals(&resp), expected);
    assert_eq!(additionals(&over_tcp(server.tcp, &req).await), expected);
    let metrics = server.handler.render_metrics();
    assert!(
        metrics.contains("\nipssl_dns_truncated_total 0\n"),
        "{metrics}"
    );
}

#[tokio::test]
async fn names_without_records_are_nodata() {
    // Resolvers that minimise queries ask for `1.ipssl.cc` on the way to
    // `10.0.0.1.ipssl.cc`; an NXDOMAIN there would stop them short.
    let server = start();
    for name in [
        "nothing.ipssl.cc.",
        "1.ipssl.cc.",
        "0.1.ipssl.cc.",
        "0.0.1.ipssl.cc.",
        "app.ipssl.cc.",
    ] {
        let resp = over_udp(server.udp, &query(name, RecordType::A)).await;
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError, "{name}");
        assert!(resp.metadata.authoritative);
        assert!(resp.answers.is_empty());
        assert_eq!(resp.authorities.len(), 1);
        assert_eq!(resp.authorities[0].record_type(), RecordType::SOA);
        assert_eq!(resp.authorities[0].ttl, 300);
    }
    for name in ["10.0.0.1.ipssl.cc.", "10-0-0-1.app.ipssl.cc."] {
        let resp = over_udp(server.udp, &query(name, RecordType::A)).await;
        assert_eq!(rdata(&resp), ["10.0.0.1"], "{name}");
    }
}

#[tokio::test]
async fn blocklisted_name_is_nxdomain_with_soa() {
    let mut config = Config::parse(EXAMPLE_CONFIG).unwrap();
    config.blocklist = vec!["203.0.113.0/24".parse().unwrap()];
    let server = start_with(config);
    let resp = over_udp(server.udp, &query("203-0-113-5.ipssl.cc.", RecordType::A)).await;
    assert_eq!(resp.metadata.response_code, ResponseCode::NXDomain);
    assert!(resp.metadata.authoritative);
    assert_eq!(resp.authorities.len(), 1);
    assert_eq!(resp.authorities[0].record_type(), RecordType::SOA);
    assert_eq!(resp.authorities[0].ttl, 300);
}

#[tokio::test]
async fn zone_transfers_are_refused() {
    let server = start();
    for qtype in [RecordType::AXFR, RecordType::IXFR] {
        let resp = over_tcp(server.tcp, &query("ipssl.cc.", qtype)).await;
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::Refused,
            "{qtype}"
        );
        assert!(resp.answers.is_empty() && resp.authorities.is_empty());
    }
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
async fn dnssec_ok_bit_is_copied() {
    let server = start();
    for dnssec_ok in [true, false] {
        let mut req = query("10-0-0-1.ipssl.cc.", RecordType::A);
        let mut edns = Edns::new();
        edns.set_dnssec_ok(dnssec_ok);
        req.set_edns(edns);

        let resp = over_udp(server.udp, &req).await;
        let edns = resp.edns.as_ref().expect("response should carry EDNS");
        assert_eq!(edns.flags().dnssec_ok, dnssec_ok);
        assert_eq!(rdata(&resp), ["10.0.0.1"]);
    }
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
    // A burst of two that refills one token in about 12 days, so however
    // slowly the queries below are processed, no token comes back.
    let limiter = RateLimiter::new(1e-6, 2, 24, 56, 1000).with_slip(2);
    let server = start_with_limiter(Config::parse(EXAMPLE_CONFIG).unwrap(), Some(limiter));
    let req = query("10-0-0-1.ipssl.cc.", RecordType::A);

    // The burst of two is answered, then responses alternate between
    // dropped and truncated (slip = 2). Nothing waits for the dropped one;
    // the metrics below count it.
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bytes = req.to_vec().unwrap();
    for _ in 0..4 {
        socket.send_to(&bytes, server.udp).await.unwrap();
    }
    let mut buf = [0u8; 4096];
    let mut responses = Vec::new();
    while responses.len() < 3 {
        let (n, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .expect("fewer than three UDP responses")
            .unwrap();
        responses.push(Message::from_vec(&buf[..n]).unwrap());
    }
    let (slipped, answered): (Vec<_>, Vec<_>) =
        responses.into_iter().partition(|r| r.metadata.truncation);
    assert_eq!(answered.len(), 2);
    for resp in &answered {
        assert_eq!(rdata(resp), ["10.0.0.1"]);
    }
    let [slipped] = slipped.as_slice() else {
        panic!("expected one truncated response, got {}", slipped.len());
    };
    assert!(slipped.answers.is_empty());
    assert_eq!(slipped.metadata.id, req.metadata.id);
    assert_eq!(slipped.queries, req.queries);

    // TCP is never limited.
    for _ in 0..5 {
        assert_eq!(rdata(&over_tcp(server.tcp, &req).await), ["10.0.0.1"]);
    }

    let metrics = server.handler.render_metrics();
    for line in [
        r#"ipssl_dns_queries_total{protocol="udp",qtype="A"} 4"#,
        r#"ipssl_dns_queries_total{protocol="tcp",qtype="A"} 5"#,
        // 2 + 5 answers and 1 truncated response.
        r#"ipssl_dns_responses_total{rcode="NOERROR"} 8"#,
        r#"ipssl_dns_rate_limited_total{action="drop"} 1"#,
        r#"ipssl_dns_rate_limited_total{action="slip"} 1"#,
        "ipssl_rate_limit_tracked_networks 1",
        "ipssl_zone_serial 2026110501",
    ] {
        assert!(
            metrics.lines().any(|l| l == line),
            "missing {line:?} in\n{metrics}"
        );
    }
}

/// `ipssl-dns --reload`, run against a server in its own process.
#[cfg(unix)]
mod reload_helper {
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output};
    use std::time::Instant;
    use std::{fs, thread};

    use super::*;

    /// A port free on 127.0.0.1 for both UDP and TCP, for a server run as its
    /// own process: its config cannot ask for port 0.
    fn free_port() -> u16 {
        loop {
            let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let port = udp.local_addr().unwrap().port();
            if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
                return port;
            }
        }
    }

    /// A server process, killed when dropped.
    struct Process(Child);

    impl Drop for Process {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn soa_serial(resp: &Message) -> u32 {
        match &resp.answers[0].data {
            RData::SOA(soa) => soa.serial,
            other => panic!("not an SOA record: {other:?}"),
        }
    }

    #[tokio::test]
    async fn reload_helper_reports_the_servers_result() {
        let bin = env!("CARGO_BIN_EXE_ipssl-dns");
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("reload-helper");
        let _ = fs::remove_dir_all(&dir);
        let run = dir.join("run");
        fs::create_dir_all(&run).unwrap();
        let config = dir.join("config.toml");

        let dns: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        let acme = format!("127.0.0.1:{}", free_port());
        // The config with this serial, plus `extra`.
        let config_text = |serial: u32, extra: &str| {
            format!(
                r#"
                domain = "ipssl.cc"
                listen = ["{dns}"]

                [[nameservers]]
                name = "ns1.ipssl.cc"
                ipv4 = ["198.51.100.1"]

                [soa]
                email = "hostmaster@ipssl.cc"
                serial = {serial}

                {extra}
                "#
            )
        };
        let with_acme = format!("[acme]\nlisten = \"{acme}\"\nwriters = [\"127.0.0.1\"]");
        fs::write(&config, config_text(2026110501, &with_acme)).unwrap();

        let log = fs::File::create(dir.join("server.log")).unwrap();
        let server = Process(
            Command::new(bin)
                .arg("-c")
                .arg(&config)
                .env("RUNTIME_DIRECTORY", &run)
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        let pid = server.0.id().to_string();
        let status = run.join("reload");
        let started = Instant::now();
        while !status.exists() {
            assert!(started.elapsed() < Duration::from_secs(10), "no status");
            thread::sleep(Duration::from_millis(20));
        }
        let reload = |runtime_dir: &Path| -> Output {
            Command::new(bin)
                .arg("-c")
                .arg(&config)
                .args(["--reload", &pid])
                .env("RUNTIME_DIRECTORY", runtime_dir)
                .output()
                .unwrap()
        };
        let soa = query("ipssl.cc.", RecordType::SOA);
        assert_eq!(soa_serial(&over_udp(dns, &soa).await), 2026110501);

        // The new zone is served as soon as the reload returns.
        fs::write(&config, config_text(2026110502, &with_acme)).unwrap();
        let out = reload(&run);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{stdout}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            stdout.contains("reloaded the config serial=2026110502"),
            "{stdout}"
        );
        assert_eq!(soa_serial(&over_udp(dns, &soa).await), 2026110502);

        // A config only the running server refuses: it started with [acme], so
        // its challenge store would hide this record.
        let hidden = "[hosts.\"_acme-challenge.10-0-2-2\"]\ntxt = [\"manual\"]";
        fs::write(&config, config_text(2026110503, hidden)).unwrap();
        let out = reload(&run);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("keeps its running config"), "{stderr}");
        assert!(stderr.contains("restart"), "{stderr}");
        assert_eq!(soa_serial(&over_udp(dns, &soa).await), 2026110502);

        // A config the check refuses never reaches the server.
        let before = fs::read_to_string(&status).unwrap();
        fs::write(&config, "domain = ").unwrap();
        let out = reload(&run);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(fs::read_to_string(&status).unwrap(), before);

        // Nor does one when there is no runtime directory to confirm it in.
        fs::write(&config, config_text(2026110504, &with_acme)).unwrap();
        let out = reload(&dir.join("missing"));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("RuntimeDirectory"), "{stderr}");
        assert_eq!(fs::read_to_string(&status).unwrap(), before);
        assert_eq!(soa_serial(&over_udp(dns, &soa).await), 2026110502);
    }
}
