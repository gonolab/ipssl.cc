//! A minimal HTTP/1.1 server and client: enough for `GET /metrics` and the
//! small JSON API in [`crate::acme`], nothing more.
//!
//! One request per connection, a cap on concurrent connections, size
//! limits and a deadline for each request. Bodies need a `Content-Length`;
//! chunked encoding is not supported. A server can be limited to some
//! peers, which are then checked before anything else happens.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{Instant, sleep, sleep_until, timeout};
use tracing::{debug, warn};

/// Connections served at once.
const MAX_CONNECTIONS: usize = 16;

/// Connections answered `503` while all [`MAX_CONNECTIONS`] are busy;
/// past that, new connections get a fixed `503` without waiting for their
/// request, see [`turn_away`].
const MAX_REFUSALS: usize = 16;

/// Time a connection turned away with `503` has to send its request, and
/// then to take the answer.
const REFUSAL_DEADLINE: Duration = Duration::from_secs(2);

/// How long a connection given the fixed `503` stays open for reading,
/// see [`Lingering`].
const LINGER: Duration = Duration::from_secs(1);

/// Most connections given the fixed `503` that stay open at once; past
/// that the oldest is closed early.
const MAX_LINGERING: usize = 64;

/// Largest request head we read.
const MAX_HEAD: usize = 8 * 1024;

/// Largest request body we accept.
const MAX_BODY: usize = 4 * 1024;

/// Largest response the client reads.
const MAX_RESPONSE: usize = 16 * 1024;

/// Time a client has to send its request.
const READ_DEADLINE: Duration = Duration::from_secs(10);

/// Time the server has to answer once the request is in: the handler and
/// sending the response. It starts after the request is read, so a slow
/// client does not eat into the handler's time.
const DEADLINE: Duration = Duration::from_secs(10);

const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// What [`busy`] answers, as a whole response, for [`turn_away`].
const OVERLOADED: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
    Content-Type: text/plain; charset=utf-8\r\n\
    Content-Length: 24\r\n\
    Connection: close\r\n\r\n\
    busy, try again shortly\n";

pub struct Request {
    pub method: String,
    /// Path without the query string.
    pub path: String,
    pub peer: SocketAddr,
    /// Header names in lowercase.
    headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// A request as the server reads it, header names in lowercase.
    pub fn new(
        method: &str,
        path: &str,
        peer: SocketAddr,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            peer,
            headers,
            body,
        }
    }

    /// The first header called `name`, in any case.
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }

    /// Replaces the headers called `name` (lowercase) with one `value`.
    #[cfg(test)]
    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.retain(|(n, _)| n != name);
        self.headers.push((name.to_owned(), value.to_owned()));
    }
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    /// Headers besides `Content-Type`, `Content-Length` and `Connection`.
    pub headers: Vec<(&'static str, String)>,
    pub body: String,
}

impl Response {
    pub fn new(status: u16, content_type: &'static str, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    /// Adds a header. `value` must not contain line breaks.
    pub fn with_header(mut self, name: &'static str, value: String) -> Self {
        self.headers.push((name, value));
        self
    }

    pub fn text(status: u16, body: &str) -> Self {
        Self::new(status, "text/plain; charset=utf-8", format!("{body}\n"))
    }
}

/// Serves `render()` at `/metrics` until the task is dropped.
pub async fn serve_metrics<F>(listener: TcpListener, render: F)
where
    F: Fn() -> String + Send + Sync + 'static,
{
    serve(listener, move |req: Request| {
        let response = match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/metrics") => Response::new(200, METRICS_CONTENT_TYPE, render()),
            ("GET", _) => Response::text(404, "not found"),
            _ => Response::text(405, "only GET is supported"),
        };
        std::future::ready(response)
    })
    .await
}

/// Answers every request on `listener` with `handler` until the task is
/// dropped. See [`Server`] for more options.
pub async fn serve<H, F>(listener: TcpListener, handler: H)
where
    H: Fn(Request) -> F + Send + Sync + 'static,
    F: Future<Output = Response> + Send + 'static,
{
    Server::new(listener).serve(handler).await
}

/// Called with the request path (empty when the request could not be
/// read) and the status of every response.
type Observe = dyn Fn(&str, u16) + Send + Sync;

/// An HTTP server on one listener.
pub struct Server {
    listener: TcpListener,
    allow: Box<dyn Fn(IpAddr) -> bool + Send + Sync>,
    observe: Arc<Observe>,
}

impl Server {
    pub fn new(listener: TcpListener) -> Self {
        Self {
            listener,
            allow: Box::new(|_| true),
            observe: Arc::new(|_, _| {}),
        }
    }

    /// Calls `observe` with the path and status of every response, the
    /// server's own (malformed requests, `503` when busy) included.
    pub fn observe(mut self, observe: impl Fn(&str, u16) + Send + Sync + 'static) -> Self {
        self.observe = Arc::new(observe);
        self
    }

    /// Serves only peers that `allow` accepts. Connections from anyone
    /// else are closed as soon as they are accepted, before they take a
    /// slot or are read, so they cannot crowd out the peers that may
    /// connect.
    pub fn allow(mut self, allow: impl Fn(IpAddr) -> bool + Send + Sync + 'static) -> Self {
        self.allow = Box::new(allow);
        self
    }

    /// Answers every request with `handler` until the task is dropped.
    pub async fn serve<H, F>(self, handler: H)
    where
        H: Fn(Request) -> F + Send + Sync + 'static,
        F: Future<Output = Response> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let refusals = Arc::new(Semaphore::new(MAX_REFUSALS));
        let mut lingering = Lingering::default();
        loop {
            let due = lingering.next_due();
            let accepted = tokio::select! {
                accepted = self.listener.accept() => accepted,
                () = sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() => {
                    lingering.close_due(Instant::now());
                    continue;
                }
            };
            let (stream, peer) = match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    // Usually out of file descriptors; back off instead of spinning.
                    warn!(%error, "http: accept failed");
                    sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            if !(self.allow)(peer.ip()) {
                continue;
            }
            let observe = self.observe.clone();
            if let Ok(permit) = permits.clone().try_acquire_owned() {
                let handler = handler.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let deadlines = (READ_DEADLINE, DEADLINE);
                    connection(stream, peer, deadlines, &*handler, &*observe).await;
                });
            } else if let Ok(permit) = refusals.clone().try_acquire_owned() {
                // Every slot is busy. Still read the request and say so:
                // a closed connection looks like a crash to the client, or
                // to the proxy in front, which then makes up its own error.
                tokio::spawn(async move {
                    let _permit = permit;
                    let deadlines = (REFUSAL_DEADLINE, REFUSAL_DEADLINE);
                    connection(stream, peer, deadlines, &busy, &*observe).await;
                });
            } else {
                // The refusals are all taken too: say so all the same, but
                // right here, without a task or any waiting.
                turn_away(&stream);
                lingering.push(stream, Instant::now());
                observe("", 503);
            }
        }
    }
}

/// Answers `503` on a connection that found every slot of both pools
/// taken, without waiting for anything. It reads whatever part of the
/// request has arrived (up to [`MAX_HEAD`]), since closing a connection
/// with unread data resets it, and a reset can make the client drop the
/// answer before reading it; then it writes [`OVERLOADED`] into the empty
/// send buffer and ends its side of the connection. The caller keeps the
/// connection open for reading for a moment, see [`Lingering`].
///
/// This goes to the socket directly: tokio's `try_read` and `try_write`
/// report `WouldBlock` until the runtime has polled a new socket, which it
/// has not at this point.
fn turn_away(stream: &TcpStream) {
    let socket = SockRef::from(stream);
    drain(&socket, MAX_HEAD);
    if let Err(error) = socket.send(OVERLOADED) {
        debug!(%error, "http: could not answer a connection turned away");
    }
    let _ = socket.shutdown(std::net::Shutdown::Write);
}

/// Reads and drops what has arrived on `socket`, up to `limit` bytes,
/// without waiting.
fn drain(socket: &SockRef<'_>, limit: usize) {
    let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
    let mut read = 0;
    while read < limit {
        let want = buf.len().min(limit - read);
        match socket.recv(&mut buf[..want]) {
            Ok(n) if n > 0 => read += n,
            // The end of what has arrived, of the stream, or an error.
            _ => break,
        }
    }
}

/// Connections given the fixed `503`, kept open for reading for [`LINGER`]
/// by the accept loop itself. The request may arrive after the answer
/// went out: closed at once, the connection would answer it with a reset,
/// and a reset can make the client drop the answer it has not read yet.
/// Closing it a moment later, after reading what arrived, ends it cleanly.
#[derive(Default)]
struct Lingering(VecDeque<(Instant, TcpStream)>);

impl Lingering {
    fn push(&mut self, stream: TcpStream, now: Instant) {
        if self.0.len() >= MAX_LINGERING
            && let Some((_, oldest)) = self.0.pop_front()
        {
            close(oldest);
        }
        self.0.push_back((now + LINGER, stream));
    }

    /// When the next connection is due to close.
    fn next_due(&self) -> Option<Instant> {
        self.0.front().map(|&(due, _)| due)
    }

    fn close_due(&mut self, now: Instant) {
        while let Some(&(due, _)) = self.0.front()
            && due <= now
        {
            if let Some((_, stream)) = self.0.pop_front() {
                close(stream);
            }
        }
    }
}

/// Closes a connection given the fixed `503` after reading what arrived,
/// so that it ends without a reset unless more is still coming.
fn close(stream: TcpStream) {
    drain(&SockRef::from(&stream), MAX_HEAD + MAX_BODY);
}

/// Serves one connection. `deadlines` are the time the client has to
/// send its request, and then the time the server has to answer it.
async fn connection<H, F>(
    mut stream: TcpStream,
    peer: SocketAddr,
    deadlines: (Duration, Duration),
    handler: &H,
    observe: &Observe,
) where
    H: Fn(Request) -> F,
    F: Future<Output = Response>,
{
    let (read, answer) = deadlines;
    let request = match timeout(read, read_request(&mut stream, peer)).await {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            debug!(%error, "http: connection failed");
            return;
        }
        Err(_) => {
            debug!("http: request timed out");
            return;
        }
    };
    match timeout(answer, respond(stream, request, handler, observe)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => debug!(%error, "http: connection failed"),
        Err(_) => debug!("http: answer timed out"),
    }
}

/// The answer while every slot is taken.
fn busy(_: Request) -> std::future::Ready<Response> {
    std::future::ready(Response::text(503, "busy, try again shortly"))
}

/// Answers `request`, or sends the response that refuses it.
async fn respond<H, F>(
    mut stream: TcpStream,
    request: Result<Request, Response>,
    handler: &H,
    observe: &Observe,
) -> io::Result<()>
where
    H: Fn(Request) -> F,
    F: Future<Output = Response>,
{
    let (path, response) = match request {
        Ok(request) => {
            let path = request.path.clone();
            (path, handler(request).await)
        }
        Err(response) => (String::new(), response),
    };
    observe(&path, response.status);
    write_response(&mut stream, &response).await
}

/// Reads one request. The inner `Err` is the response to send when the
/// request is malformed or too large.
async fn read_request(
    stream: &mut TcpStream,
    peer: SocketAddr,
) -> io::Result<Result<Request, Response>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() >= MAX_HEAD {
            return Ok(Err(Response::text(400, "bad request")));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let Ok(head) = std::str::from_utf8(&buf[..head_end]) else {
        return Ok(Err(Response::text(400, "bad request")));
    };

    let mut lines = head.split("\r\n");
    let mut start = lines.next().unwrap_or_default().split(' ');
    let method = start.next().unwrap_or_default().to_owned();
    let target = start.next().unwrap_or_default();
    let path = target.split('?').next().unwrap_or_default().to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();

    let mut request = Request {
        method,
        path,
        peer,
        headers,
        body: Vec::new(),
    };
    if request.header("transfer-encoding").is_some() {
        return Ok(Err(Response::text(411, "send a Content-Length")));
    }
    let length = match request.header("content-length").map(str::parse::<usize>) {
        None => 0,
        Some(Ok(n)) if n <= MAX_BODY => n,
        Some(Ok(_)) => return Ok(Err(Response::text(413, "body too large"))),
        Some(Err(_)) => return Ok(Err(Response::text(400, "bad Content-Length"))),
    };

    let mut body = buf.split_off(head_end + 4);
    while body.len() < length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    request.body = body;
    Ok(Ok(request))
}

async fn write_response(stream: &mut TcpStream, response: &Response) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        response.body.len()
    );
    for (name, value) in &response.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(response.body.as_bytes()).await?;
    stream.shutdown().await
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

/// A response as the client reads it.
#[derive(Debug, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    /// Header names in lowercase.
    headers: Vec<(String, String)>,
    pub body: String,
}

impl Reply {
    /// The first header called `name`, in any case.
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }
}

/// Sends a POST with a JSON `body` to `addr` and returns the status code
/// and the response body. The caller sets the deadline.
pub async fn post_json(addr: SocketAddr, path: &str, body: &str) -> io::Result<(u16, String)> {
    let reply = post(addr, path, &[], body).await?;
    Ok((reply.status, reply.body))
}

/// Sends a POST with a JSON `body` and the extra `headers` to `addr`, and
/// returns the response. Header values must not contain line breaks. The
/// caller sets the deadline.
pub async fn post(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, String)],
    body: &str,
) -> io::Result<Reply> {
    let mut stream = TcpStream::connect(addr).await?;
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    let mut limited = (&mut stream).take(MAX_RESPONSE as u64);
    limited.read_to_end(&mut response).await?;
    parse_response(&String::from_utf8_lossy(&response))
}

/// Splits a whole response, read until the server closed the connection,
/// into the final status code, headers and body. Interim responses (1xx,
/// such as `103 Early Hints`) may come first and are skipped (RFC 9110
/// section 15.2).
fn parse_response(mut text: &str) -> io::Result<Reply> {
    loop {
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text, ""));
        let status = status_code(head)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP response"))?;
        if !(100..200).contains(&status) {
            let headers = head
                .split("\r\n")
                .skip(1)
                .filter_map(|line| line.split_once(':'))
                .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
                .collect();
            return Ok(Reply {
                status,
                headers,
                body: body.to_owned(),
            });
        }
        text = body;
    }
}

/// The status code in the status line that starts `head`.
fn status_code(head: &str) -> Option<u16> {
    let line = head.split("\r\n").next()?;
    let mut parts = line.split(' ');
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 {
        return None;
    }
    code.parse().ok().filter(|code| (100..600).contains(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn start() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_metrics(listener, || "up 1\n".to_owned()));
        addr
    }

    async fn request(addr: SocketAddr, raw: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(raw.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn serves_metrics() {
        let addr = start().await;
        let response = request(addr, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(response.contains(&format!("Content-Type: {METRICS_CONTENT_TYPE}\r\n")));
        assert!(response.contains("Content-Length: 5\r\n"));
        assert!(response.ends_with("\r\n\r\nup 1\n"));
    }

    #[tokio::test]
    async fn query_string_is_ignored() {
        let addr = start().await;
        let response = request(addr, "GET /metrics?x=1 HTTP/1.1\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    }

    #[tokio::test]
    async fn other_paths_and_methods() {
        let addr = start().await;
        let response = request(addr, "GET / HTTP/1.1\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 404 "), "{response}");
        let response = request(addr, "POST /metrics HTTP/1.1\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 405 "), "{response}");
    }

    #[tokio::test]
    async fn oversized_request_is_rejected() {
        let addr = start().await;
        // Exactly the limit and no end of head, so the server reads all of
        // it and closes cleanly (unread data would make it reset instead).
        let mut raw = "GET /metrics HTTP/1.1\r\nX: ".to_owned();
        raw.push_str(&"a".repeat(MAX_HEAD - raw.len()));
        let response = request(addr, &raw).await;
        assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
    }

    async fn start_echo() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, |req: Request| {
            let body = format!(
                "{} {} {} {}",
                req.method,
                req.path,
                req.header("content-type").unwrap_or("-"),
                String::from_utf8_lossy(&req.body)
            );
            std::future::ready(Response::new(200, "text/plain", body))
        }));
        addr
    }

    #[tokio::test]
    async fn client_posts_a_body() {
        let addr = start_echo().await;
        let (status, body) = post_json(addr, "/present", r#"{"a":1}"#).await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, r#"POST /present application/json {"a":1}"#);
    }

    #[tokio::test]
    async fn headers_go_both_ways() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, |req: Request| {
            let seen = req.header("X-Test").unwrap_or("-").to_owned();
            std::future::ready(Response::text(200, "-").with_header("X-Seen", seen))
        }));
        let headers = [("X-Test", "abc".to_owned())];
        let reply = post(addr, "/", &headers, "{}").await.unwrap();
        assert_eq!(reply.header("x-seen"), Some("abc"));
        assert_eq!(reply.header("X-SEEN"), Some("abc"));
    }

    #[test]
    fn client_skips_interim_responses() {
        let hints = "HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n";
        let last = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nX-Ipssl-Mac: ab\r\n\r\n{\"ok\":true}";
        let parsed =
            parse_response(&format!("{hints}HTTP/1.1 100 Continue\r\n\r\n{last}")).unwrap();
        assert_eq!(
            (parsed.status, parsed.body.as_str()),
            (200, r#"{"ok":true}"#)
        );
        // The final response's headers, not the interim ones'.
        assert_eq!(parsed.header("x-ipssl-mac"), Some("ab"));
        assert_eq!(parsed.header("Content-Length"), Some("11"));
        assert_eq!(parsed.header("link"), None);
        assert_eq!(parse_response(last).unwrap().status, 200);

        // Interim responses with no final one, or no HTTP at all.
        for bad in [
            hints,
            "",
            "SSH-2.0-OpenSSH_9.6\r\n",
            "HTTP/1.1 20 OK\r\n\r\n",
        ] {
            assert!(parse_response(bad).is_err(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn busy_server_answers_503() {
        let addr = start().await;
        // Connections that send nothing hold every slot until the deadline.
        let mut idle = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            idle.push(TcpStream::connect(addr).await.unwrap());
        }
        let response = request(addr, "GET /metrics HTTP/1.1\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 503 "), "{response}");

        // A freed slot serves again.
        drop(idle.pop());
        let mut served = false;
        for _ in 0..50 {
            let response = request(addr, "GET /metrics HTTP/1.1\r\n\r\n").await;
            if response.starts_with("HTTP/1.1 200 ") {
                served = true;
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(served);
    }

    #[tokio::test]
    async fn overloaded_server_still_answers_503() {
        use std::io::Write;
        use std::sync::Mutex;

        let seen = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = seen.clone();
        let server = Server::new(listener)
            .observe(move |path, status| log.lock().unwrap().push((path.to_owned(), status)));
        tokio::spawn(server.serve(|_: Request| std::future::ready(Response::text(200, "-"))));

        // Connections that send nothing hold every slot of both pools.
        let mut idle = Vec::new();
        for _ in 0..MAX_CONNECTIONS + MAX_REFUSALS {
            idle.push(TcpStream::connect(addr).await.unwrap());
        }
        // Connect and send the request with blocking calls, so the server,
        // on this test's only thread, takes the connection after both.
        let mut stream = std::net::TcpStream::connect(addr).unwrap();
        stream.write_all(b"GET /metrics HTTP/1.1\r\n\r\n").unwrap();
        stream.set_nonblocking(true).unwrap();
        let mut stream = TcpStream::from_std(stream).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(
            response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"),
            "{response:?}"
        );
        assert!(response.ends_with("\r\n\r\nbusy, try again shortly\n"));
        assert_eq!(*seen.lock().unwrap(), [(String::new(), 503)]);
    }

    #[tokio::test]
    async fn overloaded_server_answers_503_to_a_request_that_comes_late() {
        let addr = start().await;
        let mut idle = Vec::new();
        for _ in 0..MAX_CONNECTIONS + MAX_REFUSALS {
            idle.push(TcpStream::connect(addr).await.unwrap());
        }
        // The server takes the connection and answers before the request
        // arrives, so it has nothing to read yet.
        let mut stream = TcpStream::connect(addr).await.unwrap();
        sleep(Duration::from_millis(100)).await;
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        sleep(Duration::from_millis(50)).await;
        let mut response = Vec::new();
        // No reset: the answer is read in full, and then the end.
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, OVERLOADED);
    }

    #[tokio::test]
    async fn turned_away_connections_close_soon_and_are_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut clients = Vec::new();
        let mut lingering = Lingering::default();
        let now = Instant::now();
        for _ in 0..=MAX_LINGERING {
            clients.push(TcpStream::connect(addr).await.unwrap());
            let (stream, _) = listener.accept().await.unwrap();
            lingering.push(stream, now);
        }
        assert_eq!(lingering.0.len(), MAX_LINGERING);
        assert_eq!(lingering.next_due(), Some(now + LINGER));
        lingering.close_due(now);
        assert_eq!(lingering.0.len(), MAX_LINGERING);
        lingering.close_due(now + LINGER);
        assert!(lingering.0.is_empty());
        assert_eq!(lingering.next_due(), None);
    }

    #[tokio::test]
    async fn fixed_503_matches_the_busy_answer() {
        // Written the way every other response is, the busy answer comes
        // out the same as the fixed one.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, busy));
        let response = request(addr, "GET / HTTP/1.1\r\n\r\n").await;
        assert_eq!(response.as_bytes(), OVERLOADED);
    }

    #[tokio::test]
    async fn every_response_is_observed() {
        use std::sync::Mutex;

        let seen = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = seen.clone();
        let server = Server::new(listener)
            .observe(move |path, status| log.lock().unwrap().push((path.to_owned(), status)));
        tokio::spawn(server.serve(|req: Request| {
            let status = if req.path == "/ok" { 200 } else { 404 };
            std::future::ready(Response::text(status, "-"))
        }));
        request(addr, "GET /ok?x=1 HTTP/1.1\r\n\r\n").await;
        request(addr, "GET /nope HTTP/1.1\r\n\r\n").await;
        request(addr, "POST /ok HTTP/1.1\r\nContent-Length: x\r\n\r\n").await;
        assert_eq!(
            *seen.lock().unwrap(),
            [
                ("/ok".to_owned(), 200),
                ("/nope".to_owned(), 404),
                (String::new(), 400)
            ]
        );
    }

    #[tokio::test]
    async fn peers_not_allowed_are_closed_unread() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(
            Server::new(listener)
                .allow(|_| false)
                .serve(|_: Request| std::future::ready(Response::text(200, "served"))),
        );
        // Even more connections than there are slots get nothing at all.
        for _ in 0..=MAX_CONNECTIONS + MAX_REFUSALS {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            let _ = stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await;
            let mut response = Vec::new();
            // A clean close or a reset, depending on timing; never an answer.
            let _ = stream.read_to_end(&mut response).await;
            assert!(response.is_empty(), "{response:?}");
        }
    }

    #[tokio::test]
    async fn body_limits() {
        let addr = start_echo().await;
        let big = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert!(request(addr, &big).await.starts_with("HTTP/1.1 413 "));
        let chunked = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(request(addr, chunked).await.starts_with("HTTP/1.1 411 "));
    }
}
