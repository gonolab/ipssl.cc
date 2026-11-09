//! A minimal HTTP/1.1 server and client: enough for `GET /metrics` and the
//! small JSON API in [`crate::acme`], nothing more.
//!
//! One request per connection, a cap on concurrent connections, size
//! limits and a deadline for each request. Bodies need a `Content-Length`;
//! chunked encoding is not supported.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};
use tracing::{debug, warn};

/// Connections served at once; more are closed right away.
const MAX_CONNECTIONS: usize = 16;

/// Largest request head we read.
const MAX_HEAD: usize = 8 * 1024;

/// Largest request body we accept.
const MAX_BODY: usize = 4 * 1024;

/// Largest response the client reads.
const MAX_RESPONSE: usize = 16 * 1024;

/// Time a client has to send its request and read the response.
const DEADLINE: Duration = Duration::from_secs(10);

const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

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
    /// The first header called `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
}

impl Response {
    pub fn new(status: u16, content_type: &'static str, body: impl Into<String>) -> Self {
        Self {
            status,
            content_type,
            body: body.into(),
        }
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
/// dropped.
pub async fn serve<H, F>(listener: TcpListener, handler: H)
where
    H: Fn(Request) -> F + Send + Sync + 'static,
    F: Future<Output = Response> + Send + 'static,
{
    let handler = Arc::new(handler);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // Usually out of file descriptors; back off instead of spinning.
                warn!(%error, "http: accept failed");
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match timeout(DEADLINE, respond(stream, peer, &*handler)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => debug!(%error, "http: connection failed"),
                Err(_) => debug!("http: connection timed out"),
            }
        });
    }
}

async fn respond<H, F>(mut stream: TcpStream, peer: SocketAddr, handler: &H) -> io::Result<()>
where
    H: Fn(Request) -> F,
    F: Future<Output = Response>,
{
    let response = match read_request(&mut stream, peer).await? {
        Ok(request) => handler(request).await,
        Err(response) => response,
    };
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
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason(response.status),
        response.content_type,
        response.body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(response.body.as_bytes()).await?;
    stream.shutdown().await
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Content Too Large",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Unknown",
    }
}

/// Sends a POST with a JSON `body` to `addr` and returns the status code
/// and the response body. The caller sets the deadline.
pub async fn post_json(addr: SocketAddr, path: &str, body: &str) -> io::Result<(u16, String)> {
    let mut stream = TcpStream::connect(addr).await?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    let mut limited = (&mut stream).take(MAX_RESPONSE as u64);
    limited.read_to_end(&mut response).await?;
    let text = String::from_utf8_lossy(&response);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP response"))?;
    Ok((status, body.to_owned()))
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
