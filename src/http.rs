//! A minimal HTTP/1.1 server for `GET /metrics`, nothing else.
//!
//! Meant to be reached only by a local or private Prometheus, so it stays
//! small: one request per connection, a cap on concurrent connections, a
//! size limit and a deadline for each request.

use std::io;
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
const MAX_REQUEST: usize = 8 * 1024;

/// Time a client has to send its request and read the response.
const DEADLINE: Duration = Duration::from_secs(10);

const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Serves `render()` at `/metrics` until the task is dropped.
pub async fn serve<F>(listener: TcpListener, render: F)
where
    F: Fn() -> String + Send + Sync + 'static,
{
    let render = Arc::new(render);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) => {
                // Usually out of file descriptors; back off instead of spinning.
                warn!(%error, "metrics: accept failed");
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let render = render.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match timeout(DEADLINE, respond(stream, &*render)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => debug!(%error, "metrics: connection failed"),
                Err(_) => debug!("metrics: connection timed out"),
            }
        });
    }
}

async fn respond(mut stream: TcpStream, render: &(dyn Fn() -> String + Sync)) -> io::Result<()> {
    let Some(head) = read_head(&mut stream).await? else {
        return write(
            &mut stream,
            "400 Bad Request",
            "text/plain",
            "bad request\n",
        )
        .await;
    };
    let mut parts = head.split(' ');
    let method = parts.next().unwrap_or_default();
    let path = parts.next().unwrap_or_default();
    let path = path.split('?').next().unwrap_or_default();

    match (method, path) {
        ("GET", "/metrics") => write(&mut stream, "200 OK", METRICS_CONTENT_TYPE, &render()).await,
        ("GET", _) => write(&mut stream, "404 Not Found", "text/plain", "not found\n").await,
        _ => {
            let status = "405 Method Not Allowed";
            write(&mut stream, status, "text/plain", "only GET is supported\n").await
        }
    }
}

/// Reads the request head and returns its first line, or `None` if the
/// request is too large or not text. Any body is ignored.
async fn read_head(stream: &mut TcpStream) -> io::Result<Option<String>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        if buf.len() >= MAX_REQUEST {
            return Ok(None);
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let line = buf.split(|&b| b == b'\r').next().unwrap_or_default();
    Ok(std::str::from_utf8(line).ok().map(str::to_owned))
}

async fn write(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn start() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, || "up 1\n".to_owned()));
        addr
    }

    async fn request(addr: std::net::SocketAddr, raw: &str) -> String {
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
        raw.push_str(&"a".repeat(MAX_REQUEST - raw.len()));
        let response = request(addr, &raw).await;
        assert!(response.starts_with("HTTP/1.1 400 "), "{response}");
    }
}
