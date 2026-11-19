//! ipssl: wildcard DNS for any IP address (`10-0-0-1.ipssl.cc` -> `10.0.0.1`).

pub mod acme;
pub mod config;
pub mod handler;
pub mod http;
pub mod metrics;
pub mod parse;
pub mod ratelimit;
pub mod reload;
pub mod zone;

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{Context, anyhow, ensure};
use hickory_server::Server;
use hickory_server::server::RequestHandler;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;

use crate::handler::Handler;

/// How many responses may queue per TCP connection.
const TCP_RESPONSE_BUFFER: usize = 32;

/// Starts serving on already-bound sockets, all in one server. Must be
/// called inside a Tokio runtime. The server only reports a listener that
/// stopped once every other one has stopped too; [`serve_until`] notices
/// each one.
pub fn serve(
    handler: Handler,
    udp: Vec<UdpSocket>,
    tcp: Vec<TcpListener>,
    tcp_timeout: Duration,
) -> Server<Handler> {
    let mut server = Server::new(handler);
    for socket in udp {
        server.register_socket(socket);
    }
    for listener in tcp {
        server.register_listener(listener, tcp_timeout, TCP_RESPONSE_BUFFER);
    }
    server
}

/// A bound DNS socket.
pub enum Listener {
    Udp(UdpSocket),
    Tcp(TcpListener),
}

impl Listener {
    /// `udp 0.0.0.0:53` or `tcp [::]:53`, for logs and errors.
    fn describe(&self) -> String {
        let (protocol, addr) = match self {
            Self::Udp(socket) => ("udp", socket.local_addr()),
            Self::Tcp(listener) => ("tcp", listener.local_addr()),
        };
        match addr {
            Ok(addr) => format!("{protocol} {addr}"),
            Err(_) => protocol.to_string(),
        }
    }
}

/// Serves DNS on every listener until `shutdown` completes, then stops
/// them all. Must be called inside a Tokio runtime.
///
/// Each listener gets a server of its own. With one server for all of
/// them, a listener that failed (some TCP `accept` errors end it) would
/// only be reported once every other listener had stopped as well, so a
/// dead TCP listener would go unnoticed while UDP still answered. Here the
/// first listener to stop before `shutdown` ends the call with an error
/// naming it, so the process can exit and the service manager restart it.
pub async fn serve_until(
    handler: Handler,
    listeners: Vec<Listener>,
    tcp_timeout: Duration,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    let servers = listeners
        .into_iter()
        .map(|listener| {
            let name = listener.describe();
            let mut server = Server::new(handler.clone());
            match listener {
                Listener::Udp(socket) => server.register_socket(socket),
                Listener::Tcp(listener) => {
                    server.register_listener(listener, tcp_timeout, TCP_RESPONSE_BUFFER)
                }
            }
            (name, server)
        })
        .collect();
    supervise(servers, shutdown).await
}

/// Waits for `shutdown` or for the first server to stop, whichever comes
/// first; see [`serve_until`].
async fn supervise<T: RequestHandler>(
    servers: Vec<(String, Server<T>)>,
    shutdown: impl Future<Output = ()>,
) -> anyhow::Result<()> {
    ensure!(!servers.is_empty(), "no DNS listener to serve on");
    let mut stop = Vec::new();
    let mut running = JoinSet::new();
    for (name, mut server) in servers {
        stop.push(server.shutdown_token().clone());
        running.spawn(async move {
            let result = server.block_until_done().await;
            (name, result)
        });
    }

    tokio::select! {
        () = shutdown => {}
        Some(ended) = running.join_next() => {
            let (name, result) = ended.context("a DNS listener task panicked")?;
            return Err(match result {
                Ok(()) => anyhow!("{name} stopped serving"),
                Err(e) => anyhow!("{name} stopped serving: {e}"),
            });
        }
    }

    for token in &stop {
        token.cancel();
    }
    while let Some(ended) = running.join_next().await {
        if let Ok((name, Err(e))) = ended {
            tracing::warn!("{name} failed while shutting down: {e}");
        }
    }
    Ok(())
}

/// Whether binding `addr` failed only because the kernel has no IPv6
/// (`EAFNOSUPPORT` for the unspecified address `[::]`). The default
/// `listen` includes `[::]:53`, so a server without IPv6 can skip it and
/// still serve IPv4. A specific IPv6 address is always an error.
pub fn ipv6_unavailable(addr: SocketAddr, error: &io::Error) -> bool {
    addr.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) && is_eafnosupport(error)
}

#[cfg(unix)]
fn is_eafnosupport(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EAFNOSUPPORT)
}

#[cfg(not(unix))]
fn is_eafnosupport(_error: &io::Error) -> bool {
    false
}

/// Binds a UDP socket. IPv6 sockets are IPv6-only, so `0.0.0.0:53` and
/// `[::]:53` can be listened on side by side.
pub fn bind_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

/// Binds a TCP listener, IPv6-only for IPv6 addresses (see [`bind_udp`]).
pub fn bind_tcp(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::zone::Zone;

    fn handler() -> Handler {
        let config = Config::parse(include_str!("../config.example.toml")).unwrap();
        Handler::new(Zone::from_config(&config).unwrap())
    }

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    #[tokio::test]
    async fn a_listener_that_stops_ends_serving() {
        let mut udp = Server::new(handler());
        udp.register_socket(bind_udp(loopback()).unwrap());
        // A server with nothing left to serve has stopped, like one whose
        // listener failed.
        let stopped = Server::new(handler());
        let servers = vec![
            ("udp 127.0.0.1:53".to_string(), udp),
            ("tcp 127.0.0.1:53".to_string(), stopped),
        ];
        let error = supervise(servers, std::future::pending())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "tcp 127.0.0.1:53 stopped serving");
    }

    #[tokio::test]
    async fn shutdown_stops_every_listener() {
        let listeners = vec![
            Listener::Udp(bind_udp(loopback()).unwrap()),
            Listener::Tcp(bind_tcp(loopback()).unwrap()),
        ];
        let timeout = Duration::from_secs(1);
        serve_until(handler(), listeners, timeout, async {})
            .await
            .unwrap();
        assert!(
            serve_until(handler(), Vec::new(), timeout, async {})
                .await
                .is_err()
        );
    }

    #[test]
    fn only_the_ipv6_wildcard_may_be_skipped() {
        #[cfg(unix)]
        let unsupported = io::Error::from_raw_os_error(libc::EAFNOSUPPORT);
        #[cfg(not(unix))]
        let unsupported = io::Error::other("no IPv6");
        let other = io::Error::from(io::ErrorKind::AddrInUse);
        let any6: SocketAddr = "[::]:53".parse().unwrap();
        let one6: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let any4: SocketAddr = "0.0.0.0:53".parse().unwrap();

        assert_eq!(ipv6_unavailable(any6, &unsupported), cfg!(unix));
        assert!(!ipv6_unavailable(any6, &other));
        assert!(!ipv6_unavailable(one6, &unsupported));
        assert!(!ipv6_unavailable(any4, &unsupported));
    }
}
