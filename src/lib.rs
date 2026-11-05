//! ipssl: wildcard DNS for any IP address (`10-0-0-1.ipssl.cc` -> `10.0.0.1`).

pub mod config;
pub mod handler;
pub mod http;
pub mod metrics;
pub mod parse;
pub mod ratelimit;
pub mod zone;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use hickory_server::Server;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};

use crate::handler::Handler;

/// How many responses may queue per TCP connection.
const TCP_RESPONSE_BUFFER: usize = 32;

/// Starts serving on already-bound sockets. Must be called inside a Tokio runtime.
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
