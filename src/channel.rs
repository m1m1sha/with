use serde::{Deserialize, Serialize};
use std::io::{self, Error, ErrorKind};
use std::net::{SocketAddr, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

use crate::channel::context::Context;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::sender::AcceptSocketSender;
use crate::channel::tcp_channel::tcp_listen;
use crate::channel::udp_channel::udp_listen;
use utils::work::Stoper;

pub mod context;
pub mod handler;
pub mod idle;
pub mod notify;
pub mod punch;
pub mod sender;
pub mod tcp_channel;
pub mod udp_channel;

const BUFFER_SIZE: usize = 1024 * 16;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelMode {
    Relay,
    P2p,
    #[default]
    All,
}
impl ChannelMode {
    pub fn is_only_relay(&self) -> bool {
        self == &ChannelMode::Relay
    }
    pub fn is_only_p2p(&self) -> bool {
        self == &ChannelMode::P2p
    }
    pub fn is_all(&self) -> bool {
        self == &ChannelMode::All
    }
}
impl FromStr for ChannelMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "relay" => Ok(ChannelMode::Relay),
            "p2p" => Ok(ChannelMode::P2p),
            "all" => Ok(ChannelMode::All),
            _ => Err(format!("not match '{}', enum: relay/p2p/all", s)),
        }
    }
}
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Status {
    Cone,
    Symmetric,
    Close,
}

#[derive(Copy, Clone, Debug)]
pub struct Route {
    pub is_tcp: bool,
    index: usize,
    pub addr: SocketAddr,
    pub metric: u8,
    pub rt: i64,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct RouteSortKey {
    pub metric: u8,
    pub rt: i64,
}
const DEFAULT_RT: i64 = 999;
impl Route {
    pub fn new(is_tcp: bool, index: usize, addr: SocketAddr, metric: u8, rt: i64) -> Self {
        Self {
            is_tcp,
            index,
            addr,
            metric,
            rt,
        }
    }
    pub fn from(route_key: RouteKey, metric: u8, rt: i64) -> Self {
        Self {
            is_tcp: route_key.is_tcp,
            index: route_key.index,
            addr: route_key.addr,
            metric,
            rt,
        }
    }
    pub fn from_default_rt(route_key: RouteKey, metric: u8) -> Self {
        Self {
            is_tcp: route_key.is_tcp,
            index: route_key.index,
            addr: route_key.addr,
            metric,
            rt: DEFAULT_RT,
        }
    }
    pub fn route_key(&self) -> RouteKey {
        RouteKey {
            is_tcp: self.is_tcp,
            index: self.index,
            addr: self.addr,
        }
    }
    pub fn sort_key(&self) -> RouteSortKey {
        RouteSortKey {
            metric: self.metric,
            rt: self.rt,
        }
    }
    pub fn is_p2p(&self) -> bool {
        self.metric == 1
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct RouteKey {
    is_tcp: bool,
    index: usize,
    pub addr: SocketAddr,
}

impl RouteKey {
    pub(crate) fn new(is_tcp: bool, index: usize, addr: SocketAddr) -> Self {
        Self {
            is_tcp,
            index,
            addr,
        }
    }
    pub fn is_tcp(&self) -> bool {
        self.is_tcp
    }
    pub fn index(&self) -> usize {
        self.index
    }
}

pub fn init_context(
    ports: Vec<u16>,
    channel: ChannelMode,
    first_latency: bool,
    is_tcp: bool,
    packet_loss_rate: Option<f64>,
    packet_delay: u32,
) -> io::Result<(Context, mio::net::TcpListener)> {
    assert!(!ports.is_empty(), "not channel");
    let mut udps = Vec::with_capacity(ports.len());
    for port in &ports {
        //监听v6+v4双栈，主通道使用同步io
        let address: SocketAddr = format!("[::]:{}", port).parse().unwrap();
        let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None)?;

        if let Err(_) = socket.set_only_v6(false) {
            return Err(Error::new(
                ErrorKind::Other,
                format!("set_only_v6 failed: {}", &address),
            ));
        }

        if let Err(_) = socket.bind(&address.into()) {
            return Err(Error::new(
                ErrorKind::Other,
                format!("bind failed: {}", &address),
            ));
        }

        let main_channel: UdpSocket = socket.into();
        main_channel.set_write_timeout(Some(Duration::from_secs(5)))?;
        udps.push(main_channel);
    }
    let context = Context::new(
        udps,
        channel,
        first_latency,
        is_tcp,
        packet_loss_rate,
        packet_delay,
    );

    let port = context.main_local_udp_port()?[0];
    //监听v6+v4双栈，tcp通道使用异步io
    let address: SocketAddr = format!("[::]:{}", port).parse().unwrap();
    let socket = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::STREAM, None)?;

    if let Err(_) = socket.set_only_v6(false) {
        return Err(Error::new(
            ErrorKind::Other,
            format!("set_only_v6 failed: {}", &address),
        ));
    }

    if let Err(_) = socket.bind(&address.into()) {
        if ports[0] == 0 {
            //端口可能冲突，则使用任意端口
            tracing::warn!("监听tcp端口失败 {:?},重试一次", address);
            let address: SocketAddr = format!("[::]:{}", 0).parse().unwrap();

            if let Err(_) = socket.bind(&address.into()) {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("bind failed: {}", &address),
                ));
            }
        } else {
            //手动指定的ip,直接报错
            return Err(Error::new(
                ErrorKind::Other,
                format!("bind failed: {}", &address),
            ));
        }
    }
    socket.listen(2)?;
    socket.set_nonblocking(true)?;
    socket.set_nodelay(false)?;
    let tcp_listener = mio::net::TcpListener::from_std(socket.into());
    Ok((context, tcp_listener))
}

pub fn init_channel<H>(
    tcp_listener: mio::net::TcpListener,
    context: Context,
    stop_manager: Stoper,
    recv_handler: H,
) -> io::Result<(
    AcceptSocketSender<Option<Vec<mio::net::UdpSocket>>>,
    AcceptSocketSender<(mio::net::TcpStream, SocketAddr, Option<Vec<u8>>)>,
)>
where
    H: RecvChannelHandler,
{
    // udp监听，udp_socket_sender 用于NAT类型切换
    let udp_socket_sender =
        udp_listen(stop_manager.clone(), recv_handler.clone(), context.clone())?;
    // 建立tcp监听，tcp_socket_sender 用于tcp 直连
    let tcp_socket_sender = tcp_listen(
        tcp_listener,
        stop_manager.clone(),
        recv_handler.clone(),
        context.clone(),
    )?;

    Ok((udp_socket_sender, tcp_socket_sender))
}
