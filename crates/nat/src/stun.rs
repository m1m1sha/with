use std::{
    io::Result,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    ops::Sub,
    sync::Arc,
    time::{Duration, Instant},
};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

pub mod test;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
pub enum NatType {
    Symmetric,
    Cone,
}

async fn local_ipv4() -> Option<Ipv4Addr> {
    match ipv4().await {
        Ok(ipv4) => Some(ipv4),
        Err(e) => {
            tracing::warn!("获取ipv4失败：{:?}", e);
            None
        }
    }
}

pub async fn ipv4() -> Result<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("8.8.8.8:80").await?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Ok(Ipv4Addr::UNSPECIFIED),
    }
}

async fn local_ipv6() -> Option<Ipv6Addr> {
    match ipv6().await {
        Ok(ipv6) => Some(ipv6),
        Err(e) => {
            tracing::warn!("获取ipv6失败：{:?}", e);
            None
        }
    }
}

pub async fn ipv6() -> Result<Ipv6Addr> {
    let socket = UdpSocket::bind("[::]:0").await?;
    socket
        .connect("[2001:4860:4860:0000:0000:0000:0000:8888]:80")
        .await?;
    let addr = socket.local_addr()?;
    match addr.ip() {
        IpAddr::V4(_) => Ok(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(ip) => Ok(ip),
    }
}

#[derive(Clone, Debug)]
pub struct NatInfo {
    pub public_ips: Vec<Ipv4Addr>,
    pub public_ports: Vec<u16>,
    pub public_port_range: u16,
    pub nat_type: NatType,
    pub(crate) local_ipv4: Option<Ipv4Addr>,
    pub(crate) ipv6: Option<Ipv6Addr>,
    pub(crate) udp_ports: Vec<u16>,
    pub tcp_port: u16,
}

impl NatInfo {
    pub fn new(
        mut public_ips: Vec<Ipv4Addr>,
        public_ports: Vec<u16>,
        public_port_range: u16,
        mut local_ipv4: Option<Ipv4Addr>,
        mut ipv6: Option<Ipv6Addr>,
        udp_ports: Vec<u16>,
        tcp_port: u16,
        mut nat_type: NatType,
    ) -> Self {
        public_ips.retain(|ip| {
            !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_private()
        });

        if public_ips.len() > 1 {
            nat_type = NatType::Symmetric;
        }

        if let Some(ip) = local_ipv4 {
            if ip.is_multicast() || ip.is_broadcast() || ip.is_unspecified() || ip.is_loopback() {
                local_ipv4 = None
            }
        }

        if let Some(ip) = ipv6 {
            if ip.is_multicast() || ip.is_unspecified() || ip.is_loopback() {
                ipv6 = None
            }
        }

        Self {
            public_ips,
            public_ports,
            public_port_range,
            local_ipv4,
            ipv6,
            udp_ports,
            tcp_port,
            nat_type,
        }
    }

    pub fn update_addr(&mut self, index: usize, ip: Ipv4Addr, port: u16) {
        if !ip.is_multicast()
            && !ip.is_broadcast()
            && !ip.is_unspecified()
            && !ip.is_loopback()
            && !ip.is_private()
            && port != 0
        {
            if let Some(public_port) = self.public_ports.get_mut(index) {
                *public_port = port;
            }

            if !self.public_ips.contains(&ip) {
                self.public_ips.push(ip);
            }
        }
    }

    pub fn local_ipv4(&self) -> Option<Ipv4Addr> {
        self.local_ipv4
    }

    pub fn ipv6(&self) -> Option<Ipv6Addr> {
        self.ipv6
    }

    pub fn local_udp_ipv4_addr(&self, index: usize) -> Option<SocketAddr> {
        let len = self.udp_ports.len();
        if len == 0 {
            return None;
        }

        if let Some(local_ipv4) = self.local_ipv4 {
            Some(SocketAddr::V4(SocketAddrV4::new(
                local_ipv4,
                self.udp_ports[index % len],
            )))
        } else {
            None
        }
    }

    pub fn local_udp_ipv6_addr(&self, index: usize) -> Option<SocketAddr> {
        let len = self.udp_ports.len();
        if len == 0 {
            return None;
        }

        if let Some(ipv6) = self.ipv6 {
            Some(SocketAddr::V6(SocketAddrV6::new(
                ipv6,
                self.udp_ports[index % len],
                0,
                0,
            )))
        } else {
            None
        }
    }

    pub fn local_tcp_ipv6_addr(&self) -> Option<SocketAddr> {
        if self.tcp_port == 0 {
            return None;
        }

        if let Some(ipv6) = self.ipv6 {
            Some(SocketAddr::V6(SocketAddrV6::new(ipv6, self.tcp_port, 0, 0)))
        } else {
            None
        }
    }

    pub fn local_tcp_ipv4_addr(&self) -> Option<SocketAddr> {
        if self.tcp_port == 0 {
            return None;
        }

        if let Some(ipv4) = self.local_ipv4 {
            Some(SocketAddr::V4(SocketAddrV4::new(ipv4, self.tcp_port)))
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct NatTest {
    stuns: Vec<String>,
    info: Arc<Mutex<NatInfo>>,
    time: Arc<AtomicCell<Instant>>,
}

impl NatTest {
    pub fn new(
        channel_num: usize,
        mut stuns: Vec<String>,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        udp_ports: Vec<u16>,
        tcp_port: u16,
    ) -> NatTest {
        let server = stuns[0].clone();
        stuns.resize(4, server);
        let mut ports = udp_ports.clone();
        ports.resize(channel_num, 0);
        let nat_info = NatInfo::new(
            Vec::new(),
            ports,
            0,
            ipv4,
            ipv6,
            udp_ports,
            tcp_port,
            NatType::Cone,
        );
        let info = Arc::new(Mutex::new(nat_info));
        NatTest {
            stuns,
            info,
            time: Arc::new(AtomicCell::new(
                Instant::now().sub(Duration::from_secs(100)),
            )),
        }
    }

    pub fn can_update(&self) -> bool {
        let last = self.time.load();
        last.elapsed() > Duration::from_secs(10)
            && self.time.compare_exchange(last, Instant::now()).is_ok()
    }

    pub fn nat_info(&self) -> NatInfo {
        self.info.lock().clone()
    }

    pub fn update_addr(&self, index: usize, ip: Ipv4Addr, port: u16) {
        let mut guard = self.info.lock();
        guard.update_addr(index, ip, port)
    }

    pub async fn re_test(&self, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) -> Result<NatInfo> {
        let (nat_type, public_ips, port_range) = test::nat(self.stuns.clone()).await?;
        let mut guard = self.info.lock();
        guard.nat_type = nat_type;
        guard.public_ips = public_ips;
        guard.public_port_range = port_range;
        guard.local_ipv4 = ipv4;
        guard.ipv6 = ipv6;

        Ok(guard.clone())
    }
}
