use std::{
    io::Result,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;

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
