use std::io::Result;
use std::net::Ipv4Addr;
use std::sync::Arc;

use crossbeam_utils::atomic::AtomicCell;

use crate::channel::context::Context;
use crate::handler::CurrentDeviceInfo;
use cipher::Cipher;
use icmp::IcmpProxy;
use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;
use tcp::TcpProxy;
use udp::UdpProxy;
use utils::{scheduler::Scheduler, work::Stoper};

pub mod icmp;
pub mod tcp;
pub mod udp;

pub trait ProxyHandler {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> Result<bool>;
    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> Result<()>;
}

#[derive(Clone)]
pub struct IpProxyMap {
    icmp_proxy: IcmpProxy,
    tcp_proxy: TcpProxy,
    udp_proxy: UdpProxy,
}

pub fn init_proxy(
    context: Context,
    scheduler: Scheduler,
    stop_manager: Stoper,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
) -> Result<IpProxyMap> {
    let icmp_proxy = IcmpProxy::new(context, stop_manager.clone(), current_device, client_cipher)?;
    let tcp_proxy = TcpProxy::new(stop_manager.clone())?;
    let udp_proxy = UdpProxy::new(scheduler, stop_manager)?;

    Ok(IpProxyMap {
        icmp_proxy,
        tcp_proxy,
        udp_proxy,
    })
}

impl ProxyHandler for IpProxyMap {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> Result<bool> {
        match ipv4.protocol() {
            ipv4::protocol::Protocol::Tcp => self.tcp_proxy.recv_handle(ipv4, source, destination),
            ipv4::protocol::Protocol::Udp => self.udp_proxy.recv_handle(ipv4, source, destination),
            ipv4::protocol::Protocol::Icmp => {
                self.icmp_proxy.recv_handle(ipv4, source, destination)
            }
            _ => {
                tracing::warn!(
                    "不支持的ip代理ipv4协议{:?}:{}->{}->{}",
                    ipv4.protocol(),
                    source,
                    destination,
                    ipv4.destination_ip()
                );
                Ok(false)
            }
        }
    }

    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> Result<()> {
        match ipv4.protocol() {
            ipv4::protocol::Protocol::Tcp => self.tcp_proxy.send_handle(ipv4),
            ipv4::protocol::Protocol::Udp => self.udp_proxy.send_handle(ipv4),
            ipv4::protocol::Protocol::Icmp => self.icmp_proxy.send_handle(ipv4),
            _ => Ok(()),
        }
    }
}
