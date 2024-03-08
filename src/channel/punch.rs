use mio::net::TcpStream;
use nat::stun::{NatInfo, NatType};
use rand::prelude::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::time::Duration;

use crate::channel::context::Context;
use crate::channel::sender::AcceptSocketSender;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Default, Serialize, Deserialize)]
pub enum PunchMode {
    IPv4,
    IPv6,
    #[default]
    All,
}

impl FromStr for PunchMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "ipv4" => Ok(PunchMode::IPv4),
            "ipv6" => Ok(PunchMode::IPv6),
            "all" => Ok(PunchMode::All),
            _ => Err(format!("not match '{}', enum: ipv4/ipv6/all", s)),
        }
    }
}

#[derive(Clone)]
pub struct Punch {
    context: Context,
    port_vec: Vec<u16>,
    port_index: HashMap<Ipv4Addr, usize>,
    punch_model: PunchMode,
    is_tcp: bool,
    tcp_socket_sender: AcceptSocketSender<(TcpStream, SocketAddr, Option<Vec<u8>>)>,
}

impl Punch {
    pub fn new(
        context: Context,
        punch_model: PunchMode,
        is_tcp: bool,
        tcp_socket_sender: AcceptSocketSender<(TcpStream, SocketAddr, Option<Vec<u8>>)>,
    ) -> Self {
        let mut port_vec: Vec<u16> = (1..65535).collect();
        port_vec.push(65535);
        let mut rng = rand::thread_rng();
        port_vec.shuffle(&mut rng);
        Punch {
            context,
            port_vec,
            port_index: HashMap::new(),
            punch_model,
            is_tcp,
            tcp_socket_sender,
        }
    }
}

impl Punch {
    fn connect_tcp(&self, buf: &[u8], addr: SocketAddr) -> bool {
        // mio是非阻塞的，不能立马判断是否能连接成功，所以用标准库的tcp
        match std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
            Ok(tcp_stream) => {
                if tcp_stream.set_nonblocking(true).is_err() {
                    return false;
                }
                return self
                    .tcp_socket_sender
                    .try_add_socket((TcpStream::from_std(tcp_stream), addr, Some(buf.to_vec())))
                    .is_ok();
            }
            Err(e) => {
                tracing::warn!("连接到tcp失败,addr={},err={}", addr, e);
            }
        }
        false
    }
    pub fn punch(&mut self, buf: &[u8], id: Ipv4Addr, nat_info: NatInfo) -> io::Result<()> {
        if !self.context.route_table.need_punch(&id) {
            return Ok(());
        }

        if self.is_tcp && nat_info.tcp_port != 0 {
            //向tcp发起连接
            if let Some(ipv6_addr) = nat_info.local_tcp_ipv6_addr() {
                if self.connect_tcp(buf, ipv6_addr) {
                    return Ok(());
                }
            }
            //向tcp发起连接
            if let Some(ipv4_addr) = nat_info.local_tcp_ipv4_addr() {
                if self.connect_tcp(buf, ipv4_addr) {
                    return Ok(());
                }
            }
            if nat_info.nat_type == NatType::Cone && nat_info.public_ips.len() == 1 {
                let addr =
                    SocketAddr::V4(SocketAddrV4::new(nat_info.public_ips[0], nat_info.tcp_port));
                if self.connect_tcp(buf, addr) {
                    return Ok(());
                }
            }
        }
        let channel_num = self.context.channel_num();
        for index in 0..channel_num {
            if let Some(ipv4_addr) = nat_info.local_udp_ipv4_addr(index) {
                let _ = self.context.send_main_udp(index, buf, ipv4_addr);
            }
        }

        if self.punch_model != PunchMode::IPv4 {
            for index in 0..channel_num {
                if let Some(ipv6_addr) = nat_info.local_udp_ipv6_addr(index) {
                    let rs = self.context.send_main_udp(index, buf, ipv6_addr);
                    tracing::info!("发送到ipv6地址:{:?},rs={:?}", ipv6_addr, rs);
                    if rs.is_ok() && self.punch_model == PunchMode::IPv6 {
                        return Ok(());
                    }
                }
            }
        }
        match nat_info.nat_type {
            NatType::Symmetric => {
                // 假设对方绑定n个端口，通过NAT对外映射出n个 公网ip:公网端口，自己随机尝试k次的情况下
                // 猜中的概率 p = 1-((65535-n)/65535)*((65535-n-1)/(65535-1))*...*((65535-n-k+1)/(65535-k+1))
                // n取76，k取600，猜中的概率就超过50%了
                // 前提 自己是锥形网络，否则猜中了也通信不了

                //预测范围内最多发送max_k1个包
                let max_k1 = 60;
                //全局最多发送max_k2个包
                let max_k2 = 800;
                let port = nat_info.public_ports.first().copied().unwrap_or(0);
                if nat_info.public_port_range < max_k1 * 3 {
                    //端口变化不大时，在预测的范围内随机发送
                    let min_port = if port > nat_info.public_port_range {
                        port - nat_info.public_port_range
                    } else {
                        1
                    };
                    let (max_port, overflow) = port.overflowing_add(nat_info.public_port_range);
                    let max_port = if overflow { 65535 } else { max_port };
                    let k = if max_port - min_port + 1 > max_k1 {
                        max_k1 as usize
                    } else {
                        (max_port - min_port + 1) as usize
                    };
                    let mut nums: Vec<u16> = (min_port..max_port).collect();
                    nums.push(max_port);
                    {
                        let mut rng = rand::thread_rng();
                        nums.shuffle(&mut rng);
                    }
                    self.punch_symmetric(&nums[..k], buf, &nat_info.public_ips, max_k1 as usize)?;
                }
                let start = *self.port_index.entry(id).or_insert(0);
                let mut end = start + max_k2;
                let mut index = end;
                if end >= self.port_vec.len() {
                    end = self.port_vec.len();
                    index = 0
                }
                self.punch_symmetric(
                    &self.port_vec[start..end],
                    buf,
                    &nat_info.public_ips,
                    max_k2,
                )?;
                self.port_index.insert(id, index);
            }
            NatType::Cone => {
                let is_cone = self.context.is_cone();
                for index in 0..channel_num {
                    let len = nat_info.public_ports.len();
                    for ip in &nat_info.public_ips {
                        let port = nat_info.public_ports[index % len];
                        if port == 0 || ip.is_unspecified() {
                            continue;
                        }
                        let addr = SocketAddr::V4(SocketAddrV4::new(*ip, port));
                        self.context.send_main_udp(index, buf, addr)?;
                        if !is_cone {
                            //只有一方是对称，则对称方要使用全部端口发送数据，符合上述计算的概率
                            self.context.try_send_all(buf, addr);
                        }
                    }
                    if !is_cone {
                        //对称网络数据只发一遍
                        break;
                    }
                }
            }
        }
        Ok(())
    }

    fn punch_symmetric(
        &self,
        ports: &[u16],
        buf: &[u8],
        ips: &Vec<Ipv4Addr>,
        max: usize,
    ) -> io::Result<()> {
        let mut count = 0;
        for port in ports {
            for pub_ip in ips {
                count += 1;
                if count == max {
                    return Ok(());
                }
                let addr = SocketAddr::V4(SocketAddrV4::new(*pub_ip, *port));
                self.context.send_main_udp(0, buf, addr)?;
            }
        }
        Ok(())
    }
}
