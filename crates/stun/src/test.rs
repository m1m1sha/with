use std::{
    collections::HashSet,
    io::{Error, ErrorKind, Result},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use tokio::{net::UdpSocket, time};

use super::NatType;

pub async fn nat(stuns: Vec<String>) -> Result<(NatType, Vec<Ipv4Addr>, u16)> {
    let mut handles = Vec::new();

    for stun in stuns {
        let handle = tokio::spawn(async move { test_nat(stun).await });
        handles.push(handle);
    }

    let mut nat_type = NatType::Cone;
    let mut port_range = 0;
    let mut hash_set = HashSet::new();
    for handle in handles {
        if let Ok(rs) = handle.await {
            if let Ok((nat_type_t, ip_list_t, port_range_t)) = rs {
                if nat_type_t == NatType::Symmetric {
                    nat_type = NatType::Symmetric;
                }
                for x in ip_list_t {
                    hash_set.insert(x);
                }
                if port_range < port_range_t {
                    port_range = port_range_t;
                }
            }
        }
    }
    Ok((nat_type, hash_set.into_iter().collect(), port_range))
}

async fn test_nat(stun: String) -> Result<(NatType, Vec<Ipv4Addr>, u16)> {
    let udp = UdpSocket::bind("0.0.0.0:0").await?;

    udp.connect(stun).await?;
    let mut port_range = 0;
    let mut hash_set = HashSet::new();
    let mut nat_type = NatType::Cone;

    let _ = time::timeout(Duration::from_millis(300), async {
        match test(&udp, true, true).await {
            Ok((mapped_addr1, changed_addr1)) => {
                match mapped_addr1.ip() {
                    IpAddr::V4(ip) => {
                        hash_set.insert(ip);
                    }
                    IpAddr::V6(_) => {}
                }
                if udp.connect(changed_addr1).await.is_ok() {
                    if let Ok((mapped_addr2, _)) = test(&udp, false, false).await {
                        match mapped_addr2.ip() {
                            IpAddr::V4(ip) => {
                                hash_set.insert(ip);
                                if mapped_addr1 != mapped_addr2 {
                                    nat_type = NatType::Symmetric;
                                }
                            }
                            IpAddr::V6(_) => {}
                        }
                        port_range = mapped_addr2.port().abs_diff(mapped_addr1.port());
                    }
                }
            }
            Err(_) => {}
        }
    })
    .await;

    Ok((nat_type, hash_set.into_iter().collect(), port_range))
}

async fn test(
    udp: &UdpSocket,
    change_ip: bool,
    change_port: bool,
) -> Result<(SocketAddr, SocketAddr)> {
    for _ in 0..2 {
        let mut buf = [0u8; 28];
        let mut msg = stun_format::MsgBuilder::from(buf.as_mut_slice());
        msg.typ(stun_format::MsgType::BindingRequest).unwrap();
        msg.tid(1).unwrap();
        msg.add_attr(stun_format::Attr::ChangeRequest {
            change_ip,
            change_port,
        })
        .unwrap();

        udp.send(msg.as_bytes()).await?;
        let mut buf = [0; 10240];
        let (len, _addr) = match udp.recv_from(&mut buf).await {
            Ok(rs) => rs,
            Err(_) => {
                continue;
            }
        };
        let msg = stun_format::Msg::from(&buf[..len]);
        let mut mapped_addr = None;
        let mut changed_addr = None;
        for x in msg.attrs_iter() {
            match x {
                stun_format::Attr::MappedAddress(addr) => {
                    if mapped_addr.is_none() {
                        let _ = mapped_addr.insert(stun_addr(addr));
                    }
                }
                stun_format::Attr::ChangedAddress(addr) => {
                    if changed_addr.is_none() {
                        let _ = changed_addr.insert(stun_addr(addr));
                    }
                }
                stun_format::Attr::XorMappedAddress(addr) => {
                    if mapped_addr.is_none() {
                        let _ = mapped_addr.insert(stun_addr(addr));
                    }
                }
                _ => {}
            }
            if changed_addr.is_some() && mapped_addr.is_some() {
                return Ok((mapped_addr.unwrap(), changed_addr.unwrap()));
            }
        }
        if let Some(addr) = mapped_addr {
            return Ok((addr, changed_addr.unwrap_or(addr)));
        }
    }
    Err(Error::new(ErrorKind::Other, "stun response err"))
}

fn stun_addr(addr: stun_format::SocketAddr) -> SocketAddr {
    match addr {
        stun_format::SocketAddr::V4(ip, port) => {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
        }
        stun_format::SocketAddr::V6(ip, port) => {
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0))
        }
    }
}

#[cfg(test)]
mod tests {
    // 注意这个惯用法：在 tests 模块中，从外部作用域导入所有名字。
    use super::*;

    #[test]
    fn test_nat() {
        tokio_test::block_on(async {
            let (nat_type, public_ips, port_range) = nat(vec![
                "stun1.l.google.com:19302".to_string(),
                "stun2.l.google.com:19302".to_string(),
                "stun.miwifi.com:3478".to_string(),
                "stun.qq.com:3478".to_string(),
            ])
            .await
            .unwrap();

            println!("NatType: {:?}", nat_type);
            println!("Ip: {:?}", public_ips);
            println!("u16: {}", port_range);
        })
    }
}
