use std::io;
use std::net::Ipv4Addr;

use crate::channel::context::Context;
use packet::ip::ipv4::packet::IpV4Packet;
use packet::ip::ipv4::protocol::Protocol;

use crate::external::Route;
use crate::handler::{check_dest, CurrentDeviceInfo};
use cipher::Cipher;

use crate::proxy::{IpProxyMap, ProxyHandler};
use protocol::body::ENCRYPTION_RESERVED;
use protocol::turn::ip::BroadcastPacket;
use protocol::{turn, NetPacket, Version, MAX_TTL};

use std::sync::Arc;
use std::thread;

use crossbeam_utils::atomic::AtomicCell;

use nat::tun::device::IFace;
use nat::tun::Device;
use packet::icmp::IcmpPacket;
use packet::icmp::Kind;
use packet::ip::ipv4;

use crate::handler::tun::channel_group::{channel_group, GroupSyncSender};

use utils::{adder::SingleU64Adder, work::Stoper};

mod channel_group;

fn broadcast(
    server_cipher: &Cipher,
    sender: &Context,
    net_packet: &mut NetPacket<&mut [u8]>,
    current_device: &CurrentDeviceInfo,
) -> io::Result<()> {
    let mut peer_ips = Vec::with_capacity(8);
    let vec = sender.route_table.route_table_one();
    let mut relay_count = 0;
    const MAX_COUNT: usize = 8;
    for (peer_ip, route) in vec {
        if peer_ip == current_device.virtual_gateway {
            continue;
        }
        if peer_ips.len() == MAX_COUNT {
            break;
        }
        if route.is_p2p()
            && sender
                .send_by_key(net_packet.buffer(), route.route_key())
                .is_ok()
        {
            peer_ips.push(peer_ip);
        } else {
            relay_count += 1;
        }
    }
    if relay_count == 0 && !peer_ips.is_empty() && peer_ips.len() != MAX_COUNT {
        //不需要转发
        return Ok(());
    }
    //转发到服务端的可选择广播，还要进行服务端加密
    if peer_ips.is_empty() {
        sender.send_default(net_packet.buffer(), current_device.connect_server)?;
    } else {
        let buf =
            vec![0u8; 12 + 1 + peer_ips.len() * 4 + net_packet.data_len() + ENCRYPTION_RESERVED];
        //剩余的发送到服务端，需要告知哪些已发送过
        let mut server_packet = NetPacket::new_encrypt(buf)?;
        server_packet.set_version(Version::V1);
        server_packet.set_gateway_flag(true);
        server_packet.first_set_ttl(MAX_TTL);
        server_packet.set_source(net_packet.source());
        //使用对应的目的地址
        server_packet.set_destination(net_packet.destination());
        server_packet.set_protocol(protocol::Protocol::IpTurn);
        server_packet.set_transport_protocol(turn::ip::Protocol::Ipv4Broadcast.into());

        let mut broadcast = BroadcastPacket::unchecked(server_packet.payload_mut());
        broadcast.set_address(&peer_ips)?;
        broadcast.set_data(net_packet.buffer())?;
        server_cipher.encrypt_ipv4(&mut server_packet)?;
        sender.send_default(server_packet.buffer(), current_device.connect_server)?;
    }
    Ok(())
}

/// 实现一个原地发送，必须保证是如下结构
/// |12字节开头|ip报文|至少1024字节结尾|
///
#[inline]
pub fn base_handle(
    context: &Context,
    buf: &mut [u8],
    data_len: usize, //数据总长度=12+ip包长度
    current_device: CurrentDeviceInfo,
    ip_route: &Route,
    proxy_map: &Option<IpProxyMap>,
    client_cipher: &Cipher,
    server_cipher: &Cipher,
) -> io::Result<()> {
    let ipv4_packet = IpV4Packet::new(&buf[12..data_len])?;
    let protocol = ipv4_packet.protocol();
    let src_ip = ipv4_packet.source_ip();
    let mut dest_ip = ipv4_packet.destination_ip();
    let mut net_packet = NetPacket::new0(data_len, buf)?;
    net_packet.set_version(Version::V1);
    net_packet.set_protocol(protocol::Protocol::IpTurn);
    net_packet.set_transport_protocol(turn::ip::Protocol::Ipv4.into());
    net_packet.first_set_ttl(3);
    net_packet.set_source(src_ip);
    net_packet.set_destination(dest_ip);
    if dest_ip == current_device.virtual_gateway {
        if protocol == Protocol::Icmp {
            net_packet.set_gateway_flag(true);
            server_cipher.encrypt_ipv4(&mut net_packet)?;
            context.send_default(net_packet.buffer(), current_device.connect_server)?;
        }
        return Ok(());
    }
    if dest_ip.is_multicast() {
        // 当作广播处理
        dest_ip = Ipv4Addr::BROADCAST;
        net_packet.set_destination(Ipv4Addr::BROADCAST);
    }
    if dest_ip.is_broadcast() || current_device.broadcast_ip == dest_ip {
        // 广播 发送到直连目标
        client_cipher.encrypt_ipv4(&mut net_packet)?;
        broadcast(server_cipher, context, &mut net_packet, &current_device)?;
        return Ok(());
    }
    if !check_dest(
        dest_ip,
        current_device.virtual_netmask,
        current_device.virtual_network,
    ) {
        if let Some(r_dest_ip) = ip_route.route(&dest_ip) {
            //路由的目标不能是自己
            if r_dest_ip == src_ip {
                return Ok(());
            }
            //需要修改目的地址
            dest_ip = r_dest_ip;
            net_packet.set_destination(r_dest_ip);
        } else {
            return Ok(());
        }
    }

    if let Some(proxy_map) = proxy_map {
        let mut ipv4_packet = IpV4Packet::new(net_packet.payload_mut())?;
        proxy_map.send_handle(&mut ipv4_packet)?;
    }
    client_cipher.encrypt_ipv4(&mut net_packet)?;
    context.send_ipv4_by_id(net_packet.buffer(), &dest_ip, current_device.connect_server)
}

fn icmp(device_writer: &Arc<Device>, mut ipv4_packet: IpV4Packet<&mut [u8]>) -> io::Result<()> {
    if ipv4_packet.protocol() == ipv4::protocol::Protocol::Icmp {
        let mut icmp = IcmpPacket::new(ipv4_packet.payload_mut())?;
        if icmp.kind() == Kind::EchoRequest {
            icmp.set_kind(Kind::EchoReply);
            icmp.update_checksum();
            let src = ipv4_packet.source_ip();
            ipv4_packet.set_source_ip(ipv4_packet.destination_ip());
            ipv4_packet.set_destination_ip(src);
            ipv4_packet.update_checksum();
            device_writer.write(ipv4_packet.buffer)?;
        }
    }
    Ok(())
}

/// 接收tun数据，并且转发到udp上
fn handle(
    context: &Context,
    data: &mut [u8],
    len: usize,
    device_writer: &Arc<Device>,
    current_device: CurrentDeviceInfo,
    ip_route: &Route,
    proxy_map: &Option<IpProxyMap>,
    client_cipher: &Cipher,
    server_cipher: &Cipher,
) -> io::Result<()> {
    //忽略掉结构不对的情况（ipv6数据、win tap会读到空数据），不然日志打印太多了
    let ipv4_packet = match IpV4Packet::new(&mut data[12..len]) {
        Ok(packet) => packet,
        Err(_) => return Ok(()),
    };
    let src_ip = ipv4_packet.source_ip();
    let dest_ip = ipv4_packet.destination_ip();
    if src_ip == dest_ip {
        return icmp(device_writer, ipv4_packet);
    }
    return crate::handler::tun::base_handle(
        context,
        data,
        len,
        current_device,
        ip_route,
        proxy_map,
        client_cipher,
        server_cipher,
    );
}

pub fn start(
    stoper: Stoper,
    context: Context,
    device: Arc<Device>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: Route,
    ip_proxy_map: Option<IpProxyMap>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    parallel: usize,
    mut up_counter: SingleU64Adder,
) -> io::Result<()> {
    let worker = {
        let device = device.clone();
        stoper.add_listener("tun_device".into(), move || {
            if let Err(e) = device.shutdown() {
                tracing::warn!("{:?}", e);
            }
        })?
    };
    if parallel > 1 {
        let (sender, receivers) = channel_group::<(Vec<u8>, usize)>(parallel, 16);
        for (index, receiver) in receivers.into_iter().enumerate() {
            let context = context.clone();
            let device = device.clone();
            let current_device = current_device.clone();
            let ip_route = ip_route.clone();

            let ip_proxy_map = ip_proxy_map.clone();
            let client_cipher = client_cipher.clone();
            let server_cipher = server_cipher.clone();
            thread::Builder::new()
                .name(format!("tun_handler_{}", index))
                .spawn(move || {
                    while let Ok((mut buf, len)) = receiver.recv() {
                        #[cfg(not(target_os = "macos"))]
                        let start = 0;
                        #[cfg(target_os = "macos")]
                        let start = 4;
                        match handle(
                            &context,
                            &mut buf[start..],
                            len,
                            &device,
                            current_device.load(),
                            &ip_route,
                            &ip_proxy_map,
                            &client_cipher,
                            &server_cipher,
                        ) {
                            Ok(_) => {}
                            Err(e) => {
                                tracing::warn!("{:?}", e)
                            }
                        }
                    }
                })?;
        }
        thread::Builder::new()
            .name("tun_handler".into())
            .spawn(move || {
                if let Err(e) = start_multi(stoper, device, sender, &mut up_counter) {
                    tracing::warn!("stop:{}", e);
                }
                worker.stop_all();
            })?;
    } else {
        thread::Builder::new()
            .name("tun_handler".into())
            .spawn(move || {
                if let Err(e) = start_simple(
                    stoper,
                    &context,
                    device,
                    current_device,
                    ip_route,
                    ip_proxy_map,
                    client_cipher,
                    server_cipher,
                    &mut up_counter,
                ) {
                    tracing::warn!("stop:{}", e);
                }
                worker.stop_all();
            })?;
    }
    Ok(())
}

fn start_simple(
    stoper: Stoper,
    context: &Context,
    device: Arc<Device>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    ip_route: Route,
    ip_proxy_map: Option<IpProxyMap>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    up_counter: &mut SingleU64Adder,
) -> io::Result<()> {
    let mut buf = [0; 1024 * 16];
    loop {
        if stoper.is_stop() {
            return Ok(());
        }
        let len = device.read(&mut buf[12..])? + 12;
        //单线程的
        up_counter.add(len as u64);
        #[cfg(any(target_os = "macos"))]
        let mut buf = &mut buf[4..];
        // buf是重复利用的，需要重置头部
        buf[..12].fill(0);
        match handle(
            context,
            &mut buf,
            len,
            &device,
            current_device.load(),
            &ip_route,
            &ip_proxy_map,
            &client_cipher,
            &server_cipher,
        ) {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("{:?}", e)
            }
        }
    }
}

fn start_multi(
    stoper: Stoper,
    device: Arc<Device>,
    mut group_sync_sender: GroupSyncSender<(Vec<u8>, usize)>,
    up_counter: &mut SingleU64Adder,
) -> io::Result<()> {
    loop {
        if stoper.is_stop() {
            return Ok(());
        }
        let mut buf = vec![0; 1024 * 16];
        let len = device.read(&mut buf[12..])? + 12;
        //单线程的
        up_counter.add(len as u64);
        if group_sync_sender.send((buf, len)).is_err() {
            return Ok(());
        }
    }
}
