use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;
use parking_lot::{Mutex, RwLock};

use nat::tun::Device;

use crate::channel::context::Context;
use crate::channel::handler::RecvChannelHandler;
use crate::channel::RouteKey;

use crate::external::{AllowRoute, Route};
use crate::handler::callback::Callback;
use crate::handler::recv::client::ClientPacketHandler;
use crate::handler::recv::server::ServerPacketHandler;
use crate::handler::recv::turn::TurnPacketHandler;
use crate::handler::{BaseConfigInfo, CurrentDeviceInfo, PeerDeviceInfo, SELF_IP};
use cipher::Cipher;
use cipher::RsaCipher;

use crate::proxy::IpProxyMap;
use nat::stun::{NatInfo, NatTest};
use protocol::NetPacket;
use utils::adder::U64Adder;

mod client;
mod server;
mod turn;

#[derive(Clone)]
pub struct RecvDataHandler<Call> {
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    turn: TurnPacketHandler,
    client: ClientPacketHandler,
    server: ServerPacketHandler<Call>,
    counter: U64Adder,
}

impl<Call: Callback> RecvChannelHandler for RecvDataHandler<Call> {
    fn handle(&mut self, buf: &mut [u8], route_key: RouteKey, context: &Context) {
        if let Err(e) = self.handle0(buf, route_key, context) {
            tracing::error!("[{}]-{:?}", thread::current().name().unwrap_or(""), e);
        }
    }
}

impl<Call: Callback> RecvDataHandler<Call> {
    pub fn new(
        rsa_cipher: Arc<Mutex<Option<RsaCipher>>>,
        server_cipher: Cipher,
        client_cipher: Cipher,
        current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
        device: Arc<Device>,
        device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
        config_info: BaseConfigInfo,
        nat_test: NatTest,
        call: Call,
        punch_sender: SyncSender<(Ipv4Addr, NatInfo)>,
        peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>>,
        external_route: Route,
        route: AllowRoute,
        ip_proxy_map: Option<IpProxyMap>,
        counter: U64Adder,
    ) -> Self {
        let server = ServerPacketHandler::new(
            rsa_cipher,
            server_cipher,
            current_device.clone(),
            device.clone(),
            device_list,
            config_info,
            nat_test.clone(),
            call,
            external_route,
        );
        let client = ClientPacketHandler::new(
            device.clone(),
            client_cipher,
            punch_sender,
            peer_nat_info_map,
            nat_test,
            route,
            ip_proxy_map,
        );
        let turn = TurnPacketHandler::new();
        Self {
            current_device,
            turn,
            client,
            server,
            counter,
        }
    }
    fn handle0(
        &mut self,
        buf: &mut [u8],
        route_key: RouteKey,
        context: &Context,
    ) -> io::Result<()> {
        // 统计流量
        self.counter.add(buf.len() as _);
        let net_packet = NetPacket::new(buf)?;
        if net_packet.ttl() == 0 || net_packet.source_ttl() < net_packet.ttl() {
            return Ok(());
        }
        let current_device = self.current_device.load();
        let dest = net_packet.destination();
        if dest == current_device.virtual_ip
            || dest.is_broadcast()
            || dest.is_multicast()
            || dest == SELF_IP
            || dest.is_unspecified()
            || dest == current_device.broadcast_ip
        {
            //发给自己的包
            if net_packet.is_gateway() {
                //服务端-客户端包
                self.server
                    .handle(net_packet, route_key, context, &current_device)
            } else {
                //客户端-客户端包
                self.client
                    .handle(net_packet, route_key, context, &current_device)
            }
        } else {
            //转发包
            self.turn
                .handle(net_packet, route_key, context, &current_device)
        }
    }
}

pub trait PacketHandler {
    fn handle(
        &self,
        net_packet: NetPacket<&mut [u8]>,
        route_key: RouteKey,
        context: &Context,
        current_device: &CurrentDeviceInfo,
    ) -> io::Result<()>;
}
