use cipher::{Cipher, RsaCipher};
use crossbeam_utils::atomic::AtomicCell;
use nat::{
    stun::{NatInfo, NatTest},
    tun::device::IFace,
};
use parking_lot::{Mutex, RwLock};
use rand::Rng;
use std::{collections::HashMap, io::Result, net::Ipv4Addr, sync::Arc, time::Duration};
use utils::{
    adder::{SingleU64Adder, U64Adder, WatchSingleU64Adder, WatchU64Adder},
    scheduler::Scheduler,
    work::Stoper,
};

use crate::{
    channel::{
        self, context::Context, idle::Idle, init_channel, init_context, punch::Punch, RouteKey,
    },
    config::Config,
    external,
    handler::{
        self,
        callback::Callback,
        maintain::{self, PunchReceiver},
        recv::RecvDataHandler,
        BaseConfigInfo, ConnectStatus, CurrentDeviceInfo, PeerDeviceInfo,
    },
    proxy,
};

#[derive(Clone)]
pub struct With {
    stoper: Stoper,
    config: Config,
    rsa_cipher: Arc<Mutex<Option<RsaCipher>>>,
    server_cipher: Cipher,
    client_cipher: Cipher,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    nat_test: NatTest,
    context: Context,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>>,
    down_count_watcher: WatchU64Adder,
    up_count_watcher: WatchSingleU64Adder,
}

impl With {
    pub async fn new<Call: Callback>(call: Call, config: Config) -> Result<Self> {
        // 服务端非对称加密
        let rsa_cipher: Arc<Mutex<Option<RsaCipher>>> = Arc::new(Mutex::new(None));
        // 服务端对称加密
        let server_cipher: Cipher = if config.server_encrypt {
            let mut key = [0u8; 32];
            rand::thread_rng().fill(&mut key);
            Cipher::new_key(key, config.token.clone())?
        } else {
            Cipher::None
        };

        let finger = if config.finger {
            Some(config.token.clone())
        } else {
            None
        };

        // 客户端对称加密
        let client_cipher =
            Cipher::new_password(config.cipher, config.passwd.clone(), finger.clone());
        // 当前设备信息
        let current_device = Arc::new(AtomicCell::new(CurrentDeviceInfo::new0(config.server)));

        let stoper = {
            let call = call.clone();
            Stoper::new(move || call.stop())
        };

        // 设备列表
        let device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>> =
            Arc::new(Mutex::new((0, Vec::with_capacity(16))));

        // 基础信息
        let config_info = BaseConfigInfo::new(
            config.name.clone(),
            config.token.clone(),
            config.ip,
            config.passwd.clone().is_some(),
            config.udi.clone(),
            config.server.to_string().clone(),
        );

        // 端口
        let ports = config.ports.as_ref().map_or(vec![0, 0], |v| {
            if v.is_empty() {
                vec![0, 0]
            } else {
                v.clone()
            }
        });

        // 通道上下文
        let (context, tcp_listener) = init_context(
            ports,
            config.channel,
            config.latency,
            config.tcp,
            config.packet_loss_rate,
            config.packet_delay,
        )?;

        let local_ipv4 = nat::stun::local_ipv4().await;
        let local_ipv6 = nat::stun::local_ipv6().await;
        let udp_ports = context.main_local_udp_port()?;
        let tcp_port = tcp_listener.local_addr()?.port();

        // nat检测工具
        let nat_test = NatTest::new(
            context.channel_num(),
            config.stuns.clone(),
            local_ipv4,
            local_ipv6,
            udp_ports,
            tcp_port,
        );

        // 虚拟网卡
        let device = crate::tun::create_device(&config)?;
        let tun_info = handler::callback::DeviceInfo::new(device.name()?, device.version()?);
        call.clone().create_tun(tun_info);
        // 定时器
        let scheduler = Scheduler::new(stoper.clone())?;
        let inbound_route = external::Route::new(config.inbound.clone());
        let outbound_route = external::AllowRoute::new(config.outbound.clone());

        // 内置代理
        let proxy_map = match !config.inbound.is_empty() && config.proxy {
            true => Some(proxy::init_proxy(
                context.clone(),
                scheduler.clone(),
                stoper.clone(),
                current_device.clone(),
                client_cipher.clone(),
            )?),
            false => None,
        };

        let (punch_sender, punch_receiver) = maintain::punch_channel();
        let peer_nat_info_map: Arc<RwLock<HashMap<Ipv4Addr, NatInfo>>> =
            Arc::new(RwLock::new(HashMap::with_capacity(16)));
        let down_counter =
            U64Adder::with_capacity(config.ports.as_ref().map(|v| v.len()).unwrap_or_default() + 8);
        let down_count_watcher = down_counter.watch();
        let handler = RecvDataHandler::new(
            rsa_cipher.clone(),
            server_cipher.clone(),
            client_cipher.clone(),
            current_device.clone(),
            device.clone(),
            device_list.clone(),
            config_info.clone(),
            nat_test.clone(),
            call.clone(),
            punch_sender,
            peer_nat_info_map.clone(),
            inbound_route.clone(),
            outbound_route,
            proxy_map.clone(),
            down_counter,
        );

        // 初始化网络数据通道
        let (udp_socket_sender, tcp_socket_sender) =
            init_channel(tcp_listener, context.clone(), stoper.clone(), handler)?;

        // 打洞逻辑
        let punch = Punch::new(
            context.clone(),
            config.punch,
            config.tcp,
            tcp_socket_sender.clone(),
        );

        let up_counter = SingleU64Adder::new();
        let up_count_watcher = up_counter.watch();

        // 虚拟网卡启动
        handler::tun::start(
            stoper.clone(),
            context.clone(),
            device.clone(),
            current_device.clone(),
            inbound_route,
            proxy_map,
            client_cipher.clone(),
            server_cipher.clone(),
            config.parallel,
            up_counter,
        )?;

        maintain::idle_gateway(
            &scheduler,
            context.clone(),
            current_device.clone(),
            config_info.clone(),
            tcp_socket_sender.clone(),
            call.clone(),
            0,
        );
        {
            let context = context.clone();
            let nat_test = nat_test.clone();
            let device_list = device_list.clone();
            let current_device = current_device.clone();
            if !config.channel.is_only_relay() {
                // 定时nat探测
                maintain::retrieve_nat_type(
                    &scheduler,
                    context.clone(),
                    nat_test.clone(),
                    udp_socket_sender,
                );
            }
            //延迟启动
            start(
                &scheduler,
                context.clone(),
                nat_test.clone(),
                device_list.clone(),
                current_device.clone(),
                client_cipher.clone(),
                server_cipher.clone(),
                punch_receiver,
                config_info.clone(),
                punch.clone(),
                call.clone(),
            );
        }

        Ok(Self {
            stoper,
            config,
            rsa_cipher,
            server_cipher,
            client_cipher,
            current_device,
            nat_test,
            context,
            device_list,
            peer_nat_info_map,
            down_count_watcher,
            up_count_watcher,
        })
    }
}

pub fn start<Call: Callback>(
    scheduler: &Scheduler,
    context: Context,
    nat_test: NatTest,
    device_list: Arc<Mutex<(u16, Vec<PeerDeviceInfo>)>>,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
    server_cipher: Cipher,
    punch_receiver: PunchReceiver,
    config_info: BaseConfigInfo,
    punch: Punch,
    call: Call,
) {
    // 定时心跳
    maintain::heartbeat(
        &scheduler,
        context.clone(),
        current_device.clone(),
        device_list.clone(),
        client_cipher.clone(),
        server_cipher.clone(),
    );
    // 路由空闲检测逻辑
    let idle = Idle::new(Duration::from_secs(10), context.clone());
    // 定时空闲检查
    maintain::idle_route(
        &scheduler,
        idle,
        context.clone(),
        current_device.clone(),
        call,
    );
    // 定时客户端中继检测
    if !context.channel().is_only_p2p() {
        maintain::client_relay(
            &scheduler,
            context.clone(),
            current_device.clone(),
            device_list.clone(),
            client_cipher.clone(),
        );
    }
    // 定时地址探测
    maintain::addr_request(
        &scheduler,
        context.clone(),
        current_device.clone(),
        server_cipher.clone(),
        config_info.clone(),
    );
    if !context.channel().is_only_relay() {
        // 定时打洞
        maintain::punch(
            &scheduler,
            context.clone(),
            nat_test.clone(),
            device_list.clone(),
            current_device.clone(),
            client_cipher.clone(),
            punch_receiver,
            punch,
        );
    }
}

impl With {
    pub fn name(&self) -> &str {
        &self.config.name
    }
    pub fn server_encrypt(&self) -> bool {
        self.config.server_encrypt
    }
    pub fn client_encrypt(&self) -> bool {
        self.config.passwd.is_some()
    }
    pub fn current_device(&self) -> CurrentDeviceInfo {
        self.current_device.load()
    }
    pub fn peer_nat_info(&self, ip: &Ipv4Addr) -> Option<NatInfo> {
        self.peer_nat_info_map.read().get(ip).cloned()
    }
    pub fn connection_status(&self) -> ConnectStatus {
        self.current_device.load().status
    }
    pub fn nat_info(&self) -> NatInfo {
        self.nat_test.nat_info()
    }
    pub fn device_list(&self) -> Vec<PeerDeviceInfo> {
        let device_list_lock = self.device_list.lock();
        let (_epoch, device_list) = device_list_lock.clone();
        drop(device_list_lock);
        device_list
    }
    pub fn route(&self, ip: &Ipv4Addr) -> Option<channel::Route> {
        self.context.route_table.route_one(ip)
    }
    pub fn is_gateway(&self, ip: &Ipv4Addr) -> bool {
        self.current_device.load().is_gateway(ip)
    }
    pub fn route_key(&self, route_key: &RouteKey) -> Option<Ipv4Addr> {
        self.context.route_table.route_to_id(route_key)
    }
    pub fn route_table(&self) -> Vec<(Ipv4Addr, Vec<channel::Route>)> {
        self.context.route_table.route_table()
    }
    pub fn up_stream(&self) -> u64 {
        self.up_count_watcher.get()
    }
    pub fn down_stream(&self) -> u64 {
        self.down_count_watcher.get()
    }
    pub fn stop(&self) {
        self.stoper.stop()
    }
    pub fn wait(&self) {
        self.stoper.wait()
    }
}
