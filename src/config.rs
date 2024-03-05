use std::{
    io::{Error, ErrorKind, Result},
    net::{Ipv4Addr, SocketAddr},
};

use serde::{Deserialize, Serialize};

use crate::mode::{channel::ChannelMode, cipher::CipherMode, punch::PunchMode};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub udi: String,                        // 设备唯一标识
    pub stun: Vec<String>,                  // stun 节点
    pub server: SocketAddr,                 // withs 节点
    pub token: String,                      // 组网 token | 房间名
    pub passwd: String,                     // 组网密码
    pub name: String,                       // 组网昵称
    pub mtu: u32,                           // mtu
    pub ip: Option<Ipv4Addr>,               // 自定义 ip
    pub inbound: Vec<(u32, u32, Ipv4Addr)>, // 入站ip
    pub outbound: Vec<(u32, u32)>,          // 出站ip
    pub latency: bool,                      // 延迟优先
    pub parallel: usize,                    // 处理协程数
    pub finger: bool,                       // 指纹
    pub cipher: CipherMode,                 // 加密模式
    pub punch: PunchMode,                   // 打洞模式
    pub channel: ChannelMode,               // 信道模式
}

impl Config {
    pub fn new(
        udi: String,
        stun: Option<Vec<String>>,
        server: SocketAddr,
        token: String,
        passwd: String,
        name: String,
        mtu: u32,
        ip: Option<Ipv4Addr>,
        inbound: Vec<(u32, u32, Ipv4Addr)>,
        outbound: Vec<(u32, u32)>,
        latency: bool,
        parallel: usize,
        finger: bool,
        cipher: CipherMode,
        punch: PunchMode,
        channel: ChannelMode,
    ) -> Result<Self> {
        let stun = match stun {
            Some(servers) => {
                let mut servers = servers;
                for x in servers.iter_mut() {
                    if !x.contains(":") {
                        x.push_str(":3478");
                    }
                }
                servers
            }
            None => vec![
                "stun1.l.google.com:19302".to_owned(),
                "stun2.l.google.com:19302".to_owned(),
                "stun.qq.com:3478".to_owned(),
            ],
        };

        if token.is_empty() || token.len() > 128 {
            return Err(Error::new(ErrorKind::Other, "token too long or is empty"));
        }
        if udi.is_empty() || udi.len() > 128 {
            return Err(Error::new(ErrorKind::Other, "udi too long or is empty"));
        }
        if name.is_empty() || name.len() > 128 {
            return Err(Error::new(ErrorKind::Other, "name too long or is empty"));
        }

        Ok(Self {
            udi,
            stun,
            server,
            token,
            passwd,
            name,
            mtu,
            ip,
            inbound,
            outbound,
            latency,
            parallel,
            finger,
            cipher,
            punch,
            channel,
        })
    }
}
