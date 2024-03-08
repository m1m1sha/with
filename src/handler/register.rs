use crate::handler::{GATEWAY_IP, SELF_IP};
use crate::proto::message::RegistrationRequest;
use cipher::Cipher;
use prost::Message;
use protocol::body::ENCRYPTION_RESERVED;
use protocol::{service, NetPacket, Protocol, Version, MAX_TTL};
use std::{io::Result, net::Ipv4Addr};

/// 注册数据
pub fn registration_request_packet(
    server_cipher: &Cipher,
    token: String,
    device_id: String,
    name: String,
    ip: Option<Ipv4Addr>,
    is_fast: bool,
    allow_ip_change: bool,
    client_secret: bool,
) -> Result<NetPacket<Vec<u8>>> {
    let mut request = RegistrationRequest::default();
    request.token = token;
    request.device_id = device_id;
    request.name = name;
    if let Some(ip) = ip {
        request.virtual_ip = ip.into();
    }
    request.allow_ip_change = allow_ip_change;
    request.is_fast = is_fast;
    request.version = crate::WITH_VERSION.to_string();
    request.client_secret = client_secret;
    let binding = request.encode_to_vec();
    let bytes = binding.as_slice();

    let buf = vec![0u8; 12 + bytes.len() + ENCRYPTION_RESERVED];
    let mut net_packet = NetPacket::new_encrypt(buf)?;
    net_packet.set_destination(GATEWAY_IP);
    net_packet.set_source(SELF_IP);
    net_packet.set_version(Version::V1);
    net_packet.set_gateway_flag(true);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service::Protocol::RegistrationRequest.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_payload(bytes)?;
    server_cipher.encrypt_ipv4(&mut net_packet)?;
    Ok(net_packet)
}
