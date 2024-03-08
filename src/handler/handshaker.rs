use std::io::Result;

use prost::Message;

use crate::handler::{GATEWAY_IP, SELF_IP};
use crate::proto::message::HandshakeRequest;
use crate::proto::message::SecretHandshakeRequest;
use cipher::RsaCipher;
use protocol::body::RSA_ENCRYPTION_RESERVED;
use protocol::{service, NetPacket, Protocol, Version, MAX_TTL};

pub enum HandshakeEnum {
    NotSecret,
    KeyError,
    Timeout,
    ServerError(String),
    Other(String),
}

/// 第一次握手数据
pub fn handshake_request_packet(secret: bool) -> Result<NetPacket<Vec<u8>>> {
    let mut request = HandshakeRequest::default();
    request.secret = secret;
    request.version = crate::WITH_VERSION.to_string();
    let binding = request.encode_to_vec();
    let bytes = binding.as_slice();

    let buf = vec![0u8; 12 + bytes.len()];
    let mut net_packet = NetPacket::new(buf)?;
    net_packet.set_version(Version::V1);
    net_packet.set_gateway_flag(true);
    net_packet.set_destination(GATEWAY_IP);
    net_packet.set_source(SELF_IP);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service::Protocol::HandshakeRequest.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_payload(bytes)?;
    Ok(net_packet)
}

/// 第二次加密握手
pub fn secret_handshake_request_packet(
    rsa_cipher: &RsaCipher,
    token: String,
    key: &[u8],
) -> Result<NetPacket<Vec<u8>>> {
    let mut request = SecretHandshakeRequest::default();
    request.token = token;
    request.key = key.to_vec();
    let binding = request.encode_to_vec();
    let bytes = binding.as_slice();

    let mut net_packet = NetPacket::new0(
        12 + bytes.len(),
        vec![0u8; 12 + bytes.len() + RSA_ENCRYPTION_RESERVED],
    )?;
    net_packet.set_version(Version::V1);
    net_packet.set_gateway_flag(true);
    net_packet.set_destination(GATEWAY_IP);
    net_packet.set_source(SELF_IP);
    net_packet.set_protocol(Protocol::Service);
    net_packet.set_transport_protocol(service::Protocol::SecretHandshakeRequest.into());
    net_packet.first_set_ttl(MAX_TTL);
    net_packet.set_payload(bytes)?;
    rsa_cipher.encrypt(&mut net_packet)
}
