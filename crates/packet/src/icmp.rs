use crate::cal_checksum;
use crate::ip::ipv4::packet::IpV4Packet;
use byteorder::{BigEndian, ReadBytesExt};
use std::{fmt, io};

/// icmp 协议
/*  https://www.rfc-editor.org/rfc/rfc792
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      |     Code      |          Checksum             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                      不同Type和Code有不同含义                    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                 数据体 不同Type和Code有不同含义                    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

pub struct IcmpPacket<B> {
    pub buffer: B,
}

impl<B: AsRef<[u8]>> IcmpPacket<B> {
    pub fn unchecked(buffer: B) -> Self {
        Self { buffer }
    }
    pub fn new(buffer: B) -> io::Result<Self> {
        if buffer.as_ref().len() < 8 {
            Err(io::Error::from(io::ErrorKind::InvalidData))?;
        }
        let packet = Self::unchecked(buffer);
        Ok(packet)
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> IcmpPacket<B> {
    pub fn set_kind(&mut self, kind: Kind) {
        self.buffer.as_mut()[0] = kind.into();
    }
    pub fn update_checksum(&mut self) {
        self.buffer.as_mut()[2..4].copy_from_slice(&[0, 0]);
        let checksum = cal_checksum(self.buffer.as_ref());
        self.buffer.as_mut()[2..4].copy_from_slice(&checksum.to_be_bytes());
    }
}

impl<B: AsRef<[u8]>> IcmpPacket<B> {
    pub fn kind(&self) -> Kind {
        Kind::from(self.buffer.as_ref()[0])
    }
    pub fn code(&self) -> Code {
        Code::from(self.kind(), self.buffer.as_ref()[1])
    }
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.buffer.as_ref()[2..4].try_into().unwrap())
    }
    pub fn is_valid(&self) -> bool {
        self.checksum() == 0 || cal_checksum(self.buffer.as_ref()) == 0
    }
    pub fn header_other(&self) -> HeaderOther {
        match self.kind() {
            Kind::EchoReply
            | Kind::EchoRequest
            | Kind::TimestampRequest
            | Kind::TimestampReply
            | Kind::InformationRequest
            | Kind::InformationReply => {
                let ide = u16::from_be_bytes(self.buffer.as_ref()[4..6].try_into().unwrap());
                let seq = u16::from_be_bytes(self.buffer.as_ref()[6..8].try_into().unwrap());
                HeaderOther::Identifier(ide, seq)
            }
            Kind::DestinationUnreachable | Kind::TimeExceeded | Kind::SourceQuench => {
                let bytes = self.buffer.as_ref();
                HeaderOther::Unused(bytes[4], bytes[5], bytes[6], bytes[7])
            }
            Kind::Redirect => {
                let bytes = self.buffer.as_ref();
                HeaderOther::Address(bytes[4], bytes[5], bytes[6], bytes[7])
            }
            Kind::ParameterProblem => HeaderOther::Pointer(self.buffer.as_ref()[4]),
            _ => {
                let bytes = self.buffer.as_ref();
                HeaderOther::UnKnown(bytes[4], bytes[5], bytes[6], bytes[7])
            }
        }
    }
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[8..]
    }
    pub fn description(&self) -> Description<&[u8]> {
        use std::io::Cursor;
        match self.kind() {
            Kind::DestinationUnreachable
            | Kind::TimeExceeded
            | Kind::ParameterProblem
            | Kind::SourceQuench
            | Kind::Redirect => match IpV4Packet::new(self.payload()) {
                Ok(d) => Description::Ip(d),
                Err(_) => Description::Other(self.payload()),
            },
            Kind::TimestampRequest | Kind::TimestampReply => {
                let mut buffer = Cursor::new(self.payload());

                Description::Timestamp(
                    buffer.read_u32::<BigEndian>().unwrap(),
                    buffer.read_u32::<BigEndian>().unwrap(),
                    buffer.read_u32::<BigEndian>().unwrap(),
                )
            }
            _ => Description::Other(self.payload()),
        }
    }
}

impl<B: AsRef<[u8]>> fmt::Debug for IcmpPacket<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(if self.is_valid() {
            "icmp::Packet"
        } else {
            "icmp::Packet!"
        })
        .field("kind", &self.kind())
        .field("code", &self.code())
        .field("checksum", &self.checksum())
        .field("payload", &self.payload())
        .finish()
    }
}

#[derive(Debug)]
pub enum HeaderOther {
    /// 全零
    Unused(u8, u8, u8, u8),
    /// If code = 0, identifies the octet where an error was detected.
    Pointer(u8),
    /// Address of the gateway to which traffic for the network specified
    ///       in the internet destination network field of the original
    ///       datagram's data should be sent.
    Address(u8, u8, u8, u8),
    ///      Identifier          |        Sequence Number
    Identifier(u16, u16),
    UnKnown(u8, u8, u8, u8),
}

pub enum Description<B> {
    Ip(IpV4Packet<B>),
    ///时间戳  Originate Timestamp,Receive Timestamp,Transmit Timestamp
    Timestamp(u32, u32, u32),
    Other(B),
}

impl<B: AsRef<[u8]> + std::fmt::Debug> fmt::Debug for Description<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Description::Ip(packet) => f.debug_struct(&format!("{:?}", packet)).finish(),
            Description::Timestamp(originate, receive, transmit) => f
                .debug_struct("")
                .field("originate", originate)
                .field("receive", receive)
                .field("transmit", transmit)
                .finish(),
            Description::Other(bytes) => f.debug_struct(&format!("{:?}", bytes)).finish(),
        }
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Kind {
    /// ping应答，type=0
    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Data ...
    +-+-+-+-+-
      */
    EchoReply,
    /// 目的地不可达，差错报文的一种，路由器收到一个不能转发的数据报，会向源地址返回这个报文，type=3
    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             unused                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      */
    DestinationUnreachable,
    /// 源抑制报文，用于防止接收端缓存溢出，接收设备发送这个来请求源设备降低发送速度，type=4
    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             unused                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      */
    SourceQuench,
    /// 重定向报文，当路由器接收包的接口正好是去往目的地的出口时，会向源地址发送重定向报文，告知源直接将数据发往自己的下一跳，type=5
    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Gateway Internet Address                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      */
    Redirect,
    /// ping请求，type=8
    EchoRequest,
    /// 路由器通告,type=9,
    RouterAdvertisement,
    /// 路由器请求,type=10
    RouterSolicitation,
    /// 报文ttl为0后，路由器会向源发送此报文，type=11
    /// Tracert工作原理：
    /// 首先向目的地发送ttl=1的包，下一跳路由器收到后ttl-1，此时ttl=0，将向源发送 ICMP time exceeded
    /// 再发送ttl=2的包，以此类推，直到目标主机接收到改包，此时不会回复ICMP time exceeded，代表已经探测到目的地
    /*

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             unused                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      */
    TimeExceeded,
    /// 参数错误，数据有误、校验和不对等，type=12
    /*

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Pointer    |                   unused                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Internet Header + 64 bits of Original Data Datagram      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    注：Pointer指示错误的位置
      */
    ParameterProblem,
    /// 时间戳请求,type=13
    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |      Code     |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Originate Timestamp                                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Receive Timestamp                                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Transmit Timestamp                                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      */
    TimestampRequest,
    /// 时间戳响应,type=14
    TimestampReply,
    /// 信息请求，type=15
    /*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |      Code     |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      */
    InformationRequest,
    /// 信息响应，type=16
    InformationReply,
    /// 地址掩码请求，type=17
    AddressMaskRequest,
    /// 地址掩码应答，type=18
    AddressMaskReply,
    ///
    TraceRoute,
    ///
    Unknown(u8),
}

impl From<u8> for Kind {
    fn from(value: u8) -> Kind {
        use self::Kind::*;

        match value {
            0 => EchoReply,
            3 => DestinationUnreachable,
            4 => SourceQuench,
            5 => Redirect,
            8 => EchoRequest,
            9 => RouterAdvertisement,
            10 => RouterSolicitation,
            11 => TimeExceeded,
            12 => ParameterProblem,
            13 => TimestampRequest,
            14 => TimestampReply,
            15 => InformationRequest,
            16 => InformationReply,
            17 => AddressMaskRequest,
            18 => AddressMaskReply,
            30 => TraceRoute,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for Kind {
    fn into(self) -> u8 {
        use self::Kind::*;
        match self {
            EchoReply => 0,
            DestinationUnreachable => 3,
            SourceQuench => 4,
            Redirect => 5,
            EchoRequest => 8,
            RouterAdvertisement => 9,
            RouterSolicitation => 10,
            TimeExceeded => 11,
            ParameterProblem => 12,
            TimestampRequest => 13,
            TimestampReply => 14,
            InformationRequest => 15,
            InformationReply => 16,
            AddressMaskRequest => 17,
            AddressMaskReply => 18,
            TraceRoute => 30,
            Unknown(v) => v,
        }
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Code {
    DestinationUnreachable(DestinationUnreachable),
    Redirect(Redirect),
    ParameterProblem(ParameterProblem),
    Other(u8),
}

impl Code {
    pub fn from(kind: Kind, code: u8) -> Code {
        match kind {
            Kind::DestinationUnreachable => {
                Code::DestinationUnreachable(DestinationUnreachable::from(code))
            }
            Kind::Redirect => Code::Redirect(Redirect::from(code)),
            Kind::ParameterProblem => Code::ParameterProblem(ParameterProblem::from(code)),
            _ => Code::Other(code),
        }
    }
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum DestinationUnreachable {
    /// 网络不可达
    DestinationNetworkUnreachable,
    /// 主机不可达
    DestinationHostUnreachable,
    /// 协议不可达
    DestinationProtocolUnreachable,
    /// 端口不可达
    DestinationPortUnreachable,
    /// 需要进行分片但设置不分片比特
    FragmentationRequired,
    /// 源站选路失败
    SourceRouteFailed,
    /// 目的网络未知
    DestinationNetworkUnknown,
    /// 目的主机未知
    DestinationHostUnknown,
    /// 源主机被隔离（作废不用）
    SourceHostIsolated,
    /// 目的网络被强制禁止
    NetworkAdministrativelyProhibited,
    /// 目的主机被强制禁止
    HostAdministrativelyProhibited,
    /// 由于服务类型TOS，网络不可达
    NetworkUnreachableForTos,
    /// 由于服务类型TOS，主机不可达
    HostUnreachableForTos,
    /// 由于过滤，通信被强制禁止
    CommunicationAdministrativelyProhibited,
    /// 主机越权
    HostPrecedenceViolation,
    /// 优先中止生效
    PrecedentCutoffInEffect,
    ///
    Unknown(u8),
}

/// Codes for Redirect Message packets.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Redirect {
    /// 对网络重定向
    RedirectDatagramForNetwork,
    /// 对主机重定向
    RedirectDatagramForHost,
    /// 对服务类型和网络重定向
    RedirectDatagramForTosAndNetwork,
    /// 对服务类型和主机重定向
    RedirectDatagramForTosAndHost,
    ///
    Unknown(u8),
}

/// Codes for TimeExceeded Message packets.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum TimeExceeded {
    /// TTL超时报文
    Transit,
    /// 分片重组超时报文
    Reassembly,
    ///
    Unknown(u8),
}
/// Codes for Parameter Problem packets.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum ParameterProblem {
    /// 坏的IP首部（包括各种差错）
    PointerIndicatesError,
    /// 缺少必需的选项
    MissingRequiredData,
    /// 长度错误
    BadLength,
    ///
    Unknown(u8),
}

impl From<u8> for DestinationUnreachable {
    fn from(value: u8) -> Self {
        use self::DestinationUnreachable::*;

        match value {
            0 => DestinationNetworkUnreachable,
            1 => DestinationHostUnreachable,
            2 => DestinationProtocolUnreachable,
            3 => DestinationPortUnreachable,
            4 => FragmentationRequired,
            5 => SourceRouteFailed,
            6 => DestinationNetworkUnknown,
            7 => DestinationHostUnknown,
            8 => SourceHostIsolated,
            9 => NetworkAdministrativelyProhibited,
            10 => HostAdministrativelyProhibited,
            11 => NetworkUnreachableForTos,
            12 => HostUnreachableForTos,
            13 => CommunicationAdministrativelyProhibited,
            14 => HostPrecedenceViolation,
            15 => PrecedentCutoffInEffect,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for DestinationUnreachable {
    fn into(self) -> u8 {
        use self::DestinationUnreachable::*;

        match self {
            DestinationNetworkUnreachable => 0,
            DestinationHostUnreachable => 1,
            DestinationProtocolUnreachable => 2,
            DestinationPortUnreachable => 3,
            FragmentationRequired => 4,
            SourceRouteFailed => 5,
            DestinationNetworkUnknown => 6,
            DestinationHostUnknown => 7,
            SourceHostIsolated => 8,
            NetworkAdministrativelyProhibited => 9,
            HostAdministrativelyProhibited => 10,
            NetworkUnreachableForTos => 11,
            HostUnreachableForTos => 12,
            CommunicationAdministrativelyProhibited => 13,
            HostPrecedenceViolation => 14,
            PrecedentCutoffInEffect => 15,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for Redirect {
    fn from(value: u8) -> Self {
        use self::Redirect::*;

        match value {
            0 => RedirectDatagramForNetwork,
            1 => RedirectDatagramForHost,
            2 => RedirectDatagramForTosAndNetwork,
            3 => RedirectDatagramForTosAndHost,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for Redirect {
    fn into(self) -> u8 {
        use self::Redirect::*;

        match self {
            RedirectDatagramForNetwork => 0,
            RedirectDatagramForHost => 1,
            RedirectDatagramForTosAndNetwork => 2,
            RedirectDatagramForTosAndHost => 3,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for TimeExceeded {
    fn from(value: u8) -> Self {
        use self::TimeExceeded::*;

        match value {
            0 => Transit,
            1 => Reassembly,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for TimeExceeded {
    fn into(self) -> u8 {
        use self::TimeExceeded::*;

        match self {
            Transit => 0,
            Reassembly => 1,
            Unknown(v) => v,
        }
    }
}

impl From<u8> for ParameterProblem {
    fn from(value: u8) -> Self {
        use self::ParameterProblem::*;

        match value {
            0 => PointerIndicatesError,
            1 => MissingRequiredData,
            2 => BadLength,
            v => Unknown(v),
        }
    }
}

impl Into<u8> for ParameterProblem {
    fn into(self) -> u8 {
        use self::ParameterProblem::*;

        match self {
            PointerIndicatesError => 0,
            MissingRequiredData => 1,
            BadLength => 2,
            Unknown(v) => v,
        }
    }
}
