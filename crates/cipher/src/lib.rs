pub use finger::Finger;
pub use rsa::RsaCipher;
use serde::{Deserialize, Serialize};

#[cfg(feature = "aes_cbc")]
mod aes_cbc;
#[cfg(feature = "aes_ecb")]
#[cfg(not(any(feature = "openssl-vendored", feature = "openssl")))]
mod aes_ecb;
#[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
#[cfg(not(feature = "ring-cipher"))]
mod aes_gcm;
#[cfg(any(
    feature = "aes_gcm",
    feature = "server_encrypt",
    feature = "aes_cbc",
    feature = "aes_ecb",
    feature = "sm4_cbc"
))]
mod finger;
#[cfg(feature = "aes_ecb")]
#[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
#[cfg(feature = "ring-cipher")]
mod ring_aes_gcm_cipher;

#[cfg(any(
    feature = "aes_gcm",
    feature = "server_encrypt",
    feature = "aes_cbc",
    feature = "aes_ecb",
    feature = "sm4_cbc"
))]
mod rsa;
#[cfg(feature = "sm4_cbc")]
mod sm4_cbc;

#[cfg(feature = "aes_cbc")]
use crate::aes_cbc::AesCbcCipher;
#[cfg(feature = "aes_ecb")]
use crate::aes_ecb::AesEcbCipher;
#[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
#[cfg(not(feature = "ring-cipher"))]
use crate::aes_gcm::AesGcmCipher;
#[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
#[cfg(feature = "ring-cipher")]
use crate::ring_aes_gcm_cipher::AesGcmCipher;
#[cfg(feature = "sm4_cbc")]
use crate::sm4_cbc::Sm4CbcCipher;

use protocol::NetPacket;
#[cfg(any(
    feature = "aes_gcm",
    feature = "server_encrypt",
    feature = "aes_cbc",
    feature = "aes_ecb",
    feature = "sm4_cbc"
))]
use sha2::Digest;
use std::io;
use std::str::FromStr;

#[derive(Copy, Clone, Eq, PartialEq, Debug, Deserialize, Serialize, Default)]
pub enum CipherMode {
    #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
    AesGcm,
    #[cfg(feature = "aes_cbc")]
    AesCbc,
    #[cfg(feature = "aes_ecb")]
    AesEcb,
    #[cfg(feature = "sm4_cbc")]
    Sm4Cbc,
    #[default]
    None,
}

impl FromStr for CipherMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        #[cfg(not(any(
            feature = "aes_gcm",
            feature = "server_encrypt",
            feature = "aes_cbc",
            feature = "aes_ecb",
            feature = "sm4_cbc"
        )))]
        return Err(format!("not match '{}', no encrypt", s));
        #[cfg(any(
            feature = "aes_gcm",
            feature = "server_encrypt",
            feature = "aes_cbc",
            feature = "aes_ecb",
            feature = "sm4_cbc"
        ))]
        match s.to_lowercase().trim() {
            #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
            "aes_gcm" => Ok(CipherMode::AesGcm),
            #[cfg(feature = "aes_cbc")]
            "aes_cbc" => Ok(CipherMode::AesCbc),
            #[cfg(feature = "aes_ecb")]
            "aes_ecb" => Ok(CipherMode::AesEcb),
            #[cfg(feature = "sm4_cbc")]
            "sm4_cbc" => Ok(CipherMode::Sm4Cbc),
            _ => {
                let mut enums = String::new();
                #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
                enums.push_str("/aes_gcm");
                #[cfg(feature = "aes_cbc")]
                enums.push_str("/aes_cbc");
                #[cfg(feature = "aes_ecb")]
                enums.push_str("/aes_ecb");
                #[cfg(feature = "sm4_cbc")]
                enums.push_str("/sm4_cbc");
                let str = if enums.is_empty() {
                    "no encrypt"
                } else {
                    &enums[1..]
                };
                Err(format!("not match '{}', enum:{}", s, str))
            }
        }
    }
}

#[derive(Clone)]
pub enum Cipher {
    #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
    AesGcm((AesGcmCipher, Vec<u8>)),
    #[cfg(feature = "aes_cbc")]
    AesCbc(AesCbcCipher),
    #[cfg(feature = "aes_ecb")]
    AesEcb(AesEcbCipher),
    #[cfg(feature = "sm4_cbc")]
    Sm4Cbc(Sm4CbcCipher),
    None,
}
impl Cipher {
    #[cfg(not(any(
        feature = "aes_gcm",
        feature = "server_encrypt",
        feature = "aes_cbc",
        feature = "aes_ecb",
        feature = "sm4_cbc"
    )))]
    pub fn new_password(
        _model: CipherMode,
        _password: Option<String>,
        _token: Option<String>,
    ) -> Self {
        Cipher::None
    }
    #[cfg(any(
        feature = "aes_gcm",
        feature = "server_encrypt",
        feature = "aes_cbc",
        feature = "aes_ecb",
        feature = "sm4_cbc"
    ))]
    pub fn new_password(
        model: CipherMode,
        password: Option<String>,
        token: Option<String>,
    ) -> Self {
        let finger = token.map(|token| Finger::new(&token));
        if let Some(password) = password {
            let mut hasher = sha2::Sha256::new();
            hasher.update(password.as_bytes());
            let key: [u8; 32] = hasher.finalize().into();
            match model {
                #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
                CipherMode::AesGcm => {
                    if password.len() < 8 {
                        let aes = AesGcmCipher::new_128(key[..16].try_into().unwrap(), finger);
                        Cipher::AesGcm((aes, key[..16].to_vec()))
                    } else {
                        let aes = AesGcmCipher::new_256(key, finger);
                        Cipher::AesGcm((aes, key.to_vec()))
                    }
                }
                #[cfg(feature = "aes_cbc")]
                CipherMode::AesCbc => {
                    if password.len() < 8 {
                        let aes = AesCbcCipher::new_128(key[..16].try_into().unwrap(), finger);
                        Cipher::AesCbc(aes)
                    } else {
                        let aes = AesCbcCipher::new_256(key, finger);
                        Cipher::AesCbc(aes)
                    }
                }
                #[cfg(feature = "aes_ecb")]
                CipherMode::AesEcb => {
                    if password.len() < 8 {
                        let aes = AesEcbCipher::new_128(key[..16].try_into().unwrap(), finger);
                        Cipher::AesEcb(aes)
                    } else {
                        let aes = AesEcbCipher::new_256(key, finger);
                        Cipher::AesEcb(aes)
                    }
                }
                #[cfg(feature = "sm4_cbc")]
                CipherMode::Sm4Cbc => {
                    let aes = Sm4CbcCipher::new_128(key[..16].try_into().unwrap(), finger);
                    Cipher::Sm4Cbc(aes)
                }
                CipherMode::None => Cipher::None,
            }
        } else {
            Cipher::None
        }
    }
    #[cfg(not(any(
        feature = "aes_gcm",
        feature = "server_encrypt",
        feature = "aes_cbc",
        feature = "aes_ecb",
        feature = "sm4_cbc"
    )))]
    pub fn new_key(_key: [u8; 32], _token: String) -> io::Result<Self> {
        Err(io::Error::new(io::ErrorKind::Other, "key error"))
    }
    #[cfg(any(
        feature = "aes_gcm",
        feature = "server_encrypt",
        feature = "aes_cbc",
        feature = "aes_ecb",
        feature = "sm4_cbc"
    ))]
    pub fn new_key(key: [u8; 32], token: String) -> io::Result<Self> {
        let finger = Some(Finger::new(&token));
        match key.len() {
            #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
            16 => {
                let aes = AesGcmCipher::new_128(key[..16].try_into().unwrap(), finger);
                Ok(Cipher::AesGcm((aes, key[..16].to_vec())))
            }
            #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
            32 => {
                let aes = AesGcmCipher::new_256(key, finger);
                Ok(Cipher::AesGcm((aes, key.to_vec())))
            }
            _ => Err(io::Error::new(io::ErrorKind::Other, "key error")),
        }
    }
    pub fn decrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> io::Result<()> {
        match self {
            #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
            Cipher::AesGcm((aes_gcm, _)) => aes_gcm.decrypt_ipv4(net_packet),
            #[cfg(feature = "aes_cbc")]
            Cipher::AesCbc(aes_cbc) => aes_cbc.decrypt_ipv4(net_packet),
            #[cfg(feature = "aes_ecb")]
            Cipher::AesEcb(aes_ecb) => aes_ecb.decrypt_ipv4(net_packet),
            #[cfg(feature = "sm4_cbc")]
            Cipher::Sm4Cbc(sm4_cbc) => sm4_cbc.decrypt_ipv4(net_packet),
            Cipher::None => {
                if net_packet.is_encrypt() {
                    return Err(io::Error::new(io::ErrorKind::Other, "not key"));
                }
                Ok(())
            }
        }
    }
    #[cfg(not(any(
        feature = "aes_gcm",
        feature = "server_encrypt",
        feature = "aes_cbc",
        feature = "aes_ecb",
        feature = "sm4_cbc"
    )))]
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        _net_packet: &mut NetPacket<B>,
    ) -> io::Result<()> {
        Ok(())
    }
    #[cfg(any(
        feature = "aes_gcm",
        feature = "server_encrypt",
        feature = "aes_cbc",
        feature = "aes_ecb",
        feature = "sm4_cbc"
    ))]
    pub fn encrypt_ipv4<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        net_packet: &mut NetPacket<B>,
    ) -> io::Result<()> {
        match self {
            #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
            Cipher::AesGcm((aes_gcm, _)) => aes_gcm.encrypt_ipv4(net_packet),
            #[cfg(feature = "aes_cbc")]
            Cipher::AesCbc(aes_cbc) => aes_cbc.encrypt_ipv4(net_packet),
            #[cfg(feature = "aes_ecb")]
            Cipher::AesEcb(aes_ecb) => aes_ecb.encrypt_ipv4(net_packet),
            #[cfg(feature = "sm4_cbc")]
            Cipher::Sm4Cbc(sm4_cbc) => sm4_cbc.encrypt_ipv4(net_packet),
            Cipher::None => Ok(()),
        }
    }
    #[cfg(not(any(
        feature = "aes_gcm",
        feature = "server_encrypt",
        feature = "aes_cbc",
        feature = "aes_ecb",
        feature = "sm4_cbc"
    )))]
    pub fn check_finger<B: AsRef<[u8]> + AsMut<[u8]>>(
        &self,
        _net_packet: &NetPacket<B>,
    ) -> io::Result<()> {
        Ok(())
    }
    #[cfg(any(
        feature = "aes_gcm",
        feature = "server_encrypt",
        feature = "aes_cbc",
        feature = "aes_ecb",
        feature = "sm4_cbc"
    ))]
    pub fn check_finger<B: AsRef<[u8]>>(&self, net_packet: &NetPacket<B>) -> io::Result<()> {
        match self {
            #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
            Cipher::AesGcm((aes_gcm, _)) => aes_gcm
                .finger
                .as_ref()
                .map(|f| f.check_finger(net_packet))
                .unwrap_or(Ok(())),
            #[cfg(feature = "aes_cbc")]
            Cipher::AesCbc(aes_cbc) => aes_cbc
                .finger
                .as_ref()
                .map(|f| f.check_finger(net_packet))
                .unwrap_or(Ok(())),
            #[cfg(feature = "aes_ecb")]
            Cipher::AesEcb(aes_ecb) => aes_ecb
                .finger
                .as_ref()
                .map(|f| f.check_finger(net_packet))
                .unwrap_or(Ok(())),
            #[cfg(feature = "sm4_cbc")]
            Cipher::Sm4Cbc(sm4_cbc) => sm4_cbc
                .finger
                .as_ref()
                .map(|f| f.check_finger(net_packet))
                .unwrap_or(Ok(())),
            Cipher::None => Ok(()),
        }
    }
    pub fn key(&self) -> Option<&[u8]> {
        match self {
            #[cfg(any(feature = "aes_gcm", feature = "server_encrypt"))]
            Cipher::AesGcm((_, key)) => Some(key),
            #[cfg(feature = "aes_cbc")]
            Cipher::AesCbc(aes_cbc) => Some(aes_cbc.key()),
            #[cfg(feature = "aes_ecb")]
            Cipher::AesEcb(aes_ecb) => Some(aes_ecb.key()),
            #[cfg(feature = "sm4_cbc")]
            Cipher::Sm4Cbc(sm4_cbc) => Some(sm4_cbc.key()),
            Cipher::None => None,
        }
    }
}
