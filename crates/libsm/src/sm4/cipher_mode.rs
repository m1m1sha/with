// Copyright 2018 Cryptape Technology LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::cipher::Sm4Cipher;
use crate::sm4::error::{Sm4Error, Sm4Result};

pub enum CipherMode {
    Cfb,
    Ofb,
    Ctr,
    Cbc,
}

pub struct Sm4CipherMode {
    cipher: Sm4Cipher,
    mode: CipherMode,
}

fn block_xor(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut out: [u8; 16] = [0; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn block_add_one(a: &mut [u8]) {
    let mut carry = 1;

    for i in 0..16 {
        let (t, c) = a[15 - i].overflowing_add(carry);
        a[15 - i] = t;
        if !c {
            return;
        }
        carry = c as u8;
    }
}

impl Sm4CipherMode {
    pub fn new(key: &[u8], mode: CipherMode) -> Sm4Result<Sm4CipherMode> {
        let cipher = Sm4Cipher::new(key)?;
        Ok(Sm4CipherMode { cipher, mode })
    }

    pub fn encrypt(&self, data: &[u8], iv: &[u8], out: &mut [u8]) -> Sm4Result<usize> {
        if iv.len() != 16 {
            return Err(Sm4Error::ErrorBlockSize);
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_encrypt(data, iv, out),
            CipherMode::Ofb => self.ofb_encrypt(data, iv, out),
            CipherMode::Ctr => self.ctr_encrypt(data, iv, out),
            CipherMode::Cbc => self.cbc_encrypt(data, iv, out),
        }
    }

    pub fn decrypt(&self, data: &[u8], iv: &[u8], out: &mut [u8]) -> Result<usize, Sm4Error> {
        if iv.len() != 16 {
            return Err(Sm4Error::ErrorBlockSize);
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_decrypt(data, iv, out),
            CipherMode::Ofb => self.ofb_encrypt(data, iv, out),
            CipherMode::Ctr => self.ctr_encrypt(data, iv, out),
            CipherMode::Cbc => self.cbc_decrypt(data, iv, out),
        }
    }

    fn cfb_encrypt(&self, data: &[u8], iv: &[u8], out: &mut [u8]) -> Result<usize, Sm4Error> {
        let block_num = data.len() >> 4;
        let tail_len = data.len() & 0xF;
        let mut vec_buf = [0; 16];
        vec_buf.copy_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf)?;
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            out[i * 16..i * 16 + 16].copy_from_slice(&ct);
            vec_buf = ct;
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf)?;
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out[block_num * 16 + i] = b;
        }
        Ok(data.len())
    }

    fn cfb_decrypt(&self, data: &[u8], iv: &[u8], out: &mut [u8]) -> Result<usize, Sm4Error> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut buf = [0; 16];
        buf.copy_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&buf)?;
            let ct = &data[i * 16..i * 16 + 16];
            let pt = block_xor(&enc, ct);
            out[i * 16..i * 16 + 16].copy_from_slice(&pt);
            buf.copy_from_slice(ct);
        }

        // Last block
        let enc = self.cipher.encrypt(&buf)?;
        for i in 0..tail_len {
            out[block_num * 16 + i] = data[block_num * 16 + i] ^ enc[i];
        }
        Ok(data.len())
    }

    fn ofb_encrypt(&self, data: &[u8], iv: &[u8], out: &mut [u8]) -> Result<usize, Sm4Error> {
        let block_num = data.len() >> 4;
        let tail_len = data.len() & 0xF;

        let mut buf = [0; 16];
        buf.copy_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&buf)?;
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            out[i * 16..i * 16 + 16].copy_from_slice(&ct);
            buf = enc;
        }

        // Last block
        let enc = self.cipher.encrypt(&buf)?;
        for i in 0..tail_len {
            out[block_num * 16 + i] = data[block_num * 16 + i] ^ enc[i];
        }
        Ok(data.len())
    }

    fn ctr_encrypt(&self, data: &[u8], iv: &[u8], out: &mut [u8]) -> Result<usize, Sm4Error> {
        let block_num = data.len() >> 4;
        let tail_len = data.len() & 0xF;

        let mut buf = [0; 16];
        buf.copy_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&buf)?;
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            out[i * 16..i * 16 + 16].copy_from_slice(&ct);
            block_add_one(&mut buf);
        }

        // Last block
        let enc = self.cipher.encrypt(&buf)?;
        for i in 0..tail_len {
            out[block_num * 16 + i] = data[block_num * 16 + i] ^ enc[i];
        }
        Ok(data.len())
    }

    fn cbc_encrypt(&self, data: &[u8], iv: &[u8], out: &mut [u8]) -> Result<usize, Sm4Error> {
        let block_num = data.len() >> 4;
        let remind = data.len() & 0xF;

        let mut vec_buf = [0; 16];
        vec_buf.copy_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let start = i * 16;
            let end = start + 16;
            let ct = block_xor(&vec_buf, &data[start..end]);
            let enc = self.cipher.encrypt(&ct)?;

            out[start..end].copy_from_slice(&enc);
            vec_buf = enc;
        }

        if remind != 0 {
            let mut last_block = [16 - remind as u8; 16];
            last_block[..remind].copy_from_slice(&data[block_num * 16..]);

            let ct = block_xor(&vec_buf, &last_block);
            let enc = self.cipher.encrypt(&ct)?;
            out[block_num * 16..block_num * 16 + 16].copy_from_slice(&enc);
        } else {
            let ff_padding = block_xor(&vec_buf, &[0x10; 16]);
            let enc = self.cipher.encrypt(&ff_padding)?;
            out[block_num * 16..block_num * 16 + 16].copy_from_slice(&enc);
        }

        Ok(block_num * 16 + 16)
    }

    fn cbc_decrypt(&self, data: &[u8], iv: &[u8], out: &mut [u8]) -> Result<usize, Sm4Error> {
        let data_len = data.len();
        let block_num = data_len >> 4;
        if data_len & 0xF != 0 {
            return Err(Sm4Error::ErrorDataLen);
        }

        let mut vec_buf = [0; 16];
        vec_buf.copy_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let start = i * 16;
            let end = start + 16;

            let enc = self.cipher.decrypt(&data[start..end])?;
            let ct = block_xor(&vec_buf, &enc);
            out[start..end].copy_from_slice(&ct);
            vec_buf.copy_from_slice(&data[i * 16..i * 16 + 16]);
        }

        let last_u8 = out[data_len - 1];
        if last_u8 > 0x10 || last_u8 == 0 {
            return Err(Sm4Error::InvalidLastU8);
        }

        Ok(data_len - last_u8 as usize)
    }
}

// TODO: AEAD in SM4
// pub struct SM4Gcm;

// Tests below

#[cfg(test)]
mod tests {
    use super::*;

    use rand::RngCore;

    fn rand_block() -> [u8; 16] {
        let mut rng = rand::thread_rng();
        let mut block: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut block[..]);
        block
    }

    fn rand_data(len: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut dat: Vec<u8> = Vec::new();
        dat.resize(len, 0);
        rng.fill_bytes(&mut dat[..]);
        dat
    }

    #[test]
    fn test_driver() {
        test_ciphermode(CipherMode::Ctr);
        test_ciphermode(CipherMode::Cfb);
        test_ciphermode(CipherMode::Ofb);
        test_ciphermode(CipherMode::Cbc);
    }

    fn test_ciphermode(mode: CipherMode) {
        let key = rand_block();
        let iv = rand_block();

        let cmode = Sm4CipherMode::new(&key, mode).unwrap();
        let mut ct = [0; 1024];
        let pt = rand_data(10);
        let ct_len = cmode.encrypt(&pt[..], &iv, &mut ct).unwrap();
        let mut new_pt = [0; 1024];
        let new_pt_len = cmode.decrypt(&ct[..ct_len], &iv, &mut new_pt).unwrap();
        let new_pt = &new_pt[..new_pt_len];
        assert_eq!(&pt[..], new_pt);

        let mut ct = [0; 1024];
        let pt = rand_data(100);
        let ct_len = cmode.encrypt(&pt[..], &iv, &mut ct).unwrap();
        let mut new_pt = [0; 1024];
        let new_pt_len = cmode.decrypt(&ct[..ct_len], &iv, &mut new_pt).unwrap();
        let new_pt = &new_pt[..new_pt_len];
        assert_eq!(&pt[..], new_pt);

        let mut ct = [0; 1024];
        let pt = rand_data(1000);
        let ct_len = cmode.encrypt(&pt[..], &iv, &mut ct).unwrap();
        let mut new_pt = [0; 1024];
        let new_pt_len = cmode.decrypt(&ct[..ct_len], &iv, &mut new_pt).unwrap();
        let new_pt = &new_pt[..new_pt_len];
        assert_eq!(&pt[..], new_pt);
    }

    #[test]
    fn ctr_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Ctr).unwrap();
        let msg = b"hello world, this file is used for smx test\n";
        let mut lhs = [0; 1024];
        let lhs_len = cipher_mode.encrypt(msg, &iv, &mut lhs).unwrap();
        let lhs: &[u8] = &lhs[..lhs_len];

        let rhs: &[u8] = include_bytes!("example/text.sms4-ctr");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn cfb_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Cfb).unwrap();
        let msg = b"hello world, this file is used for smx test\n";
        let mut lhs = [0; 1024];
        let lhs_len = cipher_mode.encrypt(msg, &iv, &mut lhs).unwrap();
        let lhs: &[u8] = &lhs[..lhs_len];

        let rhs: &[u8] = include_bytes!("example/text.sms4-cfb");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn ofb_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Ofb).unwrap();
        let msg = b"hello world, this file is used for smx test\n";
        let mut lhs = [0; 1024];
        let lhs_len = cipher_mode.encrypt(msg, &iv, &mut lhs).unwrap();
        let lhs: &[u8] = &lhs[..lhs_len];

        let rhs: &[u8] = include_bytes!("example/text.sms4-ofb");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn cbc_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Cbc).unwrap();
        let msg = b"hello world, this file is used for smx test\n";
        let mut lhs = [0; 1024];
        let lhs_len = cipher_mode.encrypt(msg, &iv, &mut lhs).unwrap();
        let lhs: &[u8] = &lhs[..lhs_len];

        let rhs: &[u8] = include_bytes!("example/text.sms4-cbc");
        assert_eq!(lhs, rhs);
    }
}
