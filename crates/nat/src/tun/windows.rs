use std::{
    collections::HashMap,
    io::{Error, ErrorKind, Result},
    net::Ipv4Addr,
    slice,
    sync::{Arc, OnceLock},
};

use libloading::Library;
use windows::{
    core::{GUID, PCSTR},
    Win32::{
        Foundation::{
            CloseHandle, GetLastError, ERROR_NO_MORE_ITEMS, FALSE, HANDLE, WAIT_EVENT, WAIT_FAILED,
            WAIT_OBJECT_0,
        },
        System::Threading::{CreateEventA, SetEvent, WaitForMultipleObjects, INFINITE},
    },
};

use super::device::IFace;

pub mod log;
pub mod netsh;
pub mod packet;
pub mod util;
pub mod wintun_raw;

/// The maximum size of wintun's internal ring buffer (in bytes)
pub const MAX_RING_CAPACITY: u32 = 0x400_0000;
/// The minimum size of wintun's internal ring buffer (in bytes)
pub const MIN_RING_CAPACITY: u32 = 0x2_0000;
/// Maximum pool name length including zero terminator
pub const MAX_POOL: usize = 256;

#[derive(Copy, Clone, Debug)]
pub(crate) struct UnsafeHandle<T>(pub T);
unsafe impl<T> Send for UnsafeHandle<T> {}
unsafe impl<T> Sync for UnsafeHandle<T> {}

pub struct Device {
    pub(crate) luid: u64,
    pub(crate) guid: u128,
    pub(crate) index: u32,
    pub(crate) session: UnsafeHandle<wintun_raw::WINTUN_SESSION_HANDLE>,
    pub(crate) win_tun: Arc<wintun_raw::wintun>,
    pub(crate) read_event: OnceLock<HANDLE>,
    pub(crate) shutdown_event: HANDLE,
    pub(crate) adapter: UnsafeHandle<wintun_raw::WINTUN_ADAPTER_HANDLE>,
}

unsafe impl Send for Device {}
unsafe impl Sync for Device {}

impl Device {
    /// wintun.dll 路径默认为运行目录
    pub fn new(name: String, dll_path: Option<String>) -> Result<Self> {
        let path = dll_path.unwrap_or("wintun.dll".to_owned());
        let library = match unsafe { Library::new(path.clone()) } {
            Ok(library) => library,
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("dll not found in path: {}, {:?}", path, e),
                ));
            }
        };

        let win_tun = match unsafe { wintun_raw::wintun::from_library(library) } {
            Ok(win_tun) => Arc::new(win_tun),
            Err(e) => {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("library error {:?} ", e),
                ));
            }
        };

        let name_utf16 = util::encode_utf16(&name);
        if name_utf16.len() > MAX_POOL {
            return Err(Error::new(
                ErrorKind::Other,
                format!("too long {}:{:?}", MAX_POOL, name),
            ));
        }

        let description = util::encode_utf16("With Tun Adapter");

        // 多网卡时网卡名称应为: with_tun_0 / with_tun_1
        // 所以不存在删除其他实例正在使用的网卡情况
        let _ = Self::delete_with_name_before_new(&win_tun, &name_utf16);
        log::set_default_logger_if_unset(&win_tun);

        if utils::root::is_elevated() {
            // 未知影响, 但好像没事
            let _ = util::clear_network_list();
        }

        // 此处生成的guid储存于
        // \HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\
        let guid = GUID::new()?.to_u128();
        let guid_struct: wintun_raw::GUID = unsafe { std::mem::transmute(GUID::from_u128(guid)) };
        let guid_ptr = &guid_struct as *const wintun_raw::GUID;

        // 有时候创建的网卡 Description 和 ProfileName 都是默认值(网络/NetWork)
        // 此时不知道确切网卡信息, 不能够删除序号递增的网卡注册表
        let adapter = unsafe {
            win_tun.WintunCreateAdapter(name_utf16.as_ptr(), description.as_ptr(), guid_ptr)
        };

        if adapter.is_null() {
            tracing::error!("adapter is_null {:?}", Error::last_os_error());
            return Err(Error::new(ErrorKind::Other, "Failed to crate adapter"));
        }

        let session = unsafe { win_tun.WintunStartSession(adapter, MAX_RING_CAPACITY) };
        if session.is_null() {
            tracing::error!("session is_null {:?}", Error::last_os_error());
            return Err(Error::new(ErrorKind::Other, "WintunStartSession failed"));
        }

        let shutdown_event = unsafe { CreateEventA(None, FALSE, FALSE, PCSTR::null())? };
        let read_event =
            OnceLock::from(unsafe { HANDLE(win_tun.WintunGetReadWaitEvent(session) as _) });

        let luid = util::get_adapter_luid(&win_tun, adapter);
        let index = util::luid_to_index(&luid)?;

        Ok(Self {
            luid: unsafe { std::mem::transmute(luid) },
            guid,
            index,
            session: UnsafeHandle(session),
            win_tun,
            read_event,
            shutdown_event,
            adapter: UnsafeHandle(adapter),
        })
    }
    pub fn try_receive(self: &Arc<Self>) -> Result<Option<packet::Packet>> {
        let mut size = 0u32;

        let ptr = unsafe {
            self.win_tun
                .WintunReceivePacket(self.session.0, &mut size as *mut u32)
        };

        debug_assert!(size <= u16::MAX as u32);
        if ptr.is_null() {
            //Wintun returns ERROR_NO_MORE_ITEMS instead of blocking if packets are not available
            if ERROR_NO_MORE_ITEMS == unsafe { GetLastError() } {
                Ok(None)
            } else {
                Err(Error::new(ErrorKind::Other, "try_receive failed"))
            }
        } else {
            Ok(Some(packet::Packet {
                kind: packet::Kind::ReceivePacket,
                //SAFETY: ptr is non null, aligned for u8, and readable for up to size bytes (which
                //must be less than isize::MAX because bytes is a u16
                bytes: unsafe { slice::from_raw_parts_mut(ptr, size as usize) },
                device: self.clone(),
            }))
        }
    }
    pub fn receive_blocking(self: &Arc<Self>) -> Result<packet::Packet> {
        loop {
            //Try 5 times to receive without blocking so we don't have to issue a syscall to wait
            //for the event if packets are being received at a rapid rate
            for _ in 0..5 {
                match self.try_receive() {
                    Err(err) => return Err(err),
                    Ok(Some(packet)) => return Ok(packet),
                    Ok(None) => {
                        //Try again
                        continue;
                    }
                }
            }
            //Wait on both the read handle and the shutdown handle so that we stop when requested
            let handles = [self.get_read_wait_event()?, self.shutdown_event];
            let result = unsafe {
                //SAFETY: We abide by the requirements of WaitForMultipleObjects, handles is a
                //pointer to valid, aligned, stack memory
                WaitForMultipleObjects(&handles, FALSE, INFINITE)
            };
            const WAIT_OBJECT_1: WAIT_EVENT = WAIT_EVENT(WAIT_OBJECT_0.0 + 1);
            match result {
                WAIT_FAILED => return Err(Error::new(ErrorKind::Other, "WAIT_FAILED")),
                WAIT_OBJECT_0 => {
                    //We have data!
                    continue;
                }
                WAIT_OBJECT_1 => {
                    //Shutdown event triggered
                    return Err(Error::new(ErrorKind::Other, "Shutdown event triggered"));
                }
                _ => {
                    //This should never happen
                    // panic!(
                    //     "WaitForMultipleObjects returned unexpected value {:?}",
                    //     result
                    // );
                    continue;
                }
            }
        }
    }
    pub fn allocate_send_packet(self: &Arc<Self>, size: u16) -> Result<packet::Packet> {
        let ptr = unsafe {
            self.win_tun
                .WintunAllocateSendPacket(self.session.0, size as u32)
        };
        if ptr.is_null() {
            Err(Error::new(ErrorKind::Other, "allocate_send_packet failed"))
        } else {
            Ok(packet::Packet {
                //SAFETY: ptr is non null, aligned for u8, and readable for up to size bytes (which
                //must be less than isize::MAX because bytes is a u16
                bytes: unsafe { slice::from_raw_parts_mut(ptr, size as usize) },
                device: self.clone(),
                kind: packet::Kind::SendPacketPending,
            })
        }
    }
    pub fn send_packet(&self, mut packet: packet::Packet) {
        assert!(matches!(packet.kind, packet::Kind::SendPacketPending));

        unsafe {
            self.win_tun
                .WintunSendPacket(self.session.0, packet.bytes.as_ptr())
        };
        //Mark the packet at sent
        packet.kind = packet::Kind::SendPacketSent;
    }
    pub fn get_read_wait_event(&self) -> Result<HANDLE> {
        Ok(*self.read_event.get_or_init(|| unsafe {
            HANDLE(self.win_tun.WintunGetReadWaitEvent(self.session.0) as _)
        }))
    }
    pub fn delete_with_name_before_new(
        win_tun: &Arc<wintun_raw::wintun>,
        name_utf16: &Vec<u16>,
    ) -> Result<()> {
        let adapter = unsafe { win_tun.WintunOpenAdapter(name_utf16.as_ptr()) };
        if adapter.is_null() {
            tracing::warn!(
                "Could not find and clear the adapter for that name, {:?}",
                Error::last_os_error()
            );
            return Err(Error::new(ErrorKind::Other, "Failed to find and clear"));
        }
        unsafe { win_tun.WintunCloseAdapter(adapter) };
        unsafe { win_tun.WintunDeleteDriver() };
        Ok(())
    }
}
impl IFace for Device {
    fn version(&self) -> Result<String> {
        let version = unsafe { self.win_tun.WintunGetRunningDriverVersion() };
        if version == 0 {
            Err(Error::new(
                ErrorKind::Other,
                "WintunGetRunningDriverVersion",
            ))
        } else {
            Ok(format!("{}.{}", (version >> 16) & 0xFFFF, version & 0xFFFF))
        }
    }
    fn name(&self) -> Result<String> {
        let luid = self.luid;
        util::luid_to_alias(&unsafe { std::mem::transmute(luid) })
            .map(|name| util::decode_utf16(&name))
    }

    fn shutdown(&self) -> Result<()> {
        unsafe { SetEvent(self.shutdown_event)? };
        Ok(())
    }

    fn set_ip(&self, address: Ipv4Addr, mask: Ipv4Addr) -> Result<()> {
        netsh::set_interface_ip(self.index, &address, &mask)
    }

    fn mtu(&self) -> Result<u32> {
        Err(Error::from(ErrorKind::Unsupported))
    }

    fn set_mtu(&self, value: u32) -> Result<()> {
        netsh::set_adapter_mtu(self.index, value)
    }

    fn add_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr, metric: u16) -> Result<()> {
        netsh::add_route(self.index, dest, netmask, Ipv4Addr::UNSPECIFIED, metric)?;
        netsh::delete_cache()
    }

    fn delete_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr) -> Result<()> {
        netsh::delete_route(self.index, dest, netmask, Ipv4Addr::UNSPECIFIED)?;
        netsh::delete_cache()
    }

    fn read(self: &Arc<Self>, buf: &mut [u8]) -> Result<usize> {
        let packet = self.receive_blocking()?;
        let packet = packet.bytes();
        let len = packet.len();
        if len > buf.len() {
            return Err(Error::new(ErrorKind::InvalidData, "data too long"));
        }
        buf[..len].copy_from_slice(packet);
        Ok(len)
    }

    fn write(self: &Arc<Self>, buf: &[u8]) -> Result<usize> {
        let mut packet = self.allocate_send_packet(buf.len() as u16)?;
        packet.bytes_mut().copy_from_slice(buf);
        self.send_packet(packet);
        Ok(buf.len())
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        if let Err(e) = unsafe { CloseHandle(self.shutdown_event) } {
            tracing::warn!("close shutdown_event={:?}", e)
        }
        unsafe { self.win_tun.WintunEndSession(self.session.0) };
        unsafe { self.win_tun.WintunCloseAdapter(self.adapter.0) };
        if 1 != unsafe { self.win_tun.WintunDeleteDriver() } {
            tracing::warn!("WintunDeleteDriver failed")
        }
    }
}
