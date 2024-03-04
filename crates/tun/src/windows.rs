use std::{
    slice,
    sync::{Arc, OnceLock},
};

use libloading::Library;
use windows::{
    core::{PCSTR, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, GetLastError, ERROR_NO_MORE_ITEMS, FALSE, HANDLE, WIN32_ERROR},
        NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH,
        System::{Com::CLSIDFromString, Threading::CreateEventA},
    },
};

pub mod device;
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
    pub fn new(name: String, path: String) -> std::io::Result<Self> {
        let library = match unsafe { Library::new(path.clone()) } {
            Ok(library) => library,
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("wintun.dll not found in path: {}, {:?}", path, e),
                ));
            }
        };

        let win_tun = match unsafe { wintun_raw::wintun::from_library(library) } {
            Ok(win_tun) => Arc::new(win_tun),
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("library error {:?} ", e),
                ));
            }
        };

        let name_utf16 = util::encode_utf16(&name);
        if name_utf16.len() > MAX_POOL {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("too long {}:{:?}", MAX_POOL, name),
            ));
        }

        log::set_default_logger_if_unset(&win_tun);
        let _ = Self::delete_with_name_before_new(&win_tun, &name_utf16);

        let adapter = unsafe { win_tun.WintunOpenAdapter(name_utf16.as_ptr()) };
        if adapter.is_null() {
            tracing::error!("adapter.is_null {:?}", std::io::Error::last_os_error());
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to crate adapter",
            ));
        }

        let mut guid = None;
        util::get_adapters_addresses(|address: IP_ADAPTER_ADDRESSES_LH| {
            let friendly_name = PCWSTR(address.FriendlyName.0 as *const u16);
            let friendly_name = unsafe {
                match friendly_name.to_string() {
                    Ok(name) => name,
                    Err(_) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("get adapter address error"),
                        ))
                    }
                }
            };

            if friendly_name == name {
                let adapter_name = unsafe {
                    match address.AdapterName.to_string() {
                        Ok(name) => name,
                        Err(_) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                format!("get adapter name error"),
                            ))
                        }
                    }
                };
                let adapter_name_utf16: Vec<u16> = adapter_name
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                let adapter_name_ptr: *const u16 = adapter_name_utf16.as_ptr();
                let adapter = unsafe { CLSIDFromString(PCWSTR(adapter_name_ptr))? };
                guid = Some(adapter);
            }
            Ok(())
        })?;

        let guid = match guid.ok_or("Unable to find matching GUID") {
            Ok(guid) => guid.to_u128(),
            Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
        };

        let session = unsafe { win_tun.WintunStartSession(adapter, MAX_RING_CAPACITY) };
        if session.is_null() {
            tracing::error!("session.is_null {:?}", std::io::Error::last_os_error());
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "WintunStartSession failed",
            ));
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
    pub fn try_receive(self: &Arc<Self>) -> std::io::Result<Option<packet::Packet>> {
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
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "try_receive failed",
                ))
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
    pub fn delete_with_name_before_new(
        win_tun: &Arc<wintun_raw::wintun>,
        name_utf16: &Vec<u16>,
    ) -> std::io::Result<()> {
        let adapter = unsafe { win_tun.WintunOpenAdapter(name_utf16.as_ptr()) };
        if adapter.is_null() {
            tracing::error!(
                "delete_for_name adapter.is_null {:?}",
                std::io::Error::last_os_error()
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to open adapter",
            ));
        }
        unsafe { win_tun.WintunCloseAdapter(adapter) };
        unsafe { win_tun.WintunDeleteDriver() };
        Ok(())
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if let Err(e) = unsafe { CloseHandle(self.shutdown_event) } {
            tracing::warn!("close shutdown_event={:?}", e)
        }
        unsafe { self.win_tun.WintunEndSession(self.session.0) };
        unsafe { self.win_tun.WintunCloseAdapter(self.adapter.0) };
        if 0 != unsafe { self.win_tun.WintunDeleteDriver() } {
            tracing::warn!("WintunDeleteDriver failed")
        }
    }
}
