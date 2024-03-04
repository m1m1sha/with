use std::sync::Arc;

use windows::{
    core::GUID,
    Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, WIN32_ERROR},
        NetworkManagement::{
            IpHelper::{
                ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToGuid,
                ConvertInterfaceLuidToIndex, GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS,
                GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
            },
            Ndis::NET_LUID_LH,
        },
        Networking::WinSock::AF_UNSPEC,
    },
};

use super::wintun_raw;

pub fn encode_utf16(string: &str) -> Vec<u16> {
    use std::iter::once;
    string.encode_utf16().chain(once(0)).collect()
}

pub fn decode_utf16(string: &[u16]) -> String {
    let end = string.iter().position(|b| *b == 0).unwrap_or(string.len());
    String::from_utf16_lossy(&string[..end])
}

pub(crate) fn get_adapters_addresses<F>(mut callback: F) -> std::io::Result<()>
where
    F: FnMut(IP_ADAPTER_ADDRESSES_LH) -> std::io::Result<()>,
{
    let mut size = 0;
    let flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    let family = AF_UNSPEC.0 as u32;

    // Make an initial call to GetAdaptersAddresses to get the
    // size needed into the size variable
    let result = unsafe { GetAdaptersAddresses(family, flags, None, None, &mut size) };

    if WIN32_ERROR(result) != ERROR_BUFFER_OVERFLOW {
        WIN32_ERROR(result).ok()?;
    }
    // Allocate memory for the buffer
    let mut addresses: Vec<u8> = vec![0; (size + 4) as usize];

    // Make a second call to GetAdaptersAddresses to get the actual data we want
    let result = unsafe {
        let addr = Some(addresses.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH);
        GetAdaptersAddresses(family, flags, None, addr, &mut size)
    };

    WIN32_ERROR(result).ok()?;

    // If successful, output some information from the data we received
    let mut current_addresses = addresses.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !current_addresses.is_null() {
        unsafe {
            callback(*current_addresses)?;
            current_addresses = (*current_addresses).Next;
        }
    }
    Ok(())
}

pub(crate) fn get_adapter_luid(
    wintun: &Arc<wintun_raw::wintun>,
    adapter: wintun_raw::WINTUN_ADAPTER_HANDLE,
) -> NET_LUID_LH {
    let mut luid: wintun_raw::NET_LUID = unsafe { std::mem::zeroed() };
    unsafe { wintun.WintunGetAdapterLUID(adapter, &mut luid as *mut wintun_raw::NET_LUID) };
    unsafe { std::mem::transmute(luid) }
}

pub fn luid_to_index(luid: &NET_LUID_LH) -> std::io::Result<u32> {
    let mut index = 0;

    match unsafe { ConvertInterfaceLuidToIndex(luid, &mut index) } {
        WIN32_ERROR(0) => Ok(index),
        err => Err(std::io::Error::from_raw_os_error(err.0 as i32)),
    }
}

pub fn luid_to_guid(luid: &NET_LUID_LH) -> std::io::Result<GUID> {
    let mut guid = unsafe { std::mem::zeroed() };

    match unsafe { ConvertInterfaceLuidToGuid(luid, &mut guid) } {
        WIN32_ERROR(0) => Ok(guid),
        err => Err(std::io::Error::from_raw_os_error(err.0 as i32)),
    }
}

pub fn luid_to_alias(luid: &NET_LUID_LH) -> std::io::Result<Vec<u16>> {
    // IF_MAX_STRING_SIZE + 1
    let mut alias = vec![0; 257];

    match unsafe { ConvertInterfaceLuidToAlias(luid, &mut alias) } {
        WIN32_ERROR(0) => Ok(alias),
        err => Err(std::io::Error::from_raw_os_error(err.0 as i32)),
    }
}
