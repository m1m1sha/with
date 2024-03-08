use super::wintun_raw;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use windows::core::PWSTR;

/// Sets the logger wintun will use when logging. Maps to the WintunSetLogger C function
pub fn set_logger(wintun: &Arc<wintun_raw::wintun>, f: wintun_raw::WINTUN_LOGGER_CALLBACK) {
    unsafe { wintun.WintunSetLogger(f) };
}

#[allow(dead_code)]
pub fn reset_logger(wintun: &Arc<wintun_raw::wintun>) {
    set_logger(wintun, None);
}

static SET_LOGGER: AtomicBool = AtomicBool::new(false);

/// The logger that is active by default. Logs messages to the log crate
///
/// # Safety
/// `message` must be a valid pointer that points to an aligned null terminated UTF-16 string
pub unsafe extern "stdcall" fn default_logger(
    level: wintun_raw::WINTUN_LOGGER_LEVEL,
    _timestamp: wintun_raw::DWORD64,
    message: *const wintun_raw::WCHAR,
) {
    //Wintun will always give us a valid UTF16 null termineted string
    let utf8_msg = PWSTR(message as *mut u16)
        .to_string()
        .unwrap_or_else(|e| e.to_string());
    match level {
        wintun_raw::WINTUN_LOGGER_LEVEL_WINTUN_LOG_INFO => tracing::info!("WinTun: {}", utf8_msg),
        wintun_raw::WINTUN_LOGGER_LEVEL_WINTUN_LOG_WARN => tracing::warn!("WinTun: {}", utf8_msg),
        wintun_raw::WINTUN_LOGGER_LEVEL_WINTUN_LOG_ERR => tracing::error!("WinTun: {}", utf8_msg),
        _ => tracing::debug!("WinTun: {} (with invalid log level {})", utf8_msg, level),
    }
}

pub(crate) fn set_default_logger_if_unset(wintun: &Arc<wintun_raw::wintun>) {
    if SET_LOGGER
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
        .is_ok()
    {
        set_logger(wintun, Some(default_logger));
    }
}
