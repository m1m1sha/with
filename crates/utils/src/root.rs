/// 使用 https://github.com/spa5k/is_sudo/blob/main/src/window.rs
use std::io::Error;

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

// Use std::io::Error::last_os_error for errors.
// NOTE: For this example I'm simple passing on the OS error.
// However, customising the error could provide more context

/// Returns true if the current process has admin rights, otherwise false.
pub fn is_elevated() -> bool {
    _is_elevated().unwrap_or(false)
}

/// On success returns a bool indicating if the current process has admin rights.
/// Otherwise returns an OS error.
///
/// This is unlikely to fail but if it does it's even more unlikely that you have admin permissions anyway.
/// Therefore the public function above simply eats the error and returns a bool.
fn _is_elevated() -> Result<bool, Error> {
    let token = QueryAccessToken::from_current_process()?;
    token.is_elevated()
}

/// A safe wrapper around querying Windows access tokens.
pub struct QueryAccessToken(HANDLE);

impl QueryAccessToken {
    pub fn from_current_process() -> Result<Self, Error> {
        let mut handle: HANDLE = HANDLE::default();
        match unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } {
            Ok(_) => Ok(Self(handle)),
            Err(_) => Err(Error::last_os_error()),
        }
    }

    /// On success returns a bool indicating if the access token has elevated privilidges.
    /// Otherwise returns an OS error.
    pub fn is_elevated(&self) -> Result<bool, Error> {
        let mut elevation = TOKEN_ELEVATION::default();
        let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let mut ret_size = size;
        // The weird looking repetition of `as *mut _` is casting the reference to a c_void pointer.
        match unsafe {
            GetTokenInformation(
                self.0,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                size,
                &mut ret_size,
            )
        } {
            Ok(_) => Ok(elevation.TokenIsElevated != 0),
            Err(_) => Err(Error::last_os_error()),
        }
    }
}

impl Drop for QueryAccessToken {
    fn drop(&mut self) {
        if self.0 != HANDLE::default() {
            unsafe {
                let _ = CloseHandle(self.0);
            };
        }
    }
}
