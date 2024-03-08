use std::io;
use std::sync::Arc;

use nat::tun::device::IFace;
use nat::tun::Device;

use crate::config::Config;

const DEFAULT_TUN_NAME: &str = "with-tun";

pub fn create_device(config: &Config) -> io::Result<Arc<Device>> {
    #[cfg(target_os = "macos")]
    let device = Arc::new(Device::new(config.device_name.clone())?);
    #[cfg(target_os = "windows")]
    let device = Arc::new(Device::new(DEFAULT_TUN_NAME.to_owned(), None)?);
    #[cfg(target_os = "android")]
    let device = Arc::new(Device::new(config.device_fd as _)?);
    #[cfg(not(target_os = "android"))]
    {
        let mtu = if config.mtu == 0 || config.passwd.is_empty() {
            1450
        } else {
            1410
        };
        device.set_mtu(mtu)?;
    }
    Ok(device)
}
