// 参考
// https://github.com/meh/rust-tun
// https://github.com/Tazdevil971/tap-windows
// https://github.com/nulldotblack/wintun
// https://github.com/lbl8603/vnt
pub mod device;
#[cfg(target_os = "windows")]
pub mod windows;
