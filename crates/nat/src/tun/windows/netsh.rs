use encoding::{all::GBK, DecoderTrap, Encoding};
use std::{
    io::{Error, ErrorKind, Result},
    net::Ipv4Addr,
    os::windows::process::CommandExt,
};
use windows::Win32::System::Threading::CREATE_NO_WINDOW;

pub fn cmd(args: &[&str]) -> Result<Vec<u8>> {
    let out = std::process::Command::new("netsh")
        .creation_flags(CREATE_NO_WINDOW.0)
        .args(args)
        .output()?;
    if !out.status.success() {
        let stdout = if out.stderr.is_empty() {
            &out.stdout
        } else {
            &out.stderr
        };
        let mut err = String::from_utf8_lossy(stdout).to_string();

        if err.contains('�') {
            err = GBK
                .decode(stdout, DecoderTrap::Strict)
                .unwrap_or(err.to_string());
        }

        let info = format!("netsh failed with: \"{}\"", err);
        return Err(Error::new(ErrorKind::Other, info));
    }
    Ok(out.stdout)
}

/// 设置网卡mtu
pub fn set_adapter_mtu(index: u32, mtu: u32) -> Result<()> {
    let args = &[
        "interface",
        "ipv4",
        "set",
        "subinterface",
        &format!("{}", index),
        &format!("mtu={}", mtu),
        "store=persistent",
    ];
    cmd(args)?;
    Ok(())
}

/// 设置网卡名称
pub fn set_interface_name(old_name: &str, new_name: &str) -> Result<()> {
    let args = &[
        "interface",
        "set",
        "interface",
        &format!("name=\"{}\"", old_name),
        &format!("newname=\"{}\"", new_name),
    ];
    cmd(args)?;
    Ok(())
}

// 清除缓存
pub fn delete_cache() -> Result<()> {
    let args = &["interface", "ip", "delete", "destinationcache"];
    cmd(args)?;
    Ok(())
}

/// 设置网卡ip
pub fn set_interface_ip(index: u32, address: &Ipv4Addr, netmask: &Ipv4Addr) -> Result<()> {
    let args = &[
        "interface",
        "ip",
        "set",
        "address",
        &format!("{}", index),
        "static",
        &format!("\"{:?}\"", address),
        &format!("\"{:?}\"", netmask),
    ];
    cmd(args)?;
    Ok(())
}

/// 设置网卡跃点
pub fn set_interface_metric(index: u32, metric: u16) -> Result<()> {
    let args = &[
        "interface",
        "ip",
        "set",
        "interface",
        &format!("{}", index),
        &format!("metric={}", metric),
    ];
    cmd(args)?;
    Ok(())
}

/// 禁用ipv6
pub fn disabled_ipv6(index: u32) -> Result<()> {
    let args = &[
        "interface",
        "ipv6",
        "set",
        "interface",
        &format!("{}", index),
        "disabled",
    ];
    cmd(args)?;
    Ok(())
}

/// 添加路由
pub fn add_route(
    index: u32,
    dest: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
    metric: u16,
) -> Result<()> {
    let args = &[
        "route",
        "add",
        &format!("{}", dest),
        "mask",
        &format!("{}", netmask),
        &format!("{}", gateway),
        "metric",
        &format!("{}", metric),
        "if",
        &format!("{}", index),
    ];
    cmd(args)?;
    Ok(())
}

/// 删除路由
pub fn delete_route(
    index: u32,
    dest: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
) -> Result<()> {
    let args = &[
        "route",
        "delete",
        &format!("{}", dest),
        "mask",
        &format!("{}", netmask),
        &format!("{}", gateway),
        "if",
        &format!("{}", index),
    ];
    cmd(args)?;
    Ok(())
}
