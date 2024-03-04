use std::{net::Ipv4Addr, os::windows::process::CommandExt};
use windows::Win32::System::Threading::CREATE_NO_WINDOW;

pub fn cmd(args: &[&str]) -> std::io::Result<Vec<u8>> {
    let out = std::process::Command::new("netsh")
        .creation_flags(CREATE_NO_WINDOW.0)
        .args(args)
        .output()?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(if out.stderr.is_empty() {
            &out.stdout
        } else {
            &out.stderr
        });
        let info = format!("netsh failed with: \"{}\"", err);
        return Err(std::io::Error::new(std::io::ErrorKind::Other, info));
    }
    Ok(out.stdout)
}

/// 设置网卡mtu
pub fn set_adapter_mtu(name: &str, mtu: usize) -> std::io::Result<()> {
    let args = &[
        "interface",
        "ipv4",
        "set",
        "subinterface",
        &format!("\"{}\"", name),
        &format!("mtu={}", mtu),
        "store=persistent",
    ];
    cmd(args)?;
    Ok(())
}

/// 设置网卡名称
pub fn set_interface_name(old_name: &str, new_name: &str) -> std::io::Result<()> {
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

// 清楚缓存
pub fn delete_cache() -> std::io::Result<()> {
    let args = &["interface", "ip", "delete", "destinationcache"];
    cmd(args)?;
    Ok(())
}

/// 设置网卡ip
pub fn set_interface_ip(index: u32, address: &Ipv4Addr, netmask: &Ipv4Addr) -> std::io::Result<()> {
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
pub fn set_interface_metric(index: u32, metric: u16) -> std::io::Result<()> {
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
pub fn disabled_ipv6(index: u32) -> std::io::Result<()> {
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
) -> std::io::Result<()> {
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
) -> std::io::Result<()> {
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
