use std::{io::Result, net::Ipv4Addr, sync::Arc};

pub trait IFace {
    fn version(&self) -> Result<String>;
    fn name(&self) -> Result<String>;
    fn shutdown(&self) -> Result<()>;
    fn set_ip(&self, address: Ipv4Addr, mask: Ipv4Addr) -> Result<()>;
    fn mtu(&self) -> Result<u32>;
    fn set_mtu(&self, value: u32) -> Result<()>;
    fn add_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr, metric: u16) -> Result<()>;
    fn delete_route(&self, dest: Ipv4Addr, netmask: Ipv4Addr) -> Result<()>;
    fn read(self: &Arc<Self>, buf: &mut [u8]) -> Result<usize>;
    fn write(self: &Arc<Self>, buf: &[u8]) -> Result<usize>;
}
