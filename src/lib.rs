pub mod channel;
pub mod config;
pub mod external;
pub mod handler;
pub mod mode;
pub mod proto;
pub mod proxy;
pub mod tun;

pub const WITH_VERSION: &str = env!("CARGO_PKG_VERSION");
