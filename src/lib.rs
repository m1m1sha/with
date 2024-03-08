pub mod channel;
pub mod config;
pub mod external;
pub mod handler;
pub mod mode;
pub mod proto;
pub mod proxy;

pub const WITH_VERSION: &'static str = env!("CARGO_PKG_VERSION");
