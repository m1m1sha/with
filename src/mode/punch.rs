use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub enum PunchMode {
    #[default]
    All,
    IPv4,
    IPv6,
}
