use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub enum ChannelMode {
    #[default]
    All,
    P2p,
    Relay,
}
