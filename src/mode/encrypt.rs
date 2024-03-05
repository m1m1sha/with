use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub enum EncryptMode {
    #[default]
    None,
}
