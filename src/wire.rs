use serde::{Deserialize, Serialize};

#[derive(Clone)]
#[derive(Deserialize, Serialize)]
#[serde(tag = "what", rename = "keypair")]
pub struct Keypair {
    pub version: i32,
    pub algo: String,
    pub private_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>
}

