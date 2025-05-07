use serde::{Deserialize, Serialize};

#[derive(Clone)]
#[derive(Deserialize, Serialize)]
#[serde(tag = "what", rename = "keypair")]
pub struct Keypair {
    pub algo: String,
    pub private_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>
}

#[derive(Clone)]
#[derive(Deserialize, Serialize)]
#[serde(tag = "what", rename = "public_key")]
pub struct PublicKey {
    pub algo: String,
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>
}

