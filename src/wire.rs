use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::SigningKey;
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

impl Keypair {
    pub fn try_loading_signing_key(&self) -> anyhow::Result<SigningKey> {
        if self.algo != "ed25519" {
            return Err(anyhow::anyhow!("Only ed25519 keypairs are supported"));
        }

        let signing_key_raw_bytes: [u8; 32] = BASE64URL_NOPAD.decode(&self.private_key.as_bytes())?.as_slice().try_into()?;
        
        Ok(SigningKey::from_bytes(&signing_key_raw_bytes))
    }
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

