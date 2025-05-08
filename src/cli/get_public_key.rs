use clap::Args;
use data_encoding::BASE64URL_NOPAD;
use std::path::PathBuf;

#[derive(Clone, Debug)]
#[derive(Args)]
pub struct GetPublicKey {
    /// Where to load the private key from
    #[arg()]
    pub private_key_file: PathBuf
}

impl GetPublicKey {
    pub fn run(self) -> anyhow::Result<()> {
        let raw_input = std::fs::read(&self.private_key_file)?;
        let keypair_description: crate::wire::Keypair = serde_json::from_slice(&raw_input)?;
        if keypair_description.algo != "ed25519" {
            return Err(anyhow::anyhow!("Only ed25519 keypairs are supported"));
        }
        let signing_key_raw_bytes: [u8; 32] = BASE64URL_NOPAD.decode(&keypair_description.private_key.as_bytes())?.as_slice().try_into()?;
        
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_key_raw_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_description =
            crate::wire::PublicKey {
                algo: "ed25519".to_owned(),
                public_key: BASE64URL_NOPAD.encode(verifying_key.as_bytes()),
                comment: keypair_description.comment
            };
        let public_key_description_encoded = serde_json::to_string_pretty(&public_key_description)?;

        println!("{}", public_key_description_encoded);

        Ok(())
    }
}

