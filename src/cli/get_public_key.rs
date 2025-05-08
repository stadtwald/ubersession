use clap::Args;
use data_encoding::BASE64URL_NOPAD;
use std::io::Read;
use std::path::PathBuf;

#[derive(Clone, Debug)]
#[derive(Args)]
pub struct GetPublicKey {
    /// Where to load the private key from (otherwise reads from stdin)
    #[arg()]
    pub private_key_file: Option<PathBuf>
}

impl GetPublicKey {
    pub fn run(self) -> anyhow::Result<()> {
        let raw_input =
            if let Some(ref path) = self.private_key_file {
                std::fs::read(path)?
            } else {
                let mut buf = Vec::with_capacity(4096);
                std::io::stdin().read_to_end(&mut buf)?;
                buf
            };
        let keypair_description: crate::wire::Keypair = serde_json::from_slice(&raw_input)?;
        let signing_key = keypair_description.try_loading_signing_key()?;
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

