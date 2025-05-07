use clap::Args;
use data_encoding::BASE64URL_NOPAD;
use rand::rngs::OsRng;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

#[derive(Clone, Debug)]
#[derive(Args)]
pub struct GenerateKey {
    #[arg(short = 'o', long)]
    pub private_key_file: PathBuf,

    #[arg(short = 'f', long)]
    pub force: bool,

    #[arg(short = 'C', long)]
    pub comment: Option<String>
}

impl GenerateKey {
    pub fn run(self) -> anyhow::Result<()> {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let private_key = signing_key.as_bytes();
        let keypair_description = crate::wire::Keypair {
            version: 1,
            algo: "ed25519".to_owned(),
            private_key: BASE64URL_NOPAD.encode(private_key),
            comment: self.comment
        };
        let keypair_description_encoded = serde_json::to_string_pretty(&keypair_description)?;
        let mut file =
            if self.force {
                OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .mode(0o400)
                    .open(&self.private_key_file)?
            } else {
                OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o400)
                    .open(&self.private_key_file)?
            };

        file.write_all(&keypair_description_encoded.as_bytes())?;

        Ok(())
    }
}

