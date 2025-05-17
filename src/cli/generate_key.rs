/*
 * Copyright (c) 2025 William Stadtwald Demchick <william.demchick@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

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
    /// Where to output the private key to
    #[arg(short = 'o', long)]
    pub private_key_file: PathBuf,

    /// Overwrite an existing file if it exists
    #[arg(short = 'f', long)]
    pub force: bool,

    /// Don't output the public key to stdout
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Comment to include alongside the keys (optional)
    #[arg(short = 'C', long)]
    pub comment: Option<String>
}

impl GenerateKey {
    pub fn run(self) -> anyhow::Result<()> {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let private_key = signing_key.as_bytes();
        let verifying_key = signing_key.verifying_key();
        let keypair_description =
            crate::wire::Keypair {
                algo: "ed25519".to_owned(),
                private_key: BASE64URL_NOPAD.encode(private_key),
                comment: self.comment
            };
        let keypair_description_encoded = serde_json::to_string_pretty(&keypair_description)?;
        let public_key_description =
            crate::wire::PublicKey {
                algo: "ed25519".to_owned(),
                public_key: BASE64URL_NOPAD.encode(verifying_key.as_bytes()),
                comment: keypair_description.comment
            };
        let public_key_description_encoded = serde_json::to_string_pretty(&public_key_description)?;
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

        if !self.quiet {
            println!("{}", public_key_description_encoded);
        }

        Ok(())
    }
}

