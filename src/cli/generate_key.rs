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
use rand::rngs::OsRng;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use crate::keypair::{Keypair, PublicKey};

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
        let verifying_key = signing_key.verifying_key();
        let keypair =
            Keypair {
                algo: "ed25519".to_owned(),
                private_key: signing_key,
                comment: self.comment
            };
        let keypair_encoded = serde_json::to_string_pretty(&keypair)?;
        let public_key =
            PublicKey {
                algo: "ed25519".to_owned(),
                public_key: *verifying_key.as_bytes(),
                comment: keypair.comment
            };
        let public_key_encoded = serde_json::to_string_pretty(&public_key)?;
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

        file.write_all(&keypair_encoded.as_bytes())?;

        if !self.quiet {
            println!("{}", public_key_encoded);
        }

        Ok(())
    }
}

