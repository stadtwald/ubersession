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
use std::io::Read;
use std::path::PathBuf;

use crate::keypair::{Keypair, PublicKey};

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
        let keypair: Keypair = serde_json::from_slice(&raw_input)?;
        let signing_key = keypair.private_key;
        let verifying_key = signing_key.verifying_key();
        let public_key_description =
            PublicKey {
                algo: "ed25519".to_owned(),
                public_key: *verifying_key.as_bytes(),
                comment: keypair.comment
            };
        let public_key_description_encoded = serde_json::to_string_pretty(&public_key_description)?;

        println!("{}", public_key_description_encoded);

        Ok(())
    }
}

