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

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error)]
#[error("Signing algorithm must be ed25519")]
pub struct InvalidSigningAlgoId;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(try_from = "&str", into = "&'static str")]
pub struct Ed25519SigningAlgo;

impl From<Ed25519SigningAlgo> for &'static str {
    fn from(_value: Ed25519SigningAlgo) -> &'static str {
        "ed25519"
    }
}

impl<'a> TryFrom<&'a str> for Ed25519SigningAlgo {
    type Error = InvalidSigningAlgoId;

    fn try_from(value: &'a str) -> Result<Self, InvalidSigningAlgoId> {
        if value == "ed25519" {
            Ok(Ed25519SigningAlgo)
        } else {
            Err(InvalidSigningAlgoId)
        }
    }
}

impl Display for Ed25519SigningAlgo {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ed25519")
    }
}

#[derive(Clone)]
#[derive(Deserialize, Serialize)]
#[serde(tag = "what", rename = "keypair")]
pub struct Keypair {
    pub algo: Ed25519SigningAlgo,
    #[serde(with = "crate::serde::signing_key")]
    pub private_key: SigningKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>
}

#[derive(Clone)]
#[derive(Deserialize, Serialize)]
#[serde(tag = "what", rename = "public_key")]
pub struct PublicKey {
    pub algo: Ed25519SigningAlgo,
    #[serde(with = "crate::serde::public_key")]
    pub public_key: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>
}

