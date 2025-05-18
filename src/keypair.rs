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

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde::de::{Deserializer, Visitor};
use serde::ser::Serializer;
use std::fmt::Formatter;

struct SigningKeyFromBase64Visitor;

impl<'a> Visitor<'a> for SigningKeyFromBase64Visitor {
    type Value = SigningKey;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("URL-safe base64-encoded ed25519 private key")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error {
        use serde::de::Unexpected;

        let bytes: Vec<u8> = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| E::invalid_value(Unexpected::Str(value), &self))?;
        let signing_key = SigningKey::from_bytes(bytes.as_slice().try_into().map_err(|_| E::invalid_value(Unexpected::Str(value), &self))?);
        Ok(signing_key)
    }
}

fn deserialize_signing_key_from_base64<'a, D>(deserializer: D) -> Result<SigningKey, D::Error>
    where
        D: Deserializer<'a>
{
    deserializer.deserialize_str(SigningKeyFromBase64Visitor)
}

fn serialize_signing_key_to_base64<S>(value: &SigningKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
{
    serializer.serialize_str(BASE64URL_NOPAD.encode(value.as_bytes()).as_str())
}

struct PublicKeyFromBase64Visitor;

impl<'a> Visitor<'a> for PublicKeyFromBase64Visitor {
    type Value = [u8; 32];

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("URL-safe base64-encoded ed25519 public key")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error {
        use serde::de::Unexpected;

        let bytes: Vec<u8> = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| E::invalid_value(Unexpected::Str(value), &self))?;
        let public_key = bytes.as_slice().try_into().map_err(|_| E::invalid_value(Unexpected::Str(value), &self))?;
        Ok(public_key)
    }
}

fn deserialize_public_key_from_base64<'a, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'a>
{
    deserializer.deserialize_str(PublicKeyFromBase64Visitor)
}

fn serialize_public_key_to_base64<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
{
    serializer.serialize_str(BASE64URL_NOPAD.encode(value).as_str())
}


#[derive(Clone)]
#[derive(Deserialize, Serialize)]
#[serde(tag = "what", rename = "keypair")]
pub struct Keypair {
    pub algo: String,
    #[serde(
        deserialize_with = "deserialize_signing_key_from_base64",
        serialize_with = "serialize_signing_key_to_base64"
    )]
    pub private_key: SigningKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>
}

#[derive(Clone)]
#[derive(Deserialize, Serialize)]
#[serde(tag = "what", rename = "public_key")]
pub struct PublicKey {
    pub algo: String,
    #[serde(
        deserialize_with = "deserialize_public_key_from_base64",
        serialize_with = "serialize_public_key_to_base64"
    )]
    pub public_key: [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>
}

