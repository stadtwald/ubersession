use chrono::Utc;
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde::de::{Deserializer, Visitor};
use serde::ser::Serializer;
use std::fmt::Formatter;
use uuid::Uuid;

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

        let public_key: Vec<u8> = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| E::invalid_value(Unexpected::Str(value), &self))?;
        let public_key = public_key.as_slice().try_into().map_err(|_| E::invalid_value(Unexpected::Str(value), &self))?;
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

struct SignatureFromBase64Visitor;

impl<'a> Visitor<'a> for SignatureFromBase64Visitor {
    type Value = Signature;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("URL-safe base64-encoded ed25519 signature")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error {
        use serde::de::Unexpected;

        let signature_bytes: Vec<u8> = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| E::invalid_value(Unexpected::Str(value), &self))?;
        let signature_bytes: [u8; 64] = signature_bytes.as_slice().try_into().map_err(|_| E::invalid_value(Unexpected::Str(value), &self))?;
        Ok(Signature::from_bytes(&signature_bytes))
    }
}

fn deserialize_signature_from_base64<'a, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'a>
{
    deserializer.deserialize_str(SignatureFromBase64Visitor)
}

fn serialize_signature_to_base64<S>(value: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
{
    serializer.serialize_str(BASE64URL_NOPAD.encode(&value.to_bytes()).as_str())
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct SessionToken {
    #[serde(
        deserialize_with = "deserialize_public_key_from_base64",
        serialize_with = "serialize_public_key_to_base64"
    )]
    pub public_key: [u8; 32],
    #[serde(
        deserialize_with = "deserialize_signature_from_base64",
        serialize_with = "serialize_signature_to_base64"
    )]
    pub signature: Signature,
    pub host: String, // secured
    pub expires: u32, // secured
    pub id: Uuid // secured
}

impl SessionToken {
    pub fn new(signing_key: &SigningKey, ttl: u32, host: String) -> Self {
        let current_timestamp = Utc::now().timestamp().try_into().unwrap_or(u32::MAX);
        let expiry_timestamp = current_timestamp.saturating_add(ttl);
        let mut session_token =
            Self {
                public_key: signing_key.verifying_key().as_bytes().clone(),
                signature: Signature::from_bytes(&[0u8; 64]),
                host: host,
                expires: expiry_timestamp,
                id: Uuid::new_v4()
            };
        session_token.signature = signing_key.sign(&session_token.signable_message());
        session_token
    }

    pub fn resign(&mut self, signing_key: &SigningKey) -> () {
        self.public_key = signing_key.verifying_key().as_bytes().clone();
        self.signature = signing_key.sign(&self.signable_message());
    }

    fn signable_message(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9 + 16 + 4 + self.host.len());
        buf.extend("UBERSESS".as_bytes());
        buf.push(0);
        buf.extend(&self.expires.to_be_bytes());
        buf.extend(self.id.as_bytes());
        buf.extend(self.host.as_bytes());
        buf
    }

    pub fn verify(&self, verifying_key: VerifyingKey) -> bool {
        let signable_message = self.signable_message();
        (&self.public_key == verifying_key.as_bytes()) && verifying_key.verify(&signable_message, &self.signature).is_ok()
    }
}


