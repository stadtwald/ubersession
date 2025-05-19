use data_encoding::BASE64;
use ed25519_dalek::SigningKey;
use serde::de::Deserializer;
use serde::ser::Serializer;

use crate::serde::base64::FromBase64Visitor;

pub fn deserialize<'a, D>(deserializer: D) -> Result<SigningKey, D::Error>
    where
        D: Deserializer<'a>
{
    deserializer.deserialize_str(FromBase64Visitor::new("base64-encoded ed25519 private key"))
}

pub fn serialize<S>(value: &SigningKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
{
    serializer.serialize_str(BASE64.encode(value.as_bytes()).as_str())
}


