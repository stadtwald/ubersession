use data_encoding::BASE64;
use serde::de::Deserializer;
use serde::ser::Serializer;

use crate::serde::base64::FromBase64Visitor;

pub fn deserialize<'a, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'a>
{
    deserializer.deserialize_str(FromBase64Visitor::new("base64-encoded ed25519 public key"))
}

pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
{
    serializer.serialize_str(BASE64.encode(value).as_str())
}


