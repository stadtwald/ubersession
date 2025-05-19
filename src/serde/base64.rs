use data_encoding::BASE64URL_NOPAD;
use serde::de::Visitor;
use std::fmt::Formatter;
use std::marker::PhantomData;

pub struct FromBase64Visitor<T> {
    expecting_message: &'static str,
    _t: PhantomData<T>
}

impl<T> FromBase64Visitor<T> {
    pub fn new(expecting_message: &'static str) -> Self {
        Self {
            expecting_message: expecting_message,
            _t: PhantomData
        }
    }
}

impl<'a, T> Visitor<'a> for FromBase64Visitor<T>
    where
        T: for<'b> TryFrom<&'b [u8]> {
    type Value = T;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.expecting_message)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error {
        use serde::de::Unexpected;

        let bytes: Vec<u8> = BASE64URL_NOPAD.decode(value.as_bytes()).map_err(|_| E::invalid_value(Unexpected::Str(value), &self))?;
        Ok(bytes.as_slice().try_into().map_err(|_| E::invalid_value(Unexpected::Str(value), &self))?)
    }
}

