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

use data_encoding::BASE64;
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

        let bytes: Vec<u8> = BASE64.decode(value.as_bytes()).map_err(|_| E::invalid_value(Unexpected::Str(value), &self))?;
        Ok(bytes.as_slice().try_into().map_err(|_| E::invalid_value(Unexpected::Str(value), &self))?)
    }
}

