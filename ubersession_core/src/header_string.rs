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

use http::header::HeaderValue;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use thiserror::Error;

const fn valid_char(value: char) -> bool {
    (value >= '\x20' && value < '\x7F') || value == '\t'
}

#[derive(Clone, Debug, Error)]
#[error("Character not allowed in HTTP header")]
pub struct InvalidHeaderStringChar;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HeaderStringChar(char);

impl HeaderStringChar {
    pub const fn from_static(value: char) -> Self {
        if valid_char(value) {
            Self(value)
        } else {
            panic!("Character not allowed in HTTP header")
        }
    }
}

impl From<HeaderStringChar> for char {
    fn from(value: HeaderStringChar) -> Self {
        value.0
    }
}

impl PartialEq<char> for HeaderStringChar {
    fn eq(&self, other: &char) -> bool {
        &self.0 == other
    }
}

impl PartialEq<HeaderStringChar> for char {
    fn eq(&self, other: &HeaderStringChar) -> bool {
        self == &other.0
    }
}


impl TryFrom<char> for HeaderStringChar {
    type Error = InvalidHeaderStringChar;

    fn try_from(value: char) -> Result<Self, InvalidHeaderStringChar> {
        if !valid_char(value) {
            Err(InvalidHeaderStringChar)
        } else {
            Ok(Self(value))
        }
    }
}

/// A HTTP header value which is guaranteed to a valid string, too
/// Has a few utilities to infallibly manipulate things we already know are HeaderStrings.
#[derive(Clone, Debug, Eq, Hash)]
#[derive(Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct HeaderString(String);

impl HeaderString {
    pub fn new() -> Self {
        Self(String::new())
    }

    pub fn format_u8(value: u8) -> Self {
        Self::format_u64(value as u64)
    }

    pub fn format_u16(value: u16) -> Self {
        Self::format_u64(value as u64)
    }

    pub fn format_u32(value: u32) -> Self {
        Self::format_u64(value as u64)
    }

    pub fn format_u64(value: u64) -> Self {
        Self(format!("{}", value))
    }

    pub fn format_i8(value: i8) -> Self {
        Self::format_i64(value as i64)
    }

    pub fn format_i16(value: i16) -> Self {
        Self::format_i64(value as i64)
    }

    pub fn format_i32(value: i32) -> Self {
        Self::format_i64(value as i64)
    }

    pub fn format_i64(value: i64) -> Self {
        Self(format!("{}", value))
    }

    pub fn from_urlencoded<T: Serialize>(value: &T) -> Result<Self, serde_urlencoded::ser::Error> {
        serde_urlencoded::to_string(value).map(Self)
    }

    pub fn to_header_value(&self) -> HeaderValue {
        self.0.clone().try_into().unwrap()
    }

    pub fn as_str<'a>(&'a self) -> &'a str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn pop(&mut self) -> Option<HeaderStringChar> {
        self.0.pop().map(HeaderStringChar)
    }

    pub fn push(&mut self, c: HeaderStringChar) -> () {
        self.0.push(c.0);
    }

    pub fn push_str(&mut self, s: &HeaderString) -> () {
        self.0.push_str(&s.0)
    }

    pub fn push_urlencoded<T: Serialize>(&mut self, value: &T) -> Result<(), serde_urlencoded::ser::Error> {
        let s = serde_urlencoded::to_string(value)?;
        self.0.push_str(&s);
        Ok(())
    }

    fn validate(value: &str) -> Result<(), InvalidHeaderStringChar> {
        if value.chars().all(valid_char) {
            Ok(())
        } else {
            Err(InvalidHeaderStringChar)
        }
    }
}

impl Display for HeaderString {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<HeaderString> for HeaderValue {
    fn from(value: HeaderString) -> Self {
        value.0.try_into().unwrap()
    }
}

impl From<HeaderString> for String {
    fn from(value: HeaderString) -> Self {
        value.0
    }
}

impl std::str::FromStr for HeaderString {
    type Err = InvalidHeaderStringChar;

    fn from_str(value: &str) -> Result<Self, InvalidHeaderStringChar> {
        Self::validate(value)?;
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for HeaderString {
    type Error = InvalidHeaderStringChar;

    fn try_from(value: String) -> Result<Self, InvalidHeaderStringChar> {
        Self::validate(&value)?;
        Ok(Self(value))
    }
}

impl AsRef<str> for HeaderString {
    fn as_ref<'a>(&'a self) -> &'a str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Error)]
#[error("HTTP header cannot be represented as ASCII string")]
pub struct InvalidHeaderString;

impl TryFrom<HeaderValue> for HeaderString {
    type Error = InvalidHeaderString;

    fn try_from(value: HeaderValue) -> Result<Self, InvalidHeaderString> {
        Ok(Self(value.to_str().map_err(|_| InvalidHeaderString)?.to_owned()))
    }
}

#[derive(Clone, Copy, Debug, Eq)]
#[derive(Serialize)]
#[serde(into = "&str")]
pub struct StaticHeaderString(&'static str);

impl StaticHeaderString {
    pub const fn from_static(value: &'static str) -> Self {
        let mut i = 0usize;

        let bytes = value.as_bytes();

        while i < bytes.len() {
            if !valid_char(bytes[i] as char) {
                panic!("Character not allowed in HTTP header");
            }
            i += 1;
        }

        Self(value)
    }

    pub fn to_header_string(&self) -> HeaderString {
        HeaderString(self.0.to_owned())
    }

    pub fn to_header_value(&self) -> HeaderValue {
        self.0.to_owned().try_into().unwrap()
    }

    pub fn as_str<'a>(&'a self) -> &'a str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Display for StaticHeaderString {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl From<StaticHeaderString> for &'static str {
    fn from(value: StaticHeaderString) -> &'static str {
        value.0
    }
}

impl AsRef<str> for StaticHeaderString {
    fn as_ref<'a>(&'a self) -> &'a str {
        self.0
    }
}

impl<T: AsRef<str>> PartialEq<T> for HeaderString {
    fn eq(&self, other: &T) -> bool {
        self.0.as_str() == other.as_ref()
    }
}

impl<T: AsRef<str>> PartialEq<T> for StaticHeaderString {
    fn eq(&self, other: &T) -> bool {
        self.0 == other.as_ref()
    }
}

