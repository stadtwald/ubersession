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

use http::header::{HeaderMap, HeaderName, HeaderValue, COOKIE};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use std::fmt::{Display, Formatter, Write};

const COOKIE_OCTET: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b',').add(b';').add(b'\\');
const TOKEN_OCTET: &AsciiSet = &CONTROLS.add(b' ').add(b'(').add(b')').add(b'<').add(b'>').add(b'@').add(b',').add(b';').add(b':').add(b'\\').add(b'"').add(b'/').add(b'[').add(b']').add(b'?').add(b'=').add(b'{').add(b'}');

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CookieName(String);

impl CookieName {
    pub fn escape_str(value: &str) -> Self {
        Self(utf8_percent_encode(value, TOKEN_OCTET).to_string())
    }

    pub fn as_str<'a>(&'a self) -> &'a str {
        self.as_ref()
    }
}

impl Display for CookieName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<CookieName> for String {
    fn from(CookieName(value): CookieName) -> Self {
        value
    }
}

impl AsRef<str> for CookieName {
    fn as_ref<'a>(&'a self) -> &'a str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CookieValue(String);

impl CookieValue {
    pub fn escape_str(value: &str) -> Self {
        Self(utf8_percent_encode(value, COOKIE_OCTET).to_string())
    }

    pub fn unescape_str(&self) -> Result<String, std::str::Utf8Error> {
        Ok(percent_decode_str(&self.0).decode_utf8()?.to_string())
    }

    pub fn as_str<'a>(&'a self) -> &'a str {
        self.as_ref()
    }
}

impl Display for CookieValue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<CookieValue> for String {
    fn from(CookieValue(value): CookieValue) -> Self {
        value
    }
}

impl AsRef<str> for CookieValue {
    fn as_ref<'a>(&'a self) -> &'a str {
        &self.0
    }
}

pub struct CookieOptions {
    secure: bool,
    max_age: Option<i32>,
}

impl CookieOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn secure(mut self) -> Self {
        self.secure = true;
        self
    }

    pub fn with_max_age(mut self, max_age: i32) -> Self {
        self.max_age = Some(max_age);
        self
    }
}

impl Default for CookieOptions {
    fn default() -> Self {
        Self {
            secure: false,
            max_age: None
        }
    }
}

impl Display for CookieOptions {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        if self.secure {
            formatter.write_str("; Secure")?;
        }

        if let Some(max_age) = self.max_age {
            formatter.write_fmt(format_args!("; Max-Age={}", max_age))?;
        }

        Ok(())
    }
}

pub struct SetCookie {
    name: CookieName,
    value: CookieValue,
    options: CookieOptions
}

impl SetCookie {
    pub fn new(name: CookieName, value: CookieValue) -> Self {
        Self {
            name: name,
            value: value,
            options: CookieOptions::default()
        }
    }

    pub fn with_options(mut self, options: CookieOptions) -> Self {
        self.options = options;
        self
    }
}

impl Display for SetCookie {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        self.name.fmt(formatter)?;
        formatter.write_char('=')?;
        self.value.fmt(formatter)?;
        self.options.fmt(formatter)
    }
}

pub trait CookieHeaderSource {
    fn extract_cookie(&self, name: &CookieName) -> Option<CookieValue>;
}

impl CookieHeaderSource for HeaderMap {
    fn extract_cookie(&self, name: &CookieName) -> Option<CookieValue> {
        let mut m_value = None;

        for raw_cookie_header_value in self.get_all(COOKIE) {
            if let Some(cookie_header_value) = raw_cookie_header_value.to_str().ok() {
                for kv_pair in cookie_header_value.split("; ") {
                    if let Some((key, value)) = kv_pair.split_once('=') {
                        if name.as_str() == key {
                            m_value = Some(CookieValue(value.to_owned()));
                            break;
                        }
                    }
                }
                if m_value.is_some() {
                    break;
                }
            }
        }

        m_value
    }
}


