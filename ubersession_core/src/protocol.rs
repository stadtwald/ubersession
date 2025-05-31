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

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::header_string::StaticHeaderString;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(try_from = "&str", into = "&'static str")]
pub enum Protocol {
    Http,
    Https
}

impl From<Protocol> for &'static str {
    fn from(value: Protocol) -> Self {
        match value {
            Protocol::Http => "http",
            Protocol::Https => "https"
        }
    }
}

#[derive(Clone, Debug, Error)]
#[error("Protocol must be either http or https")]
pub struct InvalidProtocol;

impl TryFrom<&str> for Protocol {
    type Error = InvalidProtocol;

    fn try_from(value: &str) -> Result<Self, InvalidProtocol> {
        value.parse()
    }
}

impl std::str::FromStr for Protocol {
    type Err = InvalidProtocol;

    fn from_str(value: &str) -> Result<Self, InvalidProtocol> {
        if value == "http" {
            Ok(Protocol::Http)
        } else if value == "https" {
            Ok(Protocol::Https)
        } else {
            Err(InvalidProtocol)
        }
    }
}

const HTTP_SCHEME: StaticHeaderString = StaticHeaderString::from_static("http://");
const HTTPS_SCHEME: StaticHeaderString = StaticHeaderString::from_static("https://");

impl Protocol {
    pub fn is_secure(&self) -> bool {
        self == &Protocol::Https
    }

    pub fn url_prefix(&self) -> StaticHeaderString {
        use Protocol::*;
        match self {
            &Http => HTTP_SCHEME,
            &Https => HTTPS_SCHEME
        }
    }

    pub fn default_port(&self) -> u16 {
        use Protocol::*;
        match self {
            &Http => 80,
            &Https => 443
        }
    }
}

