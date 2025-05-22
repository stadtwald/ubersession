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

use http::header::{HeaderMap, HOST};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error)]
pub enum InvalidHostName {
    #[error("Host name must not be empty")]
    NoLabels,

    #[error("Each host name component must not be empty")]
    EmptyLabel,

    #[error("Each host name component must only contain allowed characters")]
    InvalidLabel
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[derive(Deserialize, Serialize)]
#[serde(try_from = "&str", into = "String")]
pub struct HostName(String);

impl HostName {
    pub fn new(value: &str) -> Result<Self, InvalidHostName> {
        let value = value.to_ascii_lowercase();
        if value.len() == 0 {
            Err(InvalidHostName::NoLabels)
        } else {
            for part in value.split('.') {
                if part.len() == 0 {
                    return Err(InvalidHostName::EmptyLabel);
                } else if !part.chars().all(|x| (x >= 'a' && x <= 'z') || (x >= 'A' && x <= 'Z') || (x >= '0' && x <= '9') || x == '-' || x == '_') {
                    return Err(InvalidHostName::InvalidLabel);
                }
            }
            Ok(Self(value))
        }
    }

    pub fn as_str<'a>(&'a self) -> &'a str {
        self.0.as_str()
    }
}

impl Display for HostName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::str::FromStr for HostName {
    type Err = InvalidHostName;

    fn from_str(value: &str) -> Result<Self, InvalidHostName> {
        Self::new(value)
    }
}

impl TryFrom<&str> for HostName {
    type Error = InvalidHostName;

    fn try_from(value: &str) -> Result<Self, InvalidHostName> {
        value.parse()
    }
}

impl From<HostName> for String {
    fn from(value: HostName) -> Self {
        value.0
    }
}

pub trait HostNameSource {
    fn extract_host_name(&self) -> Option<HostName>;
}

impl HostNameSource for HeaderMap {
    fn extract_host_name(&self) -> Option<HostName> {
        let header_value = self.get(HOST)?.to_str().ok()?;

        if let Some((first, _port)) = header_value.rsplit_once(':') {
            first.parse().ok()
        } else {
            header_value.parse().ok()
        }
    }
}

