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

use std::fmt::{Display, Formatter};
use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum InvalidPathPrefix {
    #[error("Path prefix cannot be empty")]
    Empty,

    #[error("Path prefix must start with forward slash")]
    NoInitialSlash
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PathPrefix(String);

impl PathPrefix {
    fn validate(value: &str) -> Result<(), InvalidPathPrefix> {
        if value.len() == 0 {
            Err(InvalidPathPrefix::Empty)
        } else if !value.starts_with('/') {
            Err(InvalidPathPrefix::NoInitialSlash)
        } else {
            Ok(())
        }
    }

    fn cons(mut value: String) -> Self {
        if !value.ends_with('/') {
            value.push('/')
        }
        Self(value)
    }
}

impl std::str::FromStr for PathPrefix {
    type Err = InvalidPathPrefix;

    fn from_str(value: &str) -> Result<Self, InvalidPathPrefix> {
        Self::validate(value).map(|_| Self::cons(value.to_owned()))
    }
}

impl TryFrom<String> for PathPrefix {
    type Error = InvalidPathPrefix;

    fn try_from(value: String) -> Result<Self, InvalidPathPrefix> {
        Self::validate(&value).map(|_| Self::cons(value))
    }
}

impl TryFrom<&str> for PathPrefix {
    type Error = InvalidPathPrefix;

    fn try_from(value: &str) -> Result<Self, InvalidPathPrefix> {
        Self::validate(value).map(|_| Self::cons(value.to_owned()))
    }
}

impl From<PathPrefix> for String {
    fn from(value: PathPrefix) -> Self {
        value.0
    }
}

impl Display for PathPrefix {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Default for PathPrefix {
    fn default() -> Self {
        Self("/_session/".to_owned())
    }
}

