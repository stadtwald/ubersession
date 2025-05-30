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
    NoInitialSlash,

    #[error("Path prefix must not contain two consecutive forward slashes")]
    TwoConsecutiveSlashes,

    #[error("Path prefix must not contain an invalid character")]
    ForbiddenCharacter
}

fn is_sub_delim(c: char) -> bool {
    c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' || c == '*' || c == '+' || c == ',' || c == ';' || c == '='
}

fn is_alpha(c: char) -> bool {
    (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

fn is_digit(c: char) -> bool {
    c >= '0' && c <= '9'
}

fn valid_char(c: char) -> bool {
    is_sub_delim(c) || is_alpha(c) || is_digit(c) || c == '-' || c == '.' || c == '_' || c == '~' || c == '/' || c == '%'
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PathPrefix(String);

impl PathPrefix {
    fn validate(value: &str) -> Result<(), InvalidPathPrefix> {
        use InvalidPathPrefix::*;
        if value.len() == 0 {
            Err(Empty)
        } else if !value.starts_with('/') {
            Err(NoInitialSlash)
        } else if value.contains("//") {
            Err(TwoConsecutiveSlashes)
        } else if !value.chars().all(valid_char) {
            Err(ForbiddenCharacter)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation() -> () {
        assert!(PathPrefix::default().to_string().parse::<PathPrefix>().is_ok());

        let must_fail = ["", "blah", "/more/fails///", "//fail", "/not\nallowed", "/also not allowed", "/no-query/allowed?hello=test"];

        for x in must_fail {
            assert!(x.parse::<PathPrefix>().is_err());
        }

        let must_succeed = ["/", "/hello", "/hello/world", "/hello/world/", "/this%20is%20allowed", "/~mike", "/UPPERCASE/is/also/allowed", "/test-page/", "/test_page/test"];

        for x in must_succeed {
            assert!(x.parse::<PathPrefix>().is_ok());
        }
    }
}
