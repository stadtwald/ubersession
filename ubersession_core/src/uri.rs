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
use http::uri::Uri as HttpUri;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use thiserror::Error;

use crate::header_string::{HeaderString, HeaderStringChar};
use crate::host_name::HostNameAndPort;
use crate::protocol::Protocol;

const QUESTION_MARK: HeaderStringChar = HeaderStringChar::from_static('?');

#[derive(Clone, Debug)]
pub struct AbsoluteComponent {
    protocol: Protocol,
    host: HostNameAndPort
}

impl AbsoluteComponent {
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn host<'a>(&'a self) -> &'a HostNameAndPort {
        &self.host
    }

    pub fn header_string(&self) -> HeaderString {
        let mut header_string = self.protocol.url_prefix().to_header_string();
        header_string.push_str(&self.host.to_header_string());
        header_string
    }
}

impl Display for AbsoluteComponent {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        self.protocol.url_prefix().fmt(formatter)?;
        self.host.fmt(formatter)
    }
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
#[serde(try_from = "&str", into = "String")]
pub struct Uri {
    absolute: Option<AbsoluteComponent>,
    path: HeaderString,
    query: Option<HeaderString>
}

#[derive(Clone, Debug, Error)]
#[error(transparent)]
pub struct InvalidUri(#[from] InvalidUriKind);

#[derive(Clone, Debug, Error)]
enum InvalidUriKind {
    #[error("URI is invalid")]
    InvalidUri,

    #[error("Absolute URI must use either http or https schemes")]
    InvalidProtocol,

    #[error("Absolute URI must have an authority")]
    MissingAuthority,

    #[error("Host name is invalid (cannot contain credentials)")]
    InvalidAuthority,

    #[error("Path is invalid")]
    InvalidPath,

    #[error("Is not a relative URI")]
    NotRelative,

    #[error("Contains a query string")]
    NotJustPath
}

#[derive(Clone, Debug, Error)]
#[error("Is not a relative URI")]
pub struct NotRelativeUri;

impl From<NotRelativeUri> for InvalidUri {
    fn from(_value: NotRelativeUri) -> Self {
        InvalidUri(InvalidUriKind::NotRelative)
    }
}

impl std::str::FromStr for Uri {
    type Err = InvalidUri;

    fn from_str(value: &str) -> Result<Self, InvalidUri> {
        let uri: HttpUri = value.parse().map_err(|_| InvalidUriKind::InvalidUri)?;

        if uri.scheme().is_none() && uri.authority().is_some() {
            Err(InvalidUriKind::InvalidUri)?
        }

        if uri.scheme().is_some() && uri.authority().is_none() {
            Err(InvalidUriKind::InvalidUri)?
        }

        let absolute =
            if let Some(scheme) = uri.scheme_str() {
                if let Ok(protocol) = scheme.parse() {
                    if let Some(authority) = uri.authority() {
                        if let Ok(host_name_and_port) = authority.as_str().parse::<HostNameAndPort>() {
                            Some(AbsoluteComponent {
                                protocol: protocol,
                                host: host_name_and_port.normalize_port(protocol)
                            })
                        } else {
                            Err(InvalidUriKind::InvalidAuthority)?
                        }
                    } else {
                        Err(InvalidUriKind::MissingAuthority)?
                    }
                } else {
                    Err(InvalidUriKind::InvalidProtocol)?
                }
            } else {
                None
            };

        let mut path = uri.path().to_owned();

        if path.len() == 0 {
            path.push('/');
        }

        if !path.starts_with('/') {
            Err(InvalidUriKind::InvalidPath)?
        }

        // see RFC 3986 section 3.3
        if path.contains("//") {
            Err(InvalidUriKind::InvalidPath)?
        }

        let query = uri.query().map(|x| x.parse().map_err(|_| InvalidUriKind::InvalidPath)).transpose()?;

        Ok(Self {
            absolute: absolute,
            path: path.try_into().map_err(|_| InvalidUriKind::InvalidPath)?,
            query: query
        })
    }

}

impl From<Uri> for HeaderValue {
    fn from(value: Uri) -> HeaderValue {
        value.header_string().into()
    }
}

impl TryFrom<&str> for Uri {
    type Error = InvalidUri;

    fn try_from(value: &str) -> Result<Self, InvalidUri> {
        value.parse()
    }
}

impl Display for Uri {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(ref absolute) = self.absolute {
            absolute.fmt(formatter)?;
        }

        formatter.write_str(self.path.as_str())?;

        if let Some(ref query) = self.query {
            formatter.write_str("?")?;
            formatter.write_str(query.as_str())?;
        }

        Ok(())
    }
}

impl From<Uri> for String {
    fn from(value: Uri) -> Self {
        value.to_string()
    }
}

impl Uri {
    pub fn is_absolute(&self) -> bool {
        self.absolute.is_some()
    }

    pub fn absolute_component<'a>(&'a self) -> Option<&'a AbsoluteComponent> {
        self.absolute.as_ref()
    }

    pub fn into_relative(self) -> Result<RelativeUri, NotRelativeUri> {
        if self.is_absolute() {
            Err(NotRelativeUri)
        } else {
            Ok(RelativeUri {
                path: self.path,
                query: self.query
            })
        }
    }

    pub fn protocol(&self) -> Option<Protocol> {
        self.absolute.as_ref().map(|x| x.protocol)
    }

    pub fn host<'a>(&'a self) -> Option<&'a HostNameAndPort> {
        self.absolute.as_ref().map(|x| &x.host)
    }

    pub fn path_str<'a>(&'a self) -> &'a HeaderString {
        &self.path
    }

    pub fn path(&self) -> UriPath {
        UriPath(self.path.clone())
    }

    pub fn query_str<'a>(&'a self) -> Option<&'a HeaderString> {
        self.query.as_ref()
    }

    pub fn without_query(mut self) -> Self {
        self.query = None;
        self
    }

    pub fn header_string(&self) -> HeaderString {
        let mut header_string =
            if let Some(ref absolute) = self.absolute {
                absolute.header_string()
            } else {
                HeaderString::new()
            };
        header_string.push_str(&self.path);
        if let Some(ref query) = self.query {
            header_string.push(QUESTION_MARK);
            header_string.push_str(query);
        }
        header_string
    }
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
#[serde(try_from = "&str", into = "String")]
pub struct RelativeUri {
    path: HeaderString,
    query: Option<HeaderString>
}

impl Display for RelativeUri {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.path.as_str())?;

        if let Some(ref query) = self.query {
            formatter.write_str("?")?;
            formatter.write_str(query.as_str())?;
        }

        Ok(())
    }
}

impl std::str::FromStr for RelativeUri {
    type Err = InvalidUri;

    fn from_str(value: &str) -> Result<Self, InvalidUri> {
        let uri: Uri = value.parse()?;
        Ok(uri.into_relative()?)
    }
}

impl TryFrom<&str> for RelativeUri {
    type Error = InvalidUri;

    fn try_from(value: &str) -> Result<Self, InvalidUri> {
        value.parse()
    }
}

impl From<RelativeUri> for String {
    fn from(value: RelativeUri) -> Self {
        value.to_string()
    }
}

impl From<RelativeUri> for HeaderValue {
    fn from(value: RelativeUri) -> Self {
        value.header_string().into()
    }
}

impl RelativeUri {
    pub fn into_uri(self) -> Uri {
        Uri {
            absolute: None,
            path: self.path,
            query: self.query
        }
    }

    pub fn path_str<'a>(&'a self) -> &'a HeaderString {
        &self.path
    }

    pub fn path(&self) -> UriPath {
        UriPath(self.path.clone())
    }

    pub fn query_str<'a>(&'a self) -> Option<&'a HeaderString> {
        self.query.as_ref()
    }

    pub fn without_query(mut self) -> Self {
        self.query = None;
        self
    }

    pub fn header_string(&self) -> HeaderString {
        let mut header_string = self.path.clone();
        if let Some(ref query) = self.query {
            header_string.push(QUESTION_MARK);
            header_string.push_str(query);
        }
        header_string
    }
}

#[derive(Clone, Debug, Eq, Hash)]
pub struct UriPath(HeaderString);

impl Display for UriPath {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::str::FromStr for UriPath {
    type Err = InvalidUri;

    fn from_str(value: &str) -> Result<Self, InvalidUri> {
        let relative_uri = value.parse::<RelativeUri>()?;

        if relative_uri.query_str().is_some() {
            Err(InvalidUriKind::NotJustPath)?
        }

        Ok(relative_uri.path())
    }
}

impl UriPath {
    pub fn as_str<'a>(&'a self) -> &'a str {
        self.0.as_str()
    }

    pub fn header_string(&self) -> HeaderString {
        self.0.clone()
    }
}

impl AsRef<str> for UriPath {
    fn as_ref<'a>(&'a self) -> &'a str {
        self.0.as_ref()
    }
}

impl AsRef<HeaderString> for UriPath {
    fn as_ref<'a>(&'a self) -> &'a HeaderString {
        &self.0
    }
}

impl<T: AsRef<str>> PartialEq<T> for UriPath {
    fn eq(&self, other: &T) -> bool {
        self.as_str() == other.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_absolute_validation() -> () {
        let must_fail = ["", "ftp://somewhere.net/dir", "http://test:test@example.net/hello"];

        for x in must_fail {
            assert!(x.parse::<Uri>().is_err());
        }

        let must_succeed = [
            "https://example.net",
            "http://example.net",
            "https://example.net/",
            "http://example.net/",
            "https://example.net/hello",
            "http://example.net/hello",
            "https://example.net/hello/",
            "http://example.net/hello/",
            "http://192.168.0.20/",
            "http://example.net:3000",
            "http://example.net:3000/",
            "http://example.net:4000/test/test",
            "http://example.net/hello/world",
            "http://example.net/this%20is%20allowed",
            "http://example.net/~mike",
            "http://example.net/UPPERCASE/is/also/allowed",
            "http://example.net/test-page/",
            "http://example.org/test_page/test",
            "http://example.com/test.php?hello=world",
            "http://example.net/?hello=world",
            "http://example.com/test/test.php?hello=world&test=another",
            "http://example.com/search?query=test%20pharse"
        ];

        for x in must_succeed {
            assert!(x.parse::<Uri>().unwrap().is_absolute());
        }
    }

    #[test]
    fn test_relative_validation() -> () {
        let must_fail = ["", "blah", "/more/fails///", "//fail", "/not\nallowed", "/also not allowed"];

        for x in must_fail {
            assert!(x.parse::<RelativeUri>().is_err());
        }

        let must_succeed = ["/", "/hello", "/hello/world", "/hello/world/", "/this%20is%20allowed", "/~mike", "/UPPERCASE/is/also/allowed", "/test-page/", "/test_page/test", "/test?hello=world&x=test"];

        for x in must_succeed {
            assert!(x.parse::<RelativeUri>().is_ok());
            assert!(!(x.parse::<Uri>().unwrap().is_absolute()));
        }
    }

    #[test]
    fn test_path_validation() -> () {
        let must_fail = ["", "http://example.net/hello", "/hello?query=string", "blah", "/?", "/test hello"];

        for x in must_fail {
            assert!(x.parse::<UriPath>().is_err());
        }

        let must_pass = ["/test", "/", "/hello-world/this/is/a/test", "/test/test", "/test/test/", "/with%20escaped%spaces"];

        for x in must_pass {
            assert!(x.parse::<UriPath>().is_ok());
        }
    }
}

