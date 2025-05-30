use http::header::HeaderValue;
use http::uri::Uri as HttpUri;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use thiserror::Error;

use crate::host_name::HostNameAndPort;
use crate::protocol::Protocol;

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
    path: String,
    query: Option<String>,
    header_value: HeaderValue
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
    NotRelative
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

        let query = uri.query().map(|x| x.to_owned());

        let mut display = absolute.as_ref().map(|x| x.to_string()).unwrap_or_else(|| String::new());
        display.push_str(&path);
        if let Some(ref query) = query {
            display.push('?');
            display.push_str(query);
        }

        Ok(Self {
            absolute: absolute,
            path: path,
            query: query,
            header_value: HeaderValue::try_from(display).map_err(|_| InvalidUriKind::InvalidUri)?
        })
    }
}

impl From<Uri> for HeaderValue {
    fn from(value: Uri) -> HeaderValue {
        value.header_value
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

        formatter.write_str(&self.path)?;

        if let Some(ref query) = self.query {
            formatter.write_str("?")?;
            formatter.write_str(&query)?;
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
                query: self.query,
                header_value: self.header_value
            })
        }
    }

    pub fn protocol(&self) -> Option<Protocol> {
        self.absolute.as_ref().map(|x| x.protocol)
    }

    pub fn host<'a>(&'a self) -> Option<&'a HostNameAndPort> {
        self.absolute.as_ref().map(|x| &x.host)
    }

    pub fn path<'a>(&'a self) -> &'a str {
        self.path.as_str()
    }

    pub fn query_str<'a>(&'a self) -> Option<&'a str> {
        self.query.as_deref()
    }

    pub fn without_query(mut self) -> Self {
        if self.query.is_none() {
            self
        } else {
            self.query = None;
            self.header_value = HeaderValue::try_from(&self.to_string()).unwrap(); // previous validation
                                                                                   // should ensure this
                                                                                   // unwrap suceeeds
            self
        }
    }

    pub fn header_value(&self) -> HeaderValue {
        self.header_value.clone()
    }
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
#[serde(try_from = "&str", into = "String")]
pub struct RelativeUri {
    path: String,
    query: Option<String>,
    header_value: HeaderValue
}

impl Display for RelativeUri {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.path)?;

        if let Some(ref query) = self.query {
            formatter.write_str("?")?;
            formatter.write_str(query)?;
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
        value.header_value
    }
}

impl RelativeUri {
    pub fn into_uri(self) -> Uri {
        Uri {
            absolute: None,
            path: self.path,
            query: self.query,
            header_value: self.header_value
        }
    }

    pub fn path<'a>(&'a self) -> &'a str {
        self.path.as_str()
    }

    pub fn query_str<'a>(&'a self) -> Option<&'a str> {
        self.query.as_deref()
    }

    pub fn without_query(mut self) -> Self {
        if self.query.is_none() {
            self
        } else {
            self.query = None;
            self.header_value = HeaderValue::try_from(&self.to_string()).unwrap(); // previous validation
                                                                                   // should ensure this
                                                                                   // unwrap suceeeds
            self
        }
    }

    pub fn header_value(&self) -> HeaderValue {
        self.header_value.clone()
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
            "http://example.com/test/test.php?hello=world&test=another"
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

        let must_succeed = ["/", "/hello", "/hello/world", "/hello/world/", "/this%20is%20allowed", "/~mike", "/UPPERCASE/is/also/allowed", "/test-page/", "/test_page/test"];

        for x in must_succeed {
            assert!(x.parse::<RelativeUri>().is_ok());
            assert!(!(x.parse::<Uri>().unwrap().is_absolute()));
        }
    }
}

