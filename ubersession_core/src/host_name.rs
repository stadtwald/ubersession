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
use std::fmt::{Display, Formatter, Write};
use thiserror::Error;

use crate::protocol::Protocol;

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

#[derive(Clone, Debug, Error)]
#[error("Cannot use 0 as a concrete TCP port")]
pub struct CannotUseZeroTcpPort;

#[derive(Clone, Debug, Error)]
pub enum InvalidHostNameAndPort {
    #[error("Cannot use 0 as a concrete TCP port")]
    CannotUseZeroTcpPort,

    #[error("Invalid port number specified")]
    InvalidTcpPort,

    #[error("{0}")]
    InvalidHostName(#[source] #[from] InvalidHostName)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostNameAndPort {
    host_name: HostName,
    port: Option<u16>
}

impl HostNameAndPort {
    pub fn new(host_name: HostName, port: Option<u16>) -> Result<Self, CannotUseZeroTcpPort> {
        if port == Some(0) {
            Err(CannotUseZeroTcpPort)
        } else {
            Ok(Self {
                host_name: host_name,
                port: port
            })
        }
    }

    pub fn host_name<'a>(&'a self) -> &'a HostName {
        &self.host_name
    }

    pub fn port(&self) -> Option<u16> {
        self.port
    }

    pub fn into_parts(self) -> (HostName, Option<u16>) {
        (self.host_name, self.port)
    }

    pub fn as_parts<'a>(&'a self) -> (&'a HostName, Option<u16>) {
        (&self.host_name, self.port)
    }

    pub fn normalize_port(mut self, protocol: Protocol) -> Self {
        if let Some(port) = self.port {
            if port == protocol.default_port() {
                self.port = None;
            }
        }
        self
    }
}

impl Display for HostNameAndPort {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        self.host_name.fmt(formatter)?;
        if let Some(port) = self.port {
            formatter.write_char(':')?;
            port.fmt(formatter)
        } else {
            Ok(())
        }
    }
}

impl std::str::FromStr for HostNameAndPort {
    type Err = InvalidHostNameAndPort;

    fn from_str(value: &str) -> Result<Self, InvalidHostNameAndPort> {
        use InvalidHostNameAndPort::*;

        if let Some((host_name_str, port_str)) = value.rsplit_once(':') {
            if let Ok(m_port) = port_str.parse::<u64>() {
                if let Ok(port) = m_port.try_into() {
                    if port > 0 {
                        match host_name_str.parse() {
                            Ok(host_name) =>
                                Ok(Self {
                                    host_name: host_name,
                                    port: Some(port)
                                }),
                            Err(err) => Err(InvalidHostName(err))
                        }
                    } else {
                        Err(CannotUseZeroTcpPort)
                    }
                } else {
                    Err(InvalidTcpPort)
                }
            } else {
                Err(InvalidTcpPort)
            }
        } else {
            Ok(Self {
                host_name: value.parse()?,
                port: None
            })
        }
    }
}


