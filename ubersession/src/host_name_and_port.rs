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

use std::fmt::{Display, Formatter, Write};
use thiserror::Error;
use ubersession_core::host_name::{HostName, InvalidHostName};

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


