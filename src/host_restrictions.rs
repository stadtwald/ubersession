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

use axum::http::header::{HeaderMap, HeaderName};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
#[serde(tag = "action", content = "network")]
pub enum RemoteAddressRule {
    #[serde(rename = "allow")]
    Allow(IpNet),
    #[serde(rename = "deny")]
    Deny(IpNet)
}

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct HostRestrictions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_address: Option<Vec<RemoteAddressRule>>, // first match wins
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HostRestrictionsResult {
    Allowed,
    Denied
}

#[allow(dead_code)]
impl HostRestrictionsResult {
    pub fn is_allowed(&self) -> bool {
        self == &HostRestrictionsResult::Allowed
    }

    pub fn is_denied(&self) -> bool {
        self == &HostRestrictionsResult::Denied
    }

    fn combine(self, other: Self) -> Self {
        use HostRestrictionsResult::*;

        match (self, other) {
            (Allowed, Allowed) => Allowed,
            _ => Denied
        }
    }
}

const X_UBERSESSION_HOST_TOKEN: HeaderName = HeaderName::from_static("x-ubersession-host-token");

impl HostRestrictions {
    pub fn evaluate(&self, remote_address: IpAddr, request_headers: &HeaderMap) -> HostRestrictionsResult {
        use HostRestrictionsResult::*;

        let remote_address_result = {
            let mut result = Allowed;
            if let Some(ref remote_address_rules) = self.remote_address {
                result = Denied;
                for rule in remote_address_rules {
                    match rule {
                        RemoteAddressRule::Allow(network) =>
                            if network.contains(&remote_address) {
                                result = Allowed;
                                break;
                            },
                        RemoteAddressRule::Deny(network) =>
                            if network.contains(&remote_address) {
                                break;
                            }
                    }
                }
            }
            result
        };
        
        let token_result = {
            let mut result = Allowed;
            if let Some(ref token) = self.token {
                result = Denied;
                if let Some(header_value) = request_headers.get(X_UBERSESSION_HOST_TOKEN) {
                    if header_value == token {
                        result = Allowed;
                    }
                }
            }
            result
        };

        return remote_address_result.combine(token_result);
    }
}

