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

use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::host_name::HostName;

#[derive(Clone, Debug)]
#[derive(Deserialize, Serialize)]
pub struct SessionToken {
    #[serde(with = "crate::serde::public_key")]
    pub public_key: [u8; 32],
    #[serde(with = "crate::serde::signature")]
    pub signature: Signature,
    pub host: HostName, // secured
    pub expires: u32, // secured
    pub id: Uuid // secured
}

impl SessionToken {
    pub fn new(signing_key: &SigningKey, ttl: u32, host: HostName) -> Self {
        let current_timestamp = Utc::now().timestamp().try_into().unwrap_or(u32::MAX);
        let expiry_timestamp = current_timestamp.saturating_add(ttl);
        let mut session_token =
            Self {
                public_key: signing_key.verifying_key().as_bytes().clone(),
                signature: Signature::from_bytes(&[0u8; 64]),
                host: host,
                expires: expiry_timestamp,
                id: Uuid::new_v4()
            };
        session_token.signature = signing_key.sign(&session_token.signable_message());
        session_token
    }

    pub fn resign(&mut self, signing_key: &SigningKey) -> () {
        self.public_key = signing_key.verifying_key().as_bytes().clone();
        self.signature = signing_key.sign(&self.signable_message());
    }

    fn signable_message(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9 + 16 + 4 + self.host.as_str().len());
        buf.extend("UBERSESS".as_bytes());
        buf.push(0);
        buf.extend(&self.expires.to_be_bytes());
        buf.extend(self.id.as_bytes());
        buf.extend(self.host.as_str().as_bytes());
        buf
    }

    pub fn verify(&self, verifying_key: VerifyingKey) -> bool {
        let signable_message = self.signable_message();
        (&self.public_key == verifying_key.as_bytes()) && verifying_key.verify(&signable_message, &self.signature).is_ok()
    }
}

pub struct SessionTokenLoader {
    pub required_http_host: HostName,
    pub verifying_key: VerifyingKey
}

impl SessionTokenLoader {
    pub fn attempt_load(&self, encoded_token: &str) -> Option<SessionToken> {
        let current_timestamp: u32 = Utc::now().timestamp().try_into().ok()?;
        let session_token: SessionToken = serde_json::from_str(&encoded_token).ok()?;
        if !session_token.verify(self.verifying_key) {
            return None;
        }
        if session_token.host != self.required_http_host {
            return None;
        }
        if session_token.expires < current_timestamp {
            return None;
        }
        Some(session_token)
    }
}


