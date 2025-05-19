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

use data_encoding::BASE64;
use ed25519_dalek::SigningKey;
use serde::de::Deserializer;
use serde::ser::Serializer;

use crate::serde::base64::FromBase64Visitor;

pub fn deserialize<'a, D>(deserializer: D) -> Result<SigningKey, D::Error>
    where
        D: Deserializer<'a>
{
    deserializer.deserialize_str(FromBase64Visitor::new("base64-encoded ed25519 private key"))
}

pub fn serialize<S>(value: &SigningKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer
{
    serializer.serialize_str(BASE64.encode(value.as_bytes()).as_str())
}


