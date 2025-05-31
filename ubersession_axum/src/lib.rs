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

pub mod adapt;

use axum::Router;
use axum::body::Body;
use axum::http::StatusCode;
use axum::http::header::{HeaderValue, InvalidHeaderValue, LOCATION};
use axum::http::request::Parts;
use axum::response::Response;
use axum::extract::{Extension, FromRequestParts};
pub use ed25519_dalek::VerifyingKey;
use std::future::ready;
use std::sync::Arc;
use uuid::Uuid;

pub use ubersession_core::cookie::{CookieHeaderSource, CookieName};
pub use ubersession_core::host_name::{HostName, HostNameSource};
pub use ubersession_core::path_prefix::PathPrefix;
pub use ubersession_core::session_token::{SessionToken, SessionTokenLoader};

#[derive(Clone, Debug)]
pub struct AxumSessionExtractionSettings {
    workflow_path: HeaderValue,
    cookie: CookieName,
    verifying_key: VerifyingKey,
    host_name: Option<HostName>
}

#[derive(Clone, Debug)]
struct ExtractSettingsWrapper(Arc<AxumSessionExtractionSettings>);

const DEFAULT_WORKFLOW_PATH: HeaderValue = HeaderValue::from_static("/_session/flow");

impl AxumSessionExtractionSettings {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self {
            workflow_path: DEFAULT_WORKFLOW_PATH,
            cookie: CookieName::escape_str("UBERSESSION"),
            verifying_key: verifying_key,
            host_name: None
        }
    }
 
    pub fn with_path_prefix(mut self, path_prefix: PathPrefix) -> Result<Self, InvalidHeaderValue> {
        self.workflow_path = HeaderValue::try_from(format!("{}flow", path_prefix))?;
        Ok(self)
    }

    pub fn with_cookie(mut self, cookie: CookieName) -> Self {
        self.cookie = cookie;
        self
    }

    pub fn with_host_name(mut self, host_name: HostName) -> Self {
        self.host_name = Some(host_name);
        self
    }

    pub fn setup_router(self, router: Router) -> Router {
        router.layer(Extension(ExtractSettingsWrapper(Arc::new(self))))
    }
}

fn extract_session_from_parts(settings: &AxumSessionExtractionSettings, parts: &Parts) -> Option<SessionToken> {
    let http_host =
        if let Some(host_name) = parts.headers.extract_host_name() {
            host_name
        } else {
            return None;
        };

    let cookie_value =
        if let Some(cookie_value) = parts.headers.extract_cookie(&settings.cookie) {
            if let Ok(cookie_value) = cookie_value.unescape_str() {
                cookie_value
            } else {
                return None;
            }
        } else {
            return None;
        };

    let verification_host = settings.host_name.as_ref().unwrap_or(&http_host);

    SessionTokenLoader::new(verification_host.clone(), settings.verifying_key).attempt_load(&cookie_value)
}

fn from_request_parts(parts: &Parts) -> Result<SessionToken, Response> {
    let settings = {
        let m_settings: Option<&ExtractSettingsWrapper> = parts.extensions.get();
        if let Some(settings) = m_settings {
            &settings.0
        } else {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Err(response);
        }
    };

    if let Some(session_token) = extract_session_from_parts(settings, parts) {
        Ok(session_token.clone())
    } else {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::SEE_OTHER;
        response.headers_mut().insert(LOCATION, settings.workflow_path.clone());
        Err(response)
    }
}


pub struct RequiredSessionToken(pub SessionToken);

impl<S> FromRequestParts<S> for RequiredSessionToken {
    type Rejection = Response;

    fn from_request_parts(parts: &mut Parts, _state: &S) -> impl Future<Output = Result<Self, Response>> {
        ready(from_request_parts(parts).map(|x| Self(x)))
    }
}

pub struct RequiredSessionId(pub Uuid);

impl<S> FromRequestParts<S> for RequiredSessionId {
    type Rejection = Response;

    fn from_request_parts(parts: &mut Parts, _state: &S) -> impl Future<Output = Result<Self, Response>> {
         ready(from_request_parts(parts).map(|x| Self(x.id)))       
    }
}


