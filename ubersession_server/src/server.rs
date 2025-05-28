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

use ed25519_dalek::SigningKey;
use http::header::{HeaderMap, HeaderValue, CACHE_CONTROL, CONTENT_TYPE, LOCATION, SET_COOKIE};
use http::{Method, Request, Response};
use http::status::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use thiserror::Error;
use ubersession_core::cookie::*;
use ubersession_core::host_name::{HostName, HostNameSource};
use ubersession_core::session_token::{SessionToken, SessionTokenLoader};

use crate::errors::*;
use crate::html::HtmlEscapedText;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Protocol {
    Http,
    Https
}

impl Protocol {
    pub fn is_secure(&self) -> bool {
        self == &Protocol::Https
    }

    pub fn url_prefix(&self) -> &'static str {
        use Protocol::*;
        match self {
            &Http => "http://",
            &Https => "https://"
        }
    }

    pub fn default_port(&self) -> u16 {
        use Protocol::*;
        match self {
            &Http => 80,
            &Https => 443
        }
    }
}

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

#[derive(Clone, Debug)]
pub struct HostSettings {
    name: HostName,
    protocol: Protocol,
    cookie: CookieName,
    url_port: Option<u16>,
    path_prefix: PathPrefix
}

impl HostSettings {
    pub fn new(name: HostName) -> Self {
        Self {
            name: name,
            protocol: Protocol::Https,
            cookie: CookieName::escape_str("UBERSESS"),
            url_port: None,
            path_prefix: PathPrefix::default()
        }
    }

    pub fn with_url_port(mut self, url_port: u16) -> Self {
        self.url_port = Some(url_port);
        self
    }

    pub fn with_path_prefix(mut self, path_prefix: PathPrefix) -> Self {
        self.path_prefix = path_prefix;
        self
    }

    pub fn with_cookie(mut self, cookie: CookieName) -> Self {
        self.cookie = cookie;
        self
    }

    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol;
        self
    }

    fn workflow_url(&self) -> String {
        let port_str =
            if let Some(port) = self.url_port {
                if port != self.protocol.default_port() {
                    format!(":{}", port)
                } else {
                    "".to_owned()
                }
            } else {
                "".to_owned()
            };
        format!("{}{}{}{}flow", self.protocol.url_prefix(), self.name, port_str, self.path_prefix)
    }
}

#[derive(Clone, Debug, Error)]
#[error("Host with same name already added")]
pub struct DuplicateHost;

#[derive(Clone, Debug)]
pub struct ServerSettings {
    signing_key: SigningKey,
    token_expiry: u32,
    verbose_workflow: bool,
    no_plain_html: bool,
    authority: HostSettings,
    hosts: HashMap<HostName, HostSettings>
}

impl ServerSettings {
    pub fn new(signing_key: SigningKey, authority: HostSettings) -> Self {
        Self {
            signing_key: signing_key,
            token_expiry: 86400 * 366 * 10,
            verbose_workflow: false,
            no_plain_html: false,
            authority: authority,
            hosts: HashMap::new()
        }
    }

    pub fn with_token_expiry(mut self, token_expiry: u32) -> Self {
        self.token_expiry = token_expiry;
        self
    }

    pub fn with_verbose_workflow(mut self) -> Self {
        self.verbose_workflow = true;
        self
    }

    pub fn without_plain_html(mut self) -> Self {
        self.no_plain_html = true;
        self
    }

    pub fn add_host(mut self, host: HostSettings) -> Result<Self, DuplicateHost> {
        if host.name == self.authority.name || self.hosts.contains_key(&host.name) {
            Err(DuplicateHost)
        } else {
            self.hosts.insert(host.name.clone(), host);
            Ok(self)
        }
    }

    pub fn build_server(self) -> Server {
        Server::new(self)
    }
}

const NO_CACHE: HeaderValue = HeaderValue::from_static("private; no-cache");
const HTML: HeaderValue = HeaderValue::from_static("text/html; charset=utf-8");

#[derive(Clone, Debug)]
pub struct Server(Arc<ServerInternal>);

#[derive(Debug)]
pub struct ServerInternal {
    signing_key: SigningKey,
    token_expiry: u32,
    verbose_workflow: bool,
    no_plain_html: bool,
    hosts: HashMap<HostName, Host>,
    authority_workflow_url: String,
    authority_name: HostName
}

impl Server {
    fn new(settings: ServerSettings) -> Self {
        let authority_workflow_url = settings.authority.workflow_url();
        let authority_name = settings.authority.name.clone();

        let mut hosts = HashMap::new();

        hosts.insert(settings.authority.name.clone(), Host::new(settings.authority, true));

        for (host_name, host_settings) in settings.hosts.iter() {
            hosts.insert(host_name.clone(), Host::new(host_settings.clone(), false));
        }

        Self(Arc::new(ServerInternal {
            signing_key: settings.signing_key,
            token_expiry: settings.token_expiry,
            verbose_workflow: settings.verbose_workflow,
            no_plain_html: settings.no_plain_html,
            hosts: hosts,
            authority_workflow_url: authority_workflow_url,
            authority_name: authority_name
        }))
    }

    pub fn handle(&self, request: Request<Vec<u8>>) -> Response<Vec<u8>> {
        let mut response = self.0.handle(request);
        response.headers_mut().insert(CACHE_CONTROL, NO_CACHE);
        response
    }
}

impl ServerInternal {
    fn handle(&self, request: Request<Vec<u8>>) -> Response<Vec<u8>> {
        if let Some(host_name) = request.headers().extract_host_name() {
            if let Some(host) = self.hosts.get(&host_name) {
                match host.handle(self, request) {
                    Ok(response) => response,
                    Err(error) =>
                        if error.is::<NotFound>() {
                            build_404()
                        } else if error.is::<InvalidRequest>() {
                            build_400()
                        } else {
                            build_500()
                        }
                }
            } else {
                build_404()
            }
        } else {
            build_400()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Behaviour {
    Authority,
    Mirror
}

#[derive(Clone, Debug)]
struct Host {
    name: HostName,
    workflow_url: String,
    workflow_path: String,
    path_prefix: String,
    cookie: CookieName,
    cookie_options: CookieOptions,
    behaviour: Behaviour
}

impl Host {
    fn new(settings: HostSettings, authority: bool) -> Self {
        Self {
            name: settings.name.clone(),
            workflow_url: settings.workflow_url(),
            workflow_path: format!("{}flow", settings.path_prefix),
            path_prefix: settings.path_prefix.into(),
            cookie: settings.cookie,
            cookie_options:
                if settings.protocol == Protocol::Http {
                    CookieOptions::default().with_max_age(10 * 366 * 86400)
                } else {
                    CookieOptions::default().with_max_age(10 * 366 * 86400).secure()
                },
            behaviour: if authority { Behaviour::Authority } else { Behaviour::Mirror }
        }
    }

    pub fn handle(&self, server: &ServerInternal, request: Request<Vec<u8>>) -> anyhow::Result<Response<Vec<u8>>> {
        if request.uri().path() != self.workflow_path {
            Err(NotFound)?
        }

        let query_parameters: ServiceRequestParameters =
            if request.method() == &Method::GET {
                match serde_urlencoded::from_str(request.uri().query().unwrap_or_else(|| "")) {
                    Ok(query_parameters) => query_parameters,
                    Err(_) => Err(InvalidRequest)?
                }
            } else {
                ServiceRequestParameters::default()
            };

        let body_parameters: Option<ServiceRequestBody> =
            if request.method() == &Method::POST {
                match serde_urlencoded::from_bytes(request.body()) {
                    Ok(body_parameters) => body_parameters,
                    Err(_) => Err(InvalidRequest)?
                }
            } else {
                None
            };

        let for_host = query_parameters.extract_host_name().unwrap_or_else(|| self.name.clone());

        let redir_path = {
            let candidate_path =
                if let Some(ref body) = body_parameters {
                    body.path.as_str()
                } else {
                    query_parameters.path.as_deref().unwrap_or("/")
                };
            if candidate_path.starts_with(&self.path_prefix) {
                "/"
            } else if !candidate_path.starts_with('/') {
                "/"
            } else {
                candidate_path
            }
        };


        if self.behaviour == Behaviour::Authority {
            let mut m_set_cookie = None;

            let authoritative_session_token =
                if let Some(current_session_token) = self.load_current_session_token(server, request.headers()) {
                    current_session_token
                } else {
                    let session_token = SessionToken::new(&server.signing_key, server.token_expiry, server.authority_name.clone());
                    let encoded_session_token = serde_json::to_string(&session_token)?;
                    let set_cookie = SetCookie::new(self.cookie.clone(), CookieValue::escape_str(&encoded_session_token)).with_options(self.cookie_options.clone()).to_string();
                    m_set_cookie = Some(HeaderValue::from_str(&set_cookie)?);
                    session_token
                };

            if self.name == for_host {
                let mut response = redirect(redir_path);
                if let Some(set_cookie) = m_set_cookie {
                    response.headers_mut().insert(SET_COOKIE, set_cookie);
                }
                Ok(response)
            } else {
                let session_token = {
                    let mut session_token = authoritative_session_token.clone();
                    session_token.host = for_host.clone();
                    session_token.resign(&server.signing_key);
                    session_token
                };
                let encoded_session_token = &serde_json::to_string(&session_token)?;

                let uri =
                    if let Some(host) = server.hosts.get(&for_host) {
                        format!("{}?{}", host.workflow_url, serde_urlencoded::to_string(&query_parameters)?)
                    } else {
                        Err(NotFound)?
                    };

                let button =
                    if server.no_plain_html {
                        ""
                    } else {
                        "<noscript>You don\'t appear to have JavaScript enabled. Please click the following button to proceed to the next page. <button>Proceed</button></noscript>"
                    };

                let styles =
                    if server.no_plain_html {
                        ""
                    } else {
                        "<style type=\"text/css\">body { background-color:#FFFFF0; color:#000040; font-family:roboto, 'open sans', sans-serif}</style>"
                    };

                let escaped_path = HtmlEscapedText::new(redir_path);
                let escaped_encoded_session_token = HtmlEscapedText::new(&encoded_session_token);
                let html = format!(
                    concat!(
                        "<!DOCTYPE html><html><head><title>Redirecting to application</title>",
                        "{additional_header_code}",
                        "</head><body>",
                        "<form method=\"post\" action=\"{action}\">",
                        "<input type=\"hidden\" name=\"token\" value=\"{token}\">",
                        "<input type=\"hidden\" name=\"path\" value=\"{path}\">",
                        "{additional_form_code}",
                        "</form>",
                        "<script type=\"text/javascript\">document.querySelector('form').submit();</script>",
                        "</body></html>"
                    ),
                    additional_header_code = styles,
                    action = uri,
                    token = escaped_encoded_session_token,
                    path = escaped_path,
                    additional_form_code = button
                );
                let mut response = Response::new(html.into_bytes());
                response.headers_mut().insert(CONTENT_TYPE, HTML);
                if let Some(set_cookie) = m_set_cookie {
                    response.headers_mut().insert(SET_COOKIE, set_cookie);
                }
                Ok(response)
            }
        } else { // mirror behaviour
            let m_current_session_token = self.load_current_session_token(server, request.headers());
           
            if let Some(ref body) = body_parameters {
                let m_new_session_token = (SessionTokenLoader { required_http_host: self.name.clone(), verifying_key: server.signing_key.verifying_key() }).attempt_load(&body.token);
                if let Some(new_session_token) = m_new_session_token {
                    let mut response = redirect(redir_path);
                    if m_current_session_token.map_or(true, |current_session_token| current_session_token.expires < new_session_token.expires) {
                        let set_cookie = SetCookie::new(self.cookie.clone(), CookieValue::escape_str(&body.token)).with_options(self.cookie_options.clone()).to_string();
                        response.headers_mut().insert(SET_COOKIE, HeaderValue::from_str(&set_cookie)?);
                    }
                    Ok(response)
                } else {
                    Err(InvalidRequest)?
                }
            } else if m_current_session_token.is_some() {
                Ok(redirect(redir_path))
            } else {
                let query = ServiceRequestParameters {
                    path: Some(redir_path.to_owned()),
                    for_host: Some(self.name.to_owned())
                };

                let uri = format!("{}?{}", server.authority_workflow_url, serde_urlencoded::to_string(&query).unwrap());

                Ok(redirect(&uri))
            }
        }
    }

    fn load_current_session_token(&self, server: &ServerInternal, request_headers: &HeaderMap) -> Option<SessionToken> {
        let cookie_value = request_headers.extract_cookie(&self.cookie)?.unescape_str().ok()?;
        (SessionTokenLoader {
            required_http_host: self.name.clone(),
            verifying_key: server.signing_key.verifying_key()
        }).attempt_load(&cookie_value)
    }

}

#[derive(Clone, Copy, Debug, Error)]
#[error("Invalid HTTP request")]
struct InvalidRequest;

#[derive(Clone, Copy, Debug, Error)]
#[error("HTTP resource not found")]
struct NotFound;

#[derive(Deserialize, Serialize)]
struct ServiceRequestParameters {
    #[serde(rename = "for")]
    for_host: Option<HostName>,
    path: Option<String>
}

impl Default for ServiceRequestParameters {
    fn default() -> Self {
        Self {
            for_host: None,
            path: None
        }
    }
}

impl HostNameSource for ServiceRequestParameters {
    fn extract_host_name(&self) -> Option<HostName> {
        self.for_host.clone()
    }
}

#[derive(Deserialize, Serialize)]
struct ServiceRequestBody {
    token: String,
    path: String
}

const SINGLE_SLASH: HeaderValue = HeaderValue::from_static("/");

fn redirect(uri: &str) -> Response<Vec<u8>> {
    let mut response = Response::new(Vec::new());

    if let Ok(redir_path_hv) = HeaderValue::from_str(uri) {
        response.headers_mut().insert(LOCATION, redir_path_hv);
    } else {
        response.headers_mut().insert(LOCATION, SINGLE_SLASH);
    }

    *response.status_mut() = StatusCode::SEE_OTHER;
    
    response
}

