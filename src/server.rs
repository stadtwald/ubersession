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

use axum::{Extension, Form, Router, serve};
use axum::extract::{ConnectInfo, Query, Request};
use axum::http::header::{HeaderMap, HeaderValue, CACHE_CONTROL, COOKIE, HOST, LOCATION, SET_COOKIE};
use axum::http::status::StatusCode;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use ed25519_dalek::SigningKey;
use percent_encoding::{percent_decode_str, percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;

use crate::errors::*;
use crate::host_restrictions::HostRestrictions;
use crate::html::HtmlEscapedText;
use crate::keypair::Keypair;
use crate::session_token::{SessionToken, SessionTokenLoader};

const COOKIE_OCTET: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b',').add(b';').add(b'\\');
const TOKEN_OCTET: &AsciiSet = &CONTROLS.add(b' ').add(b'(').add(b')').add(b'<').add(b'>').add(b'@').add(b',').add(b';').add(b':').add(b'\\').add(b'"').add(b'/').add(b'[').add(b']').add(b'?').add(b'=').add(b'{').add(b'}');

#[derive(Clone, Debug)]
pub struct Server {
    listen: SocketAddr,
    router: Router
}

#[derive(Clone, Debug)]
struct Settings {
    signing_key: SigningKey,
    token_expiry: u32,
    verbose_workflow: bool,
    no_plain_html: bool,
    authority: String,
    hosts: HashSet<String>,
    host_restrictions: HashMap<String, HostRestrictions>,
    cookie: String,
    cookie_suffix: String,
    protocol: &'static str,
    url_prefix: String
}

impl Server {
    pub fn try_init_from_serve_opts(opts: crate::cli::serve::Serve) -> anyhow::Result<Self> {
        let cookie = opts.cookie.trim();
        let mut url_prefix = opts.url_prefix.trim().to_owned();
        if opts.token_expiry < 60 {
            Err(anyhow::anyhow!("Token expiry must be at least a minute"))
        } else if cookie.len() < 1 {
            Err(anyhow::anyhow!("Cookie name must not be empty"))
        } else if !url_prefix.starts_with('/') {
            Err(anyhow::anyhow!("URL prefix must start with a forward slash (/)"))
        } else {
            let keypair: Keypair = serde_json::from_slice(std::fs::read(&opts.private_key_file)?.as_slice())?;
            let signing_key = keypair.private_key;

            let host_restrictions =
                if let Some(ref host_restrictions_file) = opts.host_restrictions_file {
                    serde_json::from_slice(std::fs::read(host_restrictions_file)?.as_slice())?
                } else {
                    HashMap::new()
                };
            
            if !url_prefix.ends_with('/') {
                url_prefix.push('/');
            }

            let mut router = Router::new();

            {
                let url = format!("{}flow", url_prefix);
                router = router.route(&url, get(handle_get).post(handle_post));
            }

            router = router.fallback(handle_404);
            router = router.method_not_allowed_fallback(handle_400);

            let authority = opts.authority.trim().to_ascii_lowercase();
            let mut hosts = HashSet::new();
            hosts.insert(authority.clone());

            for host in opts.hosts {
                hosts.insert(host.trim().to_ascii_lowercase());
            }

            let m_cookie_secure =
                if opts.insecure_http {
                    ""
                } else {
                    "; Secure"
                };

            let settings = 
                Settings {
                    signing_key: signing_key,
                    token_expiry: opts.token_expiry,
                    verbose_workflow: opts.verbose_workflow,
                    no_plain_html: opts.no_plain_html,
                    authority: authority,
                    hosts: hosts,
                    host_restrictions: host_restrictions,
                    cookie: percent_encode(cookie.as_bytes(), TOKEN_OCTET).to_string(),
                    cookie_suffix: format!("; Max-Age=316224000{}", m_cookie_secure), // expire cookie in ten years
                    protocol: if opts.insecure_http { "http" } else { "https" },
                    url_prefix: url_prefix
                };

            router = router.layer(Extension(Arc::new(settings)));
            router = router.layer(axum::middleware::from_fn(set_cache_control));

            Ok(Self {
                listen: opts.listen,
                router: router
            })
        }
    }

    pub async fn serve(self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(self.listen).await?;
        serve(listener, self.router.into_make_service_with_connect_info::<SocketAddr>()).await?;
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
struct ServiceRequestParameters {
    #[serde(rename = "for")]
    for_host: Option<String>,
    path: Option<String>
}

#[derive(Deserialize, Serialize)]
struct ServiceRequestBody {
    token: String,
    path: String
}

fn fold_errors(m_response: anyhow::Result<Response>) -> Response {
    match m_response {
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
}


async fn handle_get(request_headers: HeaderMap, Extension(settings): Extension<Arc<Settings>>, Query(query): Query<ServiceRequestParameters>, ConnectInfo(remote_address): ConnectInfo<SocketAddr>) -> Response {
    fold_errors(TransactionBuilder::new(settings).with_query(query).with_request_headers(request_headers).with_remote_address(remote_address).build_and_run().await)
}

async fn handle_post(request_headers: HeaderMap, Extension(settings): Extension<Arc<Settings>>, ConnectInfo(remote_address): ConnectInfo<SocketAddr>, Form(body): Form<ServiceRequestBody>) -> Response {
    fold_errors(TransactionBuilder::new(settings).with_request_headers(request_headers).with_body(body).with_remote_address(remote_address).build_and_run().await)
}

#[derive(Clone, Copy, Debug, Error)]
#[error("Invalid HTTP request")]
struct InvalidRequest;

#[derive(Clone, Copy, Debug, Error)]
#[error("HTTP resource not found")]
struct NotFound;

struct TransactionBuilder {
    settings: Arc<Settings>,
    query: ServiceRequestParameters,
    request_headers: HeaderMap,
    body: Option<ServiceRequestBody>,
    remote_address: Option<SocketAddr>
}

impl TransactionBuilder {
    fn new(settings: Arc<Settings>) -> Self {
        Self {
            settings: settings,
            query: ServiceRequestParameters {
                for_host: None,
                path: None
            },
            request_headers: HeaderMap::new(),
            body: None,
            remote_address: None
        }
    }

    fn with_request_headers(mut self, request_headers: HeaderMap) -> Self {
        self.request_headers = request_headers;
        self
    }

    fn with_body(mut self, body: ServiceRequestBody) -> Self {
        self.body = Some(body);
        self
    }

    fn with_query(mut self, query: ServiceRequestParameters) -> Self {
        self.query = query;
        self
    }

    fn with_remote_address(mut self, remote_address: SocketAddr) -> Self {
        self.remote_address = Some(remote_address);
        self
    }

    async fn build_and_run(self) -> anyhow::Result<Response> {
        self.build()?.run().await
    }

    fn build(self) -> anyhow::Result<Transaction> {
        let http_host =
            if let Some(http_host) = self.request_headers.get(HOST).and_then(|x| x.to_str().ok()) {
                http_host.to_owned()
            } else {
                Err(InvalidRequest)?
            };

        let for_host = self.query.for_host.as_deref().unwrap_or(http_host.as_str()).to_owned();

        let redir_path = {
            let candidate_path =
                if let Some(ref body) = self.body {
                    body.path.as_str()
                } else {
                    self.query.path.as_deref().unwrap_or("/")
                };
            if candidate_path.starts_with(&self.settings.url_prefix) {
                "/"
            } else if !candidate_path.starts_with('/') {
                "/"
            } else {
                candidate_path
            }
        }.to_owned();

        Ok(Transaction {
            settings: self.settings,
            request_headers: self.request_headers,
            query: self.query,
            http_host: http_host,
            for_host: for_host,
            redir_path: redir_path,
            body: self.body,
            remote_address: self.remote_address
        })
    }
}

struct Transaction {
    settings: Arc<Settings>,
    request_headers: HeaderMap,
    query: ServiceRequestParameters,
    http_host: String,
    for_host: String,
    redir_path: String,
    body: Option<ServiceRequestBody>,
    remote_address: Option<SocketAddr>
}

impl Transaction {
    async fn authority(self) -> anyhow::Result<Response> {
        let mut response_headers = HeaderMap::new();

        let authoritative_session_token =
            if let Some(current_session_token) = load_current_session_token(self.settings.clone(), &self.request_headers) {
                current_session_token
            } else {
                let session_token = SessionToken::new(&self.settings.signing_key, self.settings.token_expiry, self.settings.authority.clone());
                let encoded_session_token = serde_json::to_string(&session_token)?;
                let escaped_encoded_session_token = percent_encode(encoded_session_token.as_bytes(), COOKIE_OCTET);
                let cookie_value = format!("{}={}{}", self.settings.cookie, escaped_encoded_session_token, self.settings.cookie_suffix);
                response_headers.insert(SET_COOKIE, HeaderValue::from_str(&cookie_value).unwrap());
                session_token
            };

        if self.settings.authority == self.for_host {
            Ok((response_headers, redirect(&self.redir_path)).into_response())
        } else {
            let session_token = {
                let mut session_token = authoritative_session_token.clone();
                session_token.host = self.for_host.clone();
                session_token.resign(&self.settings.signing_key);
                session_token
            };
            let encoded_session_token = &serde_json::to_string(&session_token)?;

            let uri = format!("{}://{}{}flow?{}", self.settings.protocol, self.for_host, self.settings.url_prefix, serde_urlencoded::to_string(&self.query)?);

            let button =
                if self.settings.no_plain_html {
                    ""
                } else {
                    "<noscript>You don\'t appear to have JavaScript enabled. Please click the following button to proceed to the next page. <button>Proceed</button></noscript>"
                };

            let styles =
                if self.settings.no_plain_html {
                    ""
                } else {
                    "<style type=\"text/css\">body { background-color:#FFFFF0; color:#000040; font-family:roboto, 'open sans', sans-serif}</style>"
                };

            let escaped_path = HtmlEscapedText::new(&self.redir_path);
            let escaped_encoded_session_token = HtmlEscapedText::new(&encoded_session_token);
            let html = Html(format!(
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
            ));
            Ok(html.into_response())
        }
    }

    async fn app(self) -> anyhow::Result<Response> {
        let m_current_session_token = load_current_session_token(self.settings.clone(), &self.request_headers);
           
        if let Some(ref body) = self.body {
            let m_new_session_token = (SessionTokenLoader { required_http_host: &self.http_host, verifying_key: self.settings.signing_key.verifying_key() }).attempt_load(&body.token);
            if let Some(new_session_token) = m_new_session_token {
                let mut response_headers = HeaderMap::new();
                if m_current_session_token.map_or(true, |current_session_token| current_session_token.expires < new_session_token.expires) {
                    let cookie_value = format!("{}={}{}", self.settings.cookie, percent_encode(body.token.as_bytes(), COOKIE_OCTET), self.settings.cookie_suffix);
                    response_headers.insert(SET_COOKIE, HeaderValue::from_str(&cookie_value).unwrap());
                }
                Ok((response_headers, redirect(&self.redir_path)).into_response())
            } else {
                Err(InvalidRequest)?
            }
        } else if m_current_session_token.is_some() {
            Ok(redirect(&self.redir_path))
        } else {
            let query = ServiceRequestParameters {
                path: Some(self.redir_path.to_owned()),
                for_host: Some(self.http_host.to_owned())
            };

            let uri = format!("{}://{}{}flow?{}", self.settings.protocol, self.settings.authority, self.settings.url_prefix, serde_urlencoded::to_string(&query).unwrap());

            Ok(redirect(&uri))
        }
    }

    async fn run(self) -> anyhow::Result<Response> {
        if let Some(host_restrictions) = self.settings.host_restrictions.get(&self.http_host) {
            if let Some(ref remote_address) = self.remote_address {
                if host_restrictions.evaluate(remote_address.ip(), &self.request_headers).is_denied() {
                    return Err(InvalidRequest.into());
                }
            } else {
                return Err(InvalidRequest.into());
            }
        }
        if self.settings.authority == self.http_host {
            self.authority().await
        } else if self.settings.hosts.contains(&self.http_host) && self.query.for_host.as_deref().map_or(true, |x| x == self.http_host) {
            self.app().await
        } else {
            Err(NotFound)?
        }
    }
}

const NO_CACHE: HeaderValue = HeaderValue::from_static("private; no-cache");

async fn set_cache_control(request: Request, next: Next) -> impl IntoResponse {
    let response = next.run(request).await;
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, NO_CACHE);
    (headers, response)
}

struct CookieLoader(String);

impl CookieLoader {
    fn from_settings(settings: Arc<Settings>) -> Self {
        Self(settings.cookie.clone())
    }

    fn attempt_load(&self, request_headers: &HeaderMap) -> Option<String> {
        let cookie_header_value = request_headers.get(COOKIE)?.to_str().ok()?;
        if cookie_header_value.len() > 4096 {
            return None;
        }
        let mut m_value = None;
        for kv_pair in cookie_header_value.split("; ") {
            if let Some((key, value)) = kv_pair.split_once('=') {
                if self.0 == key {
                    m_value = percent_decode_str(value).decode_utf8().ok().map(|x| x.into_owned());
                    break;
                }
            }
        }
        m_value
    }
}

fn load_current_session_token(settings: Arc<Settings>, request_headers: &HeaderMap) -> Option<SessionToken> {
    let cookie_value = CookieLoader::from_settings(settings.clone()).attempt_load(request_headers)?;
    (SessionTokenLoader {
        required_http_host: request_headers.get(HOST)?.to_str().ok()?,
        verifying_key: settings.signing_key.verifying_key()
    }).attempt_load(&cookie_value)
}

const SINGLE_SLASH: HeaderValue = HeaderValue::from_static("/");

fn redirect(uri: &str) -> Response {
    let mut response_headers = HeaderMap::new();
    if let Ok(redir_path_hv) = HeaderValue::from_str(uri) {
        response_headers.insert(LOCATION, redir_path_hv);
    } else {
        response_headers.insert(LOCATION, SINGLE_SLASH);
    }
    (StatusCode::SEE_OTHER, response_headers).into_response()
}

