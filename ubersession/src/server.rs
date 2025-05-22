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
use axum::extract::{Query, Request};
use axum::http::header::{HeaderMap, HeaderValue, CACHE_CONTROL, HOST, LOCATION, SET_COOKIE};
use axum::http::status::StatusCode;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use ubersession_core::cookie::*;

use crate::errors::*;
use crate::html::HtmlEscapedText;
use crate::keypair::Keypair;
use crate::session_token::{SessionToken, SessionTokenLoader};

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
    cookie: CookieName,
    cookie_options: CookieOptions,
    protocol: &'static str,
    url_prefix: String
}

impl Server {
    pub fn try_init_from_serve_opts(opts: crate::cli::serve::Serve) -> anyhow::Result<Self> {
        if opts.token_expiry < 60 {
            Err(anyhow::anyhow!("Token expiry must be at least a minute"))
        } else if opts.cookie.len() < 1 {
            Err(anyhow::anyhow!("Cookie name must not be empty"))
        } else if !opts.url_prefix.starts_with('/') {
            Err(anyhow::anyhow!("URL prefix must start with a forward slash (/)"))
        } else {
            let raw_input = std::fs::read(&opts.private_key_file)?;
            let keypair: Keypair = serde_json::from_slice(&raw_input)?;
            let signing_key = keypair.private_key;
            let mut url_prefix = opts.url_prefix.to_owned();
            
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

            let cookie_options = CookieOptions::default().with_max_age(316224000); // expire cookie in ten years

            let cookie_options =
                if opts.insecure_http {
                    cookie_options
                } else {
                    cookie_options.secure()
                };

            let settings = 
                Settings {
                    signing_key: signing_key,
                    token_expiry: opts.token_expiry,
                    verbose_workflow: opts.verbose_workflow,
                    no_plain_html: opts.no_plain_html,
                    authority: authority,
                    hosts: hosts,
                    cookie: CookieName::escape_str(&opts.cookie),
                    cookie_options: cookie_options,
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
        serve(listener, self.router).await?;
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


async fn handle_get(request_headers: HeaderMap, Extension(settings): Extension<Arc<Settings>>, Query(query): Query<ServiceRequestParameters>) -> Response {
    fold_errors(TransactionBuilder::new(settings).with_query(query).with_request_headers(request_headers).build_and_run().await)
}

async fn handle_post(request_headers: HeaderMap, Extension(settings): Extension<Arc<Settings>>, Form(body): Form<ServiceRequestBody>) -> Response {
    fold_errors(TransactionBuilder::new(settings).with_request_headers(request_headers).with_body(body).build_and_run().await)
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
    body: Option<ServiceRequestBody>
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
            body: None
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
            body: self.body
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
    body: Option<ServiceRequestBody>
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
                let set_cookie = SetCookie::new(self.settings.cookie.clone(), CookieValue::escape_str(&encoded_session_token)).with_options(self.settings.cookie_options.clone()).to_string();
                response_headers.insert(SET_COOKIE, HeaderValue::from_str(&set_cookie)?);
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
                    let set_cookie = SetCookie::new(self.settings.cookie.clone(), CookieValue::escape_str(&body.token)).with_options(self.settings.cookie_options.clone()).to_string();
                    response_headers.insert(SET_COOKIE, HeaderValue::from_str(&set_cookie)?);
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

fn load_current_session_token(settings: Arc<Settings>, request_headers: &HeaderMap) -> Option<SessionToken> {
    let cookie_value = request_headers.extract_cookie(&settings.cookie)?.unescape_str().ok()?;
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

