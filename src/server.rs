use axum::{Extension, Form, Router, serve};
use axum::extract::{Query, Request};
use axum::http::header::{HeaderMap, HeaderValue, CACHE_CONTROL, COOKIE, HOST, LOCATION, SET_COOKIE};
use axum::http::status::StatusCode;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::errors::*;
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
    cookie: String,
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
            let raw_input = std::fs::read(&opts.private_key_file)?;
            let keypair_description: crate::wire::Keypair = serde_json::from_slice(&raw_input)?;
            let signing_key = keypair_description.try_loading_signing_key()?;
            
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

            let settings = 
                Settings {
                    signing_key: signing_key,
                    token_expiry: opts.token_expiry,
                    verbose_workflow: opts.verbose_workflow,
                    no_plain_html: opts.no_plain_html,
                    authority: authority,
                    hosts: hosts,
                    cookie: cookie.to_owned(),
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

#[derive(Clone, Copy, Debug)]
struct InvalidRequest;

impl Error for InvalidRequest {}

impl Display for InvalidRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Invalid HTTP request")
    }
}

#[derive(Clone, Copy, Debug)]
struct NotFound;

impl Error for NotFound {}

impl Display for NotFound {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HTTP resource not found")
    }
}

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
                let encoded_session_token = BASE64URL_NOPAD.encode(serde_json::to_string(&session_token)?.as_bytes());
                let cookie_value = format!("{}={}", self.settings.cookie, encoded_session_token);
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
            let encoded_session_token = BASE64URL_NOPAD.encode(&serde_json::to_string(&session_token)?.as_bytes());

            let uri = format!("{}://{}{}flow?{}", self.settings.protocol, self.for_host, self.settings.url_prefix, serde_urlencoded::to_string(&self.query)?);
            let (button, styles) =
                if self.settings.no_plain_html {
                    ("", "")
                } else {
                    (
                        "<noscript>You don\'t appear to have JavaScript enabled. Please click the following button to proceed to the next page. <button>Proceed</button></noscript>",
                        "<style type=\"text/css\">body { background-color:#FFFFF0; color:#000040; font-family:roboto, 'open sans', sans-serif}</style>"
                    )
                };
            let escaped_path = self.redir_path.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
            let html = Html(format!("<!DOCTYPE html><html><head><title>Redirecting to application</title>{}</head><body><form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"token\" value=\"{}\"><input type=\"hidden\" name=\"path\" value=\"{}\">{}</form><script type=\"text/javascript\">document.querySelector('form').submit();</script></body></html>", styles, uri, encoded_session_token, escaped_path, button));
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
                    let cookie_value = format!("{}={}", self.settings.cookie, body.token);
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
                    m_value = Some(value.to_owned());
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

