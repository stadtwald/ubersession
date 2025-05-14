use axum::{Extension, Router, serve};
use axum::extract::{Path, Request};
use axum::http::header::{HeaderMap, HeaderValue, CACHE_CONTROL, COOKIE, HOST, LOCATION, SET_COOKIE};
use axum::http::status::StatusCode;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use chrono::Utc;
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Server {
    listen: SocketAddr,
    router: Router
}

#[derive(Clone, Debug)]
struct Settings {
    signing_key: SigningKey,
    token_expiry: u32,
    token_request_expiry: u32,
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
        } else if opts.token_request_expiry < 10 {
            Err(anyhow::anyhow!("Token request expiry must be at least ten seconds"))
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
                let url = format!("{}service/{{host}}", url_prefix);
                router = router.route(&url, get(handle_service_request));
            }

            {
                let url = format!("{}receive", url_prefix);
                router = router.route(&url, post(handle_receive_request));
            }

            {
                let url = format!("{}init", url_prefix);
                router = router.route(&url, get(handle_init_request));
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
                    token_request_expiry: opts.token_request_expiry,
                    verbose_workflow: opts.verbose_workflow,
                    no_plain_html: opts.no_plain_html,
                    authority: authority,
                    hosts: hosts,
                    cookie: cookie.to_owned(),
                    protocol: if opts.insecure_http { "http" } else { "https" },
                    url_prefix: url_prefix
                };

            router = router.layer(axum::middleware::from_fn(token_cookie));
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

async fn handle_service_request(headers: HeaderMap, Extension(settings): Extension<Arc<Settings>>, Path(host): Path<String>) -> impl IntoResponse {
    if !settings.hosts.contains(&host) {
        handle_404().await.into_response()
    } else if headers.get(HOST).map(|x| x.to_str().map_err(|_| ())) != Some(Ok(settings.authority.as_str())) {
        handle_404().await.into_response()
    } else {
        ().into_response()
    }
}

async fn handle_receive_request(headers: HeaderMap, Extension(settings): Extension<Arc<Settings>>) -> impl IntoResponse {
    if !headers.get(HOST).map_or(false, |x| x.to_str().map_or(false, |x| settings.hosts.contains(x))) {
        handle_404().await.into_response()
    } else {
        ().into_response()
    }
}

async fn handle_init_request(headers: HeaderMap, Extension(settings): Extension<Arc<Settings>>) -> impl IntoResponse {
    if !headers.get(HOST).map_or(false, |x| x.to_str().map_or(false, |x| settings.hosts.contains(x))) {
        handle_404().await.into_response()
    } else {
        ().into_response()
    }
}

async fn handle_404() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        Html("<!DOCTYPE html><html><head><title>404 Not Found</title></head><body style=\"background-color:#FFFFF0; color:#000040; font-family:roboto, 'open sans', sans-serif\"><h1>404 Not Found</h1></body></html>")
    )
}

async fn handle_400() -> impl IntoResponse {
    (
        StatusCode::BAD_REQUEST,
        Html("<!DOCTYPE html><html><head><title>400 Bad Request</title></head><body style=\"background-color:#FFFFF0; color:#000040; font-family:roboto, 'open sans', sans-serif\"><h1>400 Bad Request</h1></body></html>")
    )
}

async fn handle_500() -> impl IntoResponse {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Html("<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head><body style=\"background-color:#FFFFF0; color:#000040; font-family:roboto, 'open sans', sans-serif\"><h1>500 Internal Server Error</h1></body></html>")
    )
}


const NO_CACHE: HeaderValue = HeaderValue::from_static("private; no-cache");

async fn set_cache_control(request: Request, next: Next) -> impl IntoResponse {
    let response = next.run(request).await;
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, NO_CACHE);
    (headers, response)
}

#[derive(Clone, Debug)]
pub struct SessionToken {
    pub public_key: [u8; 32],
    pub signature: Signature,
    pub host: String, // secured
    pub expires: u32, // secured
    pub id: Uuid // secured
}

impl SessionToken {
    fn new(signing_key: &SigningKey, ttl: u32, host: String) -> Self {
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

    fn signable_message(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9 + 16 + 4 + self.host.len());
        buf.extend("UBERSESS".as_bytes());
        buf.push(0);
        buf.extend(&self.expires.to_be_bytes());
        buf.extend(self.id.as_bytes());
        buf.extend(self.host.as_bytes());
        buf
    }

    fn verify(&self, verifying_key: VerifyingKey) -> bool {
        let signable_message = self.signable_message();
        (&self.public_key == verifying_key.as_bytes()) && verifying_key.verify(&signable_message, &self.signature).is_ok()
    }
}

impl From<SessionToken> for crate::wire::SessionToken {
    fn from(token: SessionToken) -> crate::wire::SessionToken {
        crate::wire::SessionToken {
            public_key: BASE64URL_NOPAD.encode(&token.public_key),
            signature: BASE64URL_NOPAD.encode(&token.signature.to_bytes()),
            host: token.host,
            expires: token.expires,
            id: token.id
        }
    }
}

impl TryFrom<crate::wire::SessionToken> for SessionToken {
    type Error = anyhow::Error;

    fn try_from(wire: crate::wire::SessionToken) -> anyhow::Result<Self> {
        let public_key: [u8; 32] = BASE64URL_NOPAD.decode(wire.public_key.as_bytes())?.as_slice().try_into()?;
        let signature_bytes: [u8; 64] = BASE64URL_NOPAD.decode(wire.signature.as_bytes())?.as_slice().try_into()?;
        let signature = Signature::from_bytes(&signature_bytes);
        Ok(SessionToken {
            public_key: public_key,
            signature: signature,
            host: wire.host,
            expires: wire.expires,
            id: wire.id
        })
    }
}

fn load_current_session_token(settings: Arc<Settings>, request_headers: &HeaderMap) -> Option<SessionToken> {
    let current_timestamp: u32 = Utc::now().timestamp().try_into().ok()?;
    let cookie_header_value = request_headers.get(COOKIE)?.to_str().ok()?;
    if cookie_header_value.len() > 4096 {
        return None;
    }
    let raw_session_value =
        {
            let mut m_value = None;
            for kv_pair in cookie_header_value.split("; ") {
                if let Some((key, value)) = kv_pair.split_once('=') {
                    if key == settings.cookie {
                        m_value = Some(value);
                        break;
                    }
                }
            }
            m_value?
        };
    let text_session_value = BASE64URL_NOPAD.decode(raw_session_value.as_bytes()).ok()?;
    let session_token_descriptor: crate::wire::SessionToken = serde_json::from_slice(&text_session_value).ok()?;
    let session_token: SessionToken = session_token_descriptor.try_into().ok()?;
    if !session_token.verify(settings.signing_key.verifying_key()) {
        return None;
    }
    let http_host = request_headers.get(HOST)?.to_str().ok()?;
    if session_token.host != http_host {
        return None;
    }
    if session_token.expires < current_timestamp {
        return None;
    }
    Some(session_token)
}

async fn token_cookie(request_headers: HeaderMap, Extension(settings): Extension<Arc<Settings>>, mut request: Request, next: Next) -> Response {
    let mut response_headers = HeaderMap::new();

    let current_session_token =
        if let Some(current_session_token) = load_current_session_token(settings.clone(), &request_headers) {
            current_session_token
        } else {
            if request_headers.get(HOST).map_or(false, |x| x == settings.authority.as_str()) {
                let session_token = SessionToken::new(&settings.signing_key, settings.token_expiry, settings.authority.clone());
                let session_token_descriptor: crate::wire::SessionToken = session_token.clone().into();
                let encoded_session_token_descriptor = BASE64URL_NOPAD.encode(serde_json::to_string(&session_token_descriptor).unwrap().as_bytes());
                let cookie_value = format!("{}={}", settings.cookie, encoded_session_token_descriptor);
                response_headers.insert(SET_COOKIE, HeaderValue::from_str(&cookie_value).unwrap());
                session_token
            } else if let Some(http_host) = request_headers.get(HOST).and_then(|x| x.to_str().ok().map(|x| x.to_owned())).and_then(|x| if settings.hosts.contains(&x) { Some(x) } else { None }) {
                let uri = format!("{}://{}{}service/{}", settings.protocol, settings.authority, settings.url_prefix, http_host);
                if let Ok(location) = HeaderValue::from_str(&uri) {
                    response_headers.insert(LOCATION, location);
                    return (StatusCode::SEE_OTHER, response_headers).into_response();
                } else {
                    return handle_500().await.into_response();
                }
            } else {
                return handle_404().await.into_response();
            }
        };

    request.extensions_mut().insert(current_session_token);

    let response = next.run(request).await;

    (response_headers, response).into_response()
}

