use axum::{Extension, Router, serve};
use axum::extract::{Path, Request};
use axum::http::header::{HeaderMap, HeaderValue, CACHE_CONTROL, HOST};
use axum::http::status::StatusCode;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use ed25519_dalek::SigningKey;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

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
    cookie: String   
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
                    cookie: cookie.to_owned()
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

const NO_CACHE: HeaderValue = HeaderValue::from_static("private; no-cache");

async fn set_cache_control(request: Request, next: Next) -> impl IntoResponse {
    let response = next.run(request).await;
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, NO_CACHE);
    (headers, response)
}

