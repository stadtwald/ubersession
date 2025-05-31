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

use clap::Args;
use std::net::SocketAddr;
use std::path::PathBuf;

use axum::{Extension, Router, serve};
use axum::extract::Request;
use axum::response::Response;
use axum::routing;
use tokio::net::TcpListener;
use ubersession_axum::adapt::*;
use ubersession_core::cookie::*;
use ubersession_core::uri::UriPath;
use ubersession_server::*;

use crate::keypair::Keypair;

#[derive(Clone, Debug)]
#[derive(Args)]
pub struct Serve {
    /// What port to listen for requests on
    #[arg(long, default_value = "0.0.0.0:3000", env = "UBERSESSION_LISTEN")]
    pub listen: SocketAddr,

    /// What private key to use for signing tokens
    #[arg(short = 'k', long, env = "UBERSESSION_PRIVATE_KEY_FILE")]
    pub private_key_file: PathBuf,

    /// How long normal tokens last before being considered expired, in seconds
    #[arg(long, default_value_t = 366 * 86400)]
    pub token_expiry: u32,

    /// Turn off fallback to plain HTML when JavaScript support is not available
    #[arg(long)]
    pub no_plain_html: bool,

    /// Prefix to use for workflow URLs (will have / suffixed automatically)
    #[arg(long, default_value = "/_session/")]
    pub url_prefix: UriPath,

    /// Domain to use for managing authoritative session state (with optional port to use for
    /// generating URLs)
    #[arg(long, short = 'a')]
    pub authority: HostNameAndPort,

    /// Domain to propogate session to (with optional port to use for generating URLs)
    #[arg(long = "host", short = 'd')]
    pub hosts: Vec<HostNameAndPort>,

    /// Cookie to store session tokens in
    #[arg(long, default_value = "UBERSESSION")]
    pub cookie: String,

    /// Utilise plain HTTP URLs
    #[arg(long)]
    pub insecure_http: bool
}

impl Serve {
    pub fn run(self) -> anyhow::Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

        rt.block_on(self.serve())
    }

    async fn serve(self) -> anyhow::Result<()> {
        if self.token_expiry < 60 {
            Err(anyhow::anyhow!("Token expiry must be at least a minute"))
        } else if self.cookie.len() < 1 {
            Err(anyhow::anyhow!("Cookie name must not be empty"))
        } else {
            let raw_input = std::fs::read(&self.private_key_file)?;
            let keypair: Keypair = serde_json::from_slice(&raw_input)?;
            let signing_key = keypair.private_key;
            
            let protocol =
                if self.insecure_http {
                    Protocol::Http
                } else {
                    Protocol::Https
                };

            let authority_host =
                HostSettings::new(self.authority.host_name().clone())
                    .with_path_prefix(self.url_prefix.clone())
                    .with_cookie(CookieName::escape_str(&self.cookie))
                    .with_protocol(protocol)
                    .with_url_port(self.authority.port().unwrap_or_else(|| protocol.default_port()));

            let mut server_settings = ServerSettings::new(signing_key, authority_host);

            for host in self.hosts {
                let mirror_host =
                    HostSettings::new(host.host_name().clone())
                        .with_path_prefix(self.url_prefix.clone())
                        .with_cookie(CookieName::escape_str(&self.cookie))
                        .with_protocol(protocol)
                        .with_url_port(host.port().unwrap_or_else(|| protocol.default_port()));
                server_settings = server_settings.add_host(mirror_host)?;
            }

            let router = Router::new();
            let router = router.route("/", routing::any(handle));
            let router = router.route("/{*segs}", routing::any(handle));
            let router = router.method_not_allowed_fallback(handle_400);
            let router = router.layer(Extension(server_settings.build_server()));

            let listener = TcpListener::bind(self.listen).await?;
            serve(listener, router).await?;

            Ok(())
        }
    }
}

async fn handle_400() -> Response {
    adapt_response(build_400())
}

async fn handle(Extension(server): Extension<Server>, request: Request) -> Response {
    adapt_response(server.handle(adapt_request(request).await))
}


