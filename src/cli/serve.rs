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

use crate::server::Server;

#[derive(Clone, Debug)]
#[derive(Args)]
pub struct Serve {
    /// What port to listen for requests on
    #[arg(long, default_value = "0.0.0.0:3000", env = "UBERSESSION_LISTEN")]
    pub listen: SocketAddr,

    /// What private key to use for signing tokens
    #[arg(short = 'k', long, env = "UBERSESSION_PRIVATE_KEY_FILE")]
    pub private_key_file: PathBuf,

    /// Where to load host restrictions from
    #[arg(long)]
    pub host_restrictions_file: Option<PathBuf>,

    /// How long normal tokens last before being considered expired, in seconds
    #[arg(long, default_value_t = 366 * 86400)]
    pub token_expiry: u32,

    /// How long token requests last before being considered expired, in seconds
    #[arg(long, default_value_t = 600)]
    pub token_request_expiry: u32,

    /// Make workflow visible to the user
    #[arg(long)]
    pub verbose_workflow: bool,

    /// Turn off fallback to plain HTML when JavaScript support is not available
    #[arg(long)]
    pub no_plain_html: bool,

    /// Prefix to use for workflow URLs (will have / suffixed automatically)
    #[arg(long, default_value = "/_session")]
    pub url_prefix: String,

    /// Domain to use for managing authoritative session state
    #[arg(long, short = 'a')]
    pub authority: String,

    /// Domain to propogate session to
    #[arg(long = "host", short = 'd')]
    pub hosts: Vec<String>,

    /// Cookie to store session tokens in
    #[arg(long, default_value = "UBERSESSION")]
    pub cookie: String,

    /// Utilise plain HTTP URLs
    #[arg(long)]
    pub insecure_http: bool
}

impl Serve {
    pub fn run(self) -> anyhow::Result<()> {
        let server = Server::try_init_from_serve_opts(self)?;
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

        rt.block_on(server.serve())
    }
}

