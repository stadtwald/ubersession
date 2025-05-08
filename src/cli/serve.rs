use clap::Args;
use std::net::SocketAddr;
use std::path::PathBuf;

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
    #[arg(long, short = 'd')]
    pub domain: Vec<String>,

    /// Cookie to store authoritative session state in
    #[arg(long, default_value = "UBERSESSION_AUTHORITY")]
    pub authority_cookie: String,

    /// Cookie to store propogated session state in
    #[arg(long, default_value = "UBERSESSION")]
    pub cookie: String
}

impl Serve {
    pub fn run(self) -> anyhow::Result<()> {
        Ok(())
    }
}

