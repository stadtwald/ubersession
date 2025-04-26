use clap::{Args, Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Clone, Debug)]
#[derive(Args)]
struct GenerateKey {
    #[arg(short = 'o', long)]
    private_key_file: PathBuf,

    #[arg(short = 'C', long)]
    comment: Option<String>
}

#[derive(Clone, Debug)]
#[derive(Args)]
struct Serve {
    /// What port to listen for requests on
    #[arg(long, default_value = "0.0.0.0:3000", env = "UBERSESSION_LISTEN")]
    listen: SocketAddr,

    /// What private key to use for signing tokens
    #[arg(short = 'k', long, env = "UBERSESSION_PRIVATE_KEY_FILE")]
    private_key_file: PathBuf,

    /// How long normal tokens last before being considered expired, in seconds
    #[arg(long, default_value_t = 366 * 86400)]
    token_expiry: u32,

    /// How long token requests last before being considered expired, in seconds
    #[arg(long, default_value_t = 600)]
    token_request_expiry: u32,

    /// Make workflow visible to the user
    #[arg(long)]
    verbose_workflow: bool,

    /// Turn off fallback to plain HTML when JavaScript support is not available
    #[arg(long)]
    no_plain_html: bool,

    /// Prefix to use for workflow URLs (will have / suffixed automatically)
    #[arg(long, default_value = "/_session")]
    url_prefix: String
}

#[derive(Clone, Debug)]
#[derive(Subcommand)]
enum Command {
    GenerateKey(GenerateKey),
    Serve(Serve)
}

#[derive(Clone, Debug)]
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command
}

fn main() -> () {
    let opts = Cli::parse();
    ()
}

