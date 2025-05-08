mod cli;
mod wire;

use clap::Parser;

use crate::cli::{Cli, Command};

fn main() -> anyhow::Result<()> {
    let opts = Cli::parse();
    match opts.command {
        Command::GenerateKey(opts) => opts.run(),
        Command::GetPublicKey(opts) => opts.run(),
        Command::Serve(_opts) => unimplemented!("subcommand not yet implemented")
    }
}

