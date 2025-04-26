mod generate_key;
mod serve;

use clap::{Parser, Subcommand};

use crate::cli::generate_key::GenerateKey;
use crate::cli::serve::Serve;

#[derive(Clone, Debug)]
#[derive(Subcommand)]
pub enum Command {
    GenerateKey(GenerateKey),
    Serve(Serve)
}

#[derive(Clone, Debug)]
#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command
}


