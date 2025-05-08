pub mod generate_key;
pub mod get_public_key;
pub mod serve;

use clap::{Parser, Subcommand};

use crate::cli::generate_key::GenerateKey;
use crate::cli::get_public_key::GetPublicKey;
use crate::cli::serve::Serve;

#[derive(Clone, Debug)]
#[derive(Subcommand)]
pub enum Command {
    GenerateKey(GenerateKey),
    GetPublicKey(GetPublicKey),
    Serve(Serve)
}

#[derive(Clone, Debug)]
#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command
}


