use clap::Args;
use std::path::PathBuf;

#[derive(Clone, Debug)]
#[derive(Args)]
pub struct GenerateKey {
    #[arg(short = 'o', long)]
    pub private_key_file: PathBuf,

    #[arg(short = 'C', long)]
    pub comment: Option<String>
}


