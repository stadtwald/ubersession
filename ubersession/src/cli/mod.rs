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


