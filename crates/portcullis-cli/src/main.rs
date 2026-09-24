//! # portcullis-cli
//!
//! Admin CLI for Portcullis: offline `validate`, and daemon-backed
//! `apply` / `reload` / `status`.
//!
//! ## License
//!
//! MIT OR Apache-2.0

#![deny(missing_docs)]

mod commands;

use clap::{Parser, Subcommand};

/// Admin CLI for the TPT Portcullis firewall/router.
#[derive(Debug, Parser)]
#[command(name = "portcullis", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Parse + lint a config file without applying it.
    Validate {
        /// Path to the TOML ruleset config file.
        file: std::path::PathBuf,
    },
    /// Ask the running daemon to load, verify, and apply a config file.
    Apply {
        /// Path the daemon should read (must be visible to the daemon).
        file: std::path::PathBuf,
        /// Daemon control address.
        #[arg(long, default_value = "127.0.0.1:9753", env = "PORTCULLIS_CONTROL")]
        control: String,
    },
    /// Ask the daemon to re-read and re-apply its configured file.
    Reload {
        /// Daemon control address.
        #[arg(long, default_value = "127.0.0.1:9753", env = "PORTCULLIS_CONTROL")]
        control: String,
    },
    /// Query daemon status (loaded version, rule counts, last apply).
    Status {
        /// Daemon control address.
        #[arg(long, default_value = "127.0.0.1:9753", env = "PORTCULLIS_CONTROL")]
        control: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = i32::from(commands::run(cli.command));
    std::process::exit(code);
}
