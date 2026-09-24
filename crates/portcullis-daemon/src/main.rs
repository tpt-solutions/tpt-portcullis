//! Portcullis daemon binary.

use std::path::PathBuf;

use clap::Parser;
use tracing_subscriber::EnvFilter;

/// Single-box Portcullis firewall/router daemon.
#[derive(Debug, Parser)]
#[command(name = "portcullis-daemon", version, about)]
struct Args {
    /// Path to the TOML ruleset config file.
    #[arg(short, long, env = "PORTCULLIS_CONFIG")]
    config: PathBuf,

    /// Control-socket listen address (localhost TCP).
    #[arg(long, default_value = "127.0.0.1:9753", env = "PORTCULLIS_CONTROL")]
    control: String,

    /// Optional tpt-privd Unix socket path for health-check / privileged ops.
    #[arg(long, env = "PORTCULLIS_PRIVD_SOCKET")]
    privd_socket: Option<PathBuf>,

    /// Config-file poll interval in seconds (0 disables watching).
    #[arg(long, default_value_t = 2)]
    poll_secs: u64,
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse().unwrap()))
        .init();

    let args = Args::parse();
    if let Err(e) = portcullis_daemon::control::run(
        args.config,
        args.control,
        args.privd_socket,
        args.poll_secs,
    ) {
        tracing::error!(error = %e, "daemon exited with error");
        std::process::exit(1);
    }
}
