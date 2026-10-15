//! `shion-front`: the SSH server. See `docs/design-front.md`.
//!
//! The code is split along the lines of a possible future process split
//! (`notes/extended-priv-sep.md`): [`trusted`] holds the configuration and
//! credentials and launches session processes; [`network`] talks to SSH
//! clients and session processes, and asks [`trusted::Authority`] for
//! anything else.

mod network;
mod trusted;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use tokio::net::TcpListener;
use tracing::error;
use tracing_subscriber::EnvFilter;

use crate::trusted::{Authority, Config};

/// shion's SSH server: authenticates app-level users and connects them to
/// their (sandboxed) session processes.
#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// The configuration file.
    #[arg(short = 'f', long, value_name = "FILE")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        // Colours only on a terminal, not in a log file or pipe.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
    // The trusted side reads the configuration...
    let config = Config::load(&args.config)?;
    let authority = Arc::new(Authority::new(&config)?);

    // ...and the network side gets only the listening addresses from it.
    let mut listeners = Vec::new();
    for address in &config.listen {
        let listener = TcpListener::bind(address)
            .await
            .map_err(|e| format!("listen on {address}: {e}"))?;
        listeners.push(listener);
    }
    drop(config);

    network::serve(listeners, authority)
        .await
        .map_err(|e| e.to_string())
}
