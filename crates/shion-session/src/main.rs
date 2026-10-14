//! shion's per-user session process. See `docs/design-session.md`.

mod carrier;
mod channel;
mod control;
mod server;
mod settings;
mod signals;
mod state;

use std::process::ExitCode;

use clap::Parser;
use rustix::process::DumpableBehavior;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::settings::Settings;
use crate::state::State;

#[tokio::main]
async fn main() -> ExitCode {
    let settings = Settings::parse();

    // stdout is the protocol stream, so logs go to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Defense in depth (design §3): stops same-uid processes in the sandbox
    // from ptrace-ing us or reading our memory. Children get their own
    // dumpable flag back when they exec.
    if let Err(e) = rustix::process::set_dumpable_behavior(DumpableBehavior::NotDumpable) {
        warn!(error = %e, "cannot clear the dumpable flag");
    }

    // Pair up stdin/stdout as a single bi-directional "carrier", 
    // i.e. it behaves like a socket stream that can be used for async-smux
    let carrier = match carrier::from_stdio() {
        Ok(carrier) => carrier,
        Err(e) => {
            error!(error = %e, "cannot set up stdin/stdout");
            return ExitCode::FAILURE;
        }
    };

    info!(
        user = settings.user,
        pid = std::process::id(),
        "session process started"
    );
    
    server::serve(carrier, State::new(settings)).await;
    ExitCode::SUCCESS
}
