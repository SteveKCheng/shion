//! The network side: SSH connections, and their translation into SSH3
//! channels on the session processes' carriers.
//!
//! Everything here handles hostile input, from the network and from the
//! session processes alike. What it may ask of the trusted side goes
//! through [`Authority`] (see `crate::trusted`).

mod channel;
mod connection;
mod conversation;
mod forward;
mod link;

use std::io;
use std::sync::Arc;
use std::time::Duration;

use russh::server::Config;
use russh::{MethodKind, MethodSet};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use self::connection::Connection;
use self::link::Links;
use crate::trusted::Authority;

/// Serves SSH connections on `listeners` until an accept loop fails.
///
/// # Errors
/// If accepting connections fails for good.
pub async fn serve(listeners: Vec<TcpListener>, authority: Arc<Authority>) -> io::Result<()> {
    let config = Arc::new(ssh_config(&authority));
    let links = Links::new(Arc::clone(&authority));
    // A `JoinSet` owns a group of tasks; `join_next` waits for any of them.
    let mut accept_loops = JoinSet::new();
    for listener in listeners {
        info!(address = %listener.local_addr()?, "listening");
        accept_loops.spawn(accept(
            listener,
            Arc::clone(&config),
            Arc::clone(&authority),
            Arc::clone(&links),
        ));
    }
    while let Some(result) = accept_loops.join_next().await {
        result.map_err(io::Error::other)??;
    }
    Ok(())
}

fn ssh_config(authority: &Authority) -> Config {
    Config {
        server_id: russh::SshId::Standard(
            format!("SSH-2.0-shion_{}", env!("CARGO_PKG_VERSION")).into(),
        ),
        // Public keys only, for now.
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        keys: authority.host_keys(),
        // russh makes every rejection take 1 s, so that response times
        // don't reveal which users and keys exist. The "none" request that
        // OpenSSH clients start with reveals nothing, so don't make every
        // login wait for it.
        auth_rejection_time_initial: Some(Duration::ZERO),
        // Idle shells are normal; dead peers are found by keepalives.
        inactivity_timeout: None,
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        nodelay: true,
        // `..` takes every other field from the defaults.
        ..Config::default()
    }
}

async fn accept(
    listener: TcpListener,
    config: Arc<Config>,
    authority: Arc<Authority>,
    links: Arc<Links>,
) -> io::Result<()> {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Typically out of file descriptors: back off, try again.
                warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let local = tcp.local_addr()?;
        let connection = Connection::new(peer, local, Arc::clone(&authority), Arc::clone(&links));
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            debug!(%peer, "connection");
            // `run_stream` does the key exchange; the session it returns is
            // a future that runs the rest of the connection.
            let result = match russh::server::run_stream(config, tcp, connection).await {
                Ok(session) => session.await,
                Err(e) => Err(e),
            };
            if let Err(e) = result {
                debug!(%peer, error = %e, "connection ended with an error");
            }
        });
    }
}
