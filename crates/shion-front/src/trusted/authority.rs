//! [`Authority`]: what the network side may ask of the trusted side.

use std::collections::HashMap;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use russh::keys::{HashAlg, PrivateKey, PublicKey};
use tokio::process::Command;
use tracing::{info, warn};

use super::config::Config;

/// Validated configuration, and the grants handed out so far.
#[derive(Debug)]
pub struct Authority {
    users: HashMap<String, User>,
    host_keys: Vec<PrivateKey>,
    grants: Mutex<HashMap<u64, Grant>>,
    next_token: AtomicU64,
}

#[derive(Debug)]
struct User {
    authorized_keys: Vec<PublicKey>,
    /// Session command line, `{user}` already substituted.
    session: Vec<String>,
    linger: Duration,
}

/// Proof of a successful authentication, handed to the network side.
///
/// Later requests name it by `token` alone; the other fields are for the
/// network side's information (logs, `CONV_OPEN` attributes). In-process a
/// token can't be forged anyway. Across a process boundary, the master
/// would only honour tokens it gave to the same connection process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub token: u64,
    pub user: String,
    /// How the user authenticated, e.g. `publickey`.
    pub method: String,
    /// The key's fingerprint, `SHA256:…`, for public key authentication.
    pub key_fingerprint: Option<String>,
}

/// A session process started for a grant.
#[derive(Debug)]
pub struct LaunchedSession {
    /// Our end of the carrier: the process's stdin and stdout are the
    /// other end.
    pub carrier: UnixStream,
    /// How long to keep the process after the last connection closes.
    pub linger: Duration,
}

impl Authority {
    /// Validates the configuration and loads the host keys.
    ///
    /// # Errors
    /// Describes the first problem found.
    pub fn new(config: &Config) -> Result<Self, String> {
        let mut users = HashMap::new();
        for (name, user) in &config.users {
            let session = user
                .session
                .as_ref()
                .or(config.defaults.session.as_ref())
                .ok_or_else(|| {
                    format!("user {name}: no session command, and none in [defaults]")
                })?;
            if session.is_empty() {
                return Err(format!("user {name}: empty session command"));
            }
            let linger = user.linger.or(config.defaults.linger).unwrap_or(0.0);
            let linger = Duration::try_from_secs_f64(linger)
                .map_err(|e| format!("user {name}: linger: {e}"))?;
            let authorized_keys = user
                .authorized_keys
                .iter()
                .map(|line| {
                    PublicKey::from_openssh(line)
                        .map_err(|e| format!("user {name}: authorized key {line:?}: {e}"))
                })
                // Collecting an iterator of `Result`s into a `Result` stops
                // at the first error.
                .collect::<Result<_, _>>()?;
            let session = session
                .iter()
                .map(|arg| arg.replace("{user}", name))
                .collect();
            users.insert(
                name.clone(),
                User {
                    authorized_keys,
                    session,
                    linger,
                },
            );
        }

        if config.host_keys.is_empty() {
            return Err("no host_keys".into());
        }
        let host_keys = config
            .host_keys
            .iter()
            .map(|path| {
                russh::keys::load_secret_key(path, None)
                    .map_err(|e| format!("host key {}: {e}", path.display()))
            })
            .collect::<Result<_, _>>()?;

        Ok(Self {
            users,
            host_keys,
            grants: Mutex::new(HashMap::new()),
            next_token: AtomicU64::new(1),
        })
    }

    /// The host keys.
    ///
    /// The network side needs them for every key exchange. OpenSSH's
    /// monitor instead keeps them and signs on the network side's behalf;
    /// that's how this would work across a process boundary.
    pub fn host_keys(&self) -> Vec<PrivateKey> {
        self.host_keys.clone()
    }

    /// Whether `key` may log in as `user`, without granting anything: for
    /// a client asking before it proves it holds the private key.
    pub fn accepts_key(&self, user: &str, key: &PublicKey) -> bool {
        self.users.get(user).is_some_and(|u| {
            // Compare the keys only: `PublicKey`'s own `==` would compare
            // the comments too.
            u.authorized_keys
                .iter()
                .any(|k| k.key_data() == key.key_data())
        })
    }

    /// Authenticates `user` by `key`, whose possession the network side
    /// has verified (russh checks the signature before asking).
    ///
    /// Across a process boundary, the master shouldn't take the network
    /// side's word for that: it would check the signature itself, which
    /// needs the session identifier and the signed data. russh doesn't
    /// expose those yet.
    pub fn authenticate_key(&self, user: &str, key: &PublicKey) -> Option<Grant> {
        if !self.accepts_key(user, key) {
            return None;
        }
        let grant = Grant {
            token: self.next_token.fetch_add(1, Ordering::Relaxed),
            user: user.to_owned(),
            method: "publickey".into(),
            key_fingerprint: Some(key.fingerprint(HashAlg::Sha256).to_string()),
        };
        self.grants().insert(grant.token, grant.clone());
        info!(user, key = grant.key_fingerprint, "authenticated");
        Some(grant)
    }

    /// Starts a session process for the grant's user, and returns our end
    /// of its carrier.
    ///
    /// It starts a new process every time: sharing one process between a
    /// user's connections is the network side's business. That gives a
    /// compromised network side nothing it couldn't get by logging in
    /// again with the same credentials.
    ///
    /// # Errors
    /// If the token is unknown, or the process can't be started.
    pub fn launch_session(&self, token: u64) -> io::Result<LaunchedSession> {
        let user_name = self
            .grants()
            .get(&token)
            .map(|grant| grant.user.clone())
            .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "unknown grant"))?;
        // A grant is only ever made for a configured user.
        let user = &self.users[&user_name];

        let (ours, theirs) = UnixStream::pair()?;
        let theirs = OwnedFd::from(theirs);
        let mut command = Command::new(&user.session[0]);
        command
            .args(&user.session[1..])
            .stdin(Stdio::from(theirs.try_clone()?))
            .stdout(Stdio::from(theirs))
            // Its logs go to ours.
            .stderr(Stdio::inherit());
        let mut child = command.spawn()?;
        // `command` holds the child's end of the socket: drop it, or we'd
        // never see the carrier close when the child exits.
        drop(command);
        info!(
            user = user_name,
            pid = child.id(),
            "session process started"
        );

        // Reap it whenever it exits. (A `Child` that is dropped without
        // being waited for becomes a zombie, as in C.)
        tokio::spawn(async move {
            match child.wait().await {
                Ok(status) if status.success() => info!(user = user_name, "session process exited"),
                Ok(status) => warn!(user = user_name, %status, "session process failed"),
                Err(e) => warn!(user = user_name, error = %e, "cannot wait for session process"),
            }
        });

        Ok(LaunchedSession {
            carrier: ours,
            linger: user.linger,
        })
    }

    /// Forgets a grant, when its connection has closed.
    pub fn revoke(&self, token: u64) {
        self.grants().remove(&token);
    }

    fn grants(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Grant>> {
        self.grants.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
