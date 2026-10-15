//! The configuration file: TOML, written by the administrator, and so
//! trusted input. For example:
//!
//! ```toml
//! listen = ["0.0.0.0:2222"]
//! # Made with e.g. `ssh-keygen -t ed25519 -N '' -f /etc/shion/host_ed25519`.
//! host_keys = ["/etc/shion/host_ed25519"]
//!
//! [defaults]
//! # `{user}` is replaced by the user name in every argument.
//! session = [
//!     "bwrap", "--unshare-all", "--die-with-parent",
//!     "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
//!     "--bind", "/srv/agents/{user}", "/home/{user}",
//!     "--",
//!     "/usr/libexec/shion/shion-session",
//!     "--user", "{user}", "--home", "/home/{user}", "--shell", "/bin/bash",
//! ]
//! linger = 300
//!
//! [users.agent-7]
//! authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… agent-7@build"]
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The whole configuration file.
///
/// `Deserialize` is derived: serde generates the code that fills the struct
/// from TOML, field by field. `deny_unknown_fields` turns a misspelt key
/// into an error instead of a silently ignored setting.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Addresses to listen on, such as `"0.0.0.0:2222"` or `"[::]:22"`.
    pub listen: Vec<String>,
    /// Host private keys, in OpenSSH format.
    pub host_keys: Vec<PathBuf>,
    /// Settings for every user that doesn't override them.
    #[serde(default)]
    pub defaults: UserSettings,
    /// The users, by name.
    #[serde(default)]
    pub users: BTreeMap<String, UserConfig>,
}

/// Settings that can be given per user, or in `[defaults]`.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSettings {
    /// The command line that starts the user's session process, with
    /// `{user}` replaced by the user name in each argument. The process
    /// gets the carrier (a socket) as its stdin and stdout.
    pub session: Option<Vec<String>>,
    /// Seconds to keep the session process after the user's last
    /// connection has closed, so that the next one finds it running.
    /// Default 0.
    pub linger: Option<f64>,
}

/// One user's entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    /// Public keys that may log in, one `authorized_keys`-style line each
    /// (`type base64 [comment]`; options aren't supported).
    #[serde(default)]
    pub authorized_keys: Vec<String>,
    // Not `#[serde(flatten)]` with `UserSettings`: serde can't combine
    // that with `deny_unknown_fields`.
    pub session: Option<Vec<String>>,
    pub linger: Option<f64>,
}

impl Config {
    /// Reads and parses the configuration file.
    ///
    /// # Errors
    /// If the file can't be read or isn't valid.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }
}
