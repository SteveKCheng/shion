//! Per-user settings, from the command line (design §5.6).

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

/// Global settings for shion's per-user session process,
/// passed in from the command line.
///
/// Speaks smux-multiplexed SSH3 channels on stdin/stdout, and is normally
/// started by the shion front-end inside a bwrap sandbox. Logs go to
/// stderr (filter with `RUST_LOG`, e.g. `RUST_LOG=shion_session=debug`).
#[derive(Debug, Parser)]
#[command(version)]
pub struct Settings {
    /// App-level user name: sets `USER` and `LOGNAME`.
    #[arg(long, value_name = "NAME")]
    pub user: String,

    /// Home directory: sets `HOME`, and is the initial working directory.
    #[arg(long, value_name = "DIR")]
    pub home: PathBuf,

    /// Shell that runs `shell`, `exec` and `subsystem` requests.
    #[arg(long, value_name = "PATH", default_value = "/bin/sh")]
    pub shell: PathBuf,

    /// Adds a variable to the base environment (repeatable). Applied after
    /// the built-in variables, so it can override them.
    #[arg(long = "setenv", value_name = "NAME=VALUE", value_parser = parse_assignment)]
    pub env: Vec<(String, String)>,

    /// Accepts `env` requests for variables whose names match this pattern
    /// (repeatable). `*` matches any run of characters and `?` any single
    /// one, as in OpenSSH's `AcceptEnv`. Without it, `env` is refused.
    #[arg(long = "accept-env", value_name = "PATTERN")]
    pub accept_env: Vec<String>,

    /// Defines a subsystem (repeatable): a `subsystem NAME` request runs
    /// COMMAND with the shell, like `exec`. Example:
    /// `--subsystem sftp=/usr/libexec/openssh/sftp-server`.
    #[arg(long = "subsystem", value_name = "NAME=COMMAND", value_parser = parse_assignment)]
    pub subsystems: Vec<(String, String)>,

    /// Allows local forwarding (`direct-tcpip`, `ssh -L`) to HOST:PORT
    /// (repeatable). HOST is matched as the client wrote it, before name
    /// resolution, and may use `*` and `?`; PORT is a number or `*`.
    /// Without it, local forwarding is refused. Example: `'localhost:*'`.
    #[arg(long = "permit-open", value_name = "HOST:PORT", value_parser = parse_permission)]
    pub permit_open: Vec<Permission>,

    /// Allows remote forwarding (`tcpip-forward`, `ssh -R`) to listen on
    /// HOST:PORT (repeatable), matched like `--permit-open` against the
    /// requested bind address: `localhost`, an address, or the empty string
    /// for all addresses (which only `*` matches). Port 0 asks for any free
    /// port, so it needs `*`. Without it, remote forwarding is refused.
    #[arg(long = "permit-listen", value_name = "HOST:PORT", value_parser = parse_permission)]
    pub permit_listen: Vec<Permission>,

    /// Exits once no conversation has been open for this many seconds
    /// (fractions allowed), counting from startup too. Without it, the
    /// process runs until the front-end closes its stdin/stdout.
    #[arg(long, value_name = "SECONDS", value_parser = parse_seconds)]
    pub linger: Option<Duration>,
}

impl Settings {
    /// Whether an `env` request for `name` may be honored.
    pub fn accepts_env(&self, name: &[u8]) -> bool {
        self.accept_env
            .iter()
            .any(|pattern| glob_match(pattern.as_bytes(), name))
    }

    /// Whether `direct-tcpip` may connect to `host` and `port`.
    pub fn permits_open(&self, host: &str, port: u16) -> bool {
        self.permit_open.iter().any(|p| p.allows(host, port))
    }

    /// Whether `tcpip-forward` may listen on `address` and `port`.
    pub fn permits_listen(&self, address: &str, port: u16) -> bool {
        self.permit_listen.iter().any(|p| p.allows(address, port))
    }

    /// The command for subsystem `name`, if there is one. The first
    /// definition wins.
    pub fn subsystem(&self, name: &str) -> Option<&str> {
        self.subsystems
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, command)| command.as_str())
    }
}

/// Splits `NAME=VALUE`. (clap hands value parsers a `&str`, so values on
/// the command line must be UTF-8, though the environment itself needn't
/// be.)
fn parse_assignment(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((name, value)) if !name.is_empty() => Ok((name.into(), value.into())),
        _ => Err(format!("expected NAME=VALUE, got {s:?}")),
    }
}

/// A `HOST:PORT` pattern from `--permit-open` or `--permit-listen`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permission {
    host: String,
    /// `None` for `*`.
    port: Option<u16>,
}

impl Permission {
    fn allows(&self, host: &str, port: u16) -> bool {
        self.port.is_none_or(|p| p == port) && glob_match(self.host.as_bytes(), host.as_bytes())
    }
}

/// Parses `HOST:PORT`. The last colon separates them, so an IPv6 address
/// works as HOST, with or without brackets: `::1:22`, `[::1]:22`.
fn parse_permission(s: &str) -> Result<Permission, String> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| format!("expected HOST:PORT, got {s:?}"))?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let port = match port {
        "*" => None,
        _ => Some(port.parse().map_err(|e| format!("port {port:?}: {e}"))?),
    };
    Ok(Permission {
        host: host.to_owned(),
        port,
    })
}

/// Parses a non-negative number of seconds, such as `300` or `0.5`.
fn parse_seconds(s: &str) -> Result<Duration, String> {
    // `map_err` converts each error type into the `String` clap wants;
    // `try_from_secs_f64` rejects negative, NaN and infinite values.
    let seconds: f64 = s.parse().map_err(|e| format!("{e}"))?;
    Duration::try_from_secs_f64(seconds).map_err(|e| format!("{e}"))
}

/// Matches `name` against a pattern where `*` stands for any run of bytes
/// (including none) and `?` for exactly one byte.
///
/// The name comes from the client, so the matcher must not be exponential.
/// It backtracks only to the most recent `*`, which is enough: an earlier
/// `*` never needs to absorb more, because the later one can absorb the
/// same bytes. That makes it O(pattern × name) at worst.
fn glob_match(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    // After the latest `*`: where the rest of the pattern starts, and where
    // in `name` we're trying to match it.
    let mut retry = None;
    while n < name.len() {
        match pattern.get(p) {
            Some(b'*') => {
                p += 1;
                retry = Some((p, n));
            }
            Some(&c) if c == b'?' || c == name[n] => {
                p += 1;
                n += 1;
            }
            // Mismatch (or the pattern ran out): let the latest `*` swallow
            // one more byte and try the rest of the pattern again.
            _ => match retry {
                Some((after_star, start)) => {
                    p = after_star;
                    n = start + 1;
                    retry = Some((after_star, n));
                }
                None => return false,
            },
        }
    }
    // The name is used up; only `*`s, which can match nothing, may remain.
    pattern[p..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::{glob_match, parse_permission};

    #[test]
    fn permissions() {
        let p = parse_permission("localhost:*").unwrap();
        assert!(p.allows("localhost", 8080));
        assert!(!p.allows("127.0.0.1", 8080));

        let p = parse_permission("[::1]:22").unwrap();
        assert!(p.allows("::1", 22));
        assert!(!p.allows("::1", 23));
        assert_eq!(parse_permission("::1:22"), Ok(p));

        let p = parse_permission("*:80").unwrap();
        assert!(p.allows("", 80));
        assert!(p.allows("example.com", 80));

        assert!(parse_permission("localhost").is_err());
        assert!(parse_permission("localhost:http").is_err());
        assert!(parse_permission("localhost:65536").is_err());
    }

    #[test]
    fn literal_patterns() {
        assert!(glob_match(b"LANG", b"LANG"));
        assert!(!glob_match(b"LANG", b"LANGUAGE"));
        assert!(!glob_match(b"LANG", b"LAN"));
        assert!(!glob_match(b"LANG", b""));
        assert!(glob_match(b"", b""));
    }

    #[test]
    fn wildcards() {
        assert!(glob_match(b"LC_*", b"LC_ALL"));
        assert!(glob_match(b"LC_*", b"LC_"));
        assert!(!glob_match(b"LC_*", b"LANG"));
        assert!(glob_match(b"*", b""));
        assert!(glob_match(b"*_*_X", b"A_B_C_X"));
        assert!(!glob_match(b"*_*_X", b"A_B_C_Y"));
        assert!(glob_match(b"?ANG", b"LANG"));
        assert!(!glob_match(b"?ANG", b"ANG"));
        assert!(glob_match(b"a*b*c", b"abcbc"));
        assert!(glob_match(b"**a", b"a"));
    }

    #[test]
    fn long_names_are_cheap() {
        // Exponential matchers take ages on this one.
        let name = [b'a'; 10_000];
        assert!(!glob_match(b"*a*a*a*a*a*a*b", &name));
    }
}
