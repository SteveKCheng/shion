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
    use super::glob_match;

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
