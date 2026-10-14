//! Per-user settings, from the command line (design §5.6).

use std::ffi::OsString;
use std::path::PathBuf;

use clap::Parser;

/// shion's per-user session process.
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

    /// Shell that runs `shell` and `exec` requests.
    #[arg(long, value_name = "PATH", default_value = "/bin/sh")]
    pub shell: PathBuf,

    /// Adds a variable to the base environment (repeatable). Applied after
    /// the built-in variables, so it can override them.
    #[arg(long = "setenv", value_name = "NAME=VALUE", value_parser = parse_env_assignment)]
    pub env: Vec<(OsString, OsString)>,
}

/// Splits `NAME=VALUE`. (clap hands value parsers a `&str`, so values on
/// the command line must be UTF-8, though the environment itself needn't
/// be.)
fn parse_env_assignment(s: &str) -> Result<(OsString, OsString), String> {
    match s.split_once('=') {
        Some((name, value)) if !name.is_empty() => Ok((name.into(), value.into())),
        _ => Err(format!("expected NAME=VALUE, got {s:?}")),
    }
}
