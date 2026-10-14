//! `shion-attach` driving the real `shion-session`, non-interactively.
//!
//! Needs `shion-session` built next to `shion-attach`, which
//! `cargo test --workspace` takes care of.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// Runs `shion-attach` with `args`, feeding it `input`.
fn attach(args: &[&str], input: &[u8]) -> Output {
    let home = tempfile::tempdir().unwrap();
    let exe = env!("CARGO_BIN_EXE_shion-attach");
    assert!(
        std::path::Path::new(exe)
            .with_file_name("shion-session")
            .exists(),
        "build the whole workspace first"
    );
    let mut child = Command::new(exe)
        .args(args)
        .env("USER", "tester")
        .env("HOME", home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn command_output_and_exit_status() {
    let output = attach(&["echo out; echo err >&2; exit 3"], b"");
    assert_eq!(output.stdout, b"out\n");
    assert_eq!(output.stderr, b"err\n");
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn stdin_is_relayed_until_eof() {
    let output = attach(&["cat"], b"hello\nworld\n");
    assert_eq!(output.stdout, b"hello\nworld\n");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn words_are_joined_like_ssh() {
    let output = attach(&["echo", "-n", "a", "b"], b"");
    assert_eq!(output.stdout, b"a b");
}

#[test]
fn forced_pty() {
    let output = attach(&["-t", "tty"], b"");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("/dev/pts/"), "{stdout:?}");
    assert!(stdout.ends_with("\r\n"), "{stdout:?}");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn killed_by_signal() {
    let output = attach(&["kill -TERM $$"], b"");
    assert_eq!(output.status.code(), Some(255));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("killed by signal TERM"), "{stderr:?}");
}

#[test]
fn wrong_user_is_rejected() {
    let session =
        std::path::Path::new(env!("CARGO_BIN_EXE_shion-attach")).with_file_name("shion-session");
    let session = format!("{} --user someone-else --home /", session.display());
    let output = attach(&["-S", &session, "true"], b"");
    assert_eq!(output.status.code(), Some(255));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("rejected the conversation"), "{stderr:?}");
}
