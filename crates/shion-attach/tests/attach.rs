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

#[test]
fn sftp_subsystem() {
    let Some(server) = [
        "/usr/libexec/openssh/sftp-server",
        "/usr/lib/openssh/sftp-server",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).exists()) else {
        eprintln!("skipped: no sftp-server");
        return;
    };
    let home = tempfile::tempdir().unwrap();
    let local = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("remote.txt"), "from the sandbox\n").unwrap();
    std::fs::write(local.path().join("local.txt"), "to the sandbox\n").unwrap();
    let batch = local.path().join("batch");
    std::fs::write(
        &batch,
        format!(
            "get remote.txt {local}/copy.txt\nput {local}/local.txt uploaded.txt\n",
            local = local.path().display()
        ),
    )
    .unwrap();

    // `sftp -D` runs a command (split into words, with quoting) and speaks
    // sftp over its stdin/stdout: just what `shion-attach -s sftp` gives.
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_shion-attach"));
    let session = format!(
        "{} --user tester --home {} --subsystem sftp={server}",
        exe.with_file_name("shion-session").display(),
        home.path().display()
    );
    let attach = format!("{} -l tester -S '{session}' -s sftp", exe.display());
    let output = match Command::new("sftp")
        .arg("-b")
        .arg(&batch)
        .arg("-D")
        .arg(&attach)
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            eprintln!("skipped: cannot run sftp: {e}");
            return;
        }
    };
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read_to_string(local.path().join("copy.txt")).unwrap(),
        "from the sandbox\n"
    );
    assert_eq!(
        std::fs::read_to_string(home.path().join("uploaded.txt")).unwrap(),
        "to the sandbox\n"
    );
}
