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

/// A port for test number `n` to listen on.
///
/// Not "a port that was free a moment ago" (bind to port 0, read it, close
/// it): such ports come from the kernel's ephemeral range, which every
/// other `bind(0)` and outgoing connection in the parallel tests draws from
/// too, and a collision sent this test's connection to another test's
/// listener about once in 40 runs. Ports below that range (which starts at
/// 32768) are never handed out by the kernel; basing them on our process ID
/// keeps concurrent test runs apart.
fn test_port(n: u16) -> u16 {
    let base = u16::try_from(std::process::id() % 1000).unwrap();
    20_000 + base * 10 + n
}

/// A TCP server that reads one line, answers `hello <line>` and closes.
/// Returns its port.
fn greeter() -> u16 {
    use std::io::{BufRead, BufReader};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&tcp).read_line(&mut line).unwrap();
        (&tcp)
            .write_all(format!("hello {line}").as_bytes())
            .unwrap();
    });
    port
}

#[test]
fn local_forwarding() {
    use std::io::Read;
    let target = greeter();
    let port = test_port(1);
    let home = tempfile::tempdir().unwrap();
    let mut attach = Command::new(env!("CARGO_BIN_EXE_shion-attach"))
        .args(["-N", "-L", &format!("{port}:localhost:{target}")])
        .env("USER", "tester")
        .env("HOME", home.path())
        .spawn()
        .unwrap();

    // Wait for it to listen.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut tcp = loop {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(tcp) => break tcp,
            Err(e) if std::time::Instant::now() > deadline => panic!("{e}"),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    };
    tcp.write_all(b"via -L\n").unwrap();
    let mut reply = String::new();
    tcp.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "hello via -L\n");

    // `-N` runs until told to stop.
    let pid = rustix::process::Pid::from_child(&attach);
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    assert_eq!(attach.wait().unwrap().code(), Some(0));
}

#[test]
fn remote_forwarding() {
    let target = greeter();
    let port = test_port(2);
    // bash's /dev/tcp makes a TCP client inside the session.
    let output = attach(
        &[
            "-R",
            &format!("{port}:127.0.0.1:{target}"),
            &format!("bash -c 'exec 3<>/dev/tcp/localhost/{port}; echo via -R >&3; cat <&3'"),
        ],
        b"",
    );
    assert_eq!(output.stdout, b"hello via -R\n", "{output:?}");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn forwarding_specs_are_checked() {
    for spec in [
        "8080:localhost",
        "x:localhost:80",
        "1:2:3:4:5",
        "8080:localhost:65536",
    ] {
        let output = attach(&["-N", "-L", spec], b"");
        assert_eq!(output.status.code(), Some(2), "{spec}: {output:?}");
    }
}

#[test]
fn children_get_default_signal_actions() {
    // Start the session process with signals ignored, as `cmd &` in a
    // script or `nohup` would. Its children must not inherit that.
    let session =
        std::path::Path::new(env!("CARGO_BIN_EXE_shion-attach")).with_file_name("shion-session");
    let home = tempfile::tempdir().unwrap();
    let line = format!(
        "trap '' INT QUIT HUP; exec {} --user tester --home {}",
        session.display(),
        home.path().display()
    );
    let output = attach(&["-S", &line, "grep SigIgn /proc/self/status"], b"");
    assert_eq!(output.stdout, b"SigIgn:\t0000000000000000\n", "{output:?}");
}
