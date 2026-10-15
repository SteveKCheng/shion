//! End to end: OpenSSH's `ssh` and `sftp` against `shion-front`, which
//! runs `shion-session` (unsandboxed). Skipped if `ssh` or `ssh-keygen`
//! isn't installed.
//!
//! Needs `shion-session` built next to `shion-front`, which
//! `cargo test --workspace` takes care of.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use tempfile::TempDir;

/// A running `shion-front`, with a user `agent` whose home is `home`.
struct Server {
    dir: TempDir,
    port: u16,
    child: Child,
}

impl Server {
    /// Starts a server, or returns `None` if the OpenSSH tools are missing.
    /// `session_args` are appended to the session command line.
    fn start(session_args: &[&str], linger: f64) -> Option<Self> {
        if Command::new("ssh").arg("-V").output().is_err()
            || Command::new("ssh-keygen").arg("-?").output().is_err()
        {
            eprintln!("skipped: no ssh or ssh-keygen");
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        for key in ["host_key", "client_key", "other_key"] {
            let status = Command::new("ssh-keygen")
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(dir.path().join(key))
                .status()
                .unwrap();
            assert!(status.success());
        }
        std::fs::create_dir(dir.path().join("home")).unwrap();

        let front = PathBuf::from(env!("CARGO_BIN_EXE_shion-front"));
        let session = front.with_file_name("shion-session");
        assert!(session.exists(), "build the whole workspace first");
        let mut command_line = vec![
            session.display().to_string(),
            "--user".into(),
            "{user}".into(),
            "--home".into(),
            dir.path().join("home").display().to_string(),
        ];
        command_line.extend(session_args.iter().map(|&s| s.to_owned()));
        let client_key = std::fs::read_to_string(dir.path().join("client_key.pub")).unwrap();
        let config = format!(
            "listen = [\"127.0.0.1:0\"]\n\
             host_keys = [{host_key:?}]\n\
             [defaults]\n\
             session = {command_line:?}\n\
             linger = {linger}\n\
             [users.agent]\n\
             authorized_keys = [{key:?}]\n",
            host_key = dir.path().join("host_key").display().to_string(),
            key = client_key.trim(),
        );
        std::fs::write(dir.path().join("shion.toml"), config).unwrap();

        let mut child = Command::new(front)
            .arg("-f")
            .arg(dir.path().join("shion.toml"))
            .env("RUST_LOG", "info")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Find the port in the log, and keep draining the log afterwards,
        // or the server would block once the pipe is full.
        let (port_tx, port_rx) = mpsc::channel();
        let stderr = BufReader::new(child.stderr.take().unwrap());
        std::thread::spawn(move || {
            for line in stderr.lines() {
                let line = line.unwrap_or_default();
                if let Some((_, address)) = line.split_once("listening address=") {
                    let port = address
                        .trim()
                        .rsplit_once(':')
                        .unwrap()
                        .1
                        .parse::<u16>()
                        .unwrap();
                    let _ = port_tx.send(port);
                }
                if std::env::var_os("SHION_TEST_LOG").is_some() {
                    eprintln!("{line}");
                }
            }
        });
        let port = port_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("server didn't start");
        Some(Self { dir, port, child })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The client options shared by `ssh` and `sftp`.
    fn client_options(&self, key: &str) -> Vec<String> {
        let mut options = vec![
            "-F".into(),
            "/dev/null".into(),
            "-i".into(),
            self.path(key).display().to_string(),
        ];
        for option in [
            "IdentitiesOnly=yes",
            "BatchMode=yes",
            "StrictHostKeyChecking=no",
            "UserKnownHostsFile=/dev/null",
            "LogLevel=ERROR",
        ] {
            options.extend(["-o".into(), option.into()]);
        }
        options
    }

    /// An `ssh` command logging in as `agent`, with `args` before the host.
    fn ssh(&self, args: &[&str]) -> Command {
        let mut command = Command::new("ssh");
        command
            .args(self.client_options("client_key"))
            .args(["-p", &self.port.to_string()])
            .args(args)
            .arg("agent@127.0.0.1");
        command
    }

    /// Runs `ssh … remote_command` with `input` on stdin.
    fn run(&self, args: &[&str], remote_command: &str, input: &[u8]) -> Output {
        let mut child = self
            .ssh(args)
            .arg(remote_command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn exec_with_exit_status_and_stderr() {
    let Some(server) = Server::start(&[], 0.0) else {
        return;
    };
    let output = server.run(&[], "echo \"$USER at $PWD\"; echo oops >&2; exit 3", b"");
    let home = server.path("home");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("agent at {}\n", home.display())
    );
    assert_eq!(output.stderr, b"oops\n");
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn stdin_and_eof() {
    let Some(server) = Server::start(&[], 0.0) else {
        return;
    };
    let output = server.run(&[], "wc -l; echo done", b"one\ntwo\nthree\n");
    assert_eq!(output.stdout, b"3\ndone\n");
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn environment() {
    let Some(server) = Server::start(&["--accept-env", "LANG"], 0.0) else {
        return;
    };
    let output = server
        .ssh(&["-o", "SendEnv=LANG LC_ALL"])
        .arg("echo \"$LANG|${LC_ALL-unset}|$SSH_CONNECTION\"")
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let (env, connection) = stdout.trim().rsplit_once('|').unwrap();
    assert_eq!(env, "C.UTF-8|unset");
    let fields: Vec<&str> = connection.split(' ').collect();
    assert_eq!(fields.len(), 4, "{connection}");
    assert_eq!(fields[0], "127.0.0.1");
    assert_eq!(fields[3], server.port.to_string());
}

#[test]
fn terminal() {
    let Some(server) = Server::start(&[], 0.0) else {
        return;
    };
    // `-tt` asks for a terminal even though our stdin isn't one.
    let output = server.run(&["-tt"], "tty >/dev/null && echo has a tty", b"");
    assert_eq!(output.stdout, b"has a tty\r\n");
}

#[test]
fn killed_by_a_signal() {
    let Some(server) = Server::start(&[], 0.0) else {
        return;
    };
    let output = server.run(&[], "kill -TERM $$", b"");
    // `ssh` exits with 255 when the remote command dies of a signal.
    assert_eq!(output.status.code(), Some(255));
}

#[test]
fn unknown_key_is_refused() {
    let Some(server) = Server::start(&[], 0.0) else {
        return;
    };
    let output = Command::new("ssh")
        .args(server.client_options("other_key"))
        .args(["-p", &server.port.to_string(), "agent@127.0.0.1", "true"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(255));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Permission denied"));
}

#[test]
fn sftp() {
    let Some(sftp_server) = [
        "/usr/libexec/openssh/sftp-server",
        "/usr/lib/openssh/sftp-server",
    ]
    .into_iter()
    .find(|p| Path::new(p).exists()) else {
        eprintln!("skipped: no sftp-server");
        return;
    };
    let subsystem = format!("sftp={sftp_server}");
    let Some(server) = Server::start(&["--subsystem", &subsystem], 0.0) else {
        return;
    };
    std::fs::write(server.path("home/remote.txt"), "from the server\n").unwrap();
    std::fs::write(server.path("local.txt"), "to the server\n").unwrap();
    let batch = format!(
        "put {local} uploaded.txt\nget remote.txt {copy}\n",
        local = server.path("local.txt").display(),
        copy = server.path("copy.txt").display()
    );
    std::fs::write(server.path("batch"), batch).unwrap();
    let output = Command::new("sftp")
        .args(server.client_options("client_key"))
        .args(["-P", &server.port.to_string(), "-b"])
        .arg(server.path("batch"))
        .arg("agent@127.0.0.1")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read_to_string(server.path("home/uploaded.txt")).unwrap(),
        "to the server\n"
    );
    assert_eq!(
        std::fs::read_to_string(server.path("copy.txt")).unwrap(),
        "from the server\n"
    );
}

/// A port for test number `n` to listen on, outside the kernel's ephemeral
/// range (see the note on `test_port` in `shion-attach`'s tests).
fn test_port(n: u16) -> u16 {
    let base = u16::try_from(std::process::id() % 1000).unwrap();
    30_000 + base * 2 + n
}

/// A TCP server that reads one line, answers `hello <line>` and closes.
fn greeter() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
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
    let target = greeter();
    let Some(server) = Server::start(&["--permit-open", &format!("localhost:{target}")], 0.0)
    else {
        return;
    };
    let port = test_port(0);
    let mut ssh = server
        .ssh(&["-N", "-L", &format!("{port}:localhost:{target}")])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut tcp = loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(tcp) => break tcp,
            Err(e) if std::time::Instant::now() > deadline => panic!("{e}"),
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    };
    tcp.write_all(b"via -L\n").unwrap();
    let mut reply = String::new();
    tcp.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "hello via -L\n");
    let _ = ssh.kill();
    let _ = ssh.wait();
}

#[test]
fn remote_forwarding() {
    let target = greeter();
    let port = test_port(1);
    let Some(server) = Server::start(&["--permit-listen", &format!("localhost:{port}")], 0.0)
    else {
        return;
    };
    let remote = format!("bash -c 'exec 3<>/dev/tcp/localhost/{port}; echo via -R >&3; cat <&3'");
    let output = server.run(&["-R", &format!("{port}:127.0.0.1:{target}")], &remote, b"");
    assert_eq!(output.stdout, b"hello via -R\n", "{output:?}");
}

/// The process ID of the session process serving a command: the parent of
/// the shell running it.
fn session_pid(server: &Server) -> String {
    let output = server.run(&[], "ps -o ppid= -p $$", b"");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
fn connections_share_a_session_process_while_it_lingers() {
    let Some(server) = Server::start(&[], 5.0) else {
        return;
    };
    let first = session_pid(&server);
    assert_ne!(first, "");
    assert_eq!(session_pid(&server), first);
}

#[test]
fn without_linger_each_connection_gets_a_new_session_process() {
    let Some(server) = Server::start(&[], 0.0) else {
        return;
    };
    let first = session_pid(&server);
    // Give the old one a moment to go away.
    std::thread::sleep(Duration::from_millis(200));
    assert_ne!(session_pid(&server), first);
}
