//! `shion-attach`: a debug client that plays the front-end's part.
//!
//! Like `ssh`, but instead of connecting to a server it starts a session
//! process and talks to it directly over a `socketpair`, so the session can
//! be tried out (interactively, too) before any SSH front-end exists:
//!
//! ```text
//! shion-attach                    # login shell, with a pty if stdin is a terminal
//! shion-attach ls -l              # one command, no pty
//! shion-attach -t top             # one command with a pty
//! shion-attach -S 'bwrap … shion-session --user agent --home /home/agent'
//! ```
//!
//! It exits with the remote command's exit status, or 255 on errors and
//! when the command was killed by a signal (as `ssh` does).

use std::io::{self, IsTerminal};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::Stdio;

use async_smux::{MuxBuilder, MuxConnector};
use bytes::Bytes;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use rustix::termios::{InputModes, OptionalActions, SpecialCodeIndex, Termios};
use shion_wire::codec::{ControlCodec, MessageCodec, StreamStartCodec};
use shion_wire::control::{PROTOCOL_VERSION, attr};
use shion_wire::header::channel_type;
use shion_wire::message::{ExitSignal, PtyRequest, WindowSize};
use shion_wire::modes::{self, DISABLED_CHAR, opcode};
use shion_wire::{ChannelHeader, ChannelRequest, ControlMessage, ConvOpen, Message, StreamStart};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio_util::codec::Framed;

/// Our maximum packet size, and the size of our read buffer.
const PACKET_SIZE: usize = 32 * 1024;

/// Exit code for our own errors and for remote deaths by signal.
const EXIT_ERROR: u8 = 255;

/// Runs `shion-session` and attaches to it like `ssh` would to a server.
#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Request a pseudo-terminal even for a command or a non-terminal stdin.
    #[arg(short = 't', conflicts_with = "no_pty")]
    pty: bool,

    /// Never request a pseudo-terminal.
    #[arg(short = 'T')]
    no_pty: bool,

    /// Shell command line that starts the session process, which will get
    /// a socket as stdin and stdout. Default: the `shion-session` next to
    /// this program, with `--user` and `--home` from `--user` and `$HOME`.
    #[arg(short = 'S', long, value_name = "COMMAND")]
    session: Option<String>,

    /// The app-level user name to send in `CONV_OPEN`.
    #[arg(short = 'l', long, env = "USER")]
    user: String,

    /// Command to run instead of a login shell. Like `ssh`, the words are
    /// joined with spaces and the remote shell parses them.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

type Stream = shion_mux::Stream<UnixStream>;
type Channel = Framed<Stream, MessageCodec>;

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let code = match run(args).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("shion-attach: {e}");
            EXIT_ERROR
        }
    };
    // Exit right away rather than returning from `main`. Returning would
    // shut the runtime down, which waits for the blocking read that
    // `tokio::io::stdin()` may still have pending, i.e. for another
    // keystroke. (The session process avoids that problem differently: see
    // the `shion-fd` crate.) By now `run` has restored the terminal.
    std::process::exit(code.into());
}

async fn run(args: Args) -> io::Result<u8> {
    let (mut child, socket) = start_session(&args)?;

    let (connector, acceptor, worker) = MuxBuilder::client().with_connection(socket).build();
    let worker = tokio::spawn(worker);

    // The control stream must stay open for the whole conversation.
    let mut control = open_conversation(&connector, &args.user).await?;
    let mut channel = open_session(&connector).await?;

    let stdin_is_tty = io::stdin().is_terminal();
    let want_pty = args.pty || (!args.no_pty && args.command.is_empty() && stdin_is_tty);
    let mut raw_mode = None;
    if want_pty {
        if request(&mut channel, ChannelRequest::PtyReq(pty_request())).await? {
            if stdin_is_tty {
                raw_mode = Some(RawMode::enter()?);
            }
        } else {
            eprintln!("shion-attach: PTY allocation request failed");
        }
    }

    let start = if args.command.is_empty() {
        ChannelRequest::Shell
    } else {
        ChannelRequest::Exec {
            command: Bytes::from(args.command.join(" ")),
        }
    };
    if !request(&mut channel, start).await? {
        return Err(io::Error::other("the session refused to start"));
    }

    let exit = relay(channel, raw_mode.is_some()).await?;
    drop(raw_mode); // restore the terminal before printing anything

    // Closing the control stream (FIN) ends the conversation; the session
    // answers with its own FIN. Once every smux handle is gone the worker
    // closes our socket, and the session process sees EOF and exits.
    // Holding on to any of them would leave us waiting for the session
    // while it waits for us.
    control.close().await?;
    while control.next().await.is_some() {}
    drop(control);
    drop(connector);
    drop(acceptor);
    let _ = worker.await;
    let _ = child.wait().await;

    Ok(match exit {
        Some(ChannelRequest::ExitStatus { status }) => u8::try_from(status).unwrap_or(EXIT_ERROR),
        Some(ChannelRequest::ExitSignal(ExitSignal {
            signal,
            core_dumped,
            ..
        })) => {
            let core = if core_dumped { " (core dumped)" } else { "" };
            eprintln!("shion-attach: remote command killed by signal {signal}{core}");
            EXIT_ERROR
        }
        _ => {
            eprintln!("shion-attach: the session ended without an exit status");
            EXIT_ERROR
        }
    })
}

/// Starts the session process with one end of a `socketpair` as its stdin
/// and stdout, as the front-end is expected to.
fn start_session(args: &Args) -> io::Result<(Child, UnixStream)> {
    let mut cmd = if let Some(line) = &args.session {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(line);
        cmd
    } else {
        let exe = std::env::current_exe()?.with_file_name("shion-session");
        let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("/"), PathBuf::from);
        let mut cmd = Command::new(exe);
        cmd.arg("--user").arg(&args.user).arg("--home").arg(home);
        cmd
    };
    // The session logs to our stderr. Keep it quiet unless asked: in raw
    // mode its lines would come out as a staircase.
    if std::env::var_os("RUST_LOG").is_none() {
        cmd.env("RUST_LOG", "warn");
    }

    let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    let theirs = OwnedFd::from(theirs);
    cmd.stdin(Stdio::from(theirs.try_clone()?))
        .stdout(Stdio::from(theirs))
        .kill_on_drop(true);
    let child = cmd.spawn()?;
    // `cmd` holds the child's end of the socket. Drop it, or we'd never
    // see EOF when the child exits.
    drop(cmd);

    ours.set_nonblocking(true)?;
    Ok((child, UnixStream::from_std(ours)?))
}

/// Opens a new smux stream.
fn connect(connector: &MuxConnector<UnixStream>) -> io::Result<Stream> {
    // `MuxError` has no conversion to `io::Error`, but any error type can
    // be wrapped with `io::Error::other`.
    connector
        .connect()
        .map(Stream::from)
        .map_err(io::Error::other)
}

/// Sends `CONV_OPEN` and waits for `CONV_ACCEPT`.
async fn open_conversation(
    connector: &MuxConnector<UnixStream>,
    user: &str,
) -> io::Result<Framed<Stream, ControlCodec>> {
    let open = ConvOpen {
        version: PROTOCOL_VERSION,
        conversation_id: 1,
        attributes: vec![
            (attr::USER.into(), user.into()),
            (
                attr::CLIENT_VERSION.into(),
                concat!("shion-attach/", env!("CARGO_PKG_VERSION")).into(),
            ),
        ],
    };
    let mut framed = Framed::new(connect(connector)?, StreamStartCodec::default());
    framed.send(StreamStart::Control(open)).await?;
    // Same stream, different message type from now on.
    let mut framed = framed.map_codec(|_| ControlCodec::default());
    match framed.next().await.transpose()? {
        Some(ControlMessage::ConvAccept(_)) => Ok(framed),
        Some(ControlMessage::ConvReject { reason }) => Err(io::Error::other(format!(
            "the session rejected the conversation: {reason}"
        ))),
        other => Err(io::Error::other(format!(
            "unexpected reply to CONV_OPEN: {other:?}"
        ))),
    }
}

/// Opens a `session` channel.
async fn open_session(connector: &MuxConnector<UnixStream>) -> io::Result<Channel> {
    let header = ChannelHeader {
        conversation_id: 1,
        channel_type: channel_type::SESSION.into(),
        max_packet_size: PACKET_SIZE as u64,
    };
    let mut framed = Framed::new(connect(connector)?, StreamStartCodec::default());
    framed.send(StreamStart::Channel(header)).await?;
    let mut framed = framed.map_codec(|_| MessageCodec::default());
    match framed.next().await.transpose()? {
        Some(Message::OpenConfirmation { .. }) => Ok(framed),
        Some(Message::OpenFailure { description, .. }) => Err(io::Error::other(format!(
            "the session refused the channel: {description}"
        ))),
        other => Err(io::Error::other(format!(
            "unexpected reply to the channel header: {other:?}"
        ))),
    }
}

/// Sends a request with want-reply set. Returns whether it succeeded.
async fn request(channel: &mut Channel, request: ChannelRequest) -> io::Result<bool> {
    channel
        .send(Message::Request {
            want_reply: true,
            request,
        })
        .await?;
    // Nothing else can arrive before the session has started.
    match channel.next().await.transpose()? {
        Some(Message::Success) => Ok(true),
        Some(Message::Failure) => Ok(false),
        other => Err(io::Error::other(format!(
            "unexpected reply to a request: {other:?}"
        ))),
    }
}

/// `pty-req` describing our own terminal, or a plain 80×24 one if stdin
/// isn't a terminal.
fn pty_request() -> PtyRequest {
    let stdin = io::stdin();
    let size = rustix::termios::tcgetwinsize(&stdin).map_or(
        WindowSize {
            cols: 80,
            rows: 24,
            width_px: 0,
            height_px: 0,
        },
        window_size,
    );
    let modes =
        rustix::termios::tcgetattr(&stdin).map_or_else(|_| modes::encode([]), |t| encode_modes(&t));
    PtyRequest {
        term: std::env::var("TERM").unwrap_or_default(),
        size,
        modes,
    }
}

fn window_size(ws: rustix::termios::Winsize) -> WindowSize {
    WindowSize {
        cols: ws.ws_col.into(),
        rows: ws.ws_row.into(),
        width_px: ws.ws_xpixel.into(),
        height_px: ws.ws_ypixel.into(),
    }
}

/// Encodes the settings of our terminal that matter most when typing into
/// the remote one: the editing and signal characters, and UTF-8 input.
/// (OpenSSH sends everything; the remote defaults are fine for the rest.)
fn encode_modes(termios: &Termios) -> Bytes {
    let char = |index| match termios.special_codes[index] {
        0 => DISABLED_CHAR, // Linux's _POSIX_VDISABLE
        c => u32::from(c),
    };
    modes::encode([
        (opcode::VINTR, char(SpecialCodeIndex::VINTR)),
        (opcode::VQUIT, char(SpecialCodeIndex::VQUIT)),
        (opcode::VERASE, char(SpecialCodeIndex::VERASE)),
        (opcode::VKILL, char(SpecialCodeIndex::VKILL)),
        (opcode::VEOF, char(SpecialCodeIndex::VEOF)),
        (opcode::VSUSP, char(SpecialCodeIndex::VSUSP)),
        (opcode::VWERASE, char(SpecialCodeIndex::VWERASE)),
        (opcode::VLNEXT, char(SpecialCodeIndex::VLNEXT)),
        (
            opcode::IUTF8,
            u32::from(termios.input_modes.contains(InputModes::IUTF8)),
        ),
    ])
}

/// Puts our terminal into raw mode, so keystrokes (including `^C`) go to
/// the remote terminal unprocessed. Dropping it restores the terminal,
/// even if we panic.
#[derive(Debug)]
struct RawMode {
    original: Termios,
}

impl RawMode {
    fn enter() -> io::Result<Self> {
        let original = rustix::termios::tcgetattr(io::stdin())?;
        let mut raw = original.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(io::stdin(), OptionalActions::Now, &raw)?;
        Ok(Self { original })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(io::stdin(), OptionalActions::Now, &self.original);
    }
}

/// Relays stdin, stdout, stderr and window size changes until the session
/// closes the channel. Returns the `exit-status` or `exit-signal`, if any.
async fn relay(channel: Channel, track_window: bool) -> io::Result<Option<ChannelRequest>> {
    let (mut sink, mut incoming) = channel.split();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut buf = vec![0; PACKET_SIZE];
    let mut stdin_open = true;
    let mut winch = if track_window {
        Some(signal(SignalKind::window_change())?)
    } else {
        None
    };
    let mut exit = None;

    loop {
        tokio::select! {
            // `read` is cancel-safe: if another branch wins, no input is
            // lost, and the next call picks up where this one left off.
            n = stdin.read(&mut buf), if stdin_open => match n {
                Ok(0) | Err(_) => {
                    // FIN on our side, the equivalent of SSH's CHANNEL_EOF.
                    stdin_open = false;
                    sink.close().await?;
                }
                Ok(n) => sink.send(Message::Data(Bytes::copy_from_slice(&buf[..n]))).await?,
            },
            () = window_changed(&mut winch) => {
                if let Ok(ws) = rustix::termios::tcgetwinsize(io::stdin()) {
                    let request = ChannelRequest::WindowChange(window_size(ws));
                    sink.send(Message::Request { want_reply: false, request }).await?;
                }
            }
            msg = incoming.next() => match msg.transpose()? {
                None => break,
                Some(Message::Data(data)) => {
                    stdout.write_all(&data).await?;
                    stdout.flush().await?;
                }
                Some(Message::ExtendedData { data, .. }) => {
                    stderr.write_all(&data).await?;
                    stderr.flush().await?;
                }
                Some(Message::Request {
                    request: request @ (ChannelRequest::ExitStatus { .. } | ChannelRequest::ExitSignal(_)),
                    ..
                }) => exit = Some(request),
                Some(_) => {}
            },
        }
    }
    // The session has closed its side. Close ours too, if stdin hasn't
    // already, so the stream ends cleanly rather than being dropped.
    if stdin_open {
        sink.close().await?;
    }
    Ok(exit)
}

/// Waits for `SIGWINCH`, or forever if we're not tracking it.
///
/// `select!` creates every branch's future even when the branch is
/// disabled, so an `Option` has to be handled inside the future like this,
/// not with an `if` guard on the branch.
async fn window_changed(winch: &mut Option<Signal>) {
    match winch {
        Some(winch) => {
            winch.recv().await;
        }
        None => std::future::pending().await,
    }
}
