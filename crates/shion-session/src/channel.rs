//! A `session` channel: one shell or command per channel (design §5.2).
//!
//! Task layout for a running channel:
//!
//! ```text
//!               ┌────────────┐  Message   ┌────────┐
//!  stdout pump ─┤            │            │        │
//!  stderr pump ─┤  mpsc out  ├───────────►│ writer ├──► smux stream
//!  this task  ──┤            │            │        │    (FIN when all
//!               └────────────┘            └────────┘     senders drop)
//!
//!  smux stream ──► this task ──mpsc──► stdin pump ──► child stdin
//! ```
//!
//! Output ordering falls out of ownership: the writer sends FIN once every
//! `Sender` is gone. The pumps drop theirs at EOF, and this task drops its
//! last one right after queuing `exit-status`, so `exit-status` always
//! follows all output and precedes FIN, as RFC 4254 requires.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;

use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use rustix::process::{Pid, Signal};
use shion_wire::codec::MessageCodec;
use shion_wire::control::attr;
use shion_wire::header::channel_type;
use shion_wire::message::{EXTENDED_DATA_STDERR, ExitSignal, open_failure};
use shion_wire::{ChannelHeader, ChannelRequest, CodecError, ConvOpen, Message};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc;
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

use crate::server::Stream;
use crate::settings::Settings;
use crate::signals;
use crate::state::State;

/// Largest data payload we accept per message, announced in our
/// `CHANNEL_OPEN_CONFIRMATION`.
const OUR_MAX_PACKET: u64 = 32 * 1024;

/// `PATH` for children unless `--setenv PATH=…` says otherwise.
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

type Incoming = SplitStream<Framed<Stream, MessageCodec>>;
type Outgoing = SplitSink<Framed<Stream, MessageCodec>, Message>;
type Out = mpsc::Sender<Message>;

pub async fn run(
    framed: Framed<Stream, MessageCodec>,
    header: ChannelHeader,
    state: Arc<State>,
) -> Result<(), CodecError> {
    // `split` gives independent read and write halves, so one task can
    // read while another writes.
    let (mut sink, mut incoming) = framed.split();

    let conversation = match check_open(&header, &state) {
        Ok(conversation) => conversation,
        Err((reason, description)) => {
            warn!(conversation = header.conversation_id, channel_type = header.channel_type, %description, "refusing channel");
            sink.send(Message::OpenFailure {
                reason,
                description,
                language: String::new(),
            })
            .await?;
            return sink.close().await;
        }
    };
    sink.send(Message::OpenConfirmation {
        max_packet_size: OUR_MAX_PACKET,
    })
    .await?;

    // Never send more per message than the peer accepts, nor more than we'd
    // want to buffer.
    let packet_size = usize::try_from(header.max_packet_size.clamp(1, OUR_MAX_PACKET)).unwrap_or(1);

    let (out, out_rx) = mpsc::channel(32);
    let writer = tokio::spawn(write_messages(sink, out_rx));

    if let Some(child) = setup(&mut incoming, &out, &state.settings, &conversation).await? {
        let status = supervise(child, &mut incoming, &out, packet_size).await?;
        info!(conversation = header.conversation_id, %status, "session ended");
        let _ = out.send(exit_message(status)).await;
    }

    drop(out); // the last Sender: the writer flushes, sends FIN and exits
    writer.await.map_err(io::Error::other)??;

    // Wait for the peer's FIN too, so the stream is fully closed before we
    // drop it. Anything still arriving is irrelevant now.
    while let Some(Ok(_)) = incoming.next().await {}
    Ok(())
}

/// Decides whether to accept the channel. On refusal, returns the reason
/// code and description for `CHANNEL_OPEN_FAILURE`.
fn check_open(header: &ChannelHeader, state: &State) -> Result<Arc<ConvOpen>, (u64, String)> {
    if header.channel_type != channel_type::SESSION {
        return Err((
            open_failure::UNKNOWN_CHANNEL_TYPE,
            format!("unsupported channel type {:?}", header.channel_type),
        ));
    }
    state.conversation(header.conversation_id).ok_or_else(|| {
        (
            open_failure::ADMINISTRATIVELY_PROHIBITED,
            format!("no conversation {}", header.conversation_id),
        )
    })
}

/// Owns the write half: sends everything queued on `rx`, then FIN.
async fn write_messages(
    mut sink: Outgoing,
    mut rx: mpsc::Receiver<Message>,
) -> Result<(), CodecError> {
    while let Some(msg) = rx.recv().await {
        sink.send(msg).await?;
    }
    sink.close().await
}

/// Answers a request if the peer asked for an answer.
async fn reply(out: &Out, want_reply: bool, ok: bool) {
    if want_reply {
        // If the writer is gone, the stream is dead and nobody is listening.
        let _ = out
            .send(if ok {
                Message::Success
            } else {
                Message::Failure
            })
            .await;
    }
}

/// Handles requests until `shell` or `exec` starts a child. Returns `None`
/// if the peer closes the channel first.
async fn setup(
    incoming: &mut Incoming,
    out: &Out,
    settings: &Settings,
    conversation: &ConvOpen,
) -> Result<Option<Child>, CodecError> {
    while let Some(msg) = incoming.next().await {
        match msg? {
            Message::Request {
                want_reply,
                request,
            } => {
                let command = match request {
                    ChannelRequest::Shell => None,
                    ChannelRequest::Exec { command } => Some(command),
                    // pty-req (M2), env and subsystem (M3), x11-req (never).
                    other => {
                        debug!(request = other.type_name(), "refusing request");
                        reply(out, want_reply, false).await;
                        continue;
                    }
                };
                match spawn(settings, conversation, command.as_deref()) {
                    Ok(child) => {
                        // Queued before any output can be: the pumps that
                        // produce output don't exist yet.
                        reply(out, want_reply, true).await;
                        return Ok(Some(child));
                    }
                    Err(e) => {
                        warn!(error = %e, shell = %settings.shell.display(), "cannot start session");
                        reply(out, want_reply, false).await;
                    }
                }
            }
            Message::Data(_) | Message::ExtendedData { .. } => {
                debug!("discarding data sent before the session started");
            }
            other => warn!(?other, "unexpected message"),
        }
    }
    Ok(None)
}

/// Starts `command` (or a login shell) with a fresh environment.
fn spawn(
    settings: &Settings,
    conversation: &ConvOpen,
    command: Option<&[u8]>,
) -> io::Result<Child> {
    let mut cmd = Command::new(&settings.shell);
    match command {
        // Unix command lines are bytes, not necessarily UTF-8.
        Some(command) => cmd.arg("-c").arg(OsStr::from_bytes(command)),
        // A leading '-' in argv[0] tells the shell it's a login shell.
        None => cmd.arg0(login_arg0(&settings.shell)),
    };

    cmd.env_clear()
        .env("HOME", &settings.home)
        .env("USER", &settings.user)
        .env("LOGNAME", &settings.user)
        .env("SHELL", &settings.shell)
        .env("PATH", DEFAULT_PATH);
    if let (Some(client), Some(server)) = (
        conversation.attribute(attr::CLIENT_ADDRESS),
        conversation.attribute(attr::SERVER_ADDRESS),
    ) {
        // Both are "<ip> <port>", which is what these variables are made of.
        cmd.env("SSH_CONNECTION", format!("{client} {server}"));
        if let Some((_, server_port)) = server.rsplit_once(' ') {
            cmd.env("SSH_CLIENT", format!("{client} {server_port}"));
        }
    }
    cmd.envs(settings.env.iter().map(|(name, value)| (name, value)));

    cmd.current_dir(&settings.home)
        // Its own process group, so signals can reach the whole pipeline.
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let child = cmd.spawn()?;
    debug!(pid = child.id(), command = ?command.map(String::from_utf8_lossy), "spawned");
    Ok(child)
}

fn login_arg0(shell: &Path) -> OsString {
    let mut arg0 = OsString::from("-");
    arg0.push(shell.file_name().unwrap_or(shell.as_os_str()));
    arg0
}

/// Runs the child to completion while relaying data and requests.
async fn supervise(
    mut child: Child,
    incoming: &mut Incoming,
    out: &Out,
    packet_size: usize,
) -> Result<ExitStatus, CodecError> {
    // With `process_group(0)` the group ID equals the child's PID.
    let pgid = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw);

    // All three were configured as pipes in `spawn`, so `take` can't fail.
    let stdin = child.stdin.take().expect("stdin is piped");
    let stdout = child.stdout.take().expect("stdout is piped");
    let stderr = child.stderr.take().expect("stderr is piped");

    let (input, input_rx) = mpsc::channel(16);
    let mut input = Some(input);
    tokio::spawn(pump_input(input_rx, stdin));
    let stdout_pump = tokio::spawn(pump_output(stdout, out.clone(), None, packet_size));
    let stderr_pump = tokio::spawn(pump_output(
        stderr,
        out.clone(),
        Some(EXTENDED_DATA_STDERR),
        packet_size,
    ));

    let finished = async move {
        let status = child.wait().await;
        // The child is gone, but output may still be in the pipes. Like
        // OpenSSH, we also wait for any background process that inherited
        // them (`ssh host 'sleep 60 &'` hangs for a minute there too).
        let _ = stdout_pump.await;
        let _ = stderr_pump.await;
        status
    };
    // `select!` polls `finished` repeatedly through a reference, so it must
    // stay at a fixed address: `pin!` guarantees that.
    let mut finished = std::pin::pin!(finished);
    let mut peer_eof = false;

    loop {
        tokio::select! {
            status = &mut finished => return Ok(status?),
            msg = incoming.next(), if !peer_eof => match msg {
                None => {
                    // Peer's FIN = SSH's CHANNEL_EOF. Dropping the sender
                    // ends the stdin pump, which closes the child's stdin.
                    peer_eof = true;
                    input = None;
                }
                Some(Err(e)) => {
                    signals::kill_group(pgid, Signal::HUP);
                    return Err(e);
                }
                Some(Ok(Message::Data(data))) => {
                    if let Some(tx) = &input {
                        if tx.send(data).await.is_err() {
                            input = None; // the child closed its stdin
                        }
                    }
                }
                Some(Ok(Message::Request { want_reply, request: ChannelRequest::Signal { name } })) => {
                    let delivered = signals::from_name(&name).is_some_and(|sig| signals::kill_group(pgid, sig));
                    debug!(signal = name, delivered, "signal request");
                    reply(out, want_reply, delivered).await;
                }
                Some(Ok(Message::Request { want_reply, request })) => {
                    debug!(request = request.type_name(), "refusing request on running session");
                    reply(out, want_reply, false).await;
                }
                Some(Ok(other)) => debug!(?other, "ignoring message"),
            },
        }
    }
}

/// Copies data from the channel into the child's stdin.
async fn pump_input(mut rx: mpsc::Receiver<Bytes>, mut stdin: ChildStdin) {
    while let Some(data) = rx.recv().await {
        if let Err(e) = stdin.write_all(&data).await {
            debug!(error = %e, "child's stdin closed");
            return;
        }
    }
    // `stdin` is dropped here, closing the pipe: the child reads EOF.
}

/// Copies the child's stdout or stderr to the channel, in chunks of at most
/// `packet_size`.
async fn pump_output(
    mut from: impl AsyncRead + Unpin,
    out: Out,
    data_type: Option<u64>,
    packet_size: usize,
) {
    let mut buf = vec![0; packet_size];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) => {
                debug!(error = %e, "reading child output failed");
                return;
            }
        };
        let data = Bytes::copy_from_slice(&buf[..n]);
        let msg = match data_type {
            None => Message::Data(data),
            Some(data_type) => Message::ExtendedData { data_type, data },
        };
        if out.send(msg).await.is_err() {
            return;
        }
    }
}

/// `exit-status`, or `exit-signal` if a signal killed the child.
fn exit_message(status: ExitStatus) -> Message {
    let request = match (status.code(), status.signal()) {
        (Some(code), _) => ChannelRequest::ExitStatus {
            status: u64::try_from(code).unwrap_or(255),
        },
        (None, Some(raw)) => match signals::name(raw) {
            Some(name) => ChannelRequest::ExitSignal(ExitSignal {
                signal: name.to_owned(),
                core_dumped: status.core_dumped(),
                description: String::new(),
                language: String::new(),
            }),
            // Not one of the signals SSH has a name for: report it the way
            // shells do.
            None => ChannelRequest::ExitStatus {
                status: 128 + u64::try_from(raw).unwrap_or(0),
            },
        },
        (None, None) => ChannelRequest::ExitStatus { status: 255 },
    };
    Message::Request {
        want_reply: false,
        request,
    }
}
