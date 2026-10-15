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
//! With a terminal, the child's stdin, stdout and stderr are all the pty
//! slave, so one "terminal pump" reading the master replaces the stdout
//! and stderr pumps, and the stdin pump writes to the master.
//!
//! Output ordering falls out of ownership: the writer sends FIN once every
//! `Sender` is gone. The pumps drop theirs at EOF, and this task drops its
//! last one right after queuing `exit-status`, so `exit-status` always
//! follows all output and precedes FIN, as RFC 4254 requires.

use std::ffi::{OsStr, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use rustix::process::{Pid, Signal};
use shion_wire::codec::MessageCodec;
use shion_wire::control::attr;
use shion_wire::message::{EXTENDED_DATA_STDERR, ExitSignal, open_failure};
use shion_wire::{ChannelHeader, ChannelRequest, CodecError, ConvOpen, Message};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

use crate::pty::Terminal;
use crate::server::Stream;
use crate::settings::Settings;
use crate::signals;
use crate::state::{Conversation, ServerState};

/// Largest data payload we accept per message, announced in our
/// `CHANNEL_OPEN_CONFIRMATION` (or our header, for channels we open).
pub const OUR_MAX_PACKET: u64 = 32 * 1024;

/// `PATH` for children unless `--setenv PATH=…` says otherwise.
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Once a child with a terminal has exited, how long the terminal may stay
/// silent before we stop reading it. Its output usually ends with `EIO`
/// right away, but a background job holding the slave open would otherwise
/// keep the channel open forever.
const TERMINAL_LINGER: Duration = Duration::from_millis(100);

pub type Incoming = SplitStream<Framed<Stream, MessageCodec>>;
pub type Outgoing = SplitSink<Framed<Stream, MessageCodec>, Message>;
/// Queue of messages for the task that owns [`Outgoing`].
pub type Out = mpsc::Sender<Message>;

/// Runs a `session` channel.
pub async fn run(
    framed: Framed<Stream, MessageCodec>,
    header: ChannelHeader,
    state: Arc<ServerState>,
) -> Result<(), CodecError> {
    // `split` gives independent read and write halves, so one task can
    // read while another writes.
    let (mut sink, mut incoming) = framed.split();

    let conversation = match conversation_of(&header, &state) {
        Ok(conversation) => conversation,
        Err(description) => {
            return refuse(
                sink,
                &header,
                open_failure::ADMINISTRATIVELY_PROHIBITED,
                description,
            )
            .await;
        }
    };
    sink.send(Message::OpenConfirmation {
        max_packet_size: OUR_MAX_PACKET,
    })
    .await?;

    let packet_size = packet_size(header.max_packet_size);

    let (out, out_rx) = mpsc::channel(32);
    let writer = tokio::spawn(write_messages(sink, out_rx));

    if let Some((child, terminal)) =
        setup(&mut incoming, &out, &state.settings, &conversation.open).await?
    {
        let status = supervise(
            child,
            terminal,
            &conversation,
            &mut incoming,
            &out,
            packet_size,
        )
        .await?;
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

/// Finds the open conversation a channel belongs to. If there's none,
/// returns the description for `CHANNEL_OPEN_FAILURE`.
pub fn conversation_of(
    header: &ChannelHeader,
    state: &ServerState,
) -> Result<Arc<Conversation>, String> {
    state
        .conversation(header.conversation_id)
        .ok_or_else(|| format!("no conversation {}", header.conversation_id))
}

/// Refuses a channel with `CHANNEL_OPEN_FAILURE`, then closes our side.
pub async fn refuse(
    mut sink: Outgoing,
    header: &ChannelHeader,
    reason: u64,
    description: String,
) -> Result<(), CodecError> {
    warn!(conversation = header.conversation_id, channel_type = header.kind.name(), %description, "refusing channel");
    sink.send(Message::OpenFailure {
        reason,
        description,
        language: String::new(),
    })
    .await?;
    sink.close().await
}

/// How much to send per data message, given the peer's maximum: never more
/// than the peer accepts, nor more than we'd want to buffer.
pub fn packet_size(peer_max: u64) -> usize {
    usize::try_from(peer_max.clamp(1, OUR_MAX_PACKET)).unwrap_or(1)
}

/// Owns the write half: sends everything queued on `rx`, then FIN.
pub async fn write_messages(
    mut sink: Outgoing,
    mut rx: mpsc::Receiver<Message>,
) -> Result<(), CodecError> {
    while let Some(msg) = rx.recv().await {
        sink.send(msg).await?;
    }
    sink.close().await
}

/// Answers a request if the peer asked for an answer.
pub async fn reply(out: &Out, want_reply: bool, ok: bool) {
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

/// Handles requests until `shell`, `exec` or `subsystem` starts a child.
/// Returns `None` if the peer closes the channel first.
async fn setup(
    incoming: &mut Incoming,
    out: &Out,
    settings: &Settings,
    conversation: &ConvOpen,
) -> Result<Option<(Child, Option<Terminal>)>, CodecError> {
    // Allocated by `pty-req`, as OpenSSH does, so that failure is reported
    // in reply to that request rather than to `shell`.
    let mut terminal = None;
    // Variables from accepted `env` requests.
    let mut client_env = Vec::new();

    while let Some(msg) = incoming.next().await {
        match msg? {
            Message::Request {
                want_reply,
                request,
            } => {
                let command = match request {
                    ChannelRequest::Shell => None,
                    ChannelRequest::Exec { command } => Some(command),
                    ChannelRequest::Subsystem { name } => {
                        // Like OpenSSH, run the subsystem's command with
                        // the shell, as if the client had sent `exec`.
                        if let Some(command) = settings.subsystem(&name) {
                            debug!(subsystem = name, command, "starting subsystem");
                            Some(Bytes::copy_from_slice(command.as_bytes()))
                        } else {
                            debug!(subsystem = name, "refusing unknown subsystem");
                            reply(out, want_reply, false).await;
                            continue;
                        }
                    }
                    ChannelRequest::Env { name, value } => {
                        let ok = accept_env(settings, &mut client_env, &name, &value);
                        reply(out, want_reply, ok).await;
                        continue;
                    }
                    ChannelRequest::PtyReq(request) => {
                        // One terminal per channel.
                        let ok = terminal.is_none()
                            && match Terminal::open(&request) {
                                Ok(t) => {
                                    terminal = Some(t);
                                    true
                                }
                                Err(e) => {
                                    warn!(error = %e, "cannot allocate a pty");
                                    false
                                }
                            };
                        reply(out, want_reply, ok).await;
                        continue;
                    }
                    ChannelRequest::WindowChange(size) => {
                        // Also allowed before the session starts.
                        let ok = terminal.as_ref().is_some_and(|t| t.resize(size).is_ok());
                        reply(out, want_reply, ok).await;
                        continue;
                    }
                    // x11-req, and requests that only make sense later.
                    other => {
                        debug!(request = other.type_name(), "refusing request");
                        reply(out, want_reply, false).await;
                        continue;
                    }
                };
                match spawn(
                    settings,
                    conversation,
                    command.as_deref(),
                    terminal.as_ref(),
                    &client_env,
                ) {
                    Ok(child) => {
                        if let Some(t) = &mut terminal {
                            t.close_slave();
                        }
                        // Queued before any output can be: the pumps that
                        // produce output don't exist yet.
                        reply(out, want_reply, true).await;
                        return Ok(Some((child, terminal)));
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

/// Executes a command with a fresh environment.
///
/// `command` is the string to pass to the shell via its `-c` option.
/// If `None`, then an (interactive) log-in shell is spawned.
///
/// Note: There is no SSH request to launch a program executable directly
/// with an argument vector.
///
/// `stdin`, `stdout`, and `stderr` for the child process are pipes, or the
/// `terminal`'s slave if there is one.
///
/// `client_env` holds the variables from accepted `env` requests.
fn spawn(
    settings: &Settings,
    conversation: &ConvOpen,
    command: Option<&[u8]>,
    terminal: Option<&Terminal>,
    client_env: &[(OsString, OsString)],
) -> io::Result<Child> {
    let shell = &settings.shell;
    let mut prog = Command::new(shell);

    // Set the program to execute.
    if let Some(command) = command {
        // Unix command lines are bytes, not necessarily UTF-8.
        prog.arg("-c").arg(OsStr::from_bytes(command));
    } else {
        // A leading '-' in argv[0] tells the shell it's a log-in shell.
        let mut arg0 = OsString::from("-");
        arg0.push(shell.file_name().unwrap_or(shell.as_os_str()));
        prog.arg0(arg0);
    }

    // Default environment variables; possibly overridden below.
    prog.env_clear()
        .env("HOME", &settings.home)
        .env("USER", &settings.user)
        .env("LOGNAME", &settings.user)
        .env("SHELL", &settings.shell)
        .env("PATH", DEFAULT_PATH);

    // Overrides and additions from `--setenv`, then from the client. The
    // client can only set what `--accept-env` allows.
    prog.envs(settings.env.iter().map(|(name, value)| (name, value)));
    prog.envs(client_env.iter().map(|(name, value)| (name, value)));

    // Facts about this connection come last, so neither can fake them.
    if let (Some(client), Some(server)) = (
        conversation.attribute(attr::CLIENT_ADDRESS),
        conversation.attribute(attr::SERVER_ADDRESS),
    ) {
        // Both are "<ip> <port>", which is what these variables are made of.
        prog.env("SSH_CONNECTION", format!("{client} {server}"));
        if let Some((_, server_port)) = server.rsplit_once(' ') {
            prog.env("SSH_CLIENT", format!("{client} {server_port}"));
        }
    }

    if let Some(terminal) = terminal {
        if !terminal.term().is_empty() {
            prog.env("TERM", terminal.term());
        }
        prog.env("SSH_TTY", terminal.path());
    }

    prog.current_dir(&settings.home);

    // Configure I/O to child process.
    if let Some(terminal) = terminal {
        // A new session whose controlling terminal is the pty. That also
        // makes a new process group.
        terminal.configure(&mut prog)?;
    } else {
        // Its own process group, so signals can reach the whole pipeline.
        prog.process_group(0)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    }

    let child = prog.spawn()?;
    debug!(pid = child.id(), command = ?command.map(String::from_utf8_lossy), "spawned");
    Ok(child)
}

/// Most variables a client may set with `env` per channel, as in OpenSSH.
const MAX_CLIENT_ENV: usize = 128;

/// Handles an `env` request: records the variable in `client_env` if
/// `--accept-env` allows it. Returns whether it was accepted.
fn accept_env(
    settings: &Settings,
    client_env: &mut Vec<(OsString, OsString)>,
    name: &[u8],
    value: &[u8],
) -> bool {
    // The environment is a list of NUL-terminated `NAME=VALUE` strings, so
    // neither part may contain NUL, and the name may not contain `=`.
    let valid =
        !name.is_empty() && !name.contains(&b'=') && !name.contains(&0) && !value.contains(&0);
    let ok = valid && client_env.len() < MAX_CLIENT_ENV && settings.accepts_env(name);
    let name = OsStr::from_bytes(name);
    if ok {
        debug!(?name, "accepting env");
        client_env.push((name.to_owned(), OsStr::from_bytes(value).to_owned()));
    } else {
        debug!(?name, "refusing env");
    }
    ok
}

/// Runs the child to completion while relaying data and requests.
///
/// Its process group is tracked by `conversation`, which hangs it up if
/// the conversation ends first.
async fn supervise(
    mut child: Child,
    terminal: Option<Terminal>,
    conversation: &Arc<Conversation>,
    incoming: &mut Incoming,
    out: &Out,
    packet_size: usize,
) -> Result<ExitStatus, CodecError> {
    // With `process_group(0)` or `setsid` the group ID equals the child's
    // PID.
    let pgid = child
        .id()
        .and_then(|id| i32::try_from(id).ok())
        .and_then(Pid::from_raw);
    // Tracked until this function returns, i.e. until the child has exited
    // and its output has been relayed. (`Option::map` runs `track` only if
    // there is a group.)
    let _tracked = pgid.map(|pgid| conversation.track(pgid));

    let (input, input_rx) = mpsc::channel(16);
    let mut input = Some(input); // for dropping `input` early

    // Tells the terminal pump that the child has exited.
    let (exited, child_exited) = oneshot::channel();

    let output = match &terminal {
        None => {
            // All three were configured as pipes in `spawn`, so `take`
            // can't fail.
            let stdin = child.stdin.take().expect("stdin is piped");
            let stdout = child.stdout.take().expect("stdout is piped");
            let stderr = child.stderr.take().expect("stderr is piped");
            tokio::spawn(pump_input(input_rx, stdin));

            // Data for stderr is distinguished from stdout, in the SSH
            // protocol, by sending it as extended data of type
            // `EXTENDED_DATA_STDERR`.
            let out = out.clone();
            tokio::spawn(async move {
                tokio::join!(
                    pump_output(stdout, out.clone(), None, packet_size),
                    pump_output(stderr, out, Some(EXTENDED_DATA_STDERR), packet_size),
                );
            })
        }
        Some(terminal) => {
            // One fd for both directions. `split` lets two tasks share it.
            let (reader, writer) = tokio::io::split(terminal.stream()?);
            tokio::spawn(pump_input(input_rx, writer));
            tokio::spawn(pump_terminal(
                reader,
                out.clone(),
                packet_size,
                child_exited,
            ))
        }
    };

    // Future that completes when the child exits (normally or terminated
    // by a signal) and its output has been relayed.
    //
    // With pipes, that means waiting for EOF, even if a descendant process
    // that inherited the pipes keeps them open. OpenSSH does the same,
    // which can be observed by running `ssh host 'sleep 60 &'`: it will
    // hang for a full minute. With a terminal, see `pump_terminal`.
    let finished = async move {
        let status = child.wait().await;
        // Fails only if the receiver is gone, i.e. there's no terminal.
        let _ = exited.send(());
        let _ = output.await;
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
                    // Peer's FIN, i.e. the connection being half-closed from the peer's side,
                    // implied EOF in SSH3.  SSH3 assumes a transport that supports half-close,
                    // in particular QUIC, but async-smux does support this requirement.
                    // There is no SSH_MSG_CHANNEL_EOF message as in SSH2.  Dropping the sender
                    // causes the pump_input task to see the end of the queue, which in turn
                    // causes it to drop its stdin.
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
                    // With a terminal, signal what `^C` would; the shell
                    // itself may be in a different process group.
                    let target = terminal.as_ref().and_then(Terminal::foreground_group).or(pgid);
                    let delivered = signals::from_name(&name).is_some_and(|sig| signals::kill_group(target, sig));
                    debug!(signal = name, delivered, "signal request");
                    reply(out, want_reply, delivered).await;
                }
                Some(Ok(Message::Request { want_reply, request: ChannelRequest::WindowChange(size) })) => {
                    let ok = terminal.as_ref().is_some_and(|t| t.resize(size).is_ok());
                    reply(out, want_reply, ok).await;
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

/// Continuously copies data into the child process's stdin (a pipe or the
/// pty master).
///
/// `rx` is the queue where the SSH message parser pushes data to pump
/// into the child process.
///
/// Copying stops when `rx` is closed, or writing to the child fails.
///
/// `stdin` is dropped at the end of the copying by this function. If it is
/// a pipe, that closes our end of the pipe and the child process reads EOF.
///
/// On the other hand, if `stdin` is a pty slave, dropping it does not
/// cause the child process to get EOF.  The pty master stays open,
/// so the child simply gets no more input, as with OpenSSH.  Note
/// that a command like `ssh -tt ‹host› cat < /dev/null` does hang,
/// while `ssh ‹host› cat < /dev/null` does not.
async fn pump_input(mut rx: mpsc::Receiver<Bytes>, mut stdin: impl AsyncWrite + Unpin) {
    while let Some(data) = rx.recv().await {
        if let Err(e) = stdin.write_all(&data).await {
            debug!(error = %e, "child's stdin closed");
            return;
        }
    }
}

/// Continually copies the child's stdout or stderr to put into the
/// relevant SSH channel, in chunks of at most `packet_size`.
///
/// Copying stops when the child's stream reaches end-of-file,
/// or the receiving channel for that output has been closed,
/// or some other error is encountered.
///
/// The payload bytes are wrapped in either a `SSH_MSG_CHANNEL_DATA` or
/// `SSH_MSG_CHANNEL_EXTENDED_DATA` message.  If `data_type` is not None,
/// that will be the data type code inside `SSH_MSG_CHANNEL_EXTENDED_DATA`.
///
/// `out` is the MPSC queue where this function will push the output
/// SSH messages into.
pub async fn pump_output(
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
        if !send_output(&out, data_type, &buf[..n]).await {
            return;
        }
    }
}

/// Like [`pump_output`], for a terminal: copies the child's output from the
/// pty master.
///
/// The master reports end-of-file as `EIO` once every copy of the slave is
/// closed, normally right after the child exits. But a background job may
/// still hold the slave, so once `child_exited` fires we also stop if the
/// terminal stays silent for [`TERMINAL_LINGER`].
async fn pump_terminal(
    mut master: impl AsyncRead + Unpin,
    out: Out,
    packet_size: usize,
    mut child_exited: oneshot::Receiver<()>,
) {
    let mut buf = vec![0; packet_size];
    let mut exited = false;
    loop {
        let read = master.read(&mut buf);
        let result = if exited {
            match tokio::time::timeout(TERMINAL_LINGER, read).await {
                Ok(result) => result,
                Err(_elapsed) => {
                    debug!("terminal idle after the child exited");
                    return;
                }
            }
        } else {
            // Whichever finishes first. The losing future is dropped, which
            // cancels it: a pending `read` on a non-blocking fd consumes
            // nothing, so no output is lost.
            tokio::select! {
                result = read => result,
                _ = &mut child_exited => {
                    exited = true;
                    continue;
                }
            }
        };
        let n = match result {
            Ok(0) => return,
            Ok(n) => n,
            Err(e) => {
                // EIO is the normal end.
                debug!(error = %e, "terminal closed");
                return;
            }
        };
        if !send_output(&out, None, &buf[..n]).await {
            return;
        }
    }
}

/// Queues `data` as `CHANNEL_DATA`, or as `CHANNEL_EXTENDED_DATA` if
/// `data_type` is given. Returns false if the writer is gone.
async fn send_output(out: &Out, data_type: Option<u64>, data: &[u8]) -> bool {
    let data = Bytes::copy_from_slice(data);
    let msg = match data_type {
        None => Message::Data(data),
        Some(data_type) => Message::ExtendedData { data_type, data },
    };
    out.send(msg).await.is_ok()
}

/// Create the SSH request message to report that a child process has exited.
///
/// The request type in the message is:
///
///   - `exit-status` when the child process has exited normally.
///   - `exit-signal` when the child process has been terminated by a signal.
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
