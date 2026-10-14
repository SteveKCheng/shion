//! Test harness: runs the real `shion-session` binary and plays the
//! front-end's part over its stdin/stdout.

// Each test file compiles this module separately and uses a different
// subset of it.
#![allow(dead_code)]

use std::future::Future;
use std::os::fd::OwnedFd;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use async_smux::{MuxAcceptor, MuxBuilder, MuxConnector};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use shion_wire::codec::{ControlCodec, MessageCodec, StreamStartCodec};
use shion_wire::control::{PROTOCOL_VERSION, attr};
use shion_wire::header::channel_type;
use shion_wire::message::{EXTENDED_DATA_STDERR, PtyRequest, WindowSize};
use shion_wire::{ChannelHeader, ChannelRequest, ControlMessage, ConvOpen, Message, StreamStart};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncWrite, Join};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio_util::codec::Framed;

pub const USER: &str = "agent-7";
pub const CLIENT_ADDRESS: &str = "192.0.2.5 51334";
pub const SERVER_ADDRESS: &str = "192.0.2.1 2222";

/// Boxed halves, so pipes and sockets can both be used.
type Carrier = Join<Box<dyn AsyncRead + Send + Unpin>, Box<dyn AsyncWrite + Send + Unpin>>;

/// How the harness connects to the session's stdin and stdout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// Two pipes.
    Pipes,
    /// One end of a `socketpair` as both stdin and stdout, as the
    /// front-end is likely to do it.
    Socket,
}
type Stream = shion_mux::Stream<Carrier>;
pub type Control = Framed<Stream, ControlCodec>;
pub type Channel = Framed<Stream, MessageCodec>;

/// Fails the test instead of hanging it.
pub async fn within<F: Future>(f: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), f)
        .await
        .expect("test timed out")
}

pub struct Harness {
    child: Child,
    connector: MuxConnector<Carrier>,
    acceptor: MuxAcceptor<Carrier>,
    worker: JoinHandle<()>,
    pub home: TempDir,
}

impl Harness {
    pub fn start() -> Self {
        Self::start_with(&[])
    }

    /// Starts `shion-session --user agent-7 --home <tempdir> <extra_args>`.
    pub fn start_with(extra_args: &[&str]) -> Self {
        Self::start_over(Transport::Pipes, extra_args)
    }

    pub fn start_over(transport: Transport, extra_args: &[&str]) -> Self {
        let home = tempfile::tempdir().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_shion-session"));
        command
            .args(["--user", USER, "--home"])
            .arg(home.path())
            .args(extra_args)
            // Its logs appear in the test output; RUST_LOG=debug for more.
            .env(
                "RUST_LOG",
                std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()),
            )
            .kill_on_drop(true);

        let (child, carrier) = match transport {
            Transport::Pipes => {
                let mut child = command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap();
                let reader: Box<dyn AsyncRead + Send + Unpin> =
                    Box::new(child.stdout.take().unwrap());
                let writer: Box<dyn AsyncWrite + Send + Unpin> =
                    Box::new(child.stdin.take().unwrap());
                (child, tokio::io::join(reader, writer))
            }
            Transport::Socket => {
                let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
                let theirs_too = theirs.try_clone().unwrap();
                let child = command
                    .stdin(OwnedFd::from(theirs))
                    .stdout(OwnedFd::from(theirs_too))
                    .spawn()
                    .unwrap();
                // `command` still holds the child's ends; drop them, or
                // we'd never see EOF from the child's side.
                drop(command);
                ours.set_nonblocking(true).unwrap();
                let (reader, writer) = tokio::net::UnixStream::from_std(ours).unwrap().into_split();
                let reader: Box<dyn AsyncRead + Send + Unpin> = Box::new(reader);
                let writer: Box<dyn AsyncWrite + Send + Unpin> = Box::new(writer);
                (child, tokio::io::join(reader, writer))
            }
        };
        let (connector, acceptor, worker) = MuxBuilder::client().with_connection(carrier).build();
        let worker = tokio::spawn(async move {
            let _ = worker.await;
        });
        Self {
            child,
            connector,
            acceptor,
            worker,
            home,
        }
    }

    pub fn conv_open(id: u64) -> ConvOpen {
        ConvOpen {
            version: PROTOCOL_VERSION,
            conversation_id: id,
            attributes: vec![
                (attr::USER.into(), USER.into()),
                (attr::CLIENT_ADDRESS.into(), CLIENT_ADDRESS.into()),
                (attr::SERVER_ADDRESS.into(), SERVER_ADDRESS.into()),
            ],
        }
    }

    /// Opens a control stream with `open` and returns the first reply.
    pub async fn try_conversation(&self, open: ConvOpen) -> (Control, ControlMessage) {
        let stream = Stream::from(self.connector.connect().unwrap());
        let mut framed = Framed::new(stream, StreamStartCodec::default());
        framed.send(StreamStart::Control(open)).await.unwrap();
        let mut framed = framed.map_codec(|_| ControlCodec::default());
        let reply = framed.next().await.expect("control stream closed").unwrap();
        (framed, reply)
    }

    /// Opens conversation `id`, which must be accepted.
    pub async fn conversation(&self, id: u64) -> Control {
        let (control, reply) = self.try_conversation(Self::conv_open(id)).await;
        assert!(matches!(reply, ControlMessage::ConvAccept(_)), "{reply:?}");
        control
    }

    /// Opens a channel and returns its first message.
    pub async fn try_channel(&self, header: ChannelHeader) -> (Channel, Message) {
        let stream = Stream::from(self.connector.connect().unwrap());
        let mut framed = Framed::new(stream, StreamStartCodec::default());
        framed.send(StreamStart::Channel(header)).await.unwrap();
        let mut framed = framed.map_codec(|_| MessageCodec::default());
        let reply = framed.next().await.expect("channel closed").unwrap();
        (framed, reply)
    }

    /// Opens a `session` channel, which must be confirmed.
    pub async fn session(&self, conversation_id: u64) -> Channel {
        self.session_with_packet_size(conversation_id, 32_768).await
    }

    pub async fn session_with_packet_size(
        &self,
        conversation_id: u64,
        max_packet_size: u64,
    ) -> Channel {
        let header = ChannelHeader {
            conversation_id,
            channel_type: channel_type::SESSION.into(),
            max_packet_size,
        };
        let (channel, reply) = self.try_channel(header).await;
        assert!(
            matches!(reply, Message::OpenConfirmation { .. }),
            "{reply:?}"
        );
        channel
    }

    /// Closes the carrier, as a front-end exiting would, and waits for the
    /// session process to exit. Drop all `Control`s and `Channel`s first:
    /// the smux worker keeps the carrier open while any stream is alive.
    pub async fn shutdown(mut self) -> ExitStatus {
        drop(self.connector);
        drop(self.acceptor);
        // With every smux handle gone the worker finishes and drops the
        // pipes, so the session process reads EOF.
        self.worker.await.unwrap();
        self.child.wait().await.unwrap()
    }
}

/// Sends a request with want-reply set and returns the reply.
pub async fn request(channel: &mut Channel, request: ChannelRequest) -> Message {
    channel
        .send(Message::Request {
            want_reply: true,
            request,
        })
        .await
        .unwrap();
    channel.next().await.expect("channel closed").unwrap()
}

/// Sends `exec` and asserts that it was accepted.
pub async fn exec(channel: &mut Channel, command: &str) {
    let reply = request(
        channel,
        ChannelRequest::Exec {
            command: Bytes::copy_from_slice(command.as_bytes()),
        },
    )
    .await;
    assert_eq!(reply, Message::Success, "exec {command:?}");
}

/// Sends `pty-req` for a `cols`×`rows` terminal and asserts that it was
/// accepted.
pub async fn pty_req(channel: &mut Channel, cols: u64, rows: u64, modes: Bytes) {
    let reply = request(
        channel,
        ChannelRequest::PtyReq(PtyRequest {
            term: "xterm-256color".into(),
            size: WindowSize {
                cols,
                rows,
                width_px: 0,
                height_px: 0,
            },
            modes,
        }),
    )
    .await;
    assert_eq!(reply, Message::Success, "pty-req");
}

/// Sends data to the child.
pub async fn send(channel: &mut Channel, data: &str) {
    channel
        .send(Message::Data(Bytes::copy_from_slice(data.as_bytes())))
        .await
        .unwrap();
}

/// Reads output until it contains `needle`, and returns all of it.
pub async fn read_until(channel: &mut Channel, needle: &str) -> String {
    let mut seen = String::new();
    while !seen.contains(needle) {
        match channel.next().await.expect("channel closed").unwrap() {
            Message::Data(data) => seen.push_str(std::str::from_utf8(&data).unwrap()),
            other => panic!("unexpected message {other:?} after {seen:?}"),
        }
    }
    seen
}

/// Everything a channel sent after the session started.
#[derive(Debug, Default)]
pub struct Outcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit: Option<ChannelRequest>,
    pub largest_packet: usize,
}

impl Outcome {
    pub fn stdout(&self) -> &str {
        std::str::from_utf8(&self.stdout).unwrap()
    }
    pub fn stderr(&self) -> &str {
        std::str::from_utf8(&self.stderr).unwrap()
    }
}

/// Reads until the session closes the channel. Checks that exit-status or
/// exit-signal comes last.
pub async fn collect(channel: &mut Channel) -> Outcome {
    let mut outcome = Outcome::default();
    while let Some(msg) = channel.next().await {
        assert!(outcome.exit.is_none(), "message after exit status: {msg:?}");
        match msg.unwrap() {
            Message::Data(data) => {
                outcome.largest_packet = outcome.largest_packet.max(data.len());
                outcome.stdout.extend_from_slice(&data);
            }
            Message::ExtendedData {
                data_type: EXTENDED_DATA_STDERR,
                data,
            } => {
                outcome.largest_packet = outcome.largest_packet.max(data.len());
                outcome.stderr.extend_from_slice(&data);
            }
            Message::Request {
                want_reply: false,
                request: exit @ (ChannelRequest::ExitStatus { .. } | ChannelRequest::ExitSignal(_)),
            } => {
                outcome.exit = Some(exit);
            }
            other => panic!("unexpected message {other:?}"),
        }
    }
    outcome
}

/// What `Outcome::exit` should be for a normal exit with `status`.
#[allow(clippy::unnecessary_wraps)] // to compare with `Outcome::exit` directly
pub fn exit_status(status: u64) -> Option<ChannelRequest> {
    Some(ChannelRequest::ExitStatus { status })
}
