//! `session` channels: SSH2 on the client's side, SSH3 on the session
//! process's.
//!
//! Messages from the client arrive through the russh handler's callbacks
//! (see `connection`), which pass them here as [`ToSession`]. The two
//! directions run as two independent futures, so neither ever waits for
//! the other: [`to_session`] only waits on the smux stream, and only
//! [`to_client`] waits on russh. That matters because russh's callbacks run
//! inside its connection loop. If one task did both, it could wait for
//! russh to take output while russh waits for it to take input.

use std::sync::Arc;

use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use russh::server::Handle;
use russh::{ChannelId, ChannelOpenFailure, Sig};
use shion_wire::message::{ExitSignal, open_failure};
use shion_wire::{ChannelKind, ChannelRequest, Message};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, warn};

use super::conversation::{Conversation, OpenResult};
use super::link::ChannelStream;

/// What the handler passes on from the client.
#[derive(Debug)]
pub enum ToSession {
    /// A channel request, and where to send the answer if one is wanted.
    Request {
        request: ChannelRequest,
        reply: Option<oneshot::Sender<bool>>,
    },
    Data(Bytes),
    /// `CHANNEL_EOF`.
    Eof,
}

/// The russh type for answering a channel open.
pub type OpenReply = russh::server::ChannelOpenHandle;

/// Opens the channel stream, answers the client's channel open according
/// to the session process's answer, then relays until both sides are done.
pub async fn run(
    conversation: Arc<Conversation>,
    id: ChannelId,
    from_client: mpsc::Receiver<ToSession>,
    open_reply: OpenReply,
    handle: Handle,
) {
    let stream = match conversation.open_channel(ChannelKind::Session).await {
        Ok(OpenResult::Confirmed(stream)) => stream,
        Ok(OpenResult::Refused {
            reason,
            description,
        }) => {
            debug!(%description, "session channel refused");
            open_reply.reject(open_failure_reason(reason)).await;
            return;
        }
        Err(e) => {
            warn!(error = %e, "cannot open a session channel");
            open_reply
                .reject(ChannelOpenFailure::ResourceShortage)
                .await;
            return;
        }
    };
    // The conversation must end with the connection, not with its last
    // channel, so don't hold on to it.
    drop(conversation);
    open_reply.accept().await;

    let (sink, incoming) = stream.split();
    // The answers that `to_client` is to deliver, in the order the
    // requests went out. (Unbounded, but there's at most one entry per
    // request awaiting an answer, and the handler awaits each one.)
    let (pending, pending_rx) = mpsc::unbounded_channel();
    tokio::join!(
        to_session(sink, from_client, pending),
        to_client(incoming, pending_rx, id, handle),
    );
}

/// Turns an SSH3 reason code for a channel open failure into russh's.
pub fn open_failure_reason(reason: u64) -> ChannelOpenFailure {
    match reason {
        open_failure::ADMINISTRATIVELY_PROHIBITED => ChannelOpenFailure::AdministrativelyProhibited,
        open_failure::CONNECT_FAILED => ChannelOpenFailure::ConnectFailed,
        open_failure::UNKNOWN_CHANNEL_TYPE => ChannelOpenFailure::UnknownChannelType,
        _ => ChannelOpenFailure::ResourceShortage,
    }
}

type Sink = SplitSink<ChannelStream, Message>;
type Incoming = SplitStream<ChannelStream>;

/// Client → session process.
async fn to_session(
    mut sink: Sink,
    mut from_client: mpsc::Receiver<ToSession>,
    pending: mpsc::UnboundedSender<oneshot::Sender<bool>>,
) {
    let mut eof = false;
    // Runs until the handler drops its sender: the client closed the
    // channel, or the connection is gone.
    while let Some(msg) = from_client.recv().await {
        let message = match msg {
            ToSession::Request { request, reply } => {
                if eof {
                    continue; // dropping `reply` answers "failure"
                }
                let want_reply = reply.is_some();
                if let Some(reply) = reply {
                    let _ = pending.send(reply);
                }
                Message::Request {
                    want_reply,
                    request,
                }
            }
            ToSession::Data(data) if !eof => Message::Data(data),
            ToSession::Data(_) => continue,
            ToSession::Eof => {
                // Our FIN is SSH's EOF.
                eof = true;
                let _ = sink.close().await;
                continue;
            }
        };
        if sink.send(message).await.is_err() {
            // The stream is gone; `to_client` will notice too. Keep
            // draining, so the handler never blocks on us.
            eof = true;
        }
    }
    if !eof {
        let _ = sink.close().await;
    }
}

/// Session process → client.
async fn to_client(
    mut incoming: Incoming,
    mut pending: mpsc::UnboundedReceiver<oneshot::Sender<bool>>,
    id: ChannelId,
    handle: Handle,
) {
    while let Some(msg) = incoming.next().await {
        let msg = match msg {
            Ok(msg) => msg,
            Err(e) => {
                warn!(error = %e, "bad message from the session process");
                break;
            }
        };
        let delivered = match msg {
            Message::Data(data) => handle.data(id, data).await.is_ok(),
            Message::ExtendedData { data_type, data } => {
                let code = u32::try_from(data_type).unwrap_or(u32::MAX);
                handle.extended_data(id, code, data).await.is_ok()
            }
            Message::Success | Message::Failure => {
                if let Ok(reply) = pending.try_recv() {
                    let _ = reply.send(msg == Message::Success);
                }
                true
            }
            Message::Request {
                request: ChannelRequest::ExitStatus { status },
                ..
            } => handle
                .exit_status_request(id, u32::try_from(status).unwrap_or(255))
                .await
                .is_ok(),
            Message::Request {
                request:
                    ChannelRequest::ExitSignal(ExitSignal {
                        signal,
                        core_dumped,
                        description,
                        language,
                    }),
                ..
            } => handle
                .exit_signal_request(
                    id,
                    signal_from_name(&signal),
                    core_dumped,
                    description,
                    language,
                )
                .await
                .is_ok(),
            other => {
                debug!(?other, "ignoring message from the session process");
                true
            }
        };
        if !delivered {
            break; // the connection is gone
        }
    }
    // The session process is done with the channel: the program has
    // exited, and its output has all been sent. As sshd does, close the
    // channel now rather than wait for the client's EOF.
    let _ = handle.eof(id).await;
    let _ = handle.close(id).await;
}

/// russh's name for a signal, as SSH spells it (no `SIG` prefix).
pub fn signal_name(signal: &Sig) -> String {
    match signal {
        Sig::ABRT => "ABRT",
        Sig::ALRM => "ALRM",
        Sig::FPE => "FPE",
        Sig::HUP => "HUP",
        Sig::ILL => "ILL",
        Sig::INT => "INT",
        Sig::KILL => "KILL",
        Sig::PIPE => "PIPE",
        Sig::QUIT => "QUIT",
        Sig::SEGV => "SEGV",
        Sig::TERM => "TERM",
        Sig::USR1 => "USR1",
        Sig::Custom(name) => name,
    }
    .to_owned()
}

fn signal_from_name(name: &str) -> Sig {
    match name {
        "ABRT" => Sig::ABRT,
        "ALRM" => Sig::ALRM,
        "FPE" => Sig::FPE,
        "HUP" => Sig::HUP,
        "ILL" => Sig::ILL,
        "INT" => Sig::INT,
        "KILL" => Sig::KILL,
        "PIPE" => Sig::PIPE,
        "QUIT" => Sig::QUIT,
        "SEGV" => Sig::SEGV,
        "TERM" => Sig::TERM,
        "USR1" => Sig::USR1,
        other => Sig::Custom(other.to_owned()),
    }
}
