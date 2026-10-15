//! A conversation: one SSH connection, as the session process sees it.

use std::io;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use shion_wire::codec::{ControlCodec, MessageCodec, StreamStartCodec};
use shion_wire::control::PROTOCOL_VERSION;
use shion_wire::{
    ChannelHeader, ChannelKind, ControlMessage, ConvOpen, GlobalRequest, Message, StreamStart,
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use russh::server::Handle;

use super::link::{ChannelStream, Link, Links, Opened, Stream};
use crate::trusted::Grant;

/// Our maximum packet size, announced in the headers and confirmations we
/// send to the session process. It's also russh's default, which it
/// announces to SSH clients; and the session process's maximum is the same,
/// so client data can be passed on without splitting.
pub const PACKET_SIZE: u32 = 32 * 1024;

type Control = Framed<Stream, ControlCodec>;
type GlobalRequestCall = (GlobalRequest, oneshot::Sender<ControlMessage>);

/// An open conversation. Dropping it ends the conversation: the control
/// stream closes, and the session process hangs up its processes.
#[derive(Debug)]
pub struct Conversation {
    links: Arc<Links>,
    link: Arc<Link>,
    id: u64,
    requests: mpsc::Sender<GlobalRequestCall>,
    /// Cancelled when the conversation is dropped.
    ended: CancellationToken,
}

/// How a channel open went.
#[derive(Debug)]
pub enum OpenResult {
    Confirmed(ChannelStream),
    Refused { reason: u64, description: String },
}

impl Conversation {
    /// Joins (or launches) the grant's session process and opens a
    /// conversation with the given `CONV_OPEN` attributes. Also returns
    /// where the channels that the session process opens will arrive.
    ///
    /// # Errors
    /// If the session process can't be started, or refuses.
    pub async fn open(
        links: &Arc<Links>,
        grant: &Grant,
        attributes: Vec<(String, String)>,
    ) -> io::Result<(Self, mpsc::Receiver<Opened>)> {
        let (link, id, opened) = links.join(grant)?;
        // From here on, dropping `conversation` unregisters it.
        let (requests, requests_rx) = mpsc::channel(1);
        let conversation = Self {
            links: Arc::clone(links),
            link,
            id,
            requests,
            ended: CancellationToken::new(),
        };

        let open = ConvOpen {
            version: PROTOCOL_VERSION,
            conversation_id: id,
            attributes,
        };
        let mut framed = Framed::new(conversation.link.connect()?, StreamStartCodec::default());
        framed.send(StreamStart::Control(open)).await?;
        let mut control = framed.map_codec(|_| ControlCodec::default());
        match control.next().await.transpose()? {
            Some(ControlMessage::ConvAccept(_)) => {}
            Some(ControlMessage::ConvReject { reason }) => {
                return Err(io::Error::other(format!(
                    "session process refused: {reason}"
                )));
            }
            other => {
                return Err(io::Error::other(format!(
                    "unexpected reply to CONV_OPEN: {other:?}"
                )));
            }
        }
        info!(user = grant.user, conversation = id, "conversation opened");
        tokio::spawn(run_control(control, requests_rx, id));
        Ok((conversation, opened))
    }

    /// Sends a global request and returns the reply, or `None` if the
    /// conversation is over.
    pub async fn global_request(&self, request: GlobalRequest) -> Option<ControlMessage> {
        let (reply, reply_rx) = oneshot::channel();
        self.requests.send((request, reply)).await.ok()?;
        reply_rx.await.ok()
    }

    /// Opens a channel stream of the given kind and waits for the session
    /// process to confirm or refuse it.
    ///
    /// # Errors
    /// If the carrier is gone or the stream fails.
    pub async fn open_channel(&self, kind: ChannelKind) -> io::Result<OpenResult> {
        let header = ChannelHeader {
            conversation_id: self.id,
            kind,
            max_packet_size: PACKET_SIZE.into(),
        };
        let mut framed = Framed::new(self.link.connect()?, StreamStartCodec::default());
        framed.send(StreamStart::Channel(header)).await?;
        let mut stream = framed.map_codec(|_| MessageCodec::default());
        Ok(match stream.next().await.transpose()? {
            Some(Message::OpenConfirmation { .. }) => OpenResult::Confirmed(stream),
            Some(Message::OpenFailure {
                reason,
                description,
                ..
            }) => OpenResult::Refused {
                reason,
                description,
            },
            other => {
                return Err(io::Error::other(format!(
                    "unexpected reply to a channel header: {other:?}"
                )));
            }
        })
    }

    /// Disconnects the client if the session process's carrier closes
    /// while the conversation is still open.
    pub fn disconnect_on_carrier_close(&self, handle: Handle) {
        // Tokens rather than `self`: the task mustn't keep the
        // conversation alive.
        let closed = self.link.closed();
        let ended = self.ended.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = closed.cancelled() => {
                    let _ = handle
                        .disconnect(russh::Disconnect::ByApplication, "session process ended".into(), String::new())
                        .await;
                }
                () = ended.cancelled() => {}
            }
        });
    }
}

impl Drop for Conversation {
    fn drop(&mut self) {
        // Dropping `requests` (after this) stops `run_control`, which
        // closes the control stream.
        self.ended.cancel();
        self.link.leave(&self.links, self.id);
    }
}

/// Owns the control stream: sends global requests one at a time and hands
/// back their replies, until the conversation is dropped.
async fn run_control(
    mut control: Control,
    mut requests: mpsc::Receiver<GlobalRequestCall>,
    id: u64,
) {
    loop {
        tokio::select! {
            call = requests.recv() => {
                let Some((request, reply)) = call else { break };
                let sent = control.send(ControlMessage::GlobalRequest { want_reply: true, request }).await;
                // Replies come in order, and the session process sends
                // nothing else, so the next message is the answer.
                match (sent, control.next().await) {
                    (Ok(()), Some(Ok(answer))) => {
                        let _ = reply.send(answer);
                    }
                    _ => break,
                }
            }
            // Nothing arrives unasked: this only notices the stream ending.
            msg = control.next() => {
                if msg.is_none_or(|m| m.is_err()) {
                    debug!(conversation = id, "control stream closed by the session process");
                    break;
                }
            }
        }
    }
    // FIN, then wait for the session's.
    let _ = control.close().await;
    while let Some(Ok(_)) = control.next().await {}
    debug!(conversation = id, "conversation closed");
}
