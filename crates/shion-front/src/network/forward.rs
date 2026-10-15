//! TCP forwarding channels: `direct-tcpip` (the client opens them) and
//! `forwarded-tcpip` (the session process opens them).
//!
//! These carry no requests, so unlike `session` channels they don't need
//! the handler's callbacks: each one is a russh [`Channel`] object relayed
//! to a channel stream by a task of its own.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::{SinkExt, StreamExt};
use russh::server::{Handle, Msg};
use russh::{Channel, ChannelMsg};
use shion_wire::header::TcpipEndpoints;
use shion_wire::message::open_failure;
use shion_wire::{ChannelHeader, ChannelKind, Message};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::channel::{OpenReply, open_failure_reason};
use super::conversation::{Conversation, OpenResult, PACKET_SIZE};
use super::link::{ChannelStream, Opened};

/// Handles a `direct-tcpip` channel open from the client: the session
/// process decides (and connects), and we answer the client accordingly.
pub async fn direct(
    conversation: Arc<Conversation>,
    channel: Channel<Msg>,
    target: TcpipEndpoints,
    open_reply: OpenReply,
) {
    let opened = conversation
        .open_channel(ChannelKind::DirectTcpip(target))
        .await;
    drop(conversation);
    match opened {
        Ok(OpenResult::Confirmed(stream)) => {
            open_reply.accept().await;
            relay(channel, stream).await;
        }
        Ok(OpenResult::Refused {
            reason,
            description,
        }) => {
            debug!(%description, "direct-tcpip refused");
            open_reply.reject(open_failure_reason(reason)).await;
        }
        Err(e) => {
            warn!(error = %e, "cannot open a direct-tcpip channel");
            open_reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
        }
    }
}

/// Opens a `forwarded-tcpip` channel to the client for each channel the
/// session process opens, until the conversation ends.
pub async fn deliver(mut opened: mpsc::Receiver<Opened>, handle: Handle) {
    while let Some((header, stream)) = opened.recv().await {
        tokio::spawn(forwarded(header, stream, handle.clone()));
    }
}

async fn forwarded(header: ChannelHeader, mut stream: ChannelStream, handle: Handle) {
    let ChannelKind::ForwardedTcpip(endpoints) = header.kind else {
        let description = format!("unsupported channel type {:?}", header.kind.name());
        refuse(&mut stream, open_failure::UNKNOWN_CHANNEL_TYPE, description).await;
        return;
    };
    let TcpipEndpoints {
        host,
        port,
        originator_address,
        originator_port,
    } = endpoints;
    // Returns once the client has confirmed or refused.
    let result = handle
        .channel_open_forwarded_tcpip(
            host,
            port.into(),
            originator_address,
            originator_port.into(),
        )
        .await;
    match result {
        Ok(channel) => {
            let confirmation = Message::OpenConfirmation {
                max_packet_size: PACKET_SIZE.into(),
            };
            if stream.send(confirmation).await.is_ok() {
                relay(channel, stream).await;
            }
        }
        Err(e) => {
            debug!(error = %e, "client refused forwarded-tcpip");
            refuse(&mut stream, open_failure::CONNECT_FAILED, e.to_string()).await;
        }
    }
}

async fn refuse(stream: &mut ChannelStream, reason: u64, description: String) {
    let _ = stream
        .send(Message::OpenFailure {
            reason,
            description,
            language: String::new(),
        })
        .await;
    let _ = stream.close().await;
}

/// Relays between an SSH channel and a channel stream.
///
/// EOF goes through in both directions as a half-close; once both
/// directions have ended, whichever ended second closes the SSH channel.
/// We read the client's side until it closes the channel, even after its
/// EOF: russh delivers every channel event (window adjustments too) through
/// a bounded queue, and leaving it full would stall the whole connection.
async fn relay(channel: Channel<Msg>, stream: ChannelStream) {
    let (mut read_half, write_half) = channel.split();
    let (mut sink, mut incoming) = stream.split();
    let client_eof = AtomicBool::new(false);
    let session_eof = AtomicBool::new(false);

    let from_client = async {
        while let Some(msg) = read_half.wait().await {
            match msg {
                ChannelMsg::Data { data } if !client_eof.load(Ordering::Relaxed) => {
                    if sink.send(Message::Data(data)).await.is_err() {
                        debug!("forwarding stream gone");
                    }
                }
                ChannelMsg::Eof => {
                    client_eof.store(true, Ordering::Relaxed);
                    let _ = sink.close().await;
                    if session_eof.load(Ordering::Relaxed) {
                        let _ = write_half.close().await;
                    }
                }
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    };
    let to_client = async {
        while let Some(Ok(msg)) = incoming.next().await {
            if let Message::Data(data) = msg
                && write_half.data_bytes(data).await.is_err()
            {
                break;
            }
        }
        session_eof.store(true, Ordering::Relaxed);
        let _ = write_half.eof().await;
        if client_eof.load(Ordering::Relaxed) {
            let _ = write_half.close().await;
        }
        // Never finish: only the client closing the channel ends the relay.
        std::future::pending::<()>().await;
    };

    // When the client closes the channel, the other direction is cut short
    // if it's still going, since nobody is left to read it.
    tokio::select! {
        () = from_client => {}
        () = to_client => {}
    }
    let _ = sink.close().await;
}
