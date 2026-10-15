//! A conversation's control stream (design §4.3).

use std::collections::HashMap;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use shion_wire::codec::ControlCodec;
use shion_wire::control::{ForwardAddress, PROTOCOL_VERSION};
use shion_wire::header::channel_type;
use shion_wire::message::request_type;
use shion_wire::wire::put_varint;
use shion_wire::{CodecError, ControlMessage, ConvAccept, ConvOpen, GlobalRequest};
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

use crate::forward::{self, Listener};
use crate::server::{Connector, Stream};
use crate::state::{Conversation, ServerState};

/// Runs a conversation from `CONV_OPEN` until the front-end closes the
/// control stream, or the stream fails.
///
/// Each "conversation", i.e. a high-level SSH connection from the end user's point of view,
/// is associated with exactly one control stream.  This function will register the new
/// conversation, mapped by its ID.
pub async fn run(
    mut framed: Framed<Stream, ControlCodec>,
    open: ConvOpen,
    state: Arc<ServerState>,
    connector: Connector,
) -> Result<(), CodecError> {
    // Register the newly opened conversation into this session process's global state.
    let id = open.conversation_id;
    let registration = match state.register(open) {
        Ok(registration) => registration,
        Err(reason) => {
            warn!(conversation = id, %reason, "rejecting conversation");
            framed.send(ControlMessage::ConvReject { reason }).await?;
            return framed.close().await;
        }
    };

    info!(conversation = id, "conversation opened");
    framed.send(ControlMessage::ConvAccept(accept())).await?;

    let conversation = registration.conversation();
    // This conversation's `tcpip-forward` listeners, by address and port.
    // Dropping them (at the latest, when this function returns) stops them.
    let mut listeners = HashMap::new();

    // Dispatch messages from the control stream
    while let Some(msg) = framed.next().await {
        match msg? {
            ControlMessage::GlobalRequest {
                want_reply,
                request,
            } => {
                let reply =
                    global_request(request, &state, conversation, &connector, &mut listeners).await;
                if want_reply {
                    framed.send(reply).await?;
                }
            }
            ControlMessage::Unknown { msg_type, .. } => {
                debug!(
                    conversation = id,
                    msg_type, "ignoring unknown control message"
                );
            }
            other => warn!(conversation = id, ?other, "unexpected control message"),
        }
    }

    info!(conversation = id, "conversation closed");
    framed.close().await
    // `registration` is dropped here, which ends the conversation: its
    // process groups get SIGHUP. (Returning early through `?` drops it too.)
}

/// Handles a global request, and returns the reply.
async fn global_request(
    request: GlobalRequest,
    state: &ServerState,
    conversation: &Arc<Conversation>,
    connector: &Connector,
    listeners: &mut HashMap<ForwardAddress, Listener>,
) -> ControlMessage {
    match request {
        GlobalRequest::TcpipForward(request) => {
            match forward::listen(&request, state, conversation, connector).await {
                Ok((port, listener)) => {
                    // Only a request for port 0 gets the port back (RFC
                    // 4254 §7.1).
                    let body = if request.port == 0 {
                        let mut body = BytesMut::new();
                        put_varint(&mut body, port.into()).expect("a u16 fits in a varint");
                        body.freeze()
                    } else {
                        Bytes::new()
                    };
                    // `..request` takes the remaining fields from `request`.
                    listeners.insert(ForwardAddress { port, ..request }, listener);
                    ControlMessage::RequestSuccess { body }
                }
                Err(e) => {
                    info!(conversation = conversation.id(), address = request.address, port = request.port, error = %e, "refusing tcpip-forward");
                    ControlMessage::RequestFailure
                }
            }
        }
        GlobalRequest::CancelTcpipForward(request) => {
            // The client names the port that was bound, even if it asked
            // for 0, so the key matches.
            if listeners.remove(&request).is_some() {
                info!(
                    conversation = conversation.id(),
                    address = request.address,
                    port = request.port,
                    "forwarding cancelled"
                );
                ControlMessage::RequestSuccess { body: Bytes::new() }
            } else {
                ControlMessage::RequestFailure
            }
        }
        GlobalRequest::Other { name, .. } => {
            debug!(conversation = conversation.id(), %name, "refusing global request");
            ControlMessage::RequestFailure
        }
    }
}

/// Creates the `ConvAccept` message that we send back to the front-end process.
fn accept() -> ConvAccept {
    // Report for the front-end process, all the request types that this session
    // process can parse (from the client), minus the two that only flow from this process
    // back to the client.
    //
    // Requests that we parse but don't support (yet) get a polite CHANNEL_FAILURE instead
    // of killing the channel.
    let request_types = request_type::ALL
        .iter()
        .filter(|&&t| t != request_type::EXIT_STATUS && t != request_type::EXIT_SIGNAL)
        .map(|&t| t.to_owned())
        .collect();

    ConvAccept {
        version: PROTOCOL_VERSION,
        channel_types: vec![
            channel_type::SESSION.to_owned(),
            channel_type::DIRECT_TCPIP.to_owned(),
        ],
        request_types,
    }
}
