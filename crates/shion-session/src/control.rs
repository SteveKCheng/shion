//! A conversation's control stream (design §4.3).

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use shion_wire::codec::ControlCodec;
use shion_wire::control::PROTOCOL_VERSION;
use shion_wire::header::channel_type;
use shion_wire::message::request_type;
use shion_wire::{CodecError, ControlMessage, ConvAccept, ConvOpen};
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

use crate::server::Stream;
use crate::state::ServerState;

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
) -> Result<(), CodecError> {
    // Register the newly opened conversation into this session process's global state.
    let id = open.conversation_id;
    let _registration = match state.register(open) {
        Ok(registration) => registration,
        Err(reason) => {
            warn!(conversation = id, %reason, "rejecting conversation");
            framed.send(ControlMessage::ConvReject { reason }).await?;
            return framed.close().await;
        }
    };

    info!(conversation = id, "conversation opened");
    framed.send(ControlMessage::ConvAccept(accept())).await?;

    // Dispatch messages from the control stream
    while let Some(msg) = framed.next().await {
        match msg? {
            ControlMessage::GlobalRequest {
                name, want_reply, ..
            } => {
                // Port forwarding arrives with M4; until then, refuse.
                debug!(conversation = id, %name, "refusing global request");
                if want_reply {
                    framed.send(ControlMessage::RequestFailure).await?;
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
    // `_registration` is dropped here, which ends the conversation: its
    // process groups get SIGHUP. (Returning early through `?` drops it too.)
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
        channel_types: vec![channel_type::SESSION.to_owned()],
        request_types,
    }
}
