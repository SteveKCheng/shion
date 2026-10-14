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
use crate::state::State;

/// Runs a conversation from `CONV_OPEN` until the front-end closes the
/// control stream.
pub async fn run(
    mut framed: Framed<Stream, ControlCodec>,
    open: ConvOpen,
    state: Arc<State>,
) -> Result<(), CodecError> {
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
    // `_registration` is dropped here, which unregisters the conversation.
}

fn accept() -> ConvAccept {
    // Every request we can parse, minus the two that only flow from us to
    // the client. Requests we parse but don't support (yet) get a polite
    // CHANNEL_FAILURE instead of killing the channel.
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
