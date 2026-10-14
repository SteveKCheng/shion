//! Accepts smux streams from the front-end and hands each one to the right
//! handler.

use std::sync::Arc;

use async_smux::MuxBuilder;
use futures_util::StreamExt;
use shion_wire::codec::{ControlCodec, MessageCodec, StreamStartCodec};
use shion_wire::{CodecError, StreamStart};
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

use crate::carrier::Carrier;
use crate::state::ServerState;
use crate::{channel, control};

/// One smux stream over our carrier.
pub type Stream = shion_mux::Stream<Carrier>;

/// Serves the front-end until the carrier closes.
///
/// Each stream opened by the front-end inside `carrier` will be dispatched
/// to the appropriate handler.
pub async fn serve(carrier: Carrier, state: Arc<ServerState>) {
    // The front-end is the smux "client" (odd stream IDs); we're the
    // "server" (even IDs, which we'll need for forwarded-tcpip in M4).
    let (_connector, mut acceptor, worker) = MuxBuilder::server().with_connection(carrier).build();
    // Note `_connector`, not `_`: a plain `_` pattern would drop the connector
    // immediately, while a named binding keeps it alive until the end of
    // the function.
    let worker = tokio::spawn(worker);

    while let Some(stream) = acceptor.accept().await {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_stream(stream.into(), state).await {
                warn!(error = %e, "stream failed");
            }
        });
    }

    info!("carrier closed");
    match worker.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!(error = %e, "smux connection failed"),
        Err(e) => warn!(error = %e, "smux worker panicked"),
    }
}

/// Reads the first message of a stream to find out what kind it is,
/// then dispatches to the appropriate handler for the stream.
async fn handle_stream(stream: Stream, state: Arc<ServerState>) -> Result<(), CodecError> {
    let mut framed = Framed::new(stream, StreamStartCodec::default());

    // `transpose` turns Option<Result<T, E>> into Result<Option<T>, E>, so
    // `?` can take care of the error and `let … else` of the `None`.
    let Some(start) = framed.next().await.transpose()? else {
        debug!("stream closed before its first message");
        return Ok(());
    };

    // `map_codec` swaps the codec but keeps any bytes already read past the
    // first message.
    match start {
        StreamStart::Control(open) => {
            control::run(framed.map_codec(|_| ControlCodec::default()), open, state).await
        }
        StreamStart::Channel(header) => {
            channel::run(framed.map_codec(|_| MessageCodec::default()), header, state).await
        }
    }
}
