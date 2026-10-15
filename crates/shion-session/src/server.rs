//! Accepts smux streams from the front-end and hands each one to the right
//! handler.

use std::sync::Arc;
use std::time::Duration;

use async_smux::MuxBuilder;
use async_smux::error::MuxError;
use futures_util::StreamExt;
use shion_wire::codec::{ControlCodec, MessageCodec, StreamStartCodec};
use shion_wire::{CodecError, StreamStart};
use tokio::sync::watch;
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

use crate::carrier::Carrier;
use crate::state::ServerState;
use crate::{channel, control};

/// One smux stream over our carrier.
pub type Stream = shion_mux::Stream<Carrier>;

/// Serves the front-end until the carrier closes, or until `--linger`
/// says we've been idle long enough.
///
/// Each stream opened by the front-end inside `carrier` will be dispatched
/// to the appropriate handler.
pub async fn serve(carrier: Carrier, state: Arc<ServerState>) {
    // The front-end is the smux "client" (odd stream IDs); we're the
    // "server" (even IDs, which we'll need for forwarded-tcpip in M4).
    let (mut connector, mut acceptor, worker) =
        MuxBuilder::server().with_connection(carrier).build();
    let worker = tokio::spawn(worker);

    // Pinned for the same reason as in `channel::supervise`: `select!`
    // polls it again on every iteration.
    let mut idle = std::pin::pin!(idle_for(state.open_count(), state.settings.linger));

    loop {
        tokio::select! {
            // `accept` is cancel-safe: it only takes a stream off the
            // queue when it returns it.
            stream = acceptor.accept() => {
                let Some(stream) = stream else {
                    info!("carrier closed");
                    break;
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(stream.into(), state).await {
                        warn!(error = %e, "stream failed");
                    }
                });
            }
            () = &mut idle => {
                info!("no conversations for the linger time; exiting");
                // Drains what's queued, then closes the carrier, which
                // tells the front-end we're gone. Streams that are still
                // open (a channel whose conversation has ended but whose
                // child ignored SIGHUP) are cut off.
                if let Err(e) = connector.close().await {
                    debug!(error = %e, "closing the carrier failed");
                }
                break;
            }
        }
    }

    match worker.await {
        // async-smux reports the front-end closing the carrier as
        // `ConnectionClosed`: for us, that's the normal way to end.
        Ok(Ok(()) | Err(MuxError::ConnectionClosed)) => {}
        Ok(Err(e)) => warn!(error = %e, "smux connection failed"),
        Err(e) => warn!(error = %e, "smux worker panicked"),
    }
}

/// Completes once no conversation has been open for `linger`, or never if
/// `linger` is `None`.
///
/// The race with a front-end that opens a conversation just as we give up
/// can't be avoided here: the front-end sees the carrier close, and must
/// start a new session process, as it would after a crash.
async fn idle_for(mut open_count: watch::Receiver<usize>, linger: Option<Duration>) {
    let Some(linger) = linger else {
        return std::future::pending().await;
    };
    loop {
        // `borrow_and_update` reads the current value and marks it seen,
        // so `changed` waits for the next update. Every open and close
        // counts as one, even when the number ends up the same: a
        // conversation that came and went restarts the timer too.
        let idle = *open_count.borrow_and_update() == 0;
        let changed = if idle {
            tokio::select! {
                () = tokio::time::sleep(linger) => return,
                changed = open_count.changed() => changed,
            }
        } else {
            open_count.changed().await
        };
        // Fails only if the sender is gone, but `ServerState` owns it and
        // outlives us.
        if changed.is_err() {
            return std::future::pending().await;
        }
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
