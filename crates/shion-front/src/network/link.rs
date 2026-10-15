//! Links: the network side's ends of session process carriers.
//!
//! There is one session process per user, shared by all of that user's
//! connections (design §2). The first connection has the trusted side
//! launch it; later ones open more conversations over the same carrier.
//! When the last conversation ends, the link lingers as configured, then
//! closes the carrier, and the session process exits.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_smux::{MuxAcceptor, MuxBuilder, MuxConnector};
use futures_util::{SinkExt, StreamExt};
use shion_wire::codec::{HeaderCodec, MessageCodec};
use shion_wire::message::open_failure;
use shion_wire::{ChannelHeader, Message};
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::trusted::{Authority, Grant};

/// One smux stream over a carrier.
pub type Stream = shion_mux::Stream<UnixStream>;
/// A channel stream, past its header.
pub type ChannelStream = Framed<Stream, MessageCodec>;
/// A channel that the session process opened, for its conversation.
pub type Opened = (ChannelHeader, ChannelStream);

/// Every link, by user name.
#[derive(Debug)]
pub struct Links {
    authority: Arc<Authority>,
    links: Mutex<HashMap<String, Arc<Link>>>,
}

/// One session process's carrier.
pub struct Link {
    user: String,
    connector: MuxConnector<UnixStream>,
    linger: Duration,
    state: Mutex<LinkState>,
    next_conversation: AtomicU64,
    /// Cancelled when the carrier has closed.
    closed: CancellationToken,
}

#[derive(Debug, Default)]
struct LinkState {
    /// Open conversations, and where to deliver the channels the session
    /// process opens for each.
    conversations: HashMap<u64, mpsc::Sender<Opened>>,
    /// Counts conversation openings, so that a linger timer can tell
    /// whether the link has been used since it started.
    generation: u64,
}

impl Links {
    pub fn new(authority: Arc<Authority>) -> Arc<Self> {
        Arc::new(Self {
            authority,
            links: Mutex::new(HashMap::new()),
        })
    }

    /// Registers a conversation for the grant's user, launching their
    /// session process if it isn't running. Returns the link, the
    /// conversation ID, and where channels opened by the session process
    /// for it will arrive.
    ///
    /// # Errors
    /// If the session process can't be launched.
    pub fn join(
        self: &Arc<Self>,
        grant: &Grant,
    ) -> io::Result<(Arc<Link>, u64, mpsc::Receiver<Opened>)> {
        // Holding the lock while launching (which doesn't block) means two
        // connections arriving together can't both launch a process.
        let mut links = self.links();
        let link = match links.get(&grant.user) {
            Some(link) if !link.closed.is_cancelled() => Arc::clone(link),
            _ => {
                let link = self.launch(grant)?;
                links.insert(grant.user.clone(), Arc::clone(&link));
                link
            }
        };
        drop(links);

        let (tx, rx) = mpsc::channel(8);
        let id = link.next_conversation.fetch_add(1, Ordering::Relaxed);
        let mut state = link.state();
        state.conversations.insert(id, tx);
        state.generation += 1;
        drop(state);
        Ok((link, id, rx))
    }

    fn launch(self: &Arc<Self>, grant: &Grant) -> io::Result<Arc<Link>> {
        let launched = self.authority.launch_session(grant.token)?;
        launched.carrier.set_nonblocking(true)?;
        let carrier = UnixStream::from_std(launched.carrier)?;
        // We're the smux "client": our streams get odd IDs.
        let (connector, acceptor, worker) = MuxBuilder::client().with_connection(carrier).build();
        let link = Arc::new(Link {
            user: grant.user.clone(),
            connector,
            linger: launched.linger,
            state: Mutex::new(LinkState::default()),
            next_conversation: AtomicU64::new(1),
            closed: CancellationToken::new(),
        });

        // When the carrier closes (the session process exited, or we closed
        // it), forget the link, so that the next connection launches a new
        // process. A `Weak` reference doesn't keep `Links` alive.
        let links = Arc::downgrade(self);
        let weak_link = Arc::downgrade(&link);
        let closed = link.closed.clone();
        let user = grant.user.clone();
        tokio::spawn(async move {
            if let Err(e) = worker.await {
                debug!(user, error = %e, "carrier closed");
            }
            closed.cancel();
            if let (Some(links), Some(link)) = (links.upgrade(), weak_link.upgrade()) {
                links.forget(&link);
            }
            info!(user, "session process gone");
        });
        tokio::spawn(route_opened(acceptor, Arc::downgrade(&link)));
        Ok(link)
    }

    /// Removes `link` from the table, unless a newer link replaced it.
    fn forget(&self, link: &Arc<Link>) {
        let mut links = self.links();
        if links.get(&link.user).is_some_and(|l| Arc::ptr_eq(l, link)) {
            links.remove(&link.user);
        }
    }

    fn links(&self) -> MutexGuard<'_, HashMap<String, Arc<Link>>> {
        self.links.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

// `MuxConnector` isn't `Debug`, so this can't be derived.
impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl Link {
    /// Opens a new smux stream to the session process.
    ///
    /// # Errors
    /// If the carrier has closed.
    pub fn connect(&self) -> io::Result<Stream> {
        self.connector
            .connect()
            .map(Stream::from)
            .map_err(io::Error::other)
    }

    /// Cancelled when the carrier has closed.
    pub fn closed(&self) -> CancellationToken {
        self.closed.clone()
    }

    /// Unregisters a conversation. If it was the last, the carrier closes
    /// after the linger time, unless a new conversation comes along.
    pub fn leave(self: &Arc<Self>, links: &Arc<Links>, id: u64) {
        let mut state = self.state();
        state.conversations.remove(&id);
        if !state.conversations.is_empty() {
            return;
        }
        let generation = state.generation;
        drop(state);

        let link = Arc::clone(self);
        let links = Arc::clone(links);
        tokio::spawn(async move {
            tokio::time::sleep(link.linger).await;
            {
                let state = link.state();
                if !state.conversations.is_empty() || state.generation != generation {
                    return; // used again in the meantime
                }
            }
            info!(user = link.user, "closing idle session process");
            links.forget(&link);
            // Sends whatever is queued, then closes the carrier: the
            // session process reads EOF and exits. Closing through a clone
            // closes the shared connection.
            if let Err(e) = link.connector.clone().close().await {
                debug!(error = %e, "closing the carrier failed");
            }
        });
    }

    fn state(&self) -> MutexGuard<'_, LinkState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Hands each channel the session process opens to its conversation.
async fn route_opened(mut acceptor: MuxAcceptor<UnixStream>, link: std::sync::Weak<Link>) {
    while let Some(stream) = acceptor.accept().await {
        let link = link.clone();
        tokio::spawn(async move {
            let mut framed = Framed::new(Stream::from(stream), HeaderCodec::default());
            let header = match framed.next().await {
                Some(Ok(header)) => header,
                Some(Err(e)) => {
                    warn!(error = %e, "bad channel header from the session process");
                    return;
                }
                None => return,
            };
            let mut channel = framed.map_codec(|_| MessageCodec::default());
            let target = link.upgrade().and_then(|link| {
                link.state()
                    .conversations
                    .get(&header.conversation_id)
                    .cloned()
            });
            if let Some(target) = target {
                // If the conversation has just gone away, `channel` is
                // dropped, which closes the stream.
                let _ = target.send((header, channel)).await;
            } else {
                debug!(
                    conversation = header.conversation_id,
                    "channel for an unknown conversation"
                );
                let _ = channel
                    .send(Message::OpenFailure {
                        reason: open_failure::ADMINISTRATIVELY_PROHIBITED,
                        description: format!("no conversation {}", header.conversation_id),
                        language: String::new(),
                    })
                    .await;
                let _ = channel.close().await;
            }
        });
    }
}
