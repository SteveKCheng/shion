//! [`ServerState`]: state shared by every task in the session process.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rustix::process::{Pid, Signal};
use shion_wire::ConvOpen;
use shion_wire::control::{PROTOCOL_VERSION, attr};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::settings::Settings;
use crate::signals;

/// The session process's global state.
///
/// Shared through an `Arc` (an atomically reference-counted pointer, like
/// `std::shared_ptr`). The conversation table needs a `Mutex` because
/// several tasks, possibly on different threads, use it. Rust won't compile
/// unsynchronized shared mutation at all, so there's no way to forget it.
#[derive(Debug)]
pub struct ServerState {
    pub settings: Settings,
    conversations: Mutex<HashMap<u64, Arc<Conversation>>>,
    /// The number of open conversations, for `--linger`.
    ///
    /// A `watch` channel holds one value that any number of receivers can
    /// read and wait for changes of: a condition variable bundled with the
    /// value it guards.
    open_count: watch::Sender<usize>,
}

impl ServerState {
    pub fn new(settings: Settings) -> Arc<Self> {
        Arc::new(Self {
            settings,
            conversations: Mutex::new(HashMap::new()),
            open_count: watch::Sender::new(0),
        })
    }

    /// Validates a `CONV_OPEN` and records the conversation.
    ///
    /// The returned [`Registration`] ends the conversation when dropped. On
    /// failure, returns the reason to send in `CONV_REJECT`.
    ///
    /// `self: &Arc<Self>` lets the method keep its own reference to the
    /// state (for the `Registration`), not just borrow it for the call.
    pub fn register(self: &Arc<Self>, open: ConvOpen) -> Result<Registration, String> {
        if open.version != PROTOCOL_VERSION {
            return Err(format!("unsupported protocol version {}", open.version));
        }
        if let Some(user) = open.attribute(attr::USER) {
            if user != self.settings.user {
                return Err(format!(
                    "this session process serves {:?}, not {user:?}",
                    self.settings.user
                ));
            }
        }
        let id = open.conversation_id;
        let mut table = self.table();
        if table.contains_key(&id) {
            return Err(format!("conversation {id} already exists"));
        }
        let conversation = Arc::new(Conversation::new(open));
        table.insert(id, Arc::clone(&conversation));
        // `send_replace` stores the value even if nobody is watching.
        self.open_count.send_replace(table.len());
        Ok(Registration {
            state: Arc::clone(self),
            conversation,
        })
    }

    /// Looks up an open conversation.
    pub fn conversation(&self, id: u64) -> Option<Arc<Conversation>> {
        self.table().get(&id).cloned()
    }

    /// Watches the number of open conversations.
    pub fn open_count(&self) -> watch::Receiver<usize> {
        self.open_count.subscribe()
    }

    /// Access the table of all conversations, locking it for the duration of access.
    fn table(&self) -> MutexGuard<'_, HashMap<u64, Arc<Conversation>>> {
        // A lock is "poisoned" if a thread panicked while holding it. Every
        // update of this table is a single insert or remove, so it can't be
        // left half-modified; carry on rather than propagate the panic.
        self.conversations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

/// Proof that a conversation is registered.
///
/// Dropping it ends the conversation, however the owning task ends: normal
/// return, `?` error, or panic. This is RAII, as in C++, except that the
/// compiler also stops you from using the guard after it has been moved or
/// dropped.
#[derive(Debug)]
pub struct Registration {
    state: Arc<ServerState>,
    conversation: Arc<Conversation>,
}

impl Registration {
    pub fn conversation(&self) -> &Arc<Conversation> {
        &self.conversation
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut table = self.state.table();
        table.remove(&self.conversation.id());
        self.state.open_count.send_replace(table.len());
        // Unlock before signalling: no need to hold up other tasks.
        drop(table);
        self.conversation.end();
    }
}

/// One conversation: an SSH connection, as far as we're concerned.
#[derive(Debug)]
pub struct Conversation {
    pub open: ConvOpen,
    /// Process groups started by this conversation's channels and still
    /// being supervised, or `None` once the conversation has ended.
    groups: Mutex<Option<HashSet<Pid>>>,
    /// Cancelled when the conversation ends. Tasks that don't run a process
    /// (port forwarding) wait on it to know when to stop.
    ended: CancellationToken,
}

impl Conversation {
    fn new(open: ConvOpen) -> Self {
        Self {
            open,
            groups: Mutex::new(Some(HashSet::new())),
            ended: CancellationToken::new(),
        }
    }

    pub fn id(&self) -> u64 {
        self.open.conversation_id
    }

    /// Records a process group to hang up when the conversation ends. The
    /// returned guard forgets it again.
    ///
    /// If the conversation has already ended (a channel can be opened just
    /// before that and start its child just after), the group is hung up
    /// right away.
    pub fn track(self: &Arc<Self>, pgid: Pid) -> TrackedGroup {
        let tracked = self
            .groups()
            .as_mut()
            .is_some_and(|groups| groups.insert(pgid));
        if !tracked {
            debug!(
                conversation = self.id(),
                pgid = pgid.as_raw_nonzero(),
                "conversation already ended"
            );
            signals::kill_group(Some(pgid), Signal::HUP);
        }
        TrackedGroup {
            conversation: Arc::clone(self),
            pgid,
        }
    }

    /// Completes when the conversation has ended (at once if it has).
    pub async fn ended(&self) {
        self.ended.cancelled().await;
    }

    /// Ends the conversation: tells port forwarding to stop, and sends
    /// `SIGHUP` to every process group it started that is still being
    /// supervised, as a terminal hangup would.
    fn end(&self) {
        self.ended.cancel();
        // `take` leaves `None` behind, so nothing is tracked from now on.
        let Some(groups) = self.groups().take() else {
            return;
        };
        for pgid in groups {
            debug!(
                conversation = self.id(),
                pgid = pgid.as_raw_nonzero(),
                "hanging up"
            );
            signals::kill_group(Some(pgid), Signal::HUP);
        }
    }

    fn groups(&self) -> MutexGuard<'_, Option<HashSet<Pid>>> {
        // As for the conversation table: updates are single operations.
        self.groups.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A process group that [`Conversation::track`] is tracking, until dropped.
#[derive(Debug)]
pub struct TrackedGroup {
    conversation: Arc<Conversation>,
    pgid: Pid,
}

impl Drop for TrackedGroup {
    fn drop(&mut self) {
        if let Some(groups) = self.conversation.groups().as_mut() {
            groups.remove(&self.pgid);
        }
    }
}
