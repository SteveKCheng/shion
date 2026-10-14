//! [`ServerState`]: state shared by every task in the session process.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use shion_wire::ConvOpen;
use shion_wire::control::{PROTOCOL_VERSION, attr};

use crate::settings::Settings;

/// The session process's global state.
///
/// Shared through an `Arc` (an atomically reference-counted pointer, like
/// `std::shared_ptr`). The conversation table needs a `Mutex` because
/// several tasks, possibly on different threads, use it. Rust won't compile
/// unsynchronized shared mutation at all, so there's no way to forget it.
#[derive(Debug)]
pub struct ServerState {
    pub settings: Settings,
    conversations: Mutex<HashMap<u64, Arc<ConvOpen>>>,
}

impl ServerState {
    pub fn new(settings: Settings) -> Arc<Self> {
        Arc::new(Self {
            settings,
            conversations: Mutex::new(HashMap::new()),
        })
    }

    /// Validates a `CONV_OPEN` and records the conversation.
    ///
    /// The returned [`Registration`] removes it again when dropped. On failure,
    /// returns the reason to send in `CONV_REJECT`.
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
        table.insert(id, Arc::new(open));
        Ok(Registration {
            state: Arc::clone(self),
            id,
        })
    }

    /// Looks up an open conversation.
    pub fn conversation(&self, id: u64) -> Option<Arc<ConvOpen>> {
        self.table().get(&id).cloned()
    }

    /// Access the table of all conversations, locking it for the duration of access.
    fn table(&self) -> MutexGuard<'_, HashMap<u64, Arc<ConvOpen>>> {
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
/// Dropping it unregisters the conversation, however the owning task ends:
/// normal return, `?` error, or panic. This is RAII, as in C++, except that
/// the compiler also stops you from using the guard after it has been moved
/// or dropped.
#[derive(Debug)]
pub struct Registration {
    state: Arc<ServerState>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.state.table().remove(&self.id);
    }
}
