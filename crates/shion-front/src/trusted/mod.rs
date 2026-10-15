//! The trusted side: configuration, credentials, and launching session
//! processes.
//!
//! Nothing in here reads from the network. Its inputs are the
//! configuration file, which the administrator wrote, and requests from the
//! network side through [`Authority`]'s methods, which carry plain data
//! only. That keeps the door open to the design in
//! `notes/extended-priv-sep.md`: this module would become the privileged
//! master process, [`Authority`]'s methods the requests on its control
//! socket, and the carrier that
//! [`Authority::launch_session`] returns a socket passed back
//! with `SCM_RIGHTS`. Until then, the rule is organizational: the network
//! side never touches the configuration directly, and this side never
//! touches a network connection or a carrier's contents.

mod authority;
mod config;

pub use authority::{Authority, Grant};
pub use config::Config;
