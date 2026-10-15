//! Wire formats spoken between the shion front-end and session process.
//!
//! - [`header`] and [`message`]: SSH3 channel streams, byte-compatible
//!   with draft-michel-remote-terminal-http3 as implemented by sshoq.
//! - [`modes`]: the terminal modes blob inside `pty-req`, which keeps its
//!   SSH2 encoding.
//! - [`control`]: shion's own per-conversation control stream.
//! - [`codec`]: `tokio_util` codecs that frame all of the above on a byte
//!   stream (an smux stream, in practice).
//!
//! The crate does no I/O itself, so everything can be unit-tested on plain
//! byte slices.

pub mod codec;
pub mod control;
pub mod error;
pub mod header;
pub mod message;
pub mod modes;
pub mod stream;
pub mod wire;

use bytes::BytesMut;

pub use control::{ControlMessage, ConvAccept, ConvOpen, GlobalRequest};
pub use error::{CodecError, DecodeError, EncodeError};
pub use header::{ChannelHeader, ChannelKind};
pub use message::{ChannelRequest, Message};
pub use stream::StreamStart;
pub use wire::Reader;

/// A value with a wire encoding.
///
/// Rust traits are roughly C++ concepts plus virtual interfaces in one
/// feature. Here the trait is only used statically: `WireCodec<T: Wire>`
/// gets a separate, monomorphized copy for each `T`, as a template would.
pub trait Wire: Sized {
    /// Decodes one value from the front of `r`.
    ///
    /// # Errors
    /// [`DecodeError::Incomplete`] if `r` ends before the value does, or
    /// another [`DecodeError`] if the bytes are invalid.
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError>;

    /// Appends the encoding of `self` to `dst`.
    ///
    /// # Errors
    /// [`EncodeError`] if a number is out of range. `dst` may then contain
    /// a partial encoding.
    fn encode(&self, dst: &mut BytesMut) -> Result<(), EncodeError>;
}
