//! Streaming codecs for use with `tokio_util::codec::{FramedRead,
//! FramedWrite, Framed}`.
//!
//! A channel stream carries a [`ChannelHeader`] followed by [`Message`]s.
//! Read it with a [`HeaderCodec`] first, then switch codecs while keeping
//! the read buffer, using `FramedRead::map_decoder`:
//!
//! ```ignore
//! let mut framed = FramedRead::new(stream, HeaderCodec::default());
//! let header = framed.next().await;
//! let mut framed = framed.map_decoder(|_| MessageCodec::default());
//! ```

use std::marker::PhantomData;

use bytes::{Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::Wire;
use crate::control::ControlMessage;
use crate::error::{CodecError, DecodeError};
use crate::header::ChannelHeader;
use crate::message::Message;
use crate::stream::StreamStart;
use crate::wire::Reader;

/// Default limit on the length of any single string or control message
/// body.
pub const DEFAULT_MAX_LEN: usize = 1 << 20;

/// Codec for any [`Wire`] type.
///
/// `PhantomData<fn() -> T>` says "this type is about `T`" without storing a
/// `T`. Using the function-pointer form keeps the codec `Send` and `Sync`
/// whatever `T` is, which is the usual idiom.
#[derive(Debug)]
pub struct WireCodec<T> {
    max_len: usize,
    _marker: PhantomData<fn() -> T>,
}

pub type HeaderCodec = WireCodec<ChannelHeader>;
pub type MessageCodec = WireCodec<Message>;
pub type ControlCodec = WireCodec<ControlMessage>;
pub type StreamStartCodec = WireCodec<StreamStart>;

impl<T> WireCodec<T> {
    /// A codec that rejects strings longer than `max_len` bytes.
    #[must_use]
    pub fn with_max_len(max_len: usize) -> Self {
        Self {
            max_len,
            _marker: PhantomData,
        }
    }
}

// Written by hand: `#[derive(Default)]` would require `T: Default`.
impl<T> Default for WireCodec<T> {
    fn default() -> Self {
        Self::with_max_len(DEFAULT_MAX_LEN)
    }
}

/// Adapts shion-wire's [`Wire`] trait to Tokio's [`Decoder`] trait.
impl<T: Wire> Decoder for WireCodec<T> {
    type Item = T;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<T>, CodecError> {
        let mut r = Reader::new(src, self.max_len);
        match T::decode(&mut r) {
            Ok(item) => {
                let n = r.consumed();
                // `r` borrows `src`, and is no longer used after the line
                // above, so `src` can be modified again.
                src.advance(n);
                Ok(Some(item))
            }
            Err(DecodeError::Incomplete) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<T>, CodecError> {
        match self.decode(src)? {
            Some(item) => Ok(Some(item)),
            None if src.is_empty() => Ok(None),
            None => Err(CodecError::Truncated {
                buffered: src.len(),
            }),
        }
    }
}

/// Adapts shion-wire's [`Wire`] trait to Tokio's [`Encoder`] trait.
impl<T: Wire> Encoder<T> for WireCodec<T> {
    type Error = CodecError;

    fn encode(&mut self, item: T, dst: &mut BytesMut) -> Result<(), CodecError> {
        let start = dst.len();
        item.encode(dst).map_err(|e| {
            // Don't leave half a message in the output buffer.
            dst.truncate(start);
            CodecError::from(e)
        })
    }
}
