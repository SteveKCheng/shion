//! The header at the start of every SSH3 channel stream.

use bytes::BytesMut;

use crate::Wire;
use crate::error::{DecodeError, EncodeError};
use crate::wire::{Reader, put_string, put_varint};

/// Signal value that opens every SSH3 channel stream. In HTTP/3 it tells the
/// stack "this bidirectional stream belongs to SSH3, not to a request".
pub const CHANNEL_SIGNAL: u64 = 0xaf36_27e6;

/// Channel type names (RFC 4254 §6.1, §7).
pub mod channel_type {
    pub const SESSION: &str = "session";
    pub const DIRECT_TCPIP: &str = "direct-tcpip";
    pub const FORWARDED_TCPIP: &str = "forwarded-tcpip";
}

/// Common part of an SSH3 channel header:
///
/// ```text
/// varint  0xaf3627e6        CHANNEL_SIGNAL
/// varint  conversation id
/// string  channel type
/// varint  max packet size
/// ```
///
/// Some channel types (the forwarding ones) follow this with type-specific
/// fields. Those aren't part of this struct; they stay on the stream for a
/// type-specific decoder to read next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelHeader {
    pub conversation_id: u64,
    pub channel_type: String,
    /// Largest payload the sender of the header is willing to receive in
    /// one data message.
    pub max_packet_size: u64,
}

impl Wire for ChannelHeader {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let signal = r.varint()?;
        if signal != CHANNEL_SIGNAL {
            return Err(DecodeError::BadChannelSignal(signal));
        }
        Ok(Self {
            conversation_id: r.varint()?,
            channel_type: r.string("channel type")?,
            max_packet_size: r.varint()?,
        })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        put_varint(dst, CHANNEL_SIGNAL)?;
        put_varint(dst, self.conversation_id)?;
        put_string(dst, &self.channel_type)?;
        put_varint(dst, self.max_packet_size)
    }
}
