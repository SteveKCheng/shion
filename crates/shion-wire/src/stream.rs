//! Telling the two kinds of stream apart by their first message.
//!
//! The front-end opens both control streams and channel streams, and the
//! session has to tell them apart before it knows how to decode the rest.
//! The first varint does that unambiguously: a channel stream starts with
//! [`CHANNEL_SIGNAL`] (`0xaf3627e6`), a control stream with
//! [`control_type::CONV_OPEN`] (192).

use bytes::BytesMut;

use crate::Wire;
use crate::control::{ControlMessage, ConvOpen, control_type};
use crate::error::{DecodeError, EncodeError};
use crate::header::{CHANNEL_SIGNAL, ChannelHeader};
use crate::wire::Reader;

/// The first message on a front-end-initiated stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamStart {
    /// A channel stream. [`crate::Message`]s follow.
    Channel(ChannelHeader),
    /// A control stream opening a new conversation. More
    /// [`ControlMessage`]s follow.
    Control(ConvOpen),
}

impl Wire for StreamStart {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        // Look at the first varint without consuming it: the full decoders
        // below expect to read it themselves.
        match r.clone().varint()? {
            CHANNEL_SIGNAL => Ok(Self::Channel(ChannelHeader::decode(r)?)),
            control_type::CONV_OPEN => match ControlMessage::decode(r)? {
                ControlMessage::ConvOpen(open) => Ok(Self::Control(open)),
                // Can't happen: type 192 always decodes as ConvOpen. Still,
                // returning an error is cheaper to reason about than a panic.
                _ => Err(DecodeError::UnknownStreamStart(control_type::CONV_OPEN)),
            },
            other => Err(DecodeError::UnknownStreamStart(other)),
        }
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        match self {
            Self::Channel(header) => header.encode(dst),
            Self::Control(open) => ControlMessage::ConvOpen(open.clone()).encode(dst),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::PROTOCOL_VERSION;
    use crate::header::channel_type;

    fn roundtrip(start: &StreamStart) {
        let mut buf = BytesMut::new();
        start.encode(&mut buf).unwrap();
        let mut r = Reader::new(&buf, 1024);
        assert_eq!(&StreamStart::decode(&mut r).unwrap(), start);
        assert_eq!(r.consumed(), buf.len());
    }

    #[test]
    fn both_kinds_roundtrip() {
        roundtrip(&StreamStart::Channel(ChannelHeader {
            conversation_id: 3,
            channel_type: channel_type::SESSION.into(),
            max_packet_size: 32_768,
        }));
        roundtrip(&StreamStart::Control(ConvOpen {
            version: PROTOCOL_VERSION,
            conversation_id: 3,
            attributes: vec![],
        }));
    }

    #[test]
    fn other_control_messages_cannot_start_a_stream() {
        let mut buf = BytesMut::new();
        ControlMessage::RequestFailure.encode(&mut buf).unwrap();
        assert_eq!(
            StreamStart::decode(&mut Reader::new(&buf, 1024)),
            Err(DecodeError::UnknownStreamStart(
                control_type::REQUEST_FAILURE
            ))
        );
    }

    #[test]
    fn empty_is_incomplete() {
        assert_eq!(
            StreamStart::decode(&mut Reader::new(&[], 1024)),
            Err(DecodeError::Incomplete)
        );
    }
}
