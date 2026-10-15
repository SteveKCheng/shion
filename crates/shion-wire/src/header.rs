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

/// An SSH3 channel header:
///
/// ```text
/// varint  0xaf3627e6        CHANNEL_SIGNAL
/// varint  conversation id
/// string  channel type
/// varint  max packet size
/// ...     type-specific fields (see `ChannelKind`)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelHeader {
    pub conversation_id: u64,
    /// The channel type, with its type-specific fields.
    pub kind: ChannelKind,
    /// Largest payload the sender of the header is willing to receive in
    /// one data message.
    pub max_packet_size: u64,
}

/// A channel's type, and the fields that go with it.
///
/// The type-specific fields follow the max packet size on the wire, so a
/// receiver can only find the end of a header whose type it knows (the same
/// wart as with channel requests). An [`ChannelKind::Other`] header is
/// decoded without them; such a channel can only be refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelKind {
    /// `session`: a shell, command or subsystem.
    Session,
    /// `direct-tcpip` (local forwarding, `ssh -L`): connect to `host` and
    /// `port` of the endpoints.
    DirectTcpip(TcpipEndpoints),
    /// `forwarded-tcpip` (remote forwarding, `ssh -R`): a connection
    /// arrived at a listener set up by `tcpip-forward`.
    ForwardedTcpip(TcpipEndpoints),
    /// Any other channel type.
    Other(String),
}

impl ChannelKind {
    /// The channel type name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Session => channel_type::SESSION,
            Self::DirectTcpip(_) => channel_type::DIRECT_TCPIP,
            Self::ForwardedTcpip(_) => channel_type::FORWARDED_TCPIP,
            Self::Other(name) => name,
        }
    }
}

/// The type-specific fields of the TCP/IP forwarding channels. They are
/// RFC 4254 §7.2's, encoded the SSH3 way (varints for numbers):
///
/// ```text
/// string  host     direct-tcpip: host to connect to (a name or an address)
///                  forwarded-tcpip: the address that was connected to
/// varint  port     the port to connect to / that was connected to
/// string  originator address
/// varint  originator port
/// ```
///
/// shion's own choice: SSH3 has no settled format for these. sshoq's
/// `direct-tcp` header carries only a binary IP address, which would make
/// the front-end resolve host names outside the sandbox (design §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpipEndpoints {
    pub host: String,
    pub port: u16,
    pub originator_address: String,
    pub originator_port: u16,
}

impl Wire for ChannelHeader {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let signal = r.varint()?;
        if signal != CHANNEL_SIGNAL {
            return Err(DecodeError::BadChannelSignal(signal));
        }
        let conversation_id = r.varint()?;
        let name = r.string("channel type")?;
        let max_packet_size = r.varint()?;
        let kind = match name.as_str() {
            channel_type::SESSION => ChannelKind::Session,
            channel_type::DIRECT_TCPIP => ChannelKind::DirectTcpip(TcpipEndpoints::decode(r)?),
            channel_type::FORWARDED_TCPIP => {
                ChannelKind::ForwardedTcpip(TcpipEndpoints::decode(r)?)
            }
            _ => ChannelKind::Other(name),
        };
        Ok(Self {
            conversation_id,
            kind,
            max_packet_size,
        })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        put_varint(dst, CHANNEL_SIGNAL)?;
        put_varint(dst, self.conversation_id)?;
        put_string(dst, self.kind.name())?;
        put_varint(dst, self.max_packet_size)?;
        match &self.kind {
            ChannelKind::DirectTcpip(endpoints) | ChannelKind::ForwardedTcpip(endpoints) => {
                endpoints.encode(dst)
            }
            ChannelKind::Session | ChannelKind::Other(_) => Ok(()),
        }
    }
}

impl Wire for TcpipEndpoints {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            host: r.string("host")?,
            port: r.port()?,
            originator_address: r.string("originator address")?,
            originator_port: r.port()?,
        })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        put_string(dst, &self.host)?;
        put_varint(dst, self.port.into())?;
        put_string(dst, &self.originator_address)?;
        put_varint(dst, self.originator_port.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(header: &ChannelHeader) -> BytesMut {
        let mut buf = BytesMut::new();
        header.encode(&mut buf).unwrap();
        let mut r = Reader::new(&buf, 1024);
        assert_eq!(&ChannelHeader::decode(&mut r).unwrap(), header);
        assert_eq!(r.consumed(), buf.len());
        buf
    }

    #[test]
    fn direct_tcpip() {
        let buf = roundtrip(&ChannelHeader {
            conversation_id: 1,
            kind: ChannelKind::DirectTcpip(TcpipEndpoints {
                host: "db".into(),
                port: 5432,
                originator_address: "::1".into(),
                originator_port: 40000,
            }),
            max_packet_size: 100,
        });
        // After the 8-byte signal: 1 · "direct-tcpip" · 100 (2 bytes) ·
        // "db" · 5432 (2 bytes) · "::1" · 40000 (4 bytes).
        assert_eq!(
            &buf[8..],
            b"\x01\x0cdirect-tcpip\x40\x64\x02db\x55\x38\x03::1\x80\x00\x9c\x40"
        );
    }

    #[test]
    fn forwarded_tcpip() {
        roundtrip(&ChannelHeader {
            conversation_id: 7,
            kind: ChannelKind::ForwardedTcpip(TcpipEndpoints {
                host: "127.0.0.1".into(),
                port: 8080,
                originator_address: "127.0.0.1".into(),
                originator_port: 51000,
            }),
            max_packet_size: 32_768,
        });
    }

    #[test]
    fn other_types_have_no_fields() {
        roundtrip(&ChannelHeader {
            conversation_id: 7,
            kind: ChannelKind::Other("direct-tcp".into()),
            max_packet_size: 32_768,
        });
    }

    #[test]
    fn ports_must_fit_in_16_bits() {
        let mut buf = BytesMut::new();
        ChannelHeader {
            conversation_id: 1,
            kind: ChannelKind::Other(channel_type::DIRECT_TCPIP.into()),
            max_packet_size: 100,
        }
        .encode(&mut buf)
        .unwrap();
        put_string(&mut buf, "host").unwrap();
        put_varint(&mut buf, 65_536).unwrap();
        assert_eq!(
            ChannelHeader::decode(&mut Reader::new(&buf, 1024)),
            Err(DecodeError::OutOfRange {
                what: "port",
                value: 65_536
            })
        );
    }
}
