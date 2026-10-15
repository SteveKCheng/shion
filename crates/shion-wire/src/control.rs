//! Messages on a conversation's control stream (design §4.3).
//!
//! This protocol is shion's own (SSH3 uses HTTP here), so unlike channel
//! messages every message is length-delimited:
//!
//! ```text
//! varint  type
//! varint  body length
//! bytes   body
//! ```
//!
//! That lets a receiver skip message types it doesn't know
//! ([`ControlMessage::Unknown`]) and ignore fields appended to a body by a
//! newer peer.

use bytes::{Bytes, BytesMut};

use crate::Wire;
use crate::error::{DecodeError, EncodeError};
use crate::wire::{Reader, put_bool, put_string, put_varint};

/// Version of the control protocol spoken by this crate.
pub const PROTOCOL_VERSION: u64 = 1;

/// Control message type numbers. Global requests and their replies reuse
/// SSH2's numbers; the rest come from the local-extension range 192–255.
pub mod control_type {
    pub const GLOBAL_REQUEST: u64 = 80;
    pub const REQUEST_SUCCESS: u64 = 81;
    pub const REQUEST_FAILURE: u64 = 82;
    pub const CONV_OPEN: u64 = 192;
    pub const CONV_ACCEPT: u64 = 193;
    pub const CONV_REJECT: u64 = 194;
}

/// Global request names (RFC 4254 §7.1).
pub mod global_request_type {
    pub const TCPIP_FORWARD: &str = "tcpip-forward";
    pub const CANCEL_TCPIP_FORWARD: &str = "cancel-tcpip-forward";
}

/// Well-known keys for [`ConvOpen::attributes`].
pub mod attr {
    /// App-level user name; the session checks it against its `--user`.
    pub const USER: &str = "user";
    /// `"<ip> <port>"` of the SSH client.
    pub const CLIENT_ADDRESS: &str = "client-address";
    /// `"<ip> <port>"` the client connected to.
    pub const SERVER_ADDRESS: &str = "server-address";
    /// The client's SSH identification string.
    pub const CLIENT_VERSION: &str = "client-version";
    /// How the user authenticated, e.g. `publickey`.
    pub const AUTH_METHOD: &str = "auth-method";
    /// Fingerprint of the key used, e.g. `SHA256:…`.
    pub const AUTH_KEY: &str = "auth-key";
}

/// Front-end → session: start a conversation (one SSH2 connection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvOpen {
    pub version: u64,
    /// Chosen by the front-end, unique within the session process. Channel
    /// headers name it in their `conversation_id` field.
    pub conversation_id: u64,
    /// Facts about this connection, as key/value pairs (see [`attr`]).
    pub attributes: Vec<(String, String)>,
}

impl ConvOpen {
    /// Value of the first attribute named `key`, if any.
    #[must_use]
    pub fn attribute(&self, key: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Session → front-end: the conversation is up, and here is what this
/// session process supports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvAccept {
    pub version: u64,
    pub channel_types: Vec<String>,
    pub request_types: Vec<String>,
}

/// Represents a global SSH request (§4, RFC 4254), or a control message
/// privately used by Shion, sent over its control stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    ConvOpen(ConvOpen),
    ConvAccept(ConvAccept),
    ConvReject {
        reason: String,
    },
    /// An SSH2 global request (e.g. `tcpip-forward`), on the control
    /// stream of the conversation (connection) it belongs to.
    GlobalRequest {
        want_reply: bool,
        request: GlobalRequest,
    },
    /// Reply to a global request. For `tcpip-forward` with port 0, the body
    /// is the port that was allocated (a varint); otherwise it's empty.
    RequestSuccess {
        body: Bytes,
    },
    RequestFailure,
    /// A message type this version doesn't know. Receivers should ignore it.
    Unknown {
        msg_type: u64,
        body: Bytes,
    },
}

/// The payload of a [`ControlMessage::GlobalRequest`]:
///
/// ```text
/// string  request name
/// bool    want reply
/// ...     request-specific fields
/// ```
///
/// Being inside a length-delimited control message, a request we don't
/// know can be skipped, unlike a channel request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalRequest {
    /// `tcpip-forward`: listen on `address` and `port` (0 = pick one), and
    /// open a `forwarded-tcpip` channel for each connection. Fields as in
    /// RFC 4254 §7.1, with a varint port: `string address, varint port`.
    TcpipForward(ForwardAddress),
    /// `cancel-tcpip-forward`: stop listening (same fields).
    CancelTcpipForward(ForwardAddress),
    /// Any other request; `body` is everything after `want reply`.
    Other { name: String, body: Bytes },
}

/// Where a `tcpip-forward` listens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ForwardAddress {
    /// As in RFC 4254: `""` means every address, `"localhost"` the loopback
    /// addresses, anything else a host name or address to bind to.
    pub address: String,
    pub port: u16,
}

impl GlobalRequest {
    /// The request name.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::TcpipForward(_) => global_request_type::TCPIP_FORWARD,
            Self::CancelTcpipForward(_) => global_request_type::CANCEL_TCPIP_FORWARD,
            Self::Other { name, .. } => name,
        }
    }
}

impl ForwardAddress {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            address: r.string("forward address")?,
            port: r.port()?,
        })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        put_string(dst, &self.address)?;
        put_varint(dst, self.port.into())
    }
}

impl Wire for ControlMessage {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let msg_type = r.varint()?;
        let mut body = r.block("control message")?;
        // We're now inside a complete body, so running short means the body
        // is malformed, not that more data is coming.
        Self::decode_body(msg_type, &mut body).map_err(|e| e.within_block("control message"))
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        use control_type as t;
        // Encode the body first: its length goes in front of it.
        let mut body = BytesMut::new();
        let b = &mut body;
        let msg_type = match self {
            Self::ConvOpen(o) => {
                put_varint(b, o.version)?;
                put_varint(b, o.conversation_id)?;
                put_varint(b, o.attributes.len() as u64)?;
                for (k, v) in &o.attributes {
                    put_string(b, k)?;
                    put_string(b, v)?;
                }
                t::CONV_OPEN
            }
            Self::ConvAccept(a) => {
                put_varint(b, a.version)?;
                encode_string_list(b, &a.channel_types)?;
                encode_string_list(b, &a.request_types)?;
                t::CONV_ACCEPT
            }
            Self::ConvReject { reason } => {
                put_string(b, reason)?;
                t::CONV_REJECT
            }
            Self::GlobalRequest {
                want_reply,
                request,
            } => {
                put_string(b, request.name())?;
                put_bool(b, *want_reply);
                match request {
                    GlobalRequest::TcpipForward(address)
                    | GlobalRequest::CancelTcpipForward(address) => address.encode(b)?,
                    GlobalRequest::Other { body, .. } => b.extend_from_slice(body),
                }
                t::GLOBAL_REQUEST
            }
            Self::RequestSuccess { body } => {
                b.extend_from_slice(body);
                t::REQUEST_SUCCESS
            }
            Self::RequestFailure => t::REQUEST_FAILURE,
            Self::Unknown { msg_type, body } => {
                b.extend_from_slice(body);
                *msg_type
            }
        };
        put_varint(dst, msg_type)?;
        put_string(dst, &body)
    }
}

impl ControlMessage {
    fn decode_body(msg_type: u64, b: &mut Reader<'_>) -> Result<Self, DecodeError> {
        use control_type as t;
        Ok(match msg_type {
            t::CONV_OPEN => Self::ConvOpen(ConvOpen {
                version: b.varint()?,
                conversation_id: b.varint()?,
                attributes: decode_attributes(b)?,
            }),
            t::CONV_ACCEPT => Self::ConvAccept(ConvAccept {
                version: b.varint()?,
                channel_types: decode_string_list(b, "channel types")?,
                request_types: decode_string_list(b, "request types")?,
            }),
            t::CONV_REJECT => Self::ConvReject {
                reason: b.string("reject reason")?,
            },
            t::GLOBAL_REQUEST => {
                let name = b.string("global request name")?;
                let want_reply = b.bool()?;
                let request = match name.as_str() {
                    global_request_type::TCPIP_FORWARD => {
                        GlobalRequest::TcpipForward(ForwardAddress::decode(b)?)
                    }
                    global_request_type::CANCEL_TCPIP_FORWARD => {
                        GlobalRequest::CancelTcpipForward(ForwardAddress::decode(b)?)
                    }
                    _ => GlobalRequest::Other {
                        name,
                        body: Bytes::copy_from_slice(b.rest()),
                    },
                };
                Self::GlobalRequest {
                    want_reply,
                    request,
                }
            }
            t::REQUEST_SUCCESS => Self::RequestSuccess {
                body: Bytes::copy_from_slice(b.rest()),
            },
            t::REQUEST_FAILURE => Self::RequestFailure,
            _ => Self::Unknown {
                msg_type,
                body: Bytes::copy_from_slice(b.rest()),
            },
        })
    }
}

// The count comes from the peer, so we never preallocate from it: each
// element takes at least one byte, so the loop stops at the end of the body.
fn decode_string_list(r: &mut Reader<'_>, what: &'static str) -> Result<Vec<String>, DecodeError> {
    let n = r.varint()?;
    let mut list = Vec::new();
    for _ in 0..n {
        list.push(r.string(what)?);
    }
    Ok(list)
}

fn encode_string_list(dst: &mut BytesMut, list: &[String]) -> Result<(), EncodeError> {
    put_varint(dst, list.len() as u64)?;
    for s in list {
        put_string(dst, s)?;
    }
    Ok(())
}

fn decode_attributes(r: &mut Reader<'_>) -> Result<Vec<(String, String)>, DecodeError> {
    let n = r.varint()?;
    let mut attrs = Vec::new();
    for _ in 0..n {
        attrs.push((r.string("attribute key")?, r.string("attribute value")?));
    }
    Ok(attrs)
}
