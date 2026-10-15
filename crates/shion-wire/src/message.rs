//! Messages exchanged on an SSH3 channel stream after its header.
//!
//! These are RFC 4254's connection-protocol messages minus the parts the
//! transport takes over (channel numbers, `WINDOW_ADJUST`, `EOF`, `CLOSE`),
//! with every `uint32` replaced by a QUIC varint. Messages are *not*
//! length-prefixed: a message's extent follows from its type, so decoding
//! an unknown type or request is necessarily fatal for the stream.

use bytes::{Bytes, BytesMut};

use crate::Wire;
use crate::error::{DecodeError, EncodeError};
use crate::wire::{Reader, put_bool, put_string, put_varint};

/// Message type numbers (RFC 4250 §4.1.2).
pub mod msg {
    pub const CHANNEL_OPEN_CONFIRMATION: u64 = 91;
    pub const CHANNEL_OPEN_FAILURE: u64 = 92;
    pub const CHANNEL_DATA: u64 = 94;
    pub const CHANNEL_EXTENDED_DATA: u64 = 95;
    pub const CHANNEL_REQUEST: u64 = 98;
    pub const CHANNEL_SUCCESS: u64 = 99;
    pub const CHANNEL_FAILURE: u64 = 100;
}

/// Data type code for stderr in [`Message::ExtendedData`] (RFC 4254 §5.2).
pub const EXTENDED_DATA_STDERR: u64 = 1;

/// Reason codes for [`Message::OpenFailure`] (RFC 4254 §5.1).
pub mod open_failure {
    pub const ADMINISTRATIVELY_PROHIBITED: u64 = 1;
    pub const CONNECT_FAILED: u64 = 2;
    pub const UNKNOWN_CHANNEL_TYPE: u64 = 3;
    pub const RESOURCE_SHORTAGE: u64 = 4;
}

/// One message on an SSH channel.
///
/// This type only includes messages that are sent on their dedicated SSH channels
/// (§5, RFC 4254; mapped to QUIC bi-directional streams in draft-michel-remote-terminal-http3).
/// 
/// Global requests in SSH, and control messages used privately by Shion, are not
/// included inside this type.  Those are in [`crate::control::ControlMessage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    OpenConfirmation {
        max_packet_size: u64,
    },
    OpenFailure {
        reason: u64,
        description: String,
        language: String,
    },
    Data(Bytes),
    ExtendedData {
        data_type: u64,
        data: Bytes,
    },
    Request {
        want_reply: bool,
        request: ChannelRequest,
    },
    Success,
    Failure,
}

/// Window dimensions as sent in `pty-req` and `window-change`. Characters
/// and pixels; zero means "unknown".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WindowSize {
    pub cols: u64,
    pub rows: u64,
    pub width_px: u64,
    pub height_px: u64,
}

/// `pty-req` (RFC 4254 §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyRequest {
    /// Value for `TERM`, e.g. `xterm-256color`.
    pub term: String,
    pub size: WindowSize,
    /// Terminal modes, still in SSH2's encoding even inside SSH3 (RFC 4254
    /// §8: opcode byte + `uint32` argument, terminated by opcode 0). See
    /// [`crate::modes`] for the codec.
    pub modes: Bytes,
}

/// `x11-req` (RFC 4254 §6.3.1). We don't support X11, but we still parse
/// the request so it can be refused with `CHANNEL_FAILURE` without killing
/// the channel (unknown requests can't be skipped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X11Request {
    pub single_connection: bool,
    pub auth_protocol: String,
    pub auth_cookie: String,
    pub screen: u64,
}

/// `exit-signal` (RFC 4254 §6.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitSignal {
    /// Signal name without the `SIG` prefix, e.g. `TERM`.
    pub signal: String,
    pub core_dumped: bool,
    pub description: String,
    pub language: String,
}

/// The payload of a `CHANNEL_REQUEST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelRequest {
    PtyReq(PtyRequest),
    X11Req(X11Request),
    /// `env`. Name and value are raw bytes: Unix environment strings needn't
    /// be UTF-8.
    Env {
        name: Bytes,
        value: Bytes,
    },
    Shell,
    /// `exec`. The command is raw bytes, for the same reason as `Env`.
    Exec {
        command: Bytes,
    },
    Subsystem {
        name: String,
    },
    WindowChange(WindowSize),
    /// `signal`, with the name without the `SIG` prefix.
    Signal {
        name: String,
    },
    ExitStatus {
        status: u64,
    },
    ExitSignal(ExitSignal),
}

/// Request type names, as they appear on the wire.
pub mod request_type {
    pub const PTY_REQ: &str = "pty-req";
    pub const X11_REQ: &str = "x11-req";
    pub const ENV: &str = "env";
    pub const SHELL: &str = "shell";
    pub const EXEC: &str = "exec";
    pub const SUBSYSTEM: &str = "subsystem";
    pub const WINDOW_CHANGE: &str = "window-change";
    pub const SIGNAL: &str = "signal";
    pub const EXIT_STATUS: &str = "exit-status";
    pub const EXIT_SIGNAL: &str = "exit-signal";

    /// Every request type this crate can decode.
    pub const ALL: &[&str] = &[
        PTY_REQ,
        X11_REQ,
        ENV,
        SHELL,
        EXEC,
        SUBSYSTEM,
        WINDOW_CHANGE,
        SIGNAL,
        EXIT_STATUS,
        EXIT_SIGNAL,
    ];
}

impl ChannelRequest {
    /// The request type name, e.g. `"pty-req"`.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        use request_type as t;
        match self {
            Self::PtyReq(_) => t::PTY_REQ,
            Self::X11Req(_) => t::X11_REQ,
            Self::Env { .. } => t::ENV,
            Self::Shell => t::SHELL,
            Self::Exec { .. } => t::EXEC,
            Self::Subsystem { .. } => t::SUBSYSTEM,
            Self::WindowChange(_) => t::WINDOW_CHANGE,
            Self::Signal { .. } => t::SIGNAL,
            Self::ExitStatus { .. } => t::EXIT_STATUS,
            Self::ExitSignal(_) => t::EXIT_SIGNAL,
        }
    }

    /// Decodes the type-specific body of a request whose type name has
    /// already been read.
    fn decode_body(type_name: String, r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        use request_type as t;
        Ok(match type_name.as_str() {
            t::PTY_REQ => Self::PtyReq(PtyRequest {
                term: r.string("pty-req term")?,
                size: decode_window_size(r)?,
                modes: r.bytes("pty-req modes")?,
            }),
            t::X11_REQ => Self::X11Req(X11Request {
                single_connection: r.bool()?,
                auth_protocol: r.string("x11-req protocol")?,
                auth_cookie: r.string("x11-req cookie")?,
                screen: r.varint()?,
            }),
            t::ENV => Self::Env {
                name: r.bytes("env name")?,
                value: r.bytes("env value")?,
            },
            t::SHELL => Self::Shell,
            t::EXEC => Self::Exec {
                command: r.bytes("exec command")?,
            },
            t::SUBSYSTEM => Self::Subsystem {
                name: r.string("subsystem name")?,
            },
            t::WINDOW_CHANGE => Self::WindowChange(decode_window_size(r)?),
            t::SIGNAL => Self::Signal {
                name: r.string("signal name")?,
            },
            t::EXIT_STATUS => Self::ExitStatus {
                status: r.varint()?,
            },
            t::EXIT_SIGNAL => Self::ExitSignal(ExitSignal {
                signal: r.string("exit-signal name")?,
                core_dumped: r.bool()?,
                description: r.string("exit-signal description")?,
                language: r.string("exit-signal language")?,
            }),
            _ => return Err(DecodeError::UnknownRequest(type_name)),
        })
    }

    fn encode_body(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        match self {
            Self::PtyReq(p) => {
                put_string(dst, &p.term)?;
                encode_window_size(dst, &p.size)?;
                put_string(dst, &p.modes)
            }
            Self::X11Req(x) => {
                put_bool(dst, x.single_connection);
                put_string(dst, &x.auth_protocol)?;
                put_string(dst, &x.auth_cookie)?;
                put_varint(dst, x.screen)
            }
            Self::Env { name, value } => {
                put_string(dst, name)?;
                put_string(dst, value)
            }
            Self::Shell => Ok(()),
            Self::Exec { command } => put_string(dst, command),
            Self::Subsystem { name } | Self::Signal { name } => put_string(dst, name),
            Self::WindowChange(size) => encode_window_size(dst, size),
            Self::ExitStatus { status } => put_varint(dst, *status),
            Self::ExitSignal(e) => {
                put_string(dst, &e.signal)?;
                put_bool(dst, e.core_dumped);
                put_string(dst, &e.description)?;
                put_string(dst, &e.language)
            }
        }
    }
}

fn decode_window_size(r: &mut Reader<'_>) -> Result<WindowSize, DecodeError> {
    Ok(WindowSize {
        cols: r.varint()?,
        rows: r.varint()?,
        width_px: r.varint()?,
        height_px: r.varint()?,
    })
}

fn encode_window_size(dst: &mut BytesMut, s: &WindowSize) -> Result<(), EncodeError> {
    for v in [s.cols, s.rows, s.width_px, s.height_px] {
        put_varint(dst, v)?;
    }
    Ok(())
}

impl Wire for Message {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(match r.varint()? {
            msg::CHANNEL_OPEN_CONFIRMATION => Self::OpenConfirmation {
                max_packet_size: r.varint()?,
            },
            msg::CHANNEL_OPEN_FAILURE => Self::OpenFailure {
                reason: r.varint()?,
                description: r.string("open failure description")?,
                language: r.string("open failure language")?,
            },
            msg::CHANNEL_DATA => Self::Data(r.bytes("data")?),
            msg::CHANNEL_EXTENDED_DATA => Self::ExtendedData {
                data_type: r.varint()?,
                data: r.bytes("extended data")?,
            },
            msg::CHANNEL_REQUEST => {
                let type_name = r.string("request type")?;
                let want_reply = r.bool()?;
                let request = ChannelRequest::decode_body(type_name, r)?;
                Self::Request {
                    want_reply,
                    request,
                }
            }
            msg::CHANNEL_SUCCESS => Self::Success,
            msg::CHANNEL_FAILURE => Self::Failure,
            other => return Err(DecodeError::UnknownMessage(other)),
        })
    }

    fn encode(&self, dst: &mut BytesMut) -> Result<(), EncodeError> {
        match self {
            Self::OpenConfirmation { max_packet_size } => {
                put_varint(dst, msg::CHANNEL_OPEN_CONFIRMATION)?;
                put_varint(dst, *max_packet_size)
            }
            Self::OpenFailure {
                reason,
                description,
                language,
            } => {
                put_varint(dst, msg::CHANNEL_OPEN_FAILURE)?;
                put_varint(dst, *reason)?;
                put_string(dst, description)?;
                put_string(dst, language)
            }
            Self::Data(data) => {
                put_varint(dst, msg::CHANNEL_DATA)?;
                put_string(dst, data)
            }
            Self::ExtendedData { data_type, data } => {
                put_varint(dst, msg::CHANNEL_EXTENDED_DATA)?;
                put_varint(dst, *data_type)?;
                put_string(dst, data)
            }
            Self::Request {
                want_reply,
                request,
            } => {
                put_varint(dst, msg::CHANNEL_REQUEST)?;
                put_string(dst, request.type_name())?;
                put_bool(dst, *want_reply);
                request.encode_body(dst)
            }
            Self::Success => put_varint(dst, msg::CHANNEL_SUCCESS),
            Self::Failure => put_varint(dst, msg::CHANNEL_FAILURE),
        }
    }
}
