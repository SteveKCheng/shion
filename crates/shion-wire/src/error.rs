//! Error types for decoding and encoding.

/// Why a byte sequence could not be decoded.
///
/// [`DecodeError::Incomplete`] is special: it means "not an error *yet*,
/// wait for more bytes". The streaming codecs in [`crate::codec`] rely on
/// every decoder reporting a short buffer this way and never as anything
/// else.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("message is incomplete")]
    Incomplete,

    #[error("{what}: length {len} exceeds the limit of {max} bytes")]
    TooLong {
        what: &'static str,
        len: u64,
        max: usize,
    },

    #[error("{0}: invalid UTF-8")]
    InvalidUtf8(&'static str),

    #[error("{0}: malformed (shorter than its fields)")]
    Malformed(&'static str),

    #[error("not an SSH3 channel: signal value {0:#x}")]
    BadChannelSignal(u64),

    #[error("unknown message type {0}")]
    UnknownMessage(u64),

    #[error("unknown channel request type {0:?}")]
    UnknownRequest(String),

    #[error("stream starts with neither a channel header nor CONV_OPEN (first value {0:#x})")]
    UnknownStreamStart(u64),
}

/// Why a value could not be encoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    #[error("value {0} does not fit in a QUIC varint")]
    VarIntOutOfRange(u64),
}

/// Errors from the streaming codecs, which also see I/O failures.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Decode(#[from] DecodeError),

    #[error(transparent)]
    Encode(#[from] EncodeError),

    #[error("stream ended in the middle of a message ({buffered} bytes buffered)")]
    Truncated { buffered: usize },
}

/// Lets code that deals in `io::Error` use `?` on codec results. I/O errors
/// come back out unchanged; protocol errors become `InvalidData`.
impl From<CodecError> for std::io::Error {
    fn from(e: CodecError) -> Self {
        match e {
            CodecError::Io(e) => e,
            other => Self::new(std::io::ErrorKind::InvalidData, other),
        }
    }
}
