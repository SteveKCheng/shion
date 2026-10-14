//! Encoded terminal modes (RFC 4254 §8), the `modes` blob in `pty-req`.
//!
//! The blob is a list of `(opcode, argument)` pairs: one opcode byte, then a
//! big-endian `uint32`, ending with opcode 0. It keeps this SSH2 encoding
//! even inside SSH3 (no varints here).
//!
//! The session process decodes it into `termios` settings. The front-end
//! will need the encoder: russh hands it the modes already decoded.

use bytes::{BufMut, Bytes, BytesMut};

/// Opcodes from RFC 4254 §8, plus `IUTF8` from RFC 8160. The names match the
/// POSIX `termios` names they stand for.
pub mod opcode {
    pub const TTY_OP_END: u8 = 0;

    // Special characters (`c_cc`). The argument is the character; 255
    // means "disabled".
    pub const VINTR: u8 = 1;
    pub const VQUIT: u8 = 2;
    pub const VERASE: u8 = 3;
    pub const VKILL: u8 = 4;
    pub const VEOF: u8 = 5;
    pub const VEOL: u8 = 6;
    pub const VEOL2: u8 = 7;
    pub const VSTART: u8 = 8;
    pub const VSTOP: u8 = 9;
    pub const VSUSP: u8 = 10;
    pub const VDSUSP: u8 = 11;
    pub const VREPRINT: u8 = 12;
    pub const VWERASE: u8 = 13;
    pub const VLNEXT: u8 = 14;
    pub const VFLUSH: u8 = 15;
    pub const VSWTCH: u8 = 16;
    pub const VSTATUS: u8 = 17;
    pub const VDISCARD: u8 = 18;

    // Flags. The argument is 0 (clear) or 1 (set).
    pub const IGNPAR: u8 = 30;
    pub const PARMRK: u8 = 31;
    pub const INPCK: u8 = 32;
    pub const ISTRIP: u8 = 33;
    pub const INLCR: u8 = 34;
    pub const IGNCR: u8 = 35;
    pub const ICRNL: u8 = 36;
    pub const IUCLC: u8 = 37;
    pub const IXON: u8 = 38;
    pub const IXANY: u8 = 39;
    pub const IXOFF: u8 = 40;
    pub const IMAXBEL: u8 = 41;
    pub const IUTF8: u8 = 42;
    pub const ISIG: u8 = 50;
    pub const ICANON: u8 = 51;
    pub const XCASE: u8 = 52;
    pub const ECHO: u8 = 53;
    pub const ECHOE: u8 = 54;
    pub const ECHOK: u8 = 55;
    pub const ECHONL: u8 = 56;
    pub const NOFLSH: u8 = 57;
    pub const TOSTOP: u8 = 58;
    pub const IEXTEN: u8 = 59;
    pub const ECHOCTL: u8 = 60;
    pub const ECHOKE: u8 = 61;
    pub const PENDIN: u8 = 62;
    pub const OPOST: u8 = 70;
    pub const OLCUC: u8 = 71;
    pub const ONLCR: u8 = 72;
    pub const OCRNL: u8 = 73;
    pub const ONOCR: u8 = 74;
    pub const ONLRET: u8 = 75;
    pub const CS7: u8 = 90;
    pub const CS8: u8 = 91;
    pub const PARENB: u8 = 92;
    pub const PARODD: u8 = 93;

    // Line speeds in bits per second.
    pub const TTY_OP_ISPEED: u8 = 128;
    pub const TTY_OP_OSPEED: u8 = 129;

    /// Opcodes from here up are undefined, and since nobody knows how long
    /// their arguments are, decoding has to stop at the first one.
    pub const FIRST_UNDEFINED: u8 = 160;
}

/// The argument value that disables a special character.
pub const DISABLED_CHAR: u32 = 255;

/// Iterates over the `(opcode, argument)` pairs in an encoded modes blob.
///
/// Like OpenSSH, it is lenient: it stops quietly at `TTY_OP_END`, at an
/// undefined opcode (160 and up), or at a truncated pair, and leaves the
/// remaining modes at their defaults. Unknown opcodes below 160 are
/// returned; the caller decides whether to ignore them.
///
/// ```
/// use shion_wire::modes::{self, opcode};
/// let blob = modes::encode([(opcode::ECHO, 0)]);
/// assert_eq!(modes::decode(&blob).collect::<Vec<_>>(), [(opcode::ECHO, 0)]);
/// ```
#[must_use]
pub fn decode(blob: &[u8]) -> Decode<'_> {
    Decode { rest: blob }
}

/// The iterator returned by [`decode`].
///
/// It borrows the blob (`'a`) rather than copying it. The compiler makes
/// sure the blob outlives the iterator.
#[derive(Debug, Clone)]
pub struct Decode<'a> {
    rest: &'a [u8],
}

impl Iterator for Decode<'_> {
    type Item = (u8, u32);

    fn next(&mut self) -> Option<(u8, u32)> {
        // Slice patterns: matches if `rest` has at least 5 bytes, and
        // binds the first five and the remainder. A shorter slice (end of
        // blob or a truncated pair) falls through to `_`.
        match *self.rest {
            [op, a, b, c, d, ref rest @ ..]
                if op != opcode::TTY_OP_END && op < opcode::FIRST_UNDEFINED =>
            {
                self.rest = rest;
                Some((op, u32::from_be_bytes([a, b, c, d])))
            }
            _ => {
                self.rest = &[];
                None
            }
        }
    }
}

/// Encodes `(opcode, argument)` pairs into a modes blob, adding
/// `TTY_OP_END`.
///
/// `impl IntoIterator<Item = …>` accepts anything iterable: an array, a
/// `Vec`, or the output of `decode`.
pub fn encode(modes: impl IntoIterator<Item = (u8, u32)>) -> Bytes {
    let mut blob = BytesMut::new();
    for (op, arg) in modes {
        blob.put_u8(op);
        blob.put_u32(arg); // big-endian, as `BufMut`'s plain methods are
    }
    blob.put_u8(opcode::TTY_OP_END);
    blob.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let modes = [
            (opcode::VINTR, 3),
            (opcode::ECHO, 0),
            (opcode::TTY_OP_OSPEED, 38_400),
        ];
        let blob = encode(modes);
        assert_eq!(&blob[..], b"\x01\0\0\0\x03\x35\0\0\0\0\x81\0\0\x96\0\0");
        assert_eq!(decode(&blob).collect::<Vec<_>>(), modes);
    }

    #[test]
    fn empty_blobs() {
        assert_eq!(decode(b"").count(), 0);
        assert_eq!(decode(b"\0").count(), 0);
    }

    #[test]
    fn stops_at_end_marker() {
        assert_eq!(
            decode(b"\x35\0\0\0\x01\0\x36\0\0\0\x01").collect::<Vec<_>>(),
            [(opcode::ECHO, 1)]
        );
    }

    #[test]
    fn stops_at_undefined_opcode() {
        assert_eq!(
            decode(b"\x35\0\0\0\x01\xa0\0\0\0\x01\x36\0\0\0\x01").collect::<Vec<_>>(),
            [(opcode::ECHO, 1)]
        );
    }

    #[test]
    fn stops_at_truncated_pair() {
        assert_eq!(
            decode(b"\x35\0\0\0\x01\x36\0\0").collect::<Vec<_>>(),
            [(opcode::ECHO, 1)]
        );
    }

    #[test]
    fn unknown_defined_opcodes_are_returned() {
        assert_eq!(decode(b"\x13\0\0\0\x07").collect::<Vec<_>>(), [(19, 7)]);
    }
}
