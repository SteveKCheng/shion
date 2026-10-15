//! Primitive encodings shared by every message: QUIC variable-length
//! integers, SSH booleans, and varint-length-prefixed strings.
//!
//! Decoding goes through [`Reader`], a cursor over a borrowed byte slice.
//! Encoding appends to anything implementing [`BufMut`] (in practice a
//! `BytesMut`).

use bytes::{BufMut, Bytes};

use crate::error::{DecodeError, EncodeError};

/// Largest value a QUIC varint can hold: 2^62 − 1.
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// Number of bytes `v` occupies in its shortest varint encoding.
#[must_use]
pub const fn varint_len(v: u64) -> usize {
    if v < 1 << 6 {
        1
    } else if v < 1 << 14 {
        2
    } else if v < 1 << 30 {
        4
    } else {
        8
    }
}

/// Appends `v` as a QUIC varint (RFC 9000 §16), in its shortest form.
///
/// The two high bits of the first byte give the length (`00` → 1 byte,
/// `01` → 2, `10` → 4, `11` → 8); the remaining bits hold `v` big-endian.
///
/// # Errors
/// [`EncodeError::VarIntOutOfRange`] if `v` > [`VARINT_MAX`].
// The casts can't truncate: `varint_len` has just checked that `v` fits.
#[allow(clippy::cast_possible_truncation)]
pub fn put_varint(dst: &mut impl BufMut, v: u64) -> Result<(), EncodeError> {
    match varint_len(v) {
        1 => dst.put_u8(v as u8),
        2 => dst.put_u16(0x4000 | v as u16),
        4 => dst.put_u32(0x8000_0000 | v as u32),
        _ if v <= VARINT_MAX => dst.put_u64(0xc000_0000_0000_0000 | v),
        _ => return Err(EncodeError::VarIntOutOfRange(v)),
    }
    Ok(())
}

/// Appends an SSH boolean: one byte, 0 or 1.
pub fn put_bool(dst: &mut impl BufMut, b: bool) {
    dst.put_u8(u8::from(b));
}

/// Appends an SSH3 string: varint length, then the bytes.
///
/// (SSH2 uses a `uint32` length here; SSH3 swaps it for a varint.)
///
/// # Errors
/// Only if `s` is longer than 2^62 − 1 bytes, which can't happen in practice.
pub fn put_string(dst: &mut impl BufMut, s: impl AsRef<[u8]>) -> Result<(), EncodeError> {
    let s = s.as_ref();
    put_varint(dst, s.len() as u64)?;
    dst.put_slice(s);
    Ok(())
}

/// Number of bytes [`put_string`] writes for `s`.
#[must_use]
pub fn string_len(s: impl AsRef<[u8]>) -> usize {
    let n = s.as_ref().len();
    varint_len(n as u64) + n
}

/// Decoding cursor over a byte slice.
///
/// Each accessor consumes bytes from the front. If the slice runs out, it
/// returns [`DecodeError::Incomplete`] and the caller should retry later with
/// a longer buffer. Decoding is all-or-nothing at the message level, so it
/// doesn't matter what state the reader is left in after an error.
///
/// The lifetime `'a` ties the slices returned by [`Reader::take`] to the
/// underlying buffer, so they can be used without copying. The borrow
/// checker then makes sure the buffer isn't modified while they're alive.
/// It is `Clone` so a decoder can look ahead: clone the reader, read from
/// the clone, and the original stays where it was.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    start_len: usize,
    max_len: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader over `buf`. Strings longer than `max_len` bytes are
    /// rejected with [`DecodeError::TooLong`].
    #[must_use]
    pub fn new(buf: &'a [u8], max_len: usize) -> Self {
        Self {
            buf,
            start_len: buf.len(),
            max_len,
        }
    }

    /// Number of bytes consumed so far.
    #[must_use]
    pub fn consumed(&self) -> usize {
        self.start_len - self.buf.len()
    }

    /// The bytes not consumed yet.
    #[must_use]
    pub fn rest(&self) -> &'a [u8] {
        self.buf
    }

    /// Consumes exactly `n` bytes.
    ///
    /// # Errors
    /// [`DecodeError::Incomplete`] if fewer than `n` bytes are left.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() < n {
            return Err(DecodeError::Incomplete);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    /// Consumes one byte.
    ///
    /// # Errors
    /// [`DecodeError::Incomplete`] at the end of the buffer.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    /// Consumes an SSH boolean. As RFC 4251 §5 requires, any non-zero byte
    /// counts as true.
    ///
    /// # Errors
    /// [`DecodeError::Incomplete`] at the end of the buffer.
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        Ok(self.u8()? != 0)
    }

    /// Consumes a QUIC varint. Non-minimal encodings are accepted, as RFC
    /// 9000 allows.
    ///
    /// # Errors
    /// [`DecodeError::Incomplete`] if the varint is cut off.
    pub fn varint(&mut self) -> Result<u64, DecodeError> {
        let first = *self.buf.first().ok_or(DecodeError::Incomplete)?;
        let len = 1usize << (first >> 6);
        let bytes = self.take(len)?;
        let mut v = u64::from(bytes[0] & 0x3f);
        for &b in &bytes[1..] {
            v = (v << 8) | u64::from(b);
        }
        Ok(v)
    }

    /// Consumes a varint that must be a TCP or UDP port number.
    ///
    /// # Errors
    /// [`DecodeError::Incomplete`] if the varint is cut off,
    /// [`DecodeError::OutOfRange`] if it exceeds 65535.
    pub fn port(&mut self) -> Result<u16, DecodeError> {
        let value = self.varint()?;
        u16::try_from(value).map_err(|_| DecodeError::OutOfRange {
            what: "port",
            value,
        })
    }

    /// Consumes a string and returns its bytes without copying. `what`
    /// names the field in error messages.
    ///
    /// # Errors
    /// [`DecodeError::TooLong`] if the announced length exceeds the limit,
    /// [`DecodeError::Incomplete`] if the bytes haven't all arrived.
    pub fn string_bytes(&mut self, what: &'static str) -> Result<&'a [u8], DecodeError> {
        let len = self.varint()?;
        // Check the limit *before* waiting for the bytes, so a peer can't make
        // us buffer gigabytes just by announcing a huge length.
        let n = usize::try_from(len)
            .ok()
            .filter(|&n| n <= self.max_len)
            .ok_or(DecodeError::TooLong {
                what,
                len,
                max: self.max_len,
            })?;
        self.take(n)
    }

    /// Consumes a string as an owned, binary-safe [`Bytes`].
    ///
    /// # Errors
    /// As for [`Reader::string_bytes`].
    pub fn bytes(&mut self, what: &'static str) -> Result<Bytes, DecodeError> {
        Ok(Bytes::copy_from_slice(self.string_bytes(what)?))
    }

    /// Consumes a string that must be valid UTF-8.
    ///
    /// # Errors
    /// As for [`Reader::string_bytes`], plus [`DecodeError::InvalidUtf8`].
    pub fn string(&mut self, what: &'static str) -> Result<String, DecodeError> {
        let raw = self.string_bytes(what)?;
        let s = std::str::from_utf8(raw).map_err(|_| DecodeError::InvalidUtf8(what))?;
        Ok(s.to_owned())
    }

    /// Consumes a varint-length-prefixed block and returns a reader limited
    /// to it, for length-delimited messages.
    ///
    /// Inside the block, running out of bytes means the block is malformed,
    /// not that more data is coming. The caller has to turn `Incomplete`
    /// from the sub-reader into [`DecodeError::Malformed`];
    /// [`DecodeError::within_block`] does that.
    ///
    /// # Errors
    /// As for [`Reader::string_bytes`].
    pub fn block(&mut self, what: &'static str) -> Result<Reader<'a>, DecodeError> {
        let body = self.string_bytes(what)?;
        Ok(Reader::new(body, self.max_len))
    }
}

impl DecodeError {
    /// Turns `Incomplete` into `Malformed(what)`, for errors from a
    /// sub-reader made by [`Reader::block`].
    #[must_use]
    pub fn within_block(self, what: &'static str) -> Self {
        match self {
            DecodeError::Incomplete => DecodeError::Malformed(what),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn encode_varint(v: u64) -> Vec<u8> {
        let mut buf = BytesMut::new();
        put_varint(&mut buf, v).unwrap();
        buf.to_vec()
    }

    fn decode_varint(bytes: &[u8]) -> Result<u64, DecodeError> {
        Reader::new(bytes, 1024).varint()
    }

    /// The sample encodings from RFC 9000, Appendix A.1.
    #[test]
    fn varint_rfc9000_vectors() {
        let vectors: &[(&[u8], u64)] = &[
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
        ];
        for &(bytes, value) in vectors {
            assert_eq!(decode_varint(bytes), Ok(value));
            assert_eq!(encode_varint(value), bytes);
        }
        // RFC 9000 also points out that 0x40 0x25 is a valid, non-minimal 37.
        assert_eq!(decode_varint(&[0x40, 0x25]), Ok(37));
    }

    #[test]
    fn varint_length_boundaries() {
        for (v, len) in [
            (0, 1),
            (63, 1),
            (64, 2),
            (16_383, 2),
            (16_384, 4),
            (1_073_741_823, 4),
            (1_073_741_824, 8),
            (VARINT_MAX, 8),
        ] {
            let bytes = encode_varint(v);
            assert_eq!(bytes.len(), len, "length of {v}");
            assert_eq!(varint_len(v), len);
            assert_eq!(decode_varint(&bytes), Ok(v));
        }
    }

    #[test]
    fn varint_out_of_range() {
        let mut buf = BytesMut::new();
        assert_eq!(
            put_varint(&mut buf, VARINT_MAX + 1),
            Err(EncodeError::VarIntOutOfRange(VARINT_MAX + 1))
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn varint_incomplete() {
        assert_eq!(decode_varint(&[]), Err(DecodeError::Incomplete));
        assert_eq!(
            decode_varint(&[0x9d, 0x7f, 0x3e]),
            Err(DecodeError::Incomplete)
        );
    }

    #[test]
    fn string_limit_is_checked_before_the_data_arrives() {
        // Announces a 1 MiB string but carries none of it: a decoder that only
        // waited for more data would buffer the whole megabyte first.
        let mut buf = BytesMut::new();
        put_varint(&mut buf, 1 << 20).unwrap();
        let err = Reader::new(&buf, 1000).string_bytes("data").unwrap_err();
        assert_eq!(
            err,
            DecodeError::TooLong {
                what: "data",
                len: 1 << 20,
                max: 1000
            }
        );
    }

    #[test]
    fn string_roundtrip_and_utf8() {
        let mut buf = BytesMut::new();
        put_string(&mut buf, "héllo").unwrap();
        put_string(&mut buf, [0xff, 0xfe]).unwrap();
        assert_eq!(buf.len(), string_len("héllo") + string_len([0xff, 0xfe]));

        let mut r = Reader::new(&buf, 1024);
        assert_eq!(r.string("greeting").unwrap(), "héllo");
        assert_eq!(r.rest(), [2, 0xff, 0xfe]);
        assert_eq!(r.string("blob"), Err(DecodeError::InvalidUtf8("blob")));
    }

    #[test]
    fn bool_accepts_any_nonzero() {
        let mut r = Reader::new(&[0, 1, 7], 16);
        assert_eq!(r.bool(), Ok(false));
        assert_eq!(r.bool(), Ok(true));
        assert_eq!(r.bool(), Ok(true));
        assert_eq!(r.bool(), Err(DecodeError::Incomplete));
    }
}
