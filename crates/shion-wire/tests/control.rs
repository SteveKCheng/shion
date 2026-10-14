//! Control stream messages: round trips, and the forward-compatibility
//! rules that come from length delimiting.

use bytes::{Bytes, BytesMut};
use shion_wire::control::{PROTOCOL_VERSION, attr, control_type};
use shion_wire::wire::{put_string, put_varint};
use shion_wire::{ControlMessage, ConvAccept, ConvOpen, DecodeError, Reader, Wire};

const MAX_LEN: usize = 1 << 20;

fn roundtrip(m: &ControlMessage) {
    let mut buf = BytesMut::new();
    m.encode(&mut buf).unwrap();
    let mut r = Reader::new(&buf, MAX_LEN);
    assert_eq!(&ControlMessage::decode(&mut r).unwrap(), m);
    assert_eq!(r.consumed(), buf.len());
    for n in 0..buf.len() {
        let err = ControlMessage::decode(&mut Reader::new(&buf[..n], MAX_LEN)).unwrap_err();
        assert_eq!(err, DecodeError::Incomplete, "prefix of {n} bytes");
    }
}

/// Frames `body` as a control message of type `msg_type`.
fn frame(msg_type: u64, body: &[u8]) -> BytesMut {
    let mut buf = BytesMut::new();
    put_varint(&mut buf, msg_type).unwrap();
    put_string(&mut buf, body).unwrap();
    buf
}

fn decode(bytes: &[u8]) -> Result<ControlMessage, DecodeError> {
    ControlMessage::decode(&mut Reader::new(bytes, MAX_LEN))
}

fn conv_open() -> ConvOpen {
    ConvOpen {
        version: PROTOCOL_VERSION,
        conversation_id: 7,
        attributes: vec![
            (attr::USER.into(), "agent-7".into()),
            (attr::CLIENT_ADDRESS.into(), "192.0.2.5 51334".into()),
            (attr::AUTH_METHOD.into(), "publickey".into()),
        ],
    }
}

#[test]
fn roundtrips() {
    roundtrip(&ControlMessage::ConvOpen(conv_open()));
    roundtrip(&ControlMessage::ConvAccept(ConvAccept {
        version: PROTOCOL_VERSION,
        channel_types: vec!["session".into()],
        request_types: vec!["pty-req".into(), "shell".into(), "exec".into()],
    }));
    roundtrip(&ControlMessage::ConvReject {
        reason: "user mismatch".into(),
    });
    roundtrip(&ControlMessage::GlobalRequest {
        name: "tcpip-forward".into(),
        want_reply: true,
        body: Bytes::from_static(b"\x00\x00\x1f\x90"),
    });
    roundtrip(&ControlMessage::RequestSuccess { body: Bytes::new() });
    roundtrip(&ControlMessage::RequestFailure);
}

#[test]
fn attribute_lookup() {
    let open = conv_open();
    assert_eq!(open.attribute(attr::USER), Some("agent-7"));
    assert_eq!(open.attribute(attr::AUTH_KEY), None);
}

#[test]
fn unknown_types_are_skipped_not_fatal() {
    let mut stream = frame(250, b"from the future");
    stream.extend_from_slice(&frame(control_type::REQUEST_FAILURE, b""));

    let mut r = Reader::new(&stream, MAX_LEN);
    assert_eq!(
        ControlMessage::decode(&mut r).unwrap(),
        ControlMessage::Unknown {
            msg_type: 250,
            body: Bytes::from_static(b"from the future")
        }
    );
    assert_eq!(
        ControlMessage::decode(&mut r).unwrap(),
        ControlMessage::RequestFailure
    );
}

#[test]
fn trailing_fields_are_ignored() {
    // A CONV_REJECT from a newer peer with an extra field appended.
    let mut body = BytesMut::new();
    put_string(&mut body, "nope").unwrap();
    put_varint(&mut body, 42).unwrap();
    assert_eq!(
        decode(&frame(control_type::CONV_REJECT, &body)).unwrap(),
        ControlMessage::ConvReject {
            reason: "nope".into()
        }
    );
}

#[test]
fn short_body_is_malformed_not_incomplete() {
    // Claims 3 attributes but carries none. The body is complete, so waiting
    // for more bytes would hang forever: it must be reported as malformed.
    let mut body = BytesMut::new();
    put_varint(&mut body, PROTOCOL_VERSION).unwrap();
    put_varint(&mut body, 1).unwrap();
    put_varint(&mut body, 3).unwrap();
    assert_eq!(
        decode(&frame(control_type::CONV_OPEN, &body)).unwrap_err(),
        DecodeError::Malformed("control message")
    );
}

#[test]
fn huge_attribute_count_does_not_preallocate() {
    // 2^62 − 1 attributes announced in a 9-byte body: must fail quickly
    // rather than try to reserve memory for them.
    let mut body = BytesMut::new();
    put_varint(&mut body, PROTOCOL_VERSION).unwrap();
    put_varint(&mut body, 1).unwrap();
    put_varint(&mut body, shion_wire::wire::VARINT_MAX).unwrap();
    assert!(matches!(
        decode(&frame(control_type::CONV_OPEN, &body)),
        Err(DecodeError::Malformed(_))
    ));
}
