//! Channel header and message encodings, checked against byte sequences
//! built the same way as in sshoq's `message/message_test.go`: field by
//! field with the primitive encoders, independently of our message code.

use bytes::{Bytes, BytesMut};
use shion_wire::message::{
    EXTENDED_DATA_STDERR, ExitSignal, PtyRequest, WindowSize, X11Request, msg,
};
use shion_wire::wire::{put_bool, put_string, put_varint};
use shion_wire::{ChannelHeader, ChannelKind, ChannelRequest, DecodeError, Message, Reader, Wire};

const MAX_LEN: usize = 1 << 20;

/// Builds expected bytes field by field.
#[derive(Default)]
struct Expect(BytesMut);

impl Expect {
    fn varint(mut self, v: u64) -> Self {
        put_varint(&mut self.0, v).unwrap();
        self
    }
    fn string(mut self, s: impl AsRef<[u8]>) -> Self {
        put_string(&mut self.0, s).unwrap();
        self
    }
    fn bool(mut self, b: bool) -> Self {
        put_bool(&mut self.0, b);
        self
    }
    fn request(self, name: &str, want_reply: bool) -> Self {
        self.varint(msg::CHANNEL_REQUEST)
            .string(name)
            .bool(want_reply)
    }
}

/// Checks that `value` encodes to exactly `expected`, that `expected`
/// decodes back to `value` consuming every byte, and that every strict
/// prefix of `expected` decodes as `Incomplete` (what streaming relies on).
fn check<T: Wire + PartialEq + std::fmt::Debug>(value: &T, expected: &Expect) {
    let expected = &expected.0[..];

    let mut encoded = BytesMut::new();
    value.encode(&mut encoded).unwrap();
    assert_eq!(&encoded[..], expected, "encoding of {value:?}");

    let mut r = Reader::new(expected, MAX_LEN);
    assert_eq!(&T::decode(&mut r).unwrap(), value);
    assert_eq!(
        r.consumed(),
        expected.len(),
        "trailing bytes after {value:?}"
    );

    for n in 0..expected.len() {
        let result = T::decode(&mut Reader::new(&expected[..n], MAX_LEN));
        assert_eq!(
            result.unwrap_err(),
            DecodeError::Incomplete,
            "prefix of {n} bytes of {value:?}"
        );
    }
}

fn request(want_reply: bool, request: ChannelRequest) -> Message {
    Message::Request {
        want_reply,
        request,
    }
}

#[test]
fn channel_header() {
    let header = ChannelHeader {
        conversation_id: 4,
        kind: ChannelKind::Session,
        max_packet_size: 30_000,
    };
    check(
        &header,
        &Expect::default()
            .varint(0xaf36_27e6)
            .varint(4)
            .string("session")
            .varint(30_000),
    );
}

#[test]
fn channel_header_rejects_wrong_signal() {
    let bytes = Expect::default()
        .varint(0x1234)
        .varint(4)
        .string("session")
        .varint(1)
        .0;
    let err = ChannelHeader::decode(&mut Reader::new(&bytes, MAX_LEN)).unwrap_err();
    assert_eq!(err, DecodeError::BadChannelSignal(0x1234));
}

#[test]
fn open_confirmation_and_failure() {
    check(
        &Message::OpenConfirmation {
            max_packet_size: 32_768,
        },
        &Expect::default().varint(91).varint(32_768),
    );
    check(
        &Message::OpenFailure {
            reason: 3,
            description: "unknown channel type".into(),
            language: String::new(),
        },
        &Expect::default()
            .varint(92)
            .varint(3)
            .string("unknown channel type")
            .string(""),
    );
}

#[test]
fn data_messages() {
    check(
        &Message::Data(Bytes::from_static(b"hello, world!")),
        &Expect::default().varint(94).string("hello, world!"),
    );
    check(
        &Message::Data(Bytes::new()),
        &Expect::default().varint(94).string(""),
    );

    // Large enough to need a 4-byte length varint; sshoq uses 5 MB here.
    let big: Bytes = (0..100_000u32).map(|i| i.to_le_bytes()[0]).collect();
    check(
        &Message::Data(big.clone()),
        &Expect::default().varint(94).string(&big),
    );

    // sshoq tests extended data with type 10_000_000 to exercise varints.
    check(
        &Message::ExtendedData {
            data_type: 10_000_000,
            data: Bytes::from_static(b"hello, world!"),
        },
        &Expect::default()
            .varint(95)
            .varint(10_000_000)
            .string("hello, world!"),
    );
    check(
        &Message::ExtendedData {
            data_type: EXTENDED_DATA_STDERR,
            data: Bytes::from_static(b"oops\n"),
        },
        &Expect::default().varint(95).varint(1).string("oops\n"),
    );
}

#[test]
fn success_and_failure() {
    check(&Message::Success, &Expect::default().varint(99));
    check(&Message::Failure, &Expect::default().varint(100));
}

#[test]
fn pty_req() {
    // Window sizes up to 2^60, like sshoq's randomized test, to exercise
    // 8-byte varints.
    let size = WindowSize {
        cols: 80,
        rows: 24,
        width_px: 1 << 40,
        height_px: (1 << 60) - 1,
    };
    let modes = Bytes::from_static(&[53, 0, 0, 0, 1, 0]); // ECHO=1, end
    check(
        &request(
            true,
            ChannelRequest::PtyReq(PtyRequest {
                term: "xterm-256color".into(),
                size,
                modes: modes.clone(),
            }),
        ),
        &Expect::default()
            .request("pty-req", true)
            .string("xterm-256color")
            .varint(80)
            .varint(24)
            .varint(1 << 40)
            .varint((1 << 60) - 1)
            .string(&modes),
    );
}

#[test]
fn x11_req() {
    check(
        &request(
            false,
            ChannelRequest::X11Req(X11Request {
                single_connection: true,
                auth_protocol: "MIT-MAGIC-COOKIE-1".into(),
                auth_cookie: "0123abcd".into(),
                screen: 0,
            }),
        ),
        &Expect::default()
            .request("x11-req", false)
            .bool(true)
            .string("MIT-MAGIC-COOKIE-1")
            .string("0123abcd")
            .varint(0),
    );
}

#[test]
fn session_start_requests() {
    check(
        &request(true, ChannelRequest::Shell),
        &Expect::default().request("shell", true),
    );
    check(
        &request(
            true,
            ChannelRequest::Exec {
                command: Bytes::from_static(b"ls -l"),
            },
        ),
        &Expect::default().request("exec", true).string("ls -l"),
    );
    check(
        &request(
            true,
            ChannelRequest::Subsystem {
                name: "sftp".into(),
            },
        ),
        &Expect::default().request("subsystem", true).string("sftp"),
    );
    check(
        &request(
            false,
            ChannelRequest::Env {
                name: Bytes::from_static(b"LANG"),
                value: Bytes::from_static(b"C.UTF-8"),
            },
        ),
        &Expect::default()
            .request("env", false)
            .string("LANG")
            .string("C.UTF-8"),
    );
}

#[test]
fn exec_command_may_be_non_utf8() {
    let command = Bytes::from_static(b"cat caf\xe9.txt"); // Latin-1 file name
    check(
        &request(
            false,
            ChannelRequest::Exec {
                command: command.clone(),
            },
        ),
        &Expect::default().request("exec", false).string(&command),
    );
}

#[test]
fn running_session_requests() {
    let size = WindowSize {
        cols: 132,
        rows: 43,
        width_px: 0,
        height_px: 0,
    };
    check(
        &request(false, ChannelRequest::WindowChange(size)),
        &Expect::default()
            .request("window-change", false)
            .varint(132)
            .varint(43)
            .varint(0)
            .varint(0),
    );
    check(
        &request(false, ChannelRequest::Signal { name: "INT".into() }),
        &Expect::default().request("signal", false).string("INT"),
    );
    check(
        &request(false, ChannelRequest::ExitStatus { status: 127 }),
        &Expect::default().request("exit-status", false).varint(127),
    );
    check(
        &request(
            false,
            ChannelRequest::ExitSignal(ExitSignal {
                signal: "SEGV".into(),
                core_dumped: true,
                description: "Segmentation fault".into(),
                language: String::new(),
            }),
        ),
        &Expect::default()
            .request("exit-signal", false)
            .string("SEGV")
            .bool(true)
            .string("Segmentation fault")
            .string(""),
    );
}

#[test]
fn unknown_request_is_an_error() {
    // sshoq's own "sftp" request, which we deliberately don't implement.
    let bytes = Expect::default()
        .request("sftp", true)
        .varint(0)
        .string("/tmp")
        .0;
    let err = Message::decode(&mut Reader::new(&bytes, MAX_LEN)).unwrap_err();
    assert_eq!(err, DecodeError::UnknownRequest("sftp".into()));
}

#[test]
fn unknown_message_is_an_error() {
    // WINDOW_ADJUST exists in SSH2 but not in SSH3.
    let bytes = Expect::default().varint(93).varint(1024).0;
    let err = Message::decode(&mut Reader::new(&bytes, MAX_LEN)).unwrap_err();
    assert_eq!(err, DecodeError::UnknownMessage(93));
}

#[test]
fn oversized_data_is_rejected_early() {
    let bytes = Expect::default().varint(94).varint(10_000).0;
    let err = Message::decode(&mut Reader::new(&bytes, 4096)).unwrap_err();
    assert_eq!(
        err,
        DecodeError::TooLong {
            what: "data",
            len: 10_000,
            max: 4096
        }
    );
}
