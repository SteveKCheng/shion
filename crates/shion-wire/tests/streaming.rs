//! The codecs on a real async byte stream, delivered one byte at a time:
//! the worst case for a decoder that has to cope with partial messages.

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use shion_wire::codec::{HeaderCodec, MessageCodec};
use shion_wire::{ChannelHeader, ChannelKind, ChannelRequest, CodecError, Message};
use tokio_util::codec::{FramedRead, FramedWrite};

fn header() -> ChannelHeader {
    ChannelHeader {
        conversation_id: 1,
        kind: ChannelKind::Session,
        max_packet_size: 32_768,
    }
}

fn messages() -> Vec<Message> {
    vec![
        Message::Request {
            want_reply: true,
            request: ChannelRequest::Exec {
                command: Bytes::from_static(b"echo hi"),
            },
        },
        Message::Data(Bytes::from(vec![b'x'; 5000])),
        Message::Request {
            want_reply: false,
            request: ChannelRequest::ExitStatus { status: 0 },
        },
    ]
}

#[tokio::test]
async fn header_then_messages_one_byte_at_a_time() {
    // A duplex pipe with a 1-byte buffer: every read returns a single byte.
    let (client, server) = tokio::io::duplex(1);

    let writer = tokio::spawn(async move {
        let mut framed = FramedWrite::new(client, HeaderCodec::default());
        framed.send(header()).await.unwrap();
        // Switch codecs on the same stream; any buffered bytes carry over.
        let mut framed = framed.map_encoder(|_| MessageCodec::default());
        for m in messages() {
            framed.send(m).await.unwrap();
        }
        // Dropping `framed` closes the pipe, which the reader sees as EOF.
    });

    let mut framed = FramedRead::new(server, HeaderCodec::default());
    assert_eq!(framed.next().await.unwrap().unwrap(), header());

    let mut framed = framed.map_decoder(|_| MessageCodec::default());
    let mut received = Vec::new();
    while let Some(m) = framed.next().await {
        received.push(m.unwrap());
    }
    assert_eq!(received, messages());
    writer.await.unwrap();
}

#[tokio::test]
async fn eof_mid_message_is_an_error() {
    // A data message announcing 10 bytes, but the stream ends after 3.
    // (Type 94 is above 63, so it takes a 2-byte varint: 0x40 0x5e.)
    let bytes: &[u8] = &[0x40, 94, 10, b'a', b'b', b'c'];
    let mut framed = FramedRead::new(bytes, MessageCodec::default());
    let err = framed.next().await.unwrap().unwrap_err();
    assert!(
        matches!(err, CodecError::Truncated { buffered: 6 }),
        "{err:?}"
    );
}
