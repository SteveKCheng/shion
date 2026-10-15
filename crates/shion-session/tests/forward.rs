//! M4: TCP port forwarding.

mod common;

use std::net::SocketAddr;

use bytes::Bytes;
use common::{Channel, Control, Harness, within};
use futures_util::{SinkExt, StreamExt};
use shion_wire::control::ForwardAddress;
use shion_wire::header::TcpipEndpoints;
use shion_wire::message::open_failure;
use shion_wire::{ChannelHeader, ChannelKind, ControlMessage, GlobalRequest, Message, Reader};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Opens a `direct-tcpip` channel to `host` and `port`; returns the
/// channel and the session's first reply.
async fn direct(harness: &Harness, host: &str, port: u16) -> (Channel, Message) {
    harness
        .try_channel(ChannelHeader {
            conversation_id: 1,
            kind: ChannelKind::DirectTcpip(TcpipEndpoints {
                host: host.into(),
                port,
                originator_address: "192.0.2.5".into(),
                originator_port: 51334,
            }),
            max_packet_size: 32_768,
        })
        .await
}

/// Sends a global request and returns the reply.
async fn global_request(control: &mut Control, request: GlobalRequest) -> ControlMessage {
    control
        .send(ControlMessage::GlobalRequest {
            want_reply: true,
            request,
        })
        .await
        .unwrap();
    control
        .next()
        .await
        .expect("control stream closed")
        .unwrap()
}

/// Asks for a forward from `address`, port 0, and returns the port.
async fn tcpip_forward(control: &mut Control, address: &str) -> u16 {
    let request = GlobalRequest::TcpipForward(ForwardAddress {
        address: address.into(),
        port: 0,
    });
    match global_request(control, request).await {
        ControlMessage::RequestSuccess { body } => {
            u16::try_from(Reader::new(&body, 16).varint().unwrap()).unwrap()
        }
        other => panic!("tcpip-forward failed: {other:?}"),
    }
}

/// Reads data messages until the channel ends.
async fn read_to_end(channel: &mut Channel) -> String {
    let mut seen = String::new();
    while let Some(msg) = channel.next().await {
        match msg.unwrap() {
            Message::Data(data) => seen.push_str(std::str::from_utf8(&data).unwrap()),
            other => panic!("unexpected message {other:?}"),
        }
    }
    seen
}

/// A TCP server on 127.0.0.1 that answers one connection.
async fn server() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

#[tokio::test]
async fn direct_tcpip_relays_and_half_closes() {
    within(async {
        let (listener, port) = server().await;
        // Reads until EOF, then answers and closes: only works if our FIN
        // turns into a TCP half-close and not a full close.
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let mut request = String::new();
            tcp.read_to_string(&mut request).await.unwrap();
            tcp.write_all(format!("got {request}").as_bytes())
                .await
                .unwrap();
        });

        let harness = Harness::start_with(&["--permit-open", "localhost:*"]);
        let _control = harness.conversation(1).await;
        // `localhost` is resolved by the session process.
        let (mut channel, reply) = direct(&harness, "localhost", port).await;
        assert!(
            matches!(reply, Message::OpenConfirmation { .. }),
            "{reply:?}"
        );

        channel
            .send(Message::Data(Bytes::from_static(b"hello")))
            .await
            .unwrap();
        channel.close().await.unwrap();
        assert_eq!(read_to_end(&mut channel).await, "got hello");
        server.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn direct_tcpip_server_may_close_first() {
    within(async {
        let (listener, port) = server().await;
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            tcp.write_all(b"banner").await.unwrap();
            tcp.shutdown().await.unwrap();
            // Still reading after our own half-close.
            let mut rest = String::new();
            tcp.read_to_string(&mut rest).await.unwrap();
            rest
        });

        let harness = Harness::start_with(&["--permit-open", "127.0.0.1:*"]);
        let _control = harness.conversation(1).await;
        let (mut channel, reply) = direct(&harness, "127.0.0.1", port).await;
        assert!(
            matches!(reply, Message::OpenConfirmation { .. }),
            "{reply:?}"
        );

        // The session's FIN arrives while our side is still open.
        assert_eq!(read_to_end(&mut channel).await, "banner");
        channel
            .send(Message::Data(Bytes::from_static(b"bye")))
            .await
            .unwrap();
        channel.close().await.unwrap();
        assert_eq!(server.await.unwrap(), "bye");
    })
    .await;
}

#[tokio::test]
async fn direct_tcpip_needs_permission() {
    within(async {
        let (_listener, port) = server().await;
        let harness = Harness::start_with(&["--permit-open", "localhost:1"]);
        let _control = harness.conversation(1).await;
        for host in ["127.0.0.1", "localhost"] {
            let (_, reply) = direct(&harness, host, port).await;
            assert!(
                matches!(
                    reply,
                    Message::OpenFailure {
                        reason: open_failure::ADMINISTRATIVELY_PROHIBITED,
                        ..
                    }
                ),
                "{host}: {reply:?}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn direct_tcpip_reports_connection_failure() {
    within(async {
        let port = server().await.1; // closed again right away
        let harness = Harness::start_with(&["--permit-open", "*:*"]);
        let _control = harness.conversation(1).await;
        let (_, reply) = direct(&harness, "127.0.0.1", port).await;
        assert!(
            matches!(
                reply,
                Message::OpenFailure {
                    reason: open_failure::CONNECT_FAILED,
                    ..
                }
            ),
            "{reply:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn tcpip_forward_opens_forwarded_channels() {
    within(async {
        let mut harness = Harness::start_with(&["--permit-listen", "localhost:*"]);
        let mut control = harness.conversation(1).await;
        let port = tcpip_forward(&mut control, "localhost").await;

        let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let local: SocketAddr = tcp.local_addr().unwrap();
        let (header, mut channel) = harness.accept_channel().await;
        assert_eq!(header.conversation_id, 1);
        assert_eq!(
            header.kind,
            ChannelKind::ForwardedTcpip(TcpipEndpoints {
                host: "localhost".into(),
                port,
                originator_address: "127.0.0.1".into(),
                originator_port: local.port(),
            })
        );
        channel
            .send(Message::OpenConfirmation {
                max_packet_size: 32_768,
            })
            .await
            .unwrap();

        tcp.write_all(b"ping").await.unwrap();
        match channel.next().await.unwrap().unwrap() {
            Message::Data(data) => assert_eq!(&data[..], b"ping"),
            other => panic!("unexpected message {other:?}"),
        }

        // Cancelling stops new connections, but not this one.
        let cancel = GlobalRequest::CancelTcpipForward(ForwardAddress {
            address: "localhost".into(),
            port,
        });
        assert!(matches!(
            global_request(&mut control, cancel.clone()).await,
            ControlMessage::RequestSuccess { .. }
        ));
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
        assert_eq!(
            global_request(&mut control, cancel).await,
            ControlMessage::RequestFailure
        );

        channel
            .send(Message::Data(Bytes::from_static(b"pong")))
            .await
            .unwrap();
        channel.close().await.unwrap();
        let mut reply = String::new();
        tcp.read_to_string(&mut reply).await.unwrap();
        assert_eq!(reply, "pong");
    })
    .await;
}

#[tokio::test]
async fn refused_forwarded_channel_closes_the_connection() {
    within(async {
        let mut harness = Harness::start_with(&["--permit-listen", "localhost:*"]);
        let mut control = harness.conversation(1).await;
        let port = tcpip_forward(&mut control, "localhost").await;

        let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (_, mut channel) = harness.accept_channel().await;
        channel
            .send(Message::OpenFailure {
                reason: open_failure::CONNECT_FAILED,
                description: "nothing there".into(),
                language: String::new(),
            })
            .await
            .unwrap();
        let mut rest = Vec::new();
        tcp.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"");
    })
    .await;
}

#[tokio::test]
async fn tcpip_forward_needs_permission() {
    within(async {
        let harness = Harness::start_with(&["--permit-listen", "localhost:8080"]);
        let mut control = harness.conversation(1).await;
        // Another address, another port, and any port (0) aren't permitted.
        for (address, port) in [("", 8080), ("localhost", 8081), ("localhost", 0)] {
            let request = GlobalRequest::TcpipForward(ForwardAddress {
                address: address.into(),
                port,
            });
            assert_eq!(
                global_request(&mut control, request).await,
                ControlMessage::RequestFailure,
                "{address:?}:{port}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn ending_the_conversation_stops_forwarding() {
    within(async {
        let (listener, server_port) = server().await;
        let mut harness = Harness::start_with(&[
            "--permit-open",
            "127.0.0.1:*",
            "--permit-listen",
            "localhost:*",
        ]);
        let mut control = harness.conversation(1).await;

        // A direct-tcpip connection...
        let (mut direct_channel, reply) = direct(&harness, "127.0.0.1", server_port).await;
        assert!(
            matches!(reply, Message::OpenConfirmation { .. }),
            "{reply:?}"
        );
        let (mut server_side, _) = listener.accept().await.unwrap();

        // ...and a forwarded one.
        let port = tcpip_forward(&mut control, "localhost").await;
        let mut client_side = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (_, mut forwarded_channel) = harness.accept_channel().await;
        forwarded_channel
            .send(Message::OpenConfirmation {
                max_packet_size: 32_768,
            })
            .await
            .unwrap();

        control.close().await.unwrap();

        // Both TCP connections are closed, and so are both channels.
        let mut rest = Vec::new();
        server_side.read_to_end(&mut rest).await.unwrap();
        client_side.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"");
        assert_eq!(read_to_end(&mut direct_channel).await, "");
        assert_eq!(read_to_end(&mut forwarded_channel).await, "");
        // And nothing listens any more.
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    })
    .await;
}
