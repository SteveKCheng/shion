//! TCP port forwarding (design §5.5).
//!
//! - `direct-tcpip` channels (`ssh -L`): we connect to the requested host
//!   and port and relay.
//! - `tcpip-forward` global requests (`ssh -R`): we listen, and open a
//!   `forwarded-tcpip` channel for each connection that arrives.
//!
//! All of it happens in the session process's network namespace, i.e. the
//! sandbox's, and only as far as `--permit-open` and `--permit-listen`
//! allow. Like processes, forwarding doesn't outlive its conversation:
//! listeners close and connections are cut when it ends.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use shion_wire::codec::{HeaderCodec, MessageCodec};
use shion_wire::control::ForwardAddress;
use shion_wire::header::TcpipEndpoints;
use shion_wire::message::open_failure;
use shion_wire::{ChannelHeader, ChannelKind, CodecError, Message};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::codec::Framed;
use tracing::{debug, info, warn};

use crate::channel::{self, Incoming, OUR_MAX_PACKET, Outgoing};
use crate::server::{Connector, Stream};
use crate::state::{Conversation, ServerState};

/// How long a `direct-tcpip` connection attempt may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Responds to a `direct-tcpip` request on a SSH channel, for
/// client-to-server port forwarding, a.k.a. "local forwarding".
///
/// This function makes the desired TCP connection (from this process, which is the server side)
/// to `target`, and then relays data bi-directionally over the SSH channel.
pub async fn direct(
    framed: Framed<Stream, MessageCodec>,
    header: ChannelHeader,
    target: TcpipEndpoints,
    state: Arc<ServerState>,
) -> Result<(), CodecError> {
    let (mut sink, incoming) = framed.split();
    let conversation = match channel::conversation_of(&header, &state) {
        Ok(conversation) => conversation,
        Err(description) => {
            return channel::refuse(
                sink,
                &header,
                open_failure::ADMINISTRATIVELY_PROHIBITED,
                description,
            )
            .await;
        }
    };

    // Destructuring borrows the fields under shorter names.
    let TcpipEndpoints { host, port, .. } = &target;
    if !state.settings.permits_open(host, *port) {
        let description = format!("forwarding to {host}:{port} is not permitted");
        return channel::refuse(
            sink,
            &header,
            open_failure::ADMINISTRATIVELY_PROHIBITED,
            description,
        )
        .await;
    }

    // Given a name, `connect` resolves it here, inside the sandbox, and
    // tries each address in turn.
    let connect = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), *port)));
    let result = tokio::select! {
        // `timeout` wraps the result in another `Result`, whose error means
        // the time ran out.
        result = connect => result.unwrap_or_else(|_elapsed| Err(io::ErrorKind::TimedOut.into())),
        () = conversation.ended() => return Ok(()),
    };
    let tcp = match result {
        Ok(tcp) => tcp,
        Err(e) => {
            let description = format!("cannot connect to {host}:{port}: {e}");
            return channel::refuse(sink, &header, open_failure::CONNECT_FAILED, description).await;
        }
    };
    debug!(
        conversation = conversation.id(),
        host,
        port,
        originator = target.originator_address,
        "direct-tcpip connected"
    );

    sink.send(Message::OpenConfirmation {
        max_packet_size: OUR_MAX_PACKET,
    })
    .await?;
    relay(
        sink,
        incoming,
        tcp,
        channel::packet_size(header.max_packet_size),
        &conversation,
    )
    .await
}

/// The sockets listening for one `tcpip-forward` request.
///
/// Dropping it stops listening; connections already being forwarded carry on.
///
/// Although the SSH remote-forwarding request only has one "bind address" string,
/// it may map to multiple applicable socket protocols, e.g. IPv4 and IPv6.  A
/// socket needs to be created for each protocol, and they all listen, so this type
/// needs to track all them in a `vec`.
#[derive(Debug)]
pub struct Listener {
    tasks: Vec<JoinHandle<()>>,
}

impl Listener {
    /// Stops listening, and returns once the sockets are closed.
    ///
    /// Aborting a task only asks the runtime to stop it: the task (and the
    /// socket it owns) is dropped some time later. Waiting for it means a
    /// client told "cancelled" can count on it.
    pub async fn close(mut self) {
        // `take` leaves an empty `Vec`, so `drop` has nothing left to do.
        for task in std::mem::take(&mut self.tasks) {
            task.abort();
            // An aborted task's result is a "cancelled" error; it only
            // matters that it has finished.
            let _ = task.await;
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Starts listening on the interface/port indicated by `request`, and forwards
/// each accepted connection over a `forwarded-tcpip` channel of `conversation`.
///
/// This function is called to respond to the `tcpip-forward` SSH request, i.e.
/// for server-to-client port forwarding, a.k.a. remote forwarding.  Note that
/// `tcpip-forward` is a "global request" that is not sent in a dedicated SSH channel.
/// A new SSH channel is opened only on each incoming connection to the listening port.
///
/// Returns the port number being listened to, which the system is to choose,
/// whenever `request` specifies 0.
pub async fn listen(
    request: &ForwardAddress,
    state: &ServerState,
    conversation: &Arc<Conversation>,
    connector: &Connector,
) -> io::Result<(u16, Listener)> {
    // Validate request
    let ForwardAddress { address, port } = request;
    if !state.settings.permits_listen(address, *port) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not permitted",
        ));
    }

    // Create a socket for each applicable socket protocol for which forwarding has been requested
    let mut port = *port;
    let mut listeners = Vec::new();
    let mut last_error = None;
    for addr in bind_addresses(address, port).await? {
        // With port 0, the first bind picks the port and the others reuse
        // it, so that one port number means the same forward everywhere.
        match TcpListener::bind(SocketAddr::new(addr.ip(), port)).await {
            Ok(listener) => {
                port = listener.local_addr()?.port();
                listeners.push(listener);
            }
            Err(e) => {
                debug!(error = %e, %addr, "cannot listen");
                last_error = Some(e);
            }
        }
    }
    // As in OpenSSH, it's enough for one of the addresses to work.
    if listeners.is_empty() {
        return Err(last_error.unwrap_or_else(|| io::Error::other("no address to listen on")));
    }

    info!(
        conversation = conversation.id(),
        address, port, "forwarding connections"
    );
    let bound = ForwardAddress {
        address: address.clone(),
        port,
    };

    // Spawn a listening task for each socket
    let tasks = listeners
        .into_iter()
        .map(|listener| {
            let task = accept_loop(
                listener,
                bound.clone(),
                Arc::clone(conversation),
                connector.clone(),
            );
            tokio::spawn(task)
        })
        .collect();
    Ok((port, Listener { tasks }))
}

/// List out the socket addresses needed to be bound for a string address given
/// by a `tcpip-forward` SSH request.
///
/// Follows RFC 4254 §7.1, and OpenSSH, for an address of `*`.
async fn bind_addresses(address: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    Ok(match address {
        // All addresses. On Linux, an IPv6 wildcard socket takes IPv4
        // connections too, and then binding the IPv4 wildcard fails, which
        // is fine; the IPv4 one is there for when IPv6 is unavailable.
        "" | "*" => vec![
            (Ipv6Addr::UNSPECIFIED, port).into(),
            (Ipv4Addr::UNSPECIFIED, port).into(),
        ],
        "localhost" => vec![
            (Ipv4Addr::LOCALHOST, port).into(),
            (Ipv6Addr::LOCALHOST, port).into(),
        ],
        // An address, or a name resolved inside the sandbox.
        host => tokio::net::lookup_host((host, port)).await?.collect(),
    })
}

/// Accepts connections until aborted, which happens when the forward is
/// cancelled or the conversation ends.
async fn accept_loop(
    listener: TcpListener,
    bound: ForwardAddress,
    conversation: Arc<Conversation>,
    connector: Connector,
) {
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                let task = forwarded(
                    tcp,
                    peer,
                    bound.clone(),
                    Arc::clone(&conversation),
                    connector.clone(),
                );
                tokio::spawn(async move {
                    if let Err(e) = task.await {
                        debug!(error = %e, "forwarded connection failed");
                    }
                });
            }
            Err(e) => {
                // Typically out of file descriptors: back off rather than
                // spin, and try again.
                warn!(error = %e, "accepting a forwarded connection failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Forwards one connection that arrived at a `tcpip-forward` listener, over
/// a `forwarded-tcpip` channel that we open.
///
/// This function is called after accepting the connection on the listening port.
/// It tells the SSH client of the incoming connection and confirms with the client
/// whether to take the connection.  If yes, data on the new TCP connection
/// will be relayed.
async fn forwarded(
    tcp: TcpStream,
    peer: SocketAddr,
    bound: ForwardAddress,
    conversation: Arc<Conversation>,
    connector: Connector,
) -> Result<(), CodecError> {
    let stream = Stream::from(connector.connect().map_err(io::Error::other)?);
    let header = ChannelHeader {
        conversation_id: conversation.id(),
        kind: ChannelKind::ForwardedTcpip(TcpipEndpoints {
            // As requested, so the client can tell which forward this is.
            host: bound.address,
            port: bound.port,
            // An IPv6 wildcard socket reports IPv4 peers as
            // `::ffff:a.b.c.d`; `to_canonical` turns them back into IPv4.
            originator_address: peer.ip().to_canonical().to_string(),
            originator_port: peer.port(),
        }),
        max_packet_size: OUR_MAX_PACKET,
    };
    let mut framed = Framed::new(stream, HeaderCodec::default());
    framed.send(header).await?;
    let mut framed = framed.map_codec(|_| MessageCodec::default());

    // The front-end answers once the client has accepted or refused.
    let reply = tokio::select! {
        msg = framed.next() => msg.transpose()?,
        () = conversation.ended() => return Ok(()),
    };
    let peer_max = match reply {
        Some(Message::OpenConfirmation { max_packet_size }) => max_packet_size,
        Some(Message::OpenFailure { description, .. }) => {
            debug!(%description, "forwarded-tcpip refused");
            return framed.close().await;
        }
        Some(other) => {
            warn!(?other, "unexpected reply to forwarded-tcpip");
            return Ok(());
        }
        None => return Ok(()),
    };

    let (sink, incoming) = framed.split();
    relay(
        sink,
        incoming,
        tcp,
        channel::packet_size(peer_max),
        &conversation,
    )
    .await
}

/// Relays between a forwarding channel and a TCP connection until both
/// directions are done, or the conversation ends.
///
/// Each direction ends on its own, as TCP's do: the channel's FIN becomes a
/// TCP half-close (`shutdown`), and TCP end-of-file becomes our FIN.
///
/// This function is used for local forwarding and remote forwarding.
async fn relay(
    sink: Outgoing,
    mut incoming: Incoming,
    tcp: TcpStream,
    packet_size: usize,
    conversation: &Conversation,
) -> Result<(), CodecError> {
    let (tcp_read, mut tcp_write) = tcp.into_split();
    let (out, out_rx) = mpsc::channel(32);
    let writer = tokio::spawn(channel::write_messages(sink, out_rx));

    // Replies to requests go through a weak sender. Unlike a strong one it
    // doesn't keep the writer going, so our FIN goes out as soon as the TCP
    // side reaches end-of-file, even while the peer is still sending.
    let replies = out.downgrade();
    let to_peer = async {
        channel::pump_output(tcp_read, out, None, packet_size).await;
        Ok::<_, CodecError>(())
    };

    let from_peer = async {
        let mut tcp_open = true;
        while let Some(msg) = incoming.next().await {
            match msg? {
                // Pump data from the peer into the TCP connection.
                //
                // This part is the only real consumer of the channel once forwarding
                // begins; as below, all requests are refused.  Practically speaking,
                // there will be no head-of-line blocking even without using a MPSC queue
                // to temporarily buffer data, if writing to the TCP connection stalls.
                //
                // So no MPSC queue is used here, unlike when we pump stdout/stderr
                // for child processes in channel.rs.
                Message::Data(data) => {
                    // After a failed write, keep reading and discarding:
                    // unread data would pile up in the smux buffers, which
                    // every channel shares (design §4.5).
                    if tcp_open {
                        if let Err(e) = tcp_write.write_all(&data).await {
                            debug!(error = %e, "forwarded connection closed");
                            tcp_open = false;
                        }
                    }
                }
                Message::Request {
                    want_reply,
                    request,
                } => {
                    debug!(
                        request = request.type_name(),
                        "refusing request on a forwarding channel"
                    );
                    if let Some(out) = replies.upgrade() {
                        channel::reply(&out, want_reply, false).await;
                    }
                }
                other => debug!(?other, "ignoring message"),
            }
        }
        // The peer's FIN.
        let _ = tcp_write.shutdown().await;
        Ok::<_, CodecError>(())
    };

    // `try_join!` waits for both, unless one fails first.
    let result = tokio::select! {
        result = async { tokio::try_join!(from_peer, to_peer) } => result.map(|((), ())| ()),
        () = conversation.ended() => {
            debug!(conversation = conversation.id(), "conversation ended, cutting forwarded connection");
            Ok(())
        }
    };
    // The futures above are gone now, and with them the TCP connection and
    // the last strong sender: the writer sends FIN and finishes.
    writer.await.map_err(io::Error::other)??;
    result
}
