//! `-L` and `-R` port forwarding, as `ssh` does it, but with only the
//! essentials: TCP, and failures reported as warnings.
//!
//! Every task here stops when the [`CancellationToken`] it was given is
//! cancelled, which `run` does once the session (or `-N`) is over.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use async_smux::MuxAcceptor;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use shion_wire::codec::{ControlCodec, HeaderCodec, MessageCodec, StreamStartCodec};
use shion_wire::control::ForwardAddress;
use shion_wire::header::TcpipEndpoints;
use shion_wire::message::open_failure;
use shion_wire::{
    ChannelHeader, ChannelKind, ControlMessage, GlobalRequest, Message, Reader, StreamStart,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::task::JoinHandle;
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;

use crate::{Channel, PACKET_SIZE, Stream, connect};

type Connector = async_smux::MuxConnector<UnixStream>;
type Control = Framed<Stream, ControlCodec>;

/// A `-L` or `-R` argument: `[BIND:]PORT:HOST:HOSTPORT`.
///
/// For `-L`, we listen on BIND:PORT and the session connects to
/// HOST:HOSTPORT. For `-R`, it's the other way around.
#[derive(Debug, Clone)]
pub struct Spec {
    bind: Option<String>,
    port: u16,
    host: String,
    host_port: u16,
}

impl Spec {
    /// Parses `[BIND:]PORT:HOST:HOSTPORT`. Addresses containing colons
    /// (IPv6) go in brackets, as with `ssh`: `-L '[::1]:8080:[::1]:80'`.
    pub fn parse(s: &str) -> Result<Self, String> {
        let fields = split_outside_brackets(s);
        let (bind, rest) = match fields.as_slice() {
            [port, host, host_port] => (None, [port, host, host_port]),
            [bind, port, host, host_port] => {
                (Some(unbracket(bind).to_owned()), [port, host, host_port])
            }
            _ => return Err(format!("expected [BIND:]PORT:HOST:HOSTPORT, got {s:?}")),
        };
        let [port, host, host_port] = rest;
        let parse_port = |p: &str| p.parse::<u16>().map_err(|e| format!("port {p:?}: {e}"));
        Ok(Self {
            bind,
            port: parse_port(port)?,
            host: unbracket(host).to_owned(),
            host_port: parse_port(host_port)?,
        })
    }

    /// The session's `--permit-open` argument that allows this `-L`.
    pub fn permit_open(&self) -> String {
        format!("{}:{}", bracket(&self.host), self.host_port)
    }

    /// The session's `--permit-listen` argument that allows this `-R`.
    pub fn permit_listen(&self) -> String {
        let port = if self.port == 0 {
            "*".to_owned()
        } else {
            self.port.to_string()
        };
        format!("{}:{port}", bracket(self.bind_address()))
    }

    /// Where to listen, `localhost` unless given, as `ssh` does.
    fn bind_address(&self) -> &str {
        self.bind.as_deref().unwrap_or("localhost")
    }
}

/// Splits on colons, except inside `[…]`.
fn split_outside_brackets(s: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut in_brackets = false;
    let mut start = 0;
    for (i, c) in s.char_indices() {
        match c {
            '[' => in_brackets = true,
            ']' => in_brackets = false,
            ':' if !in_brackets => {
                fields.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    fields.push(&s[start..]);
    fields
}

fn unbracket(s: &str) -> &str {
    s.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(s)
}

fn bracket(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// `-L`: listens locally, and forwards each connection over a
/// `direct-tcpip` channel. Returns the accept tasks.
pub async fn listen_local(
    spec: &Spec,
    connector: &Connector,
    stop: &CancellationToken,
) -> io::Result<Vec<JoinHandle<()>>> {
    let addrs: Vec<SocketAddr> = match spec.bind_address() {
        "localhost" => vec![
            (Ipv4Addr::LOCALHOST, spec.port).into(),
            (Ipv6Addr::LOCALHOST, spec.port).into(),
        ],
        "" | "*" => vec![
            (Ipv6Addr::UNSPECIFIED, spec.port).into(),
            (Ipv4Addr::UNSPECIFIED, spec.port).into(),
        ],
        host => tokio::net::lookup_host((host, spec.port)).await?.collect(),
    };
    let mut tasks = Vec::new();
    let mut last_error = None;
    for addr in addrs {
        // As in the session: it's enough for one address to work.
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                let task = accept_local(listener, spec.clone(), connector.clone(), stop.clone());
                tasks.push(tokio::spawn(task));
            }
            Err(e) => last_error = Some(e),
        }
    }
    match last_error {
        Some(e) if tasks.is_empty() => Err(e),
        _ => Ok(tasks),
    }
}

async fn accept_local(
    listener: TcpListener,
    spec: Spec,
    connector: Connector,
    stop: CancellationToken,
) {
    loop {
        let (tcp, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    eprintln!("shion-attach: accept: {e}");
                    continue;
                }
            },
            () = stop.cancelled() => return,
        };
        let header = ChannelHeader {
            conversation_id: crate::CONVERSATION_ID,
            kind: ChannelKind::DirectTcpip(TcpipEndpoints {
                host: spec.host.clone(),
                port: spec.host_port,
                originator_address: peer.ip().to_canonical().to_string(),
                originator_port: peer.port(),
            }),
            max_packet_size: PACKET_SIZE as u64,
        };
        let connector = connector.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            if let Err(e) = direct(header, tcp, &connector, &stop).await {
                eprintln!("shion-attach: forwarding failed: {e}");
            }
        });
    }
}

/// Opens a `direct-tcpip` channel for one local connection and relays.
async fn direct(
    header: ChannelHeader,
    tcp: TcpStream,
    connector: &Connector,
    stop: &CancellationToken,
) -> io::Result<()> {
    let mut framed = Framed::new(connect(connector)?, StreamStartCodec::default());
    framed.send(StreamStart::Channel(header)).await?;
    let mut channel = framed.map_codec(|_| MessageCodec::default());
    let reply = tokio::select! {
        reply = channel.next() => reply.transpose()?,
        () = stop.cancelled() => return Ok(()),
    };
    match reply {
        Some(Message::OpenConfirmation { max_packet_size }) => {
            relay(channel, tcp, max_packet_size, stop).await
        }
        // `ssh` prints the same kind of message, and closes the connection.
        Some(Message::OpenFailure { description, .. }) => {
            eprintln!("shion-attach: channel open failed: {description}");
            Ok(())
        }
        other => Err(io::Error::other(format!(
            "unexpected reply to direct-tcpip: {other:?}"
        ))),
    }
}

/// The local targets of `-R` forwards, by the address and port the session
/// listens on.
pub type RemoteTargets = HashMap<ForwardAddress, (String, u16)>;

/// `-R`: asks the session to listen. On success, records the target in
/// `targets`; on failure, warns as `ssh` does.
pub async fn request_remote(
    control: &mut Control,
    spec: &Spec,
    targets: &mut RemoteTargets,
) -> io::Result<()> {
    let address = ForwardAddress {
        address: spec.bind_address().to_owned(),
        port: spec.port,
    };
    control
        .send(ControlMessage::GlobalRequest {
            want_reply: true,
            request: GlobalRequest::TcpipForward(address.clone()),
        })
        .await?;
    match control.next().await.transpose()? {
        Some(ControlMessage::RequestSuccess { body }) => {
            let port = if spec.port == 0 {
                let port = Reader::new(&body, 16).varint().map_err(io::Error::other)?;
                let port = u16::try_from(port).map_err(io::Error::other)?;
                eprintln!(
                    "Allocated port {port} for remote forward to {}:{}",
                    spec.host, spec.host_port
                );
                port
            } else {
                spec.port
            };
            targets.insert(
                ForwardAddress { port, ..address },
                (spec.host.clone(), spec.host_port),
            );
        }
        Some(ControlMessage::RequestFailure) => {
            eprintln!(
                "shion-attach: Warning: remote port forwarding failed for listen port {}",
                spec.port
            );
        }
        other => {
            return Err(io::Error::other(format!(
                "unexpected reply to tcpip-forward: {other:?}"
            )));
        }
    }
    Ok(())
}

/// Accepts the channels the session opens (`forwarded-tcpip`, for `-R`).
pub async fn accept_remote(
    mut acceptor: MuxAcceptor<UnixStream>,
    targets: RemoteTargets,
    stop: CancellationToken,
) {
    // Shared by the tasks below, read-only: `Arc` without a `Mutex`.
    let targets = Arc::new(targets);
    loop {
        let stream = tokio::select! {
            stream = acceptor.accept() => match stream {
                Some(stream) => Stream::from(stream),
                None => return,
            },
            () = stop.cancelled() => return,
        };
        let targets = Arc::clone(&targets);
        let stop = stop.clone();
        tokio::spawn(async move {
            if let Err(e) = forwarded(stream, &targets, &stop).await {
                eprintln!("shion-attach: forwarding failed: {e}");
            }
        });
    }
}

/// Handles one channel opened by the session: connects to the `-R` target
/// and relays.
async fn forwarded(
    stream: Stream,
    targets: &RemoteTargets,
    stop: &CancellationToken,
) -> io::Result<()> {
    let mut framed = Framed::new(stream, HeaderCodec::default());
    let Some(header) = framed.next().await.transpose()? else {
        return Ok(());
    };
    let mut channel = framed.map_codec(|_| MessageCodec::default());

    let target = match &header.kind {
        ChannelKind::ForwardedTcpip(endpoints) => targets.get(&ForwardAddress {
            address: endpoints.host.clone(),
            port: endpoints.port,
        }),
        _ => None,
    };
    let Some((host, port)) = target else {
        return refuse(
            &mut channel,
            open_failure::ADMINISTRATIVELY_PROHIBITED,
            "unexpected channel".into(),
        )
        .await;
    };
    match TcpStream::connect((host.as_str(), *port)).await {
        Ok(tcp) => {
            channel
                .send(Message::OpenConfirmation {
                    max_packet_size: PACKET_SIZE as u64,
                })
                .await?;
            relay(channel, tcp, header.max_packet_size, stop).await
        }
        Err(e) => {
            let description = format!("cannot connect to {host}:{port}: {e}");
            eprintln!("shion-attach: {description}");
            refuse(&mut channel, open_failure::CONNECT_FAILED, description).await
        }
    }
}

async fn refuse(channel: &mut Channel, reason: u64, description: String) -> io::Result<()> {
    channel
        .send(Message::OpenFailure {
            reason,
            description,
            language: String::new(),
        })
        .await?;
    Ok(channel.close().await?)
}

/// Relays between a channel and a TCP connection until both directions
/// have ended (each with a half-close), or until `stop`.
async fn relay(
    channel: Channel,
    tcp: TcpStream,
    peer_max: u64,
    stop: &CancellationToken,
) -> io::Result<()> {
    let packet_size = usize::try_from(peer_max)
        .unwrap_or(usize::MAX)
        .clamp(1, PACKET_SIZE);
    let (mut sink, mut incoming) = channel.split();
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let to_channel = async {
        let mut buf = vec![0; packet_size];
        loop {
            let n = tcp_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            sink.send(Message::Data(Bytes::copy_from_slice(&buf[..n])))
                .await?;
        }
        sink.close().await?; // FIN
        Ok::<_, io::Error>(())
    };
    let from_channel = async {
        let mut tcp_open = true;
        while let Some(msg) = incoming.next().await {
            if let Message::Data(data) = msg? {
                // Keep reading after a failed write; see the session's
                // `forward::relay`.
                if tcp_open && tcp_write.write_all(&data).await.is_err() {
                    tcp_open = false;
                }
            }
        }
        let _ = tcp_write.shutdown().await;
        Ok::<_, io::Error>(())
    };

    tokio::select! {
        result = async { tokio::try_join!(to_channel, from_channel) } => result.map(|((), ())| ()),
        () = stop.cancelled() => Ok(()),
    }
}
