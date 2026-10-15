//! One SSH connection: the russh [`Handler`] that authenticates the client
//! (by asking the trusted side) and turns its channels and requests into
//! SSH3 messages for the session process.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use russh::keys::PublicKey;
use russh::server::{Auth, Handler, Msg, Session};
use russh::{Channel, ChannelId, Pty, Sig};
use shion_wire::control::{ForwardAddress, attr};
use shion_wire::header::TcpipEndpoints;
use shion_wire::message::{PtyRequest, WindowSize};
use shion_wire::wire::Reader;
use shion_wire::{ChannelRequest, ControlMessage, GlobalRequest, modes};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use super::channel::{self, OpenReply, ToSession};
use super::conversation::Conversation;
use super::forward;
use super::link::Links;
use crate::trusted::{Authority, Grant};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Ssh(#[from] russh::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The state of one connection. russh calls its [`Handler`] methods one at
/// a time, in the order the client's messages arrive.
#[derive(Debug)]
pub struct Connection {
    peer: SocketAddr,
    local: SocketAddr,
    authority: Arc<Authority>,
    links: Arc<Links>,
    grant: Option<Grant>,
    /// Set once authenticated.
    conversation: Option<Arc<Conversation>>,
    /// Open `session` channels.
    channels: HashMap<ChannelId, SessionChannel>,
}

#[derive(Debug)]
struct SessionChannel {
    to_session: mpsc::Sender<ToSession>,
    /// Whether `shell`, `exec` or `subsystem` has succeeded.
    started: bool,
}

impl Connection {
    pub fn new(
        peer: SocketAddr,
        local: SocketAddr,
        authority: Arc<Authority>,
        links: Arc<Links>,
    ) -> Self {
        Self {
            peer,
            local,
            authority,
            links,
            grant: None,
            conversation: None,
            channels: HashMap::new(),
        }
    }

    /// Passes a channel request to the session process, waits for the
    /// answer, and answers the client (if it wants an answer: russh keeps
    /// track of that).
    ///
    /// Waiting here, inside russh's connection loop, holds up the client's
    /// next messages until the session process has answered. That's what
    /// keeps the answers in order: russh only knows whether the *latest*
    /// request wanted one. It's quick, and it can't deadlock: before the
    /// program starts, no output can be queued ahead of the answer, and
    /// after it starts, requests needing an answer are refused without
    /// asking (the session process would refuse them anyway).
    async fn request(
        &mut self,
        id: ChannelId,
        request: ChannelRequest,
        session: &mut Session,
    ) -> Result<bool, Error> {
        let starts = matches!(
            request,
            ChannelRequest::Shell | ChannelRequest::Exec { .. } | ChannelRequest::Subsystem { .. }
        );
        let ok = match self.channels.get(&id) {
            Some(channel) if !channel.started => {
                let (reply, reply_rx) = oneshot::channel();
                let msg = ToSession::Request {
                    request,
                    reply: Some(reply),
                };
                channel.to_session.send(msg).await.is_ok() && reply_rx.await.unwrap_or(false)
            }
            _ => false,
        };
        // A "let chain": `&&` can join `let` patterns and conditions.
        if ok
            && starts
            && let Some(channel) = self.channels.get_mut(&id)
        {
            channel.started = true;
        }
        if ok {
            session.channel_success(id)?;
        } else {
            session.channel_failure(id)?;
        }
        Ok(ok)
    }

    /// Passes on a request that gets no answer.
    async fn notify(&self, id: ChannelId, request: ChannelRequest) {
        if let Some(channel) = self.channels.get(&id) {
            let _ = channel
                .to_session
                .send(ToSession::Request {
                    request,
                    reply: None,
                })
                .await;
        }
    }

    /// Sends a global request, and returns the session process's answer.
    async fn global_request(&self, request: GlobalRequest) -> Option<ControlMessage> {
        self.conversation.as_ref()?.global_request(request).await
    }

    /// The `CONV_OPEN` attributes for this connection.
    fn attributes(&self, grant: &Grant, session: &Session) -> Vec<(String, String)> {
        // "<ip> <port>", the way `SSH_CONNECTION` wants them. `to_canonical`
        // turns an IPv4-mapped IPv6 address back into plain IPv4.
        let address = |a: &SocketAddr| format!("{} {}", a.ip().to_canonical(), a.port());
        let mut attributes = vec![
            (attr::USER.into(), grant.user.clone()),
            (attr::CLIENT_ADDRESS.into(), address(&self.peer)),
            (attr::SERVER_ADDRESS.into(), address(&self.local)),
            (
                attr::CLIENT_VERSION.into(),
                String::from_utf8_lossy(session.remote_sshid()).into_owned(),
            ),
            (attr::AUTH_METHOD.into(), grant.method.clone()),
        ];
        if let Some(fingerprint) = &grant.key_fingerprint {
            attributes.push((attr::AUTH_KEY.into(), fingerprint.clone()));
        }
        attributes
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        if let Some(grant) = &self.grant {
            self.authority.revoke(grant.token);
            info!(user = grant.user, peer = %self.peer, "connection closed");
        }
        // Dropping `channels` stops their `to_session` halves, and dropping
        // `conversation` (once the channel tasks have let go of it too) ends
        // the conversation.
    }
}

/// russh calls these. Each `async fn` here implements a trait method
/// declared as returning `impl Future<…> + Send`; the compiler checks that
/// the future really is `Send`, i.e. holds nothing thread-bound across an
/// `.await` (such as a `std::sync::MutexGuard`).
#[expect(
    clippy::unused_async_trait_impl,
    reason = "the trait wants futures, even from methods that don't wait"
)]
impl Handler for Connection {
    type Error = Error;

    async fn auth_publickey_offered(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Error> {
        Ok(if self.authority.accepts_key(user, key) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Error> {
        Ok(match self.authority.authenticate_key(user, key) {
            Some(grant) => {
                self.grant = Some(grant);
                Auth::Accept
            }
            None => Auth::reject(),
        })
    }

    async fn auth_succeeded(&mut self, session: &mut Session) -> Result<(), Error> {
        let grant = self
            .grant
            .clone()
            .ok_or_else(|| io::Error::other("authenticated without a grant"))?;
        let attributes = self.attributes(&grant, session);
        let (conversation, opened) = Conversation::open(&self.links, &grant, attributes).await?;
        let conversation = Arc::new(conversation);
        info!(user = grant.user, peer = %self.peer, "logged in");

        // Channels the session process opens (for `tcpip-forward`).
        tokio::spawn(forward::deliver(opened, session.handle()));
        conversation.disconnect_on_carrier_close(session.handle());
        self.conversation = Some(conversation);
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: OpenReply,
        session: &mut Session,
    ) -> Result<(), Error> {
        let Some(conversation) = &self.conversation else {
            return Ok(()); // dropping `reply` refuses the channel
        };
        let id = channel.id();
        // We get this channel's messages through the callbacks below, which
        // let us answer requests in order. russh sends them to `channel`
        // too, and ignores that once `channel` is gone.
        drop(channel);
        let (to_session, from_client) = mpsc::channel(32);
        self.channels.insert(
            id,
            SessionChannel {
                to_session,
                started: false,
            },
        );
        tokio::spawn(channel::run(
            Arc::clone(conversation),
            id,
            from_client,
            reply,
            session.handle(),
        ));
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
        reply: OpenReply,
        _session: &mut Session,
    ) -> Result<(), Error> {
        let (Some(conversation), Ok(port), Ok(originator_port)) = (
            &self.conversation,
            u16::try_from(port_to_connect),
            u16::try_from(originator_port),
        ) else {
            return Ok(());
        };
        let target = TcpipEndpoints {
            host: host_to_connect.into(),
            port,
            originator_address: originator_address.into(),
            originator_port,
        };
        // Connecting may take a while: don't hold up the connection.
        tokio::spawn(forward::direct(
            Arc::clone(conversation),
            channel,
            target,
            reply,
        ));
        Ok(())
    }

    async fn channel_eof(&mut self, id: ChannelId, _session: &mut Session) -> Result<(), Error> {
        if let Some(channel) = self.channels.get(&id) {
            let _ = channel.to_session.send(ToSession::Eof).await;
        }
        Ok(())
    }

    async fn channel_close(&mut self, id: ChannelId, _session: &mut Session) -> Result<(), Error> {
        // Its `to_session` half finishes, sending FIN if it hadn't.
        self.channels.remove(&id);
        Ok(())
    }

    async fn data(
        &mut self,
        id: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Error> {
        if let Some(channel) = self.channels.get(&id) {
            let _ = channel
                .to_session
                .send(ToSession::Data(Bytes::copy_from_slice(data)))
                .await;
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        id: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Error> {
        // russh has decoded the modes; the session process wants them
        // encoded, as on the wire. (`as u8` is fine: the codes are 0–160.)
        let modes = modes::encode(
            modes
                .iter()
                // russh leaves `TTY_OP_END` in place of codes it doesn't
                // know (such as IUTF8); passed on, it would end the list.
                .filter(|&&(code, _)| code != Pty::TTY_OP_END)
                .map(|&(code, value)| (code as u8, value)),
        );
        let request = ChannelRequest::PtyReq(PtyRequest {
            term: term.into(),
            size: WindowSize {
                cols: col_width.into(),
                rows: row_height.into(),
                width_px: pix_width.into(),
                height_px: pix_height.into(),
            },
            modes,
        });
        self.request(id, request, session).await?;
        Ok(())
    }

    async fn x11_request(
        &mut self,
        id: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Error> {
        session.channel_failure(id)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        id: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Error> {
        let request = ChannelRequest::Env {
            name: Bytes::copy_from_slice(variable_name.as_bytes()),
            value: Bytes::copy_from_slice(variable_value.as_bytes()),
        };
        self.request(id, request, session).await?;
        Ok(())
    }

    async fn shell_request(&mut self, id: ChannelId, session: &mut Session) -> Result<(), Error> {
        self.request(id, ChannelRequest::Shell, session).await?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Error> {
        let request = ChannelRequest::Exec {
            command: Bytes::copy_from_slice(data),
        };
        self.request(id, request, session).await?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Error> {
        let request = ChannelRequest::Subsystem { name: name.into() };
        self.request(id, request, session).await?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        id: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Error> {
        let size = WindowSize {
            cols: col_width.into(),
            rows: row_height.into(),
            width_px: pix_width.into(),
            height_px: pix_height.into(),
        };
        self.notify(id, ChannelRequest::WindowChange(size)).await;
        Ok(())
    }

    async fn signal(
        &mut self,
        id: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Error> {
        let name = channel::signal_name(&signal);
        self.notify(id, ChannelRequest::Signal { name }).await;
        Ok(())
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Error> {
        let Ok(requested) = u16::try_from(*port) else {
            return Ok(false);
        };
        let request = GlobalRequest::TcpipForward(ForwardAddress {
            address: address.into(),
            port: requested,
        });
        Ok(match self.global_request(request).await {
            Some(ControlMessage::RequestSuccess { body }) => {
                if requested == 0 {
                    // The port the session process picked.
                    match Reader::new(&body, 16).varint() {
                        Ok(bound) => *port = u32::try_from(bound).unwrap_or(0),
                        Err(e) => warn!(error = %e, "bad tcpip-forward reply"),
                    }
                }
                debug!(address, port, "tcpip-forward");
                true
            }
            _ => false,
        })
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut Session,
    ) -> Result<bool, Error> {
        let Ok(port) = u16::try_from(port) else {
            return Ok(false);
        };
        let request = GlobalRequest::CancelTcpipForward(ForwardAddress {
            address: address.into(),
            port,
        });
        Ok(matches!(
            self.global_request(request).await,
            Some(ControlMessage::RequestSuccess { .. })
        ))
    }
}
