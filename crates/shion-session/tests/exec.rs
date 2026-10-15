//! M1: conversations, and `exec`/`shell` sessions over pipes.

mod common;

use std::collections::BTreeSet;

use bytes::Bytes;
use common::{
    CLIENT_ADDRESS, Harness, SERVER_ADDRESS, Transport, collect, exec, exit_status, request, within,
};
use futures_util::{SinkExt, StreamExt};
use shion_wire::message::{WindowSize, X11Request, open_failure};
use shion_wire::{
    ChannelHeader, ChannelKind, ChannelRequest, ControlMessage, GlobalRequest, Message,
};

#[tokio::test]
async fn exec_stdout_stderr_and_exit_status() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        exec(&mut channel, "printf hello; printf oops >&2; exit 3").await;

        let outcome = collect(&mut channel).await;
        assert_eq!(outcome.stdout(), "hello");
        assert_eq!(outcome.stderr(), "oops");
        assert_eq!(outcome.exit, exit_status(3));
    })
    .await;
}

#[tokio::test]
async fn stdin_is_relayed_and_eof_closes_it() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        exec(&mut channel, "cat; echo done").await;

        channel
            .send(Message::Data(Bytes::from_static(b"hello ")))
            .await
            .unwrap();
        channel
            .send(Message::Data(Bytes::from_static(b"world\n")))
            .await
            .unwrap();
        // Our FIN (SSH's CHANNEL_EOF): cat sees EOF and exits.
        channel.close().await.unwrap();

        let outcome = collect(&mut channel).await;
        assert_eq!(outcome.stdout(), "hello world\ndone\n");
        assert_eq!(outcome.exit, exit_status(0));
    })
    .await;
}

#[tokio::test]
async fn output_respects_peer_max_packet_size() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session_with_packet_size(1, 4096).await;
        exec(&mut channel, "head -c 1000000 /dev/zero").await;

        let outcome = collect(&mut channel).await;
        assert_eq!(outcome.stdout.len(), 1_000_000);
        assert!(
            outcome.largest_packet <= 4096,
            "packet of {} bytes",
            outcome.largest_packet
        );
        assert_eq!(outcome.exit, exit_status(0));
    })
    .await;
}

#[tokio::test]
async fn killed_by_signal_reports_exit_signal() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        exec(&mut channel, "kill -TERM $$").await;

        let outcome = collect(&mut channel).await;
        let Some(ChannelRequest::ExitSignal(exit)) = outcome.exit else {
            panic!("{outcome:?}")
        };
        assert_eq!(exit.signal, "TERM");
        assert!(!exit.core_dumped);
    })
    .await;
}

#[tokio::test]
async fn signal_request_reaches_the_process_group() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        // A pipeline: the signal must reach both processes, not just the
        // shell.
        exec(&mut channel, "sleep 30 | sleep 30").await;

        let reply = request(&mut channel, ChannelRequest::Signal { name: "INT".into() }).await;
        assert_eq!(reply, Message::Success);
        let outcome = collect(&mut channel).await;
        let Some(ChannelRequest::ExitSignal(exit)) = outcome.exit else {
            panic!("{outcome:?}")
        };
        assert_eq!(exit.signal, "INT");
    })
    .await;
}

#[tokio::test]
async fn unknown_signal_name_is_refused() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        exec(&mut channel, "read line").await;

        let reply = request(
            &mut channel,
            ChannelRequest::Signal {
                name: "WINCH".into(),
            },
        )
        .await;
        assert_eq!(reply, Message::Failure);
        channel.close().await.unwrap();
        assert_eq!(collect(&mut channel).await.exit, exit_status(1));
    })
    .await;
}

#[tokio::test]
async fn environment_is_built_from_scratch() {
    within(async {
        let harness = Harness::start_with(&["--setenv", "FOO=bar", "--setenv", "PATH=/usr/bin:/bin"]);
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        exec(&mut channel, r#"printf '%s\n' "$HOME" "$USER" "$LOGNAME" "$SHELL" "$PATH" "$FOO" "$SSH_CONNECTION" "$SSH_CLIENT"; pwd"#).await;

        let outcome = collect(&mut channel).await;
        let home = harness.home.path().to_str().unwrap();
        let expected = [
            home,
            "agent-7",
            "agent-7",
            "/bin/sh",
            "/usr/bin:/bin",
            "bar",
            &format!("{CLIENT_ADDRESS} {SERVER_ADDRESS}"),
            &format!("{CLIENT_ADDRESS} 2222"),
            home,
        ];
        assert_eq!(outcome.stdout().lines().collect::<Vec<_>>(), expected);
    })
    .await;
}

#[tokio::test]
async fn nothing_is_inherited_from_our_environment() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        exec(&mut channel, "env").await;

        let outcome = collect(&mut channel).await;
        let names: BTreeSet<&str> = outcome
            .stdout()
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(name, _)| name)
            .collect();
        // The shell adds PWD, SHLVL and _ by itself.
        let expected: BTreeSet<&str> = [
            "HOME",
            "USER",
            "LOGNAME",
            "SHELL",
            "PATH",
            "SSH_CONNECTION",
            "SSH_CLIENT",
            "PWD",
            "SHLVL",
            "_",
        ]
        .into();
        assert_eq!(names, expected);
    })
    .await;
}

#[tokio::test]
async fn children_inherit_only_stdio() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        exec(&mut channel, "ls /proc/self/fd").await;

        // fd 3 is the directory `ls` itself opened to list the fds.
        assert_eq!(collect(&mut channel).await.stdout(), "0\n1\n2\n3\n");
    })
    .await;
}

#[tokio::test]
async fn shell_without_pty_is_a_login_shell() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        assert_eq!(
            request(&mut channel, ChannelRequest::Shell).await,
            Message::Success
        );

        channel
            .send(Message::Data(Bytes::from_static(b"echo $0\nexit 7\n")))
            .await
            .unwrap();
        let outcome = collect(&mut channel).await;
        assert_eq!(outcome.stdout(), "-sh\n");
        assert_eq!(outcome.exit, exit_status(7));
    })
    .await;
}

#[tokio::test]
async fn unsupported_requests_are_refused_without_closing_the_channel() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;

        let x11 = ChannelRequest::X11Req(X11Request {
            single_connection: false,
            auth_protocol: "MIT-MAGIC-COOKIE-1".into(),
            auth_cookie: "00".into(),
            screen: 0,
        });
        assert_eq!(request(&mut channel, x11).await, Message::Failure);
        // Only meaningful with a pty.
        let resize = ChannelRequest::WindowChange(WindowSize::default());
        assert_eq!(request(&mut channel, resize).await, Message::Failure);
        let sftp = ChannelRequest::Subsystem {
            name: "sftp".into(),
        };
        assert_eq!(request(&mut channel, sftp).await, Message::Failure);

        exec(&mut channel, "echo still here").await;
        assert_eq!(collect(&mut channel).await.stdout(), "still here\n");
    })
    .await;
}

#[tokio::test]
async fn failed_spawn_is_refused() {
    within(async {
        let harness = Harness::start_with(&["--shell", "/nonexistent/shell"]);
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        let reply = request(
            &mut channel,
            ChannelRequest::Exec {
                command: Bytes::from_static(b"true"),
            },
        )
        .await;
        assert_eq!(reply, Message::Failure);
    })
    .await;
}

#[tokio::test]
async fn channels_run_concurrently() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut slow = harness.session(1).await;
        let mut fast = harness.session(1).await;
        exec(&mut slow, "read line; echo slow").await;
        exec(&mut fast, "echo fast").await;

        // `fast` finishes while `slow` is still waiting for input.
        assert_eq!(collect(&mut fast).await.stdout(), "fast\n");
        slow.send(Message::Data(Bytes::from_static(b"go\n")))
            .await
            .unwrap();
        assert_eq!(collect(&mut slow).await.stdout(), "slow\n");
    })
    .await;
}

#[tokio::test]
async fn channel_needs_an_open_conversation() {
    within(async {
        let harness = Harness::start();
        let header = |conversation_id| ChannelHeader {
            conversation_id,
            kind: ChannelKind::Session,
            max_packet_size: 32_768,
        };

        let (_, reply) = harness.try_channel(header(1)).await;
        assert!(
            matches!(
                reply,
                Message::OpenFailure {
                    reason: open_failure::ADMINISTRATIVELY_PROHIBITED,
                    ..
                }
            ),
            "{reply:?}"
        );

        // Open conversation 1, close it again, and it's gone.
        let mut control = harness.conversation(1).await;
        let _ = harness.session(1).await;
        control.close().await.unwrap();
        assert!(
            control.next().await.is_none(),
            "session should close its side too"
        );
        let (_, reply) = harness.try_channel(header(1)).await;
        assert!(matches!(reply, Message::OpenFailure { .. }), "{reply:?}");
    })
    .await;
}

#[tokio::test]
async fn unknown_channel_type_is_refused() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let header = ChannelHeader {
            conversation_id: 1,
            kind: ChannelKind::Other("direct-streamlocal@openssh.com".into()),
            max_packet_size: 32_768,
        };
        let (_, reply) = harness.try_channel(header).await;
        assert!(
            matches!(
                reply,
                Message::OpenFailure {
                    reason: open_failure::UNKNOWN_CHANNEL_TYPE,
                    ..
                }
            ),
            "{reply:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn conversations_are_validated() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;

        let (_, reply) = harness.try_conversation(Harness::conv_open(1)).await;
        assert!(
            matches!(reply, ControlMessage::ConvReject { .. }),
            "duplicate id: {reply:?}"
        );

        let mut open = Harness::conv_open(2);
        open.attributes[0].1 = "someone-else".into();
        let (_, reply) = harness.try_conversation(open).await;
        assert!(
            matches!(reply, ControlMessage::ConvReject { .. }),
            "wrong user: {reply:?}"
        );

        let mut open = Harness::conv_open(3);
        open.version = 99;
        let (_, reply) = harness.try_conversation(open).await;
        assert!(
            matches!(reply, ControlMessage::ConvReject { .. }),
            "wrong version: {reply:?}"
        );
    })
    .await;
}

#[tokio::test]
async fn unknown_global_requests_are_refused() {
    within(async {
        let harness = Harness::start();
        let mut control = harness.conversation(1).await;
        let request = ControlMessage::GlobalRequest {
            want_reply: true,
            request: GlobalRequest::Other {
                name: "keepalive@openssh.com".into(),
                body: Bytes::new(),
            },
        };
        control.send(request).await.unwrap();
        assert_eq!(
            control.next().await.unwrap().unwrap(),
            ControlMessage::RequestFailure
        );
    })
    .await;
}

#[tokio::test]
async fn exits_when_the_carrier_closes() {
    within(async {
        let harness = Harness::start();
        let control = harness.conversation(1).await;
        drop(control);
        assert!(harness.shutdown().await.success());
    })
    .await;
}

#[tokio::test]
async fn works_over_a_socketpair() {
    within(async {
        let harness = Harness::start_over(Transport::Socket, &[]);
        let control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        exec(&mut channel, "cat").await;
        channel
            .send(Message::Data(Bytes::from_static(b"over a socket\n")))
            .await
            .unwrap();
        channel.close().await.unwrap();
        let outcome = collect(&mut channel).await;
        assert_eq!(outcome.stdout(), "over a socket\n");
        assert_eq!(outcome.exit, exit_status(0));

        // Every smux handle must be gone for the carrier to close.
        drop(channel);
        drop(control);
        assert!(harness.shutdown().await.success());
    })
    .await;
}
