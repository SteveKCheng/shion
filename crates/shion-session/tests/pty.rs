//! M2: sessions with a pseudo-terminal.

mod common;

use std::time::{Duration, Instant};

use bytes::Bytes;
use common::{Harness, collect, exec, exit_status, pty_req, read_until, request, send, within};
use futures_util::SinkExt;
use shion_wire::message::{ExitSignal, WindowSize};
use shion_wire::modes::{self, opcode};
use shion_wire::{ChannelRequest, Message};

/// No modes: the kernel's defaults.
fn defaults() -> Bytes {
    modes::encode([])
}

/// Whether `exit` reports death by signal `name`.
fn killed_by(exit: Option<&ChannelRequest>, name: &str) -> bool {
    matches!(exit, Some(ChannelRequest::ExitSignal(ExitSignal { signal, .. })) if signal == name)
}

#[tokio::test]
async fn exec_runs_on_the_terminal() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        pty_req(&mut channel, 80, 24, defaults()).await;
        exec(
            &mut channel,
            r#"tty; echo "$TERM"; echo "$SSH_TTY"; stty size; test -t 0 && test -t 1 && test -t 2 && echo all-tty"#,
        )
        .await;

        let outcome = collect(&mut channel).await;
        assert_eq!(outcome.exit, exit_status(0));
        assert!(outcome.stderr.is_empty(), "stderr goes to the terminal too");
        // The terminal turns each "\n" into "\r\n" (ONLCR).
        let lines: Vec<&str> = outcome.stdout().split_terminator("\r\n").collect();
        assert_eq!(lines.len(), 5, "{lines:?}");
        assert!(lines[0].starts_with("/dev/pts/"), "{lines:?}");
        assert_eq!(lines[1], "xterm-256color");
        assert_eq!(lines[2], lines[0], "SSH_TTY is the terminal");
        assert_eq!(lines[3], "24 80");
        assert_eq!(lines[4], "all-tty");
    })
    .await;
}

#[tokio::test]
async fn terminal_modes_are_applied() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        let modes = modes::encode([
            (opcode::ECHO, 0),
            (opcode::ONLCR, 0),
            (opcode::VINTR, 7), // ^G
        ]);
        pty_req(&mut channel, 80, 24, modes).await;
        exec(&mut channel, "stty -a").await;

        let outcome = collect(&mut channel).await;
        let stty = outcome.stdout();
        assert!(stty.contains(" -echo "), "{stty}");
        assert!(stty.contains(" -onlcr"), "{stty}");
        assert!(stty.contains("intr = ^G;"), "{stty}");
        assert!(!stty.contains('\r'), "no ONLCR, so no \\r: {stty:?}");
    })
    .await;
}

#[tokio::test]
async fn window_change_resizes_the_terminal() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        pty_req(&mut channel, 80, 24, defaults()).await;
        exec(&mut channel, "read line; stty size").await;

        let resize = ChannelRequest::WindowChange(WindowSize {
            cols: 100,
            rows: 30,
            width_px: 0,
            height_px: 0,
        });
        assert_eq!(request(&mut channel, resize).await, Message::Success);
        send(&mut channel, "go\n").await;

        let outcome = collect(&mut channel).await;
        // "go" is echoed back by the terminal first.
        assert_eq!(outcome.stdout(), "go\r\n30 100\r\n");
    })
    .await;
}

#[tokio::test]
async fn interactive_shell() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        pty_req(&mut channel, 80, 24, defaults()).await;
        assert_eq!(
            request(&mut channel, ChannelRequest::Shell).await,
            Message::Success
        );

        send(&mut channel, "echo $((6 * 7))\n").await;
        read_until(&mut channel, "42\r\n").await;
        send(&mut channel, "exit 5\n").await;
        let outcome = collect(&mut channel).await;
        assert_eq!(outcome.exit, exit_status(5));
    })
    .await;
}

#[tokio::test]
async fn ctrl_c_interrupts() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        pty_req(&mut channel, 80, 24, defaults()).await;
        exec(&mut channel, "sleep 30").await;

        // The terminal's line discipline turns ^C into SIGINT for its
        // foreground process group. That only works if the terminal is
        // the child's controlling terminal.
        send(&mut channel, "\x03").await;
        let outcome = collect(&mut channel).await;
        assert!(killed_by(outcome.exit.as_ref(), "INT"), "{outcome:?}");
    })
    .await;
}

#[tokio::test]
async fn signal_request_reaches_the_foreground_group() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        pty_req(&mut channel, 80, 24, defaults()).await;
        exec(&mut channel, "sleep 30").await;

        let term = ChannelRequest::Signal {
            name: "TERM".into(),
        };
        assert_eq!(request(&mut channel, term).await, Message::Success);
        let outcome = collect(&mut channel).await;
        assert!(killed_by(outcome.exit.as_ref(), "TERM"), "{outcome:?}");
    })
    .await;
}

#[tokio::test]
async fn background_job_does_not_hold_the_channel_open() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        pty_req(&mut channel, 80, 24, defaults()).await;
        // The subshell ignores the SIGHUP that the session leader's exit
        // sends, so it keeps the terminal open after `sh` has exited.
        let start = Instant::now();
        exec(&mut channel, "(trap '' HUP; exec sleep 5) & echo started").await;

        let outcome = collect(&mut channel).await;
        assert_eq!(outcome.stdout(), "started\r\n");
        assert_eq!(outcome.exit, exit_status(0));
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
    })
    .await;
}

#[tokio::test]
async fn input_before_eof_is_delivered() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        pty_req(&mut channel, 80, 24, modes::encode([(opcode::ECHO, 0)])).await;
        exec(&mut channel, "read x; echo got $x").await;

        send(&mut channel, "hi\n").await;
        // FIN on our side. On a terminal that just means no more input.
        channel.close().await.unwrap();
        assert_eq!(collect(&mut channel).await.stdout(), "got hi\r\n");
    })
    .await;
}

#[tokio::test]
async fn only_one_pty_per_channel() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        pty_req(&mut channel, 80, 24, defaults()).await;
        let again = ChannelRequest::PtyReq(shion_wire::message::PtyRequest {
            term: "vt100".into(),
            size: WindowSize::default(),
            modes: defaults(),
        });
        assert_eq!(request(&mut channel, again).await, Message::Failure);

        exec(&mut channel, "echo $TERM").await;
        assert_eq!(collect(&mut channel).await.stdout(), "xterm-256color\r\n");
    })
    .await;
}
