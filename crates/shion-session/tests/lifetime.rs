//! M3: conversation teardown and `--linger`.

mod common;

use std::time::Duration;

use common::{Harness, collect, exec, exit_status, pty_req, read_until, send, within};
use futures_util::SinkExt;
use shion_wire::ChannelRequest;
use shion_wire::message::ExitSignal;

#[tokio::test]
async fn ending_a_conversation_hangs_up_its_processes() {
    within(async {
        let harness = Harness::start();
        let mut control_1 = harness.conversation(1).await;
        let _control_2 = harness.conversation(2).await;

        let mut doomed = harness.session(1).await;
        exec(
            &mut doomed,
            "trap 'echo got HUP; exit 0' HUP; echo ready; while :; do sleep 0.1; done",
        )
        .await;
        assert_eq!(read_until(&mut doomed, "ready\n").await, "ready\n");

        let mut survivor = harness.session(2).await;
        exec(&mut survivor, "trap 'echo got HUP; exit 0' HUP; cat").await;

        // FIN on the control stream ends conversation 1.
        control_1.close().await.unwrap();
        let outcome = collect(&mut doomed).await;
        assert_eq!(outcome.stdout(), "got HUP\n");
        assert_eq!(outcome.exit, exit_status(0));

        // Conversation 2 is unaffected.
        send(&mut survivor, "still alive\n").await;
        assert_eq!(read_until(&mut survivor, "\n").await, "still alive\n");
        survivor.close().await.unwrap();
        let outcome = collect(&mut survivor).await;
        assert_eq!(outcome.exit, exit_status(0));
    })
    .await;
}

#[tokio::test]
async fn ending_a_conversation_hangs_up_its_terminals() {
    within(async {
        let harness = Harness::start();
        let mut control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        pty_req(&mut channel, 80, 24, shion_wire::modes::encode([])).await;
        exec(&mut channel, "echo ready; sleep 60").await;
        read_until(&mut channel, "ready").await;

        control.close().await.unwrap();
        let outcome = collect(&mut channel).await;
        assert!(
            matches!(&outcome.exit, Some(ChannelRequest::ExitSignal(ExitSignal { signal, .. })) if signal == "HUP"),
            "{:?}",
            outcome.exit
        );
    })
    .await;
}

#[tokio::test]
async fn linger_counts_from_startup() {
    within(async {
        let mut harness = Harness::start_with(&["--linger", "0.2"]);
        assert!(harness.wait().await.success());
    })
    .await;
}

#[tokio::test]
async fn linger_waits_for_the_last_conversation() {
    within(async {
        let mut harness = Harness::start_with(&["--linger", "0.3"]);
        let mut control_1 = harness.conversation(1).await;
        let mut control_2 = harness.conversation(2).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!harness.has_exited(), "exited with conversations open");

        control_1.close().await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!harness.has_exited(), "exited with a conversation open");

        control_2.close().await.unwrap();
        // Closed means both directions: wait for the session's FIN too.
        while futures_util::StreamExt::next(&mut control_2)
            .await
            .is_some()
        {}
        let started = tokio::time::Instant::now();
        assert!(harness.wait().await.success());
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "{:?}",
            started.elapsed()
        );
    })
    .await;
}
