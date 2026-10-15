//! M3: `env` and `subsystem` requests.

mod common;

use common::{
    CLIENT_ADDRESS, Harness, SERVER_ADDRESS, collect, env, exec, exit_status, request, within,
};
use shion_wire::{ChannelRequest, Message};

#[tokio::test]
async fn env_is_refused_by_default() {
    within(async {
        let harness = Harness::start();
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        assert!(!env(&mut channel, "LANG", "C.UTF-8").await);

        // The channel still works.
        exec(&mut channel, "printf %s \"${LANG-unset}\"").await;
        assert_eq!(collect(&mut channel).await.stdout(), "unset");
    })
    .await;
}

#[tokio::test]
async fn env_follows_the_accept_list() {
    within(async {
        let harness = Harness::start_with(&["--accept-env", "LANG", "--accept-env", "LC_*"]);
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        assert!(env(&mut channel, "LANG", "C.UTF-8").await);
        assert!(env(&mut channel, "LC_ALL", "fr_FR.UTF-8").await);
        assert!(!env(&mut channel, "LANGUAGE", "fr").await);
        assert!(!env(&mut channel, "PATH", "/evil").await);

        exec(
            &mut channel,
            "printf '%s|%s|%s|%s' \"$LANG\" \"$LC_ALL\" \"${LANGUAGE-unset}\" \"$PATH\"",
        )
        .await;
        let outcome = collect(&mut channel).await;
        assert_eq!(
            outcome.stdout(),
            "C.UTF-8|fr_FR.UTF-8|unset|/usr/local/bin:/usr/bin:/bin"
        );
        assert_eq!(outcome.exit, exit_status(0));
    })
    .await;
}

#[tokio::test]
async fn malformed_env_is_refused() {
    within(async {
        let harness = Harness::start_with(&["--accept-env", "*"]);
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        assert!(!env(&mut channel, "", "x").await);
        assert!(!env(&mut channel, "A=B", "x").await);
        assert!(!env(&mut channel, "A\0B", "x").await);
        assert!(!env(&mut channel, "A", "x\0y").await);
        assert!(env(&mut channel, "A", "x=y").await);
    })
    .await;
}

#[tokio::test]
async fn client_env_overrides_setenv_but_not_connection_facts() {
    within(async {
        let harness = Harness::start_with(&["--accept-env", "*", "--setenv", "EDITOR=vi"]);
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        assert!(env(&mut channel, "EDITOR", "emacs").await);
        assert!(
            env(
                &mut channel,
                "SSH_CONNECTION",
                "203.0.113.1 1 203.0.113.2 2"
            )
            .await
        );

        exec(
            &mut channel,
            "printf '%s|%s' \"$EDITOR\" \"$SSH_CONNECTION\"",
        )
        .await;
        let outcome = collect(&mut channel).await;
        assert_eq!(
            outcome.stdout(),
            format!("emacs|{CLIENT_ADDRESS} {SERVER_ADDRESS}")
        );
    })
    .await;
}

#[tokio::test]
async fn subsystem_runs_its_command() {
    within(async {
        let harness = Harness::start_with(&["--subsystem", "greet=echo hello from $0; cat"]);
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        let reply = request(
            &mut channel,
            ChannelRequest::Subsystem {
                name: "greet".into(),
            },
        )
        .await;
        assert_eq!(reply, Message::Success);

        common::send(&mut channel, "and stdin\n").await;
        futures_util::SinkExt::close(&mut channel).await.unwrap();
        let outcome = collect(&mut channel).await;
        assert_eq!(outcome.stdout(), "hello from /bin/sh\nand stdin\n");
        assert_eq!(outcome.exit, exit_status(0));
    })
    .await;
}

#[tokio::test]
async fn unknown_subsystem_is_refused_without_closing_the_channel() {
    within(async {
        let harness = Harness::start_with(&["--subsystem", "sftp=/nonexistent"]);
        let _control = harness.conversation(1).await;
        let mut channel = harness.session(1).await;
        let reply = request(
            &mut channel,
            ChannelRequest::Subsystem {
                name: "nope".into(),
            },
        )
        .await;
        assert_eq!(reply, Message::Failure);

        exec(&mut channel, "echo still here").await;
        assert_eq!(collect(&mut channel).await.stdout(), "still here\n");
    })
    .await;
}
