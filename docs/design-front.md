# shion — design, part 2: the front-end

Status: M5 done (2026-10-15). Companion to `design-session.md`, whose §2
topology and §4 wire protocol this builds on.

## 1. What it does

`shion-front` is the SSH server. It accepts SSH2 connections (russh),
authenticates app-level users against its own configuration, launches each
user's session process (normally inside bwrap), and translates between SSH2
channels and the SSH3 channel streams the session process speaks over its
carrier.

```
ssh client ──SSH2──► shion-front ──smux carrier──► shion-session (in bwrap)
                     ├─ trusted:  config, credentials, launching
                     └─ network:  russh, SSH2⇄SSH3, smux
```

## 2. Trusted side and network side

The crate has two top-level modules, split along the lines of a possible
future process split (`notes/extended-priv-sep.md`):

- **`trusted`**: reads the configuration file (trusted input, written by the
  administrator), holds the authorized keys and host keys, checks
  credentials, builds session command lines and launches session processes.
  It never reads from a network connection or a carrier.
- **`network`**: everything that handles hostile input: SSH clients (russh)
  and session processes (their carriers). It sees the configuration only
  through `trusted::Authority`.

Today both run in one process, so the split is organizational. But
`Authority`'s interface is shaped like the master process's control socket
protocol in the note: every argument and result is plain data, or a socket.

| `Authority` method                 | note's step | returns                                     |
|------------------------------------|-------------|---------------------------------------------|
| `accepts_key(user, key)`           | 5           | whether to let the client try this key      |
| `authenticate_key(user, key)`      | 5, 6        | a `Grant` (a token, plus user and key info) |
| `launch_session(token)`            | 7, 8        | a carrier socket, and the linger time       |
| `revoke(token)`                    | —           | (the connection has closed)                 |
| `host_keys()`                      | —           | the host private keys (see §7)              |

`launch_session` starts a new process every time it's called. Sharing one
session process between a user's connections is the network side's
business (§4). That gives a compromised network side nothing beyond what
logging in again with the same credentials would give it, which is the
property the note asks for. When the master becomes a separate process,
the carrier would come back with `SCM_RIGHTS`, and the session process
would accept several carriers (the note's step 9) instead of the network
side multiplexing conversations onto one.

## 3. Configuration

TOML, for example:

```toml
listen = ["0.0.0.0:2222"]
host_keys = ["/etc/shion/host_ed25519"]   # ssh-keygen -t ed25519 -N '' -f …

[defaults]
# `{user}` is replaced by the user name in every argument.
session = ["bwrap", "--unshare-all", "--die-with-parent", …, "--",
           "/usr/libexec/shion/shion-session",
           "--user", "{user}", "--home", "/home/{user}", "--shell", "/bin/bash",
           "--subsystem", "sftp=/usr/libexec/openssh/sftp-server",
           "--permit-open", "localhost:*", "--permit-listen", "localhost:*"]
linger = 300

[users.agent-7]
authorized_keys = ["ssh-ed25519 AAAAC3Nz… agent-7@build"]
# session = [...]   # overrides [defaults]
# linger = 0
```

Unknown keys are errors (`deny_unknown_fields`), so a misspelt setting
can't be silently ignored. Each user needs a session command, their own
or the default's. Authorized keys are parsed at startup, so a bad one stops
the server from starting rather than failing a login later.

## 4. Connections, links and conversations

- **Authentication**: public keys only. russh verifies the signature, then
  asks `Authority::authenticate_key`, which returns a `Grant`. Rejections
  take a constant 1 s, except OpenSSH's initial `none` probe, which reveals
  nothing (otherwise every login would take a second longer).
- **Link**: the network side's end of one session process's carrier, with
  its smux connection. There's one per user (`network::link::Links`). The
  first connection launches it through the `Authority`. Later connections
  join it, until the carrier closes; then the next connection launches a
  new process.
- **Conversation**: one per SSH connection. After authentication, the
  connection joins its user's link and opens a control stream (`CONV_OPEN`
  with the connection's attributes: user, addresses, client version, key
  fingerprint). Dropping the `Conversation` closes the control stream, and
  the session process hangs up that conversation's processes and
  forwards.
- **Linger**: when a link's last conversation ends, the link waits for the
  user's `linger` time, then closes the carrier, and the session process
  exits. The front-end decides when to linger, so there's no race with a
  connection arriving just as the session process gives up (as there is
  with the session's own `--linger`, which is best left unset).
- If a session process exits on its own, its users' connections are
  disconnected.

## 5. SSH2 ⇄ SSH3

`session` channels go through russh's handler callbacks; forwarding
channels use russh's `Channel` object in a task of their own (they carry no
requests).

| SSH2 (client)                          | SSH3 (session process)                          |
|----------------------------------------|-------------------------------------------------|
| `CHANNEL_OPEN session`                 | channel stream with a `session` header           |
| `CHANNEL_OPEN direct-tcpip`            | stream with a `direct-tcpip` header (§5.5 of part 1) |
| `pty-req`                              | `pty-req`, terminal modes re-encoded             |
| `env`, `shell`, `exec`, `subsystem`    | the same requests                                |
| `window-change`, `signal`              | the same, no reply                               |
| `x11-req`, `auth-agent-req`            | refused by the front-end                         |
| `CHANNEL_DATA`                         | `CHANNEL_DATA`                                   |
| `CHANNEL_EOF`                          | FIN                                              |
| `CHANNEL_CLOSE`                        | FIN, if not sent yet (no abort: part 1, §4.6)    |
| `tcpip-forward`, `cancel-tcpip-forward`| global requests on the control stream            |
| `CHANNEL_OPEN forwarded-tcpip` (ours)  | stream opened by the session process             |
| data, stderr, `exit-status`, `exit-signal` (ours) | the same, from the session process    |
| `CHANNEL_EOF` + `CHANNEL_CLOSE` (ours) | the session process's FIN                        |

Things worth knowing:

- **Request replies are in order, and answered in the callback.** russh
  only remembers whether the *latest* request on a channel wanted a reply,
  and OpenSSH pipelines `pty-req`, `env` and `shell` without waiting. So the
  callback waits for the session process's answer before returning, which
  holds up the connection's next message by a local round trip. That
  can't deadlock: before the program starts, nothing is queued ahead of the
  answer; after it starts, requests needing an answer are refused at once
  (the session process would refuse them anyway).
- **Each direction of a channel is its own future.** Client→session only
  waits on the smux stream; session→client only waits on russh. If one task
  did both, it could block on russh taking output while russh's loop
  blocks in a callback waiting for that task to take input.
- **russh's `Channel` queue must be drained.** russh delivers every event
  (window adjustments too) through a bounded queue per channel; leaving it
  full would stall the whole connection. For `session` channels we drop the
  `Channel` (russh then discards its events); forwarding channels read
  theirs until the client closes.
- **Terminal modes**: russh decodes them, and leaves `TTY_OP_END`
  placeholders for codes it doesn't know (such as IUTF8). We drop those
  when re-encoding, or they would end the list early.
- `env` values must be UTF-8: russh decodes them as strings.

## 6. Testing

`crates/shion-front/tests/ssh.rs` runs OpenSSH's `ssh` and `sftp` against a
real `shion-front` with real `shion-session` processes (without bwrap):
exec, stdin and EOF, environment, terminal, exit by signal, refused keys,
sftp, `-L`, `-R`, and sharing and lingering of session processes. A pty
driver (a Python script) checked interactive use: prompt, `stty size`,
resizing, `^C`.

That testing found two bugs outside the front-end:

- **Inherited ignored signals.** A non-interactive shell starts background
  jobs with SIGINT and SIGQUIT ignored, `nohup` ignores SIGHUP, and ignored
  signals stay ignored across `exec`. So with `shion-front &`, `^C` did
  nothing in a session, and teardown's SIGHUP would have done nothing under
  `nohup`. `shion-session` now resets those signals at startup, as sshd
  does for its children.
- **`cancel-tcpip-forward` answered too early**: aborting a tokio task only
  asks for it to stop, so the listening socket could outlive the reply.
  The session process now waits for the accept tasks to finish.

## 7. Known gaps

- **The master would trust the network side too much.** In a process split,
  the master should verify the public key signature itself (it needs the
  session identifier and signed data, which russh doesn't expose), and keep
  the host keys, signing for the network side as OpenSSH's monitor does,
  instead of handing them over (`Authority::host_keys`).
- Authentication: no passwords, keyboard-interactive or certificates.
- No early abort of a channel (`CHANNEL_CLOSE` before the session has
  finished is passed on as EOF; part 1, §4.6).
- Flow control: russh windows towards the client, but between the
  front-end and session processes there is none (part 1, §4.5).
- bwrap itself is untested here (it doesn't run on the development host).
