# shion — design, part 1: the session process

Status: decisions of 2026-10-14 incorporated (see §8)

## 1. Goals and non-goals

shion is an SSH server for *app-level* users (AI agents, mostly). Each user's
sessions run inside a Bubblewrap sandbox whose parameters come from that
user's policy. One listening port serves every user; the login user name picks
the sandbox.

Goals:

- **Privilege separation.** The process that holds the host key and checks
  credentials (the *front-end*) never runs user code. Everything that touches
  user code (the *session process*) runs inside the sandbox and holds no
  secrets.
- **No Unix accounts.** Users, shells, home directories and environment come
  from shion's own configuration. Nothing reads `/etc/passwd`, nothing calls
  `setuid`, nothing needs root.
- **Protocol boundary = SSH3 channel format.** Between front-end and session
  process, each SSH channel is a byte stream in the SSH3 wire format
  (draft-michel-remote-terminal-http3, as implemented by sshoq). Today the
  front-end translates SSH2 (russh) into that format; later an HTTP/3 front-end
  could pass SSH3 streams through without translation.
- **Streams multiplexed with smux** (async-smux) over a single byte-stream
  carrier: pipes today, a socket to a remote machine later, a named pipe on
  Windows maybe.

Non-goals for the first iteration: X11 forwarding, agent forwarding, the SSH3
(QUIC) front-end, Windows.

## 2. Process topology

```
                      untrusted network
                             │  SSH2 (TCP)
                             ▼
┌──────────────────────────────────────────────────────────────┐
│ shion-front  (unprivileged service user)                     │
│  russh server · host key · user DB · auth · policy           │
│  per user: spawns  bwrap <policy args> -- shion-session      │
│  translates russh callbacks  ⇄  SSH3 messages on smux streams│
└───────────────┬──────────────────────────────────────────────┘
                │ carrier = session's stdin/stdout (one pipe pair)
                │ smux frames (8-byte header)
┌───────────────▼──────────────────────────────────────────────┐
│ bwrap sandbox (user + mount + pid [+ net] namespaces)        │
│                                                              │
│  shion-session                                               │
│   ├── smux stream 1  control  (conversation A)               │
│   ├── smux stream 3  "session" channel → pty → bash -l       │
│   ├── smux stream 5  "session" channel → pipes → make -j8    │
│   ├── smux stream 7  "session" channel → sftp-server         │
│   └── smux stream 9  "direct-tcpip"    → 127.0.0.1:8080      │
└──────────────────────────────────────────────────────────────┘
          stderr of shion-session → front-end's log
```

Notes:

- **The front-end builds the `bwrap` command line.** The session process does
  not know or care that it is sandboxed. This keeps it portable (it could run
  unsandboxed on a remote machine or on Windows) and keeps all policy in one
  trusted place.
- **One session process per user, shared by that user's connections.** Every
  SSH2 connection becomes one *conversation*, which is exactly the concept SSH3
  already has: every channel header names the conversation it belongs to.
  Simultaneous logins therefore share the sandbox (same tmpfs, can see each
  other's processes). This is the general case: the session process needs
  per-conversation bookkeeping anyway, and running one session process per
  connection is then just a front-end policy choice; the protocol doesn't
  change.
- **bwrap stays PID 1** of the PID namespace (we don't pass `--as-pid-1`), so
  orphaned grandchildren get reaped by bwrap's init and not by us. When
  shion-session exits, the namespace and everything in it is torn down.

## 3. Threat model: what privilege separation buys here

The session process runs inside the sandbox *as the same (namespaced) uid as
the agent's shell*. A hostile agent can therefore `ptrace` it, read its
memory, or kill it. **Assume the session process is compromised** and design
so that this doesn't matter:

1. **It holds no secrets.** No host key, no user database, no credentials. It
   learns the user name and policy-derived settings from the front-end and
   that is all it ever knows.
2. **The front-end treats the carrier as hostile input.** Every frame and
   message coming up from the session is length-bounded and validated. The
   front-end only lets a session open streams for conversations that belong to
   that session's user, and it limits streams, buffered bytes and request
   rates per session.
3. **Defense in depth, not a boundary:** the session process calls
   `prctl(PR_SET_DUMPABLE, 0)` at startup, which blocks same-uid `ptrace` and
   `/proc/<pid>/mem` access. It makes casual hijacking harder; we don't rely
   on it.
4. **Children never inherit the carrier.** Rust opens everything `O_CLOEXEC`,
   and every child gets explicit stdio. We'll assert this in a test
   (`ls -l /proc/self/fd` from a spawned shell).

This is the property OpenSSH's privsep gives you, with one difference:
OpenSSH's unprivileged child is still a full SSH2 implementation handed a
serialized crypto state. Ours never sees crypto at all. It speaks a much
smaller protocol and holds nothing worth stealing.

## 4. Wire protocol between front-end and session

### 4.1 Layering

```
  ┌──────────────────────────────────────────────┐
  │ SSH3 channel messages (varint-encoded RFC4254)│  per stream
  ├──────────────────────────────────────────────┤
  │ smux stream (SYN / PSH / FIN, 8-byte header)  │
  ├──────────────────────────────────────────────┤
  │ carrier: any AsyncRead + AsyncWrite           │
  └──────────────────────────────────────────────┘
```

The mapping from QUIC concepts to smux concepts:

| SSH3 over HTTP/3            | shion over smux                           |
|-----------------------------|-------------------------------------------|
| QUIC connection             | carrier (stdin/stdout pipe pair)          |
| HTTP/3 extended CONNECT     | control stream (one per conversation)     |
| conversation ID (stream ID) | ID assigned by the front-end in CONV_OPEN |
| client bidi stream          | smux stream opened by front-end (odd IDs) |
| server bidi stream          | smux stream opened by session (even IDs)  |
| stream FIN (half-close)     | smux FIN (async-smux supports half-close) |
| stream reset                | smux FIN both ways + drop                 |
| QUIC per-stream flow control| **missing in smux v1**, see §4.5          |
| QUIC datagrams (UDP fwd)    | not supported (UDP forwarding deferred)   |

### 4.2 Channel streams: SSH3 format, byte-for-byte

I checked sshoq's `channel.go` and `message/` to confirm the format. A channel
stream starts with a header:

```
varint   0xaf3627e6          signal value ("this is an SSH3 channel")
varint   conversation id     here: the smux ID of the control stream
string   channel type        "session", "direct-tcpip", ...
varint   max packet size
...      type-specific bytes (e.g. direct-tcpip: address + port)
```

followed by a sequence of messages, each `varint type` + fields, where SSH3
replaces RFC 4254's `uint32` with QUIC varints and strings are
`varint length || bytes`:

| type | message                    | fields                                     |
|------|----------------------------|--------------------------------------------|
| 91   | CHANNEL_OPEN_CONFIRMATION  | max packet size                            |
| 92   | CHANNEL_OPEN_FAILURE       | reason code, message, language tag         |
| 94   | CHANNEL_DATA               | string data                                |
| 95   | CHANNEL_EXTENDED_DATA      | varint data type (1 = stderr), string data |
| 98   | CHANNEL_REQUEST            | string type, bool want-reply, request body |
| 99   | CHANNEL_SUCCESS            | (none)                                     |
| 100  | CHANNEL_FAILURE            | (none)                                     |

Channel requests we handle: `pty-req`, `env`, `shell`, `exec`, `subsystem`,
`window-change`, `signal`, and from our side `exit-status` and `exit-signal`.

What SSH3 drops relative to SSH2, and therefore what we drop too:
`WINDOW_ADJUST` (the transport does flow control), `EOF` (stream half-close),
`CLOSE` (stream close), and channel numbers (one channel per stream).

**One wart to be aware of:** messages carry no overall length, and a request
body's length is implied by its type. So a receiver *can't skip* a request
type it doesn't know. sshoq returns an error in that case (and its
`ParseMessage` actually `panic`s on message types it doesn't expect, which
confirms your suspicion about its robustness). Arguably that's intentional:
a request you don't understand can't be safely ignored anyway. **Decision:
accept the wart for compatibility.** An unknown request type is a protocol
error that resets that one stream. The front-end never forwards request types
the session didn't advertise in CONV_ACCEPT (§4.3). The codec does parse
`x11-req`, which we don't support, so it can be refused politely with
CHANNEL_FAILURE and doesn't kill the channel.

Where sshoq has drifted from the draft, we don't follow it:

- It has a non-standard `sftp` channel request (its own file-operation RPC).
  We don't implement it; sftp is the standard `subsystem` request.
- Its port-forwarding headers are visibly buggy. `buildRequestTCPReverse…`
  writes the port twice with a "TODO: If I do not duplicate this, the port
  does not arrive" comment, and `ForwardingRequest.Write` copies into the
  wrong buffer. These headers also carry only IP addresses, while SSH2's
  `direct-tcpip` carries a *host name*, which would have to be resolved
  inside the sandbox. We'll decide the forwarding formats in M4, and they
  won't be part of the M0 codec.

### 4.3 Control stream (per conversation)

SSH3 does this part with HTTP (the CONNECT request, its headers, and the 200
response), so there's no SSH3 format to copy. Since this protocol is ours,
it doesn't need SSH3's wart: **every control message is length-delimited**
(`varint type || varint body-length || body`). Receivers can skip message
types they don't know, and they ignore extra trailing fields in a body, so
new fields can be appended later without a version bump. Message numbers
come from SSH's local-extension range 192–255.

Front-end → session (the front-end opens one control stream per SSH2
connection):

```
192 CONV_OPEN      varint version, varint conversation id,
                   attributes: varint n, n × (string key, string value)
80  GLOBAL_REQUEST string name, bool want-reply, bytes body   (M4)
```

Session → front-end:

```
193 CONV_ACCEPT    varint version, string-list channel types,
                   string-list request types
194 CONV_REJECT    string reason
81  REQUEST_SUCCESS bytes body   (reply to a global request)
82  REQUEST_FAILURE
```

The front-end assigns the **conversation ID** (unique per session process)
and doesn't use the smux stream ID, so the scheme doesn't depend on what the
mux layer exposes. CONV_OPEN carries only facts about *this connection*, as
string attributes so they read well in logs:

| key              | example                     | used for                       |
|------------------|-----------------------------|--------------------------------|
| `user`           | `agent-7`                   | sanity check against `--user`  |
| `client-address` | `192.0.2.5 51334`           | `SSH_CLIENT`, `SSH_CONNECTION` |
| `server-address` | `192.0.2.1 2222`            | `SSH_CONNECTION`               |
| `client-version` | `SSH-2.0-OpenSSH_10.0`      | logging                        |
| `auth-method`    | `publickey`                 | logging, env                   |
| `auth-key`       | `SHA256:…` fingerprint      | logging, maybe per-key env     |

Everything about the *user* comes from the session process's command line
(§5.6).

Closing the control stream (FIN both ways) ends the conversation. The session
then sends SIGHUP to every process group the conversation started.

### 4.4 Who opens what

- Front-end opens: control streams, `session` and `direct-tcpip` channels
  (client-initiated in SSH terms).
- Session opens: `forwarded-tcpip` channels (for remote port forwards, i.e.
  `ssh -R`), naming the conversation that requested the forward in the header.
  The front-end checks that conversation ID before mapping the stream onto a
  russh channel.

### 4.5 Flow control: the one real gap in the smux idea

I read async-smux 0.4.0. It implements smux **protocol v1**: SYN, FIN, PSH and
NOP. It has no per-stream window (that's v2's UPD frame), and its receive
budget (`max_rx_queue`) is shared by the whole carrier. Once the budget is
exhausted, the worker stops reading the carrier entirely. So **one stream
whose consumer stops reading stalls every stream on the carrier.** For
example, if an agent's client stops reading a port forward, the interactive
shell on the same carrier freezes too.

**Decision: deferred.** Over a local pipe the stall only happens when a
consumer really stops reading, and interactive shells and exec rarely trip
it. If the session process ever runs remotely, where this would really
bite, the carrier would become QUIC (which has per-stream flow control)
rather than a better smux. All channel code goes through
`AsyncRead`/`AsyncWrite`, so changing the carrier later won't touch it.

## 5. Inside the session process

### 5.1 Runtime structure (tokio)

```
main
 ├─ carrier = join(stdin, stdout)           (tokio::io::join)
 ├─ smux worker task                        (drives all frame I/O)
 ├─ accept loop: for each incoming stream →
 │     read header → spawn task by type:
 │        control           → conversation::run
 │        "session"         → session_channel::run
 │        "direct-tcpip"    → forward::direct
 └─ SIGCHLD handled by tokio::process (per-child wait futures)
```

Each channel is one tokio task that owns its stream and its child process.
Nothing is shared between channels except a `Conversation` registry
(`Arc<Mutex<…>>`) used for SIGHUP-on-close and forward bookkeeping. If you're
used to C++ asio: this is "one coroutine per channel", and the borrow checker
pushes you toward exactly this ownership shape.

### 5.2 The `session` channel state machine

Expressed as a Rust `enum` so illegal transitions don't compile (`exec` after
`shell`, `pty-req` after start, and so on):

```
          pty-req / env / (want-reply → SUCCESS|FAILURE)
            ┌────┐
            ▼    │
       ┌─────────┴─┐  shell | exec | subsystem   ┌──────────┐
 open ─►  Setup    ├────────────────────────────►│ Running  │
       └───────────┘     spawn fails → FAILURE   └────┬─────┘
                                                      │ data ⇄ stdin/stdout/stderr|pty
                                                      │ window-change → TIOCSWINSZ
                                                      │ signal        → kill(-pgid)
                                                      │ peer FIN      → close stdin (see below)
                                                      ▼
                                              ┌──────────────┐
                                              │ Draining     │ child exited; flush remaining output
                                              └──────┬───────┘
                                                     ▼
                                   exit-status | exit-signal, then FIN
                                                     ▼
                                       wait for peer FIN → drop stream
```

Ordering rules from RFC 4254 that we have to keep:

- All stdout/stderr data goes out **before** `exit-status`.
- With a pty, the child exiting doesn't mean the output is finished.
  Grandchildren may hold the slave open. Like OpenSSH, we read the master
  until `EIO` *or* until the child has exited and the master has been idle
  briefly. We don't wait forever on a backgrounded daemon.
- Peer FIN on a pipe session closes the child's stdin. On a pty session
  there's no stdin to close, so OpenSSH just stops reading. We do the same.

### 5.3 Command execution

- `shell` → `<shell> -l` (argv[0] is `-bash`, as login shells expect)
- `exec cmd` → `<shell> -c cmd`
- `subsystem name` → the command from `--subsystem` (§5.6) (e.g.
  `sftp` → `/usr/libexec/openssh/sftp-server`); unknown names → FAILURE.
- The environment is **built from scratch**, never inherited: `HOME`,
  `USER`/`LOGNAME` (the app-level name), `SHELL`, `PATH`, `TERM` (if pty),
  `SSH_CONNECTION`-style info, then accepted `env` requests filtered by the
  `--accept-env` globs. cwd = home.
- Every child runs `setsid()` in `pre_exec`, so it gets its own process group.
  `signal` requests and conversation teardown target the group.

Without a pty we use `tokio::process::Command` with three pipes. That's
straightforward.

### 5.4 Pseudo-terminals

I'd write this ourselves on top of `rustix` (the `pty` and `termios` modules)
rather than pull in `portable-pty`, which is blocking and thread-based. It's
about 200 lines and the most Unix-heavy part of the project:

1. `openpt(O_RDWR|O_NOCTTY|O_CLOEXEC)`, `grantpt`, `unlockpt`, `ptsname`.
2. Apply `pty-req`: `TIOCSWINSZ` with cols/rows/px, then decode the RFC 4254
   §8 *encoded terminal modes* (opcode byte + `uint32`, terminated by 0. Note
   that inside SSH3 this blob is still SSH2-encoded) into `termios`.
3. Spawn with `Command::pre_exec`: `setsid()`, open the slave (which makes it
   the controlling terminal, or use `TIOCSCTTY` explicitly), and dup it to
   0/1/2. `pre_exec` is `unsafe` because it runs between fork and exec, so
   only async-signal-safe calls are allowed there. This is a good place to see
   how Rust's `unsafe` contract maps to the C rules you already know.
4. Master set `O_NONBLOCK` and wrapped in `tokio::io::unix::AsyncFd`, which
   gives `AsyncRead`/`AsyncWrite` without a thread per pty.
5. `window-change` → `TIOCSWINSZ` on the master (the kernel sends `SIGWINCH`).

Linux-only for now, behind a `pty` module with a small trait so a ConPTY
backend could slot in later.

### 5.5 Port forwarding (M4)

- `direct-tcpip`: the session connects *from inside the sandbox's network
  namespace*. With `--unshare-net` that means only the sandbox's loopback,
  which is exactly right for "let me reach the dev server my agent started".
  Policy can forbid it outright.
- `tcpip-forward` (global request on the control stream): the session listens
  inside the sandbox and opens a `forwarded-tcpip` stream per accepted
  connection.
- Reaching *out* of the sandbox to arbitrary hosts is deliberately not the
  session's job. If we ever want it, the front-end does it on the host
  network, policy permitting.

### 5.6 Command line: per-user settings

There's one session process per user, so per-user settings are exactly what
the command line should carry. The front-end's per-user configuration is
just an argv template, which you edit; nothing in it is hidden:

```
bwrap --unshare-all --die-with-parent \
      --ro-bind /usr /usr --symlink usr/bin /bin ... \
      --bind ~/agents/agent-7 /home/agent-7 \
      -- /usr/libexec/shion/shion-session \
         --user agent-7 --home /home/agent-7 --shell /bin/bash \
         --setenv PATH=/usr/local/bin:/usr/bin \
         --accept-env 'LANG' --accept-env 'LC_*' \
         --subsystem sftp=/usr/libexec/openssh/sftp-server \
         --linger 300
```

| option                       | meaning                                                   |
|------------------------------|-----------------------------------------------------------|
| `--user NAME`                | app-level user name → `USER`, `LOGNAME`                   |
| `--home DIR`                 | `HOME` and initial cwd                                    |
| `--shell PATH`               | login shell for `shell` and `exec`                        |
| `--setenv NAME=VALUE` (rep.) | base environment (built from scratch, nothing inherited)  |
| `--accept-env GLOB` (rep.)   | which client `env` requests are honored                   |
| `--subsystem NAME=CMD` (rep.)| subsystem table                                           |
| `--allow-forwarding …` (M4)  | port-forwarding permissions                               |
| `--linger SECONDS`           | keep the sandbox alive this long after the last logout    |

Everything on this command line is visible inside the sandbox
(`/proc/<pid>/cmdline`), which is fine because the session process holds no
secrets (§3).

## 6. Crate layout (Cargo workspace)

```
shion/
├── Cargo.toml                 [workspace]
├── crates/
│   ├── shion-wire/            pure codec, no I/O: varint, string, channel
│   │                          header, messages, channel requests, control
│   │                          messages; tokio_util::codec Decoder/Encoder
│   ├── shion-session/         the session process (bin + lib for tests)
│   ├── shion-attach/          debug client: spawns shion-session (optionally
│   │                          under bwrap) and gives you an interactive pty
│   │                          or runs one exec, so you can test M1–M3
│   │                          before any SSH front-end exists
│   └── shion-front/           russh front-end (later)
├── docs/
└── notes/
```

`shion-wire` is shared by everything and gets the most tests. It's also the
gentlest place to start learning Rust: no async, no `unsafe`, just
`enum`s, `Result`, and slices. For interop, we'll port the test vectors from
sshoq's `message_test.go`, and later run a test that feeds bytes produced by
sshoq's Go encoder through our decoder.

Main dependencies: `tokio`, `tokio-util`, `bytes`, `async-smux`, `rustix`,
`thiserror`, `tracing`, `clap`; later `russh`.

## 7. Milestones

| #  | Deliverable                                                                  | How we test it                                   |
|----|------------------------------------------------------------------------------|--------------------------------------------------|
| M0 | Workspace and `shion-wire` codec                                             | unit tests, sshoq vectors                        |
| M1 | session: carrier, control stream, `exec` over pipes, `exit-status`           | integration test spawns binary, drives smux      |
| M2 | pty, `shell`, `window-change`, `signal`, terminal modes; `shion-attach`      | interactive `bash`, `vim`, resize, `^C`          |
| M3 | subsystems (sftp), env allowlist, conversation teardown, `PR_SET_DUMPABLE`   | `sftp` via shion-attach; fd-leak test            |
| M4 | `direct-tcpip`, `tcpip-forward` / `forwarded-tcpip`                          | curl through a forward                           |
| M5 | `shion-front`: russh, user DB, bwrap policy, SSH2⇄SSH3 translation           | real `ssh`, `sftp`, `ssh -L/-R` against it       |

## 8. Decisions (2026-10-14)

1. **Flow control:** deferred (§4.5). If the session process ever runs
   remotely, the carrier becomes QUIC rather than a better smux.
2. **Session granularity:** one session process per user, shared across
   logins. One per connection is a front-end policy variant.
3. **Fidelity:** channel streams stay byte-compatible with the SSH3 draft and
   sshoq, unknown-request wart included. Exceptions: sshoq's own `sftp`
   request, and the forwarding headers, which get decided in M4.
4. **Settings:** per-user settings on the session process's command line
   (§5.6). Per-connection facts go in CONV_OPEN attributes (§4.3).
