# Implementing a SSH3 server with privilege separation

A transcript of a chat with Gemini on how to implement user-based multiplexing, with privilege separation, in SSH3.

<a id="turn-20261010-feasibility"></a>
<turn timestamp="20261010T074254">

## [2026-10-10] How feasible/practical is implementing an SSH3 server?

<query>

### User's query

Please read/skim through the attached transcript: [Implementation of user-based multiplexing of SSH servers](ssh-server-multiplexing.md).

To summarize:  I'd like to have a scalable yet easy-to-use and efficient solution for SSH multiplexing that I can run on my own system when I deal with many AI agents.  I want each "sshd" to run in a sandbox (i.e. a new process wrapped by Bubblewrap) with application-specific settings.

I'll probably go with [sshpiper](https://github.com/tg123/sshpiper)-based solution today.  But it's interesting to me intellectually to explore other answers in this space.  Maybe their implementations aren't practical yet, but let's not jump to conclusions — we should be open to discussing them first.

From the discussion, it's clear that the complexity of the SSH2 protocol and of their implementations is getting in the way:

- I don't need the complexity of traditional SSH user authorization and authentication (modelled on Unix user accounts)
- I want a user database that's completely segreated from the host system's user accounts
- Privilege separation is hard to do because complicated connection state must be serialized and almost all libraries today do not support that
- Even though the SSH2 protocol is layered in a modular way, libraries entangle everything.  They generally do not expose raw SSH2 channels independently for easy forwarding.

Now the problems I'm encountering are solved by another technological stack, and I'm obviously not the first one to think of it.  Consider [SSH3](https://github.com/francoismichel/ssh3):

- Use the QUIC protocol to handle multiple channels within a single connection
- Allow any authorization/authentication methods that would normally work over HTTPS
- If, in the future, the Linux kernel implements QUIC, it might be possible to just hand over the socket from one process to as a standard file descriptor to a child process (just as happens with TCP connections when running a server in "inetd" mode), without having to terminate the connection at the proxy, and without serialization of complex connection state.

I control my clients (the AI agents, and myself) so switching to this "HTTPS-based SSH" wouldn't be that hard.  My main concern is the quality of implementation.  Or, rather, if I were to start my own independent implementation, how much work would it take?  This is by no means going to be something I'm prioritizing my own time on — as my real work lies elsewhere — but perhaps something I would hand an coding AI to build for me at some point in the uncertain future.  So, just imagining that scenario, what matters to the project of building a SSH3 server that can sandbox each user separately, are the following:

- how complex the specification is,
- the maturity of the components, such as QUIC implementations,
- and how difficult to implement is the existing end-user functionality in SSH: command execution, terminals, sftp, port forwarding
- what languages are available for a good implementation (I would personally prefer either Rust or C#)

Could you do a survey for me?
</query>

<response>

### AI's response: introduction

Here is an analysis of the SSH3 protocol and the feasibility of building a sandboxed, multiplexed server using it, directly addressing the architectural hurdles discussed in your `ssh-server-multiplexing.md` transcript.

SSH3 (currently an IETF experimental draft by François Michel and Olivier Bonaventure) fundamentally restructures remote shell access by mapping SSH semantics onto HTTP/3 and QUIC.

### 1. Complexity of the Specification
The SSH3 specification drastically reduces custom cryptographic complexity but retains legacy connection complexity.
* **What it offloads:** SSH3 completely eliminates the need to implement SSH-specific transport (RFC 4253) and authentication (RFC 4252) layers. Transport security is entirely handled by QUIC and TLS 1.3, while authentication leverages standard HTTP Authorization headers (Bearer tokens, OIDC, X.509 certificates). This solves the multi-tenancy routing issue discussed in your transcript; because it uses HTTP/3, the client can specify the user in the URL (e.g., `/ssh3?user=ai-agent`) and use TLS SNI, allowing a reverse proxy or single listener to dynamically spin up specific `bwrap` sandboxes before establishing the shell.
* **What it retains:** SSH3 intentionally reuses the standard SSH Connection Protocol (RFC 4254) for data framing. This means your implementation would still need to parse SSH channel requests for shells and subsystems.

### 2. Maturity of QUIC Components
The QUIC and HTTP/3 ecosystems are rapidly maturing and are highly stable in modern languages.
* **Rust:** The `quinn` crate (QUIC) and `h3` crate (HTTP/3 via Hyper) are robust, asynchronous, and widely used in production.
* **C# / .NET:** Microsoft has heavily invested in QUIC. The `System.Net.Quic` namespace (backed by the highly optimized `MsQuic` C library) is built directly into .NET and natively supports HTTP/3.

### 3. Difficulty of Implementing End-User Functionality
Because SSH3 reuses the RFC 4254 Connection Protocol, implementing the end-user features requires the exact same systems-level effort detailed in your `custom-sshd.md` transcript:
* **SFTP & Command Execution:** As noted in your prior chat, SFTP is not parsed by the server. It is simply a subsystem request. You would spawn `/usr/libexec/openssh/sftp-server` inside your `bwrap` sandbox and blindly pipe the QUIC stream bytes into its standard I/O. Command execution works the same way.
* **Terminals (PTY):** This remains the most complex OS-level task. The server must intercept PTY requests, issue Linux `openpty` syscalls, pass the slave descriptor to the sandboxed shell, and forward window-resize events.
* **Port Forwarding:** This becomes significantly easier with SSH3. Because QUIC natively supports multiplexed streams and unreliable datagrams, SSH3 supports both TCP and UDP port forwarding effortlessly, bypassing the head-of-line blocking issues of TCP-based SSHv2.

### 4. Language Selection: Rust vs. C#
Both languages are excellent choices for an HTTP/3 server, but **Rust is the clear winner for your specific architectural goals.**

Your requirement to strictly isolate processes using Bubblewrap (`bwrap`), pass raw file descriptors, and manipulate Linux pseudo-terminals (`pty`) relies heavily on low-level POSIX and Linux kernel primitives.
* **Rust** excels here: libraries like `nix` and the `tokio` asynchronous runtime provide safe, direct access to the `ioctl`, `fork`, and UNIX domain socket (`SCM_RIGHTS`) calls needed to build the "Sandbox Supervisor" model discussed in your transcript.
* **C#** is incredibly productive for the networking stack, but interfacing with Linux-specific namespace sandboxing and `pty` allocation via `DllImport` (P/Invoke) to `libc` will be brittle and cumbersome.
</response>
</turn>


<a id="turn-20261010-protocol-overview"></a>
<turn timestamp="20261010T075846">

## [2026-10-10] High-level overview of the SSH3 protocol

<query>

### User's query

Not having time to read all the technical documents in detail, could you walk me through, what the "SSH3" protocol as proposed currently — I assume the reference implementation in golang works the same — does at a high level? So:

- What HTTPS requests are being made? What URLs and what methods?
- Let's say I just use basic HTTPS authentication or client certificates (totally sufficient for my local use case), how does that step go in SSH3?
- How are SSH3 channels requested, opened and closed?

This would help me understand how much complexity is involved in an independent implementation.
</query>

<response>

### AI's response: introduction

Here is a high-level walkthrough of how the SSH3 protocol (as defined in `draft-michel-ssh3`) operates under the hood, mapping secure shell semantics onto modern HTTP/3.

### 1. HTTP Requests, URLs, and Methods
An SSH3 session (termed a "conversation") is initiated using the **HTTP Extended `CONNECT`** method.

* **The Request:** The client sends an HTTP/3 `CONNECT` request to a specific URI template on the server.
* **The URL:** The target user identity is explicitly passed in the URL, typically as a query parameter. For example: `[https://example.org:4443/ssh3?user=ai-agent](https://example.org:4443/ssh3?user=ai-agent)`.
* **The Protocol Header:** To inform the server that this is an SSH3 request and not a standard proxy tunnel, the request includes the pseudo-header `:protocol = "ssh3"`.

### 2. Authentication (Basic & Client Certificates)
Because SSH3 offloads authentication to the HTTP layer, the handshake is remarkably straightforward.

* **Basic Authentication:** If you are using a password or a simple token, the client simply attaches a standard HTTP `Authorization` header to the initial `CONNECT` request (e.g., `Authorization: Basic <base64-credentials>`).
* **Client Certificates (mTLS):** If you use X.509 client certificates, the authentication happens even earlier—during the underlying QUIC/TLS 1.3 handshake. The server validates the certificate before the HTTP/3 `CONNECT` request is even processed.
* **The Verdict:** If the server accepts the credentials, it replies with a `200 OK` HTTP response. The SSH3 conversation is now securely established.

### 3. Requesting, Opening, and Closing Channels
In traditional SSHv2 (RFC 4254), the server and client had to manually multiplex multiple channels (terminals, SFTP, port forwards) over a single TCP byte stream. SSH3 eliminates this completely by mapping SSH channels directly to **HTTP/3 bidirectional streams**.

* **Opening a Channel:** To start a shell or an SFTP session, the client opens a new HTTP/3 client-initiated bidirectional stream.
* **The Channel Payload:** The client writes a specific byte sequence to this new stream to identify it:
1. An experimental Signal Value (e.g., `0xaf3627e6`) to tell the HTTP/3 stack this stream is an SSH3 channel.
2. The Conversation ID.
3. The Channel Type (a UTF-8 string like `"session"` or `"direct-tcpip"`).
* **Data Transmission:** Once the stream is open, the client and server exchange SSH messages. SSH3 largely reuses the existing SSHv2 message formats (like `"pty-req"` or `"exit-status"`), but replaces rigid 32-bit integers with QUIC variable-length integers to save bandwidth.
* **Closing a Channel:** Because each channel has its own dedicated QUIC stream, closing a channel is as simple as closing the underlying HTTP/3 stream. The QUIC protocol handles the teardown natively.

In summary, implementing SSH3 removes the burden of writing custom cryptography, multiplexing, and flow control. The complexity shifts to managing HTTP/3 streams and translating standard HTTP semantics into Linux pseudo-terminals and process executions.
</response>
</turn>


<a id="turn-20261010-quic"></a>
<turn timestamp="20261010T081826">

## [2026-10-10] Multiplexing QUIC's channels

<query>

### User's query

I can't say I'm very familiar with QUIC or its interaction with HTTP/3 as I only had a brief contact with it while coding an internal web service where we could use HTTP/3.

Could you validate my assumptions below and confirm/disconfirm what I'm asking is possible:

- Assume there is a master process that is responsible for validating credentials.  That is, it handles only the `CONNECT` request.
- After the `CONNECT` request is successful, the master process launches the sandboxed child process for the session. It forwards all SSH3-marked streams bidirectionally to the child process.
- If the forwarding can be done with stdin/stdout rather than network sockets, that would be easier, although I'm not sure if QUIC libraries support that: running the channel-multiplexing logic through arbitrary byte streams.
- Everything else going in the HTTP/3 connection that is outside of the SSH3 protocol is rejected.
- The child process is the one implementing the necessary SSH features by parsing the SSH3 channels and sending responses back.
- Perhaps even one child process could be used for all simultaneous sessions of a particular user? That's useful for simultaneous sessions to share ephemeral state like temporary filesystems.
</query>

<response>

### AI's response

Your assumptions are mostly correct in theory, but they hit a significant architectural wall regarding how QUIC and HTTP/3 multiplexing interacts with standard Unix pipes (`stdin`/`stdout`).

Here is the validation of your assumptions:

*   **Assumption 1 (Master process handles `CONNECT`):** Correct. The master process terminates the UDP connection, handles the QUIC and TLS 1.3 handshakes, and processes the HTTP/3 `Extended CONNECT` request. It validates the HTTP `Authorization` headers or X.509 client certificates.
*   **Assumption 4 (Reject everything else):** Correct. The master process acts as a strict gateway. Any HTTP/3 request that does not include the `:protocol = "ssh3"` pseudo-header is immediately dropped.
*   **Assumption 6 (One child process per user):** Correct, and highly recommended. This is the "Sandbox Supervisor" model. You spawn one `bwrap` environment per user, running a tiny init daemon inside. This allows multiple simultaneous SSH channels (shells, SFTP) to share the same ephemeral `tmpfs` and process namespace.
*   **Assumption 5 (Child parses SSH3 channels):** Correct. While SSH3 relies on QUIC for encryption and multiplexing, the payload inside those streams still contains SSH Connection Protocol messages (like `"pty-req"`, window resizes, and exit statuses). The sandboxed child process must parse these frames to know whether to spawn `/bin/bash` or `/usr/libexec/sftp-server`.

**Where the architecture breaks down: Assumptions 2 & 3 (Forwarding via `stdin`/`stdout`)**

You cannot simply forward all SSH3-marked streams bidirectionally over a single `stdin`/`stdout` pipe to the child process without destroying the primary benefit of QUIC.

In SSH3, every new SSH channel (e.g., one shell, one port forward) is mapped to its own dedicated HTTP/3 bidirectional stream. QUIC demultiplexes these streams at the transport layer to prevent head-of-line blocking. QUIC libraries are fundamentally tied to UDP datagrams and cannot natively run their stream-multiplexing logic over a raw, reliable byte stream like standard Unix pipes.

Because the master process terminates the QUIC layer, it extracts Stream A, Stream B, and Stream C into memory. If you try to write all three streams into the child's single `stdin`, the data will become a jumbled, corrupted mess unless you invent your own custom framing protocol to separate the bytes—which completely defeats the purpose of using QUIC for multiplexing in the first place.

**The Required Architecture**

To make this work, you must use Unix Domain Sockets and file descriptor passing (IPC) instead of basic `stdin`/`stdout`:

1.  The master process validates the HTTP/3 `CONNECT` request and spawns the `bwrap` Sandbox Supervisor, connected via a single Unix Domain Socket.
2.  When the client opens a new HTTP/3 stream for a shell session, the master process detects the new stream.
3.  The master creates a new local pipe (or socket pair) and uses `SCM_RIGHTS` to pass one end of that pipe over the IPC socket to the Sandbox Supervisor.
4.  The master process bridges the QUIC stream bytes to its end of the local pipe.
5.  The Sandbox Supervisor reads the SSH3 `"session"` string from the pipe, parses the `"pty-req"` message, spawns the shell, and bridges the pipe to the shell's standard I/O.
</response>
</turn>


<a id="turn-20261010-unix-domain-sockets"></a>
<turn timestamp="20261010T082317">

## [2026-10-10] Translating QUIC channels to Unix domain sockets

<query>

### User's query

Could you walk me through this approach with Unix domain sockets? I'm vaguely aware that these capabilities exist but never used it myself. How do would HTTP/3 bi-directional streams be mapped to Unix domain sockets operations?
</query>

<response>

### AI's response

Passing file descriptors over Unix domain sockets using `SCM_RIGHTS` acts as the perfect bridge between high-level HTTP/3 streams and low-level Linux processes. This technique allows the master process to dynamically create dedicated pipes for each new SSH channel and hand them into the sandbox without needing to parse the data or write a custom multiplexer.

Here is the step-by-step breakdown of how this mapping works in practice:

**1. The Control Socket (Initial Setup)**
When the master process successfully validates the initial HTTP/3 `CONNECT` request, it creates a Unix domain socket pair using the `socketpair()` system call. It keeps one end (the Master Control Socket) and spawns the `bwrap` child process, passing the other end (the Sandbox Control Socket) into the sandbox as an inherited file descriptor. This control channel is only used for sending metadata and file descriptors, never the actual SSH data.

**2. A New HTTP/3 Stream Arrives**
The client decides to open a shell, initiating a new bidirectional HTTP/3 stream over the existing QUIC connection. The master process accepts this stream. At this point, the master process holds an async reader/writer pair for the HTTP/3 stream, but the sandboxed child process has no idea this channel exists.

**3. Creating the Channel Bridge**
To connect the two, the master process creates a *new* `socketpair()`. Let's call these two connected file descriptors `Master_Data_FD` and `Sandbox_Data_FD`.

**4. Sending the File Descriptor (`SCM_RIGHTS`)**
The master process constructs a small control message (e.g., `{"event": "new_channel", "channel_id": 1}`). It sends this payload over the Master Control Socket to the child. Crucially, it attaches `Sandbox_Data_FD` to this message using a special control message header called `SCM_RIGHTS`.

`SCM_RIGHTS` instructs the Linux kernel to extract the file descriptor from the sender's process table and seamlessly inject a duplicate into the receiver's process table upon delivery. Once sent, the master process safely closes its own copy of `Sandbox_Data_FD` to prevent resource leaks.

**5. The Master Process Bridges the Data**
The master process now acts as a dumb pipe. It spawns an asynchronous background task that blindly copies bytes from the HTTP/3 stream's reader to `Master_Data_FD`, and copies bytes from `Master_Data_FD` to the HTTP/3 stream's writer. It does not parse the SSH frames; it just moves the QUIC payload bytes back and forth.

**6. The Sandbox Supervisor Takes Over**
Inside the sandbox, the supervisor daemon receives the control message, and the kernel hands it the newly injected `Sandbox_Data_FD`. The supervisor now has a direct, dedicated socket linked straight to the master's bridging task.
* It reads the first few bytes from `Sandbox_Data_FD` to parse the SSH3 channel request (e.g., seeing `"pty-req"`).
* It spawns the requested command (like `/bin/bash` or `sftp-server`).
* It hands `Sandbox_Data_FD` to the newly spawned command to use as its standard input and standard output.

When the HTTP/3 stream is closed by the client, the master process closes `Master_Data_FD`. The kernel automatically propagates this EOF (End of File) to `Sandbox_Data_FD`, naturally terminating the shell inside the sandbox without the master and child needing to manually coordinate the teardown over the control channel.

Do you have a preference for how the sandboxed supervisor handles multiple simultaneous shells for the same user—would you spawn them as sibling processes sharing the same temporary filesystem, or nested in some other way?
</response>
</turn>


<a id="turn-20261010-pty"></a>
<turn timestamp="20261010T084044">

## [2026-10-10] How much work to implement pseudo-terminals and command execution?

<query>

### User's query

Could you look at the source code to "russh" and see how much work it takes to implement PTYs and command execution? More precisely, I think "russh" as a framework does not implement those features itself but there's probably some other downstream project that uses "russh" to implement those things. Could you search on the Web?

In the optimistic case, we can just adapt its logic but make it read the SSH messages over raw FDs, as you described above. It would still be a lot of work for a human, but fortunately now I have AI agents! Perhaps the key is that they have an existing pattern to follow.

And how much work is parsing the SSH3-channel messages?
</query>

<response>

### AI's response: introduction

You are absolutely right on both fronts.

### 1. `russh` and the PTY/Command Execution Ecosystem
Your intuition is correct: `russh` is strictly an SSH protocol library. It handles the cryptography and the packet framing, but when the client asks for a PTY or to execute a command, `russh` simply triggers a callback trait method (e.g., `pty_request` or `exec`). It leaves the actual OS-level work entirely up to you.

However, the Rust ecosystem has already solved this.
* **Command Execution (`exec`):** This is straightforward. You use `tokio::process::Command` to asynchronously spawn a standard Linux process. You request standard pipes (`Stdio::piped()`), and then write a small loop that reads data from the SSH channel and writes it to the process's `stdin`, and vice versa for `stdout`/`stderr`.
* **PTY Allocation:** Handling Pseudo-Terminals (PTYs) manually involves calling raw Linux C APIs like `openpty` or `ioctl`. Fortunately, there are downstream wrapper crates like `portable-pty` and `tokio-pty-process`. These crates handle the heavy lifting of allocating the Master/Slave PTY pairs and spawning a child process hooked up to the PTY slave. Furthermore, there are high-level wrapper libraries built *on top* of `russh` (like the `simple_ssh` crate) that provide ready-to-use boilerplate for interactive PTY sessions, auto-resizing, and raw mode support.

If you were to build your Unix Domain Socket architecture, an AI agent could easily adapt this existing boilerplate. The only difference is that instead of bridging the PTY's output back to a `russh` channel, the Sandbox Supervisor would bridge the PTY's output to the `Sandbox_Data_FD` passed in via `SCM_RIGHTS`.

### 2. How much work is parsing SSH3-channel messages?
Parsing the SSH3 messages in the child process would actually be a remarkably lightweight task—perfect for an AI agent to write.

Here is why:
According to the `draft-michel-ssh3` specification, SSH3 intentionally abandons the cryptographic Transport and Authentication layers of traditional SSH, but it **completely reuses the SSHv2 Connection Protocol (RFC 4254)** for its channel data.

The only modification SSH3 makes to RFC 4254 is swapping out rigid 32-bit integers for QUIC variable-length integers (varints) to save bandwidth. This means parsing an SSH3 channel stream is just basic, stateless TLV (Type-Length-Value) binary decoding.

To implement the features you want, your sandboxed child process only needs to parse a handful of message types:
* **`"pty-req"`:** Read a string (the `TERM` environment variable like `xterm`), and four integers (width/height in characters and pixels).
* **`"env"`:** Read two strings (variable name and value).
* **`"exec"`:** Read one string (the command to run).
* **`"subsystem"`:** Read one string (e.g., `"sftp"`).
* **`"window-change"`:** Read the updated width and height integers.

Because there is zero encryption, zero MAC validation, and zero flow-control window management (QUIC handles all of that natively), writing an SSH3 parser inside the child process is just writing a loop that reads a few bytes, matches a string, and triggers the `tokio::process` logic. An AI agent could generate a complete, robust parser for these five message types in a few hundred lines of code.
</response>
</turn>


