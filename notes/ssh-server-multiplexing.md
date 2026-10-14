# Implementation of user-based multiplexing of SSH servers

A transcript of a chat with Gemini on how to implement user-based multiplexing in SSH servers.

<a id="turn-20260928-russh-privilege-separation"></a>
<turn timestamp="20260928T170105">

## [2026-09-28] russh and privilege separation

<query>

### User's query

I'm toying with the idea of implementing a SSH server that, unlike OpenSSH's `sshd`, does not depend on the standard Unix user database but reads its own configuration file for users. In other words, as is typical for database (SQL) servers used for "apps" or "services", the server's idea of "users" is decoupled from the user accounts at the OS level.

I'm not at the scale where I really need such a SSH server yet, so I just want a preliminary investigation into how hard it is to implement. To be specific let's look at using "russh" (the SSH library suite written in Rust).

I have one critical requirement though which does not come naturally to library-based implementations: I want privilege separation. So, like OpenSSH's `sshd`, I want the server to fork itself after the user has been selected. But I want to do something even more stricter than OpenSSH's dropping of `root` privileges: I want the forked process to go execute a sandboxing wrapper, specifically Bubblewrap (`bwrap`) before continuing to communicate over the socket passed in from the parent process using the SSH protocol. (Why sandbox? Because the other side will be an AI agent.)

Could you confirm first, whether russh supports what I want, and then analyze how the code would be structured?
</query>

<response>

### AI's response: introduction

Using `russh` to implement a custom, OS-decoupled SSH server is entirely supported, but your specific plan for privilege separation—passing the socket to a sandboxed process to *continue* the SSH protocol—is not possible with this library.

Here is an analysis of why that specific execution path fails, and how you should structure the architecture to achieve your exact security goals safely.

##### The Problem with State Transfer
OpenSSH achieves its strict post-authentication privilege separation by doing something very specific: the pre-authentication process serialises its entire cryptographic state (session keys, sequence numbers, negotiated ciphers) and exports it over an IPC socket to the newly spawned `sshd-session` child process before exiting.

`russh` does not support serializing or exporting its active `Session` state. The session state is heavily intertwined with memory buffers and `tokio` asynchronous tasks. Furthermore, because `bwrap` requires an `exec()` call to replace the process binary, the original memory space containing the `russh` state would be destroyed. You cannot start the SSH handshake in one process and seamlessly resume that same encrypted connection inside a `bwrap` payload using `russh`.

##### The Recommended Architecture: Terminate and Pipe
Instead of putting the SSH protocol parser inside the sandbox, you terminate the SSH connection in the parent process and only sandbox the resulting command execution.

Because your SSH server relies on a custom database rather than `/etc/shadow`, **your parent process does not need root privileges**. You can run the entire `russh` parent server as a restricted, unprivileged service user (e.g., `ai-ssh-daemon`), eliminating the need for OpenSSH's complex root-to-user privilege drops.

1. **The Unprivileged Parent:** Handles the TCP connection, custom authentication, and SSH encryption/decryption using `russh` and `tokio`.
2. **The Sandboxed Child:** When the AI agent requests a shell or command execution, the parent uses `tokio::process::Command` to spawn `bwrap`.
3. **The Bridge:** Instead of passing the TCP socket, the parent passes standard OS pipes (`stdin`/`stdout`/`stderr`) to `bwrap`. The parent decrypts incoming SSH traffic, writes it to the sandbox's `stdin`, and encrypts the sandbox's `stdout` to send back to the AI agent.

##### Code Structure Analysis

To build this, you will need to implement two primary `russh` traits: `Server` and `Handler`.

**1. The Server Trait**
This handles incoming TCP connections and instantiates a new session state for each connecting client.

```rust
use russh::server::{Server, Session};
use std::net::SocketAddr;

###[derive(Clone)]
struct MyServer {
    // A connection pool to your database (e.g., sqlx::PgPool)
}

impl Server for MyServer {
    type Handler = AiAgentSession;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        AiAgentSession {
            // Pass in database handles or initialize empty pipes
            child_stdin: None,
        }
    }
}
```
**2. The Handler Trait**
This is where the custom authentication and process sandboxing occur.

```rust
use russh::server::{Auth, Handler, Msg};
use russh::ChannelId;
use tokio::process::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::process::Stdio;

struct AiAgentSession {
    child_stdin: Option<tokio::process::ChildStdin>,
}

###[async_trait::async_trait]
impl Handler for AiAgentSession {
    type Error = anyhow::Error;

    // 1. Custom Database Authentication
    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        // Query your custom SQL/database here. 
        // Completely decoupled from the OS user database.
        let is_valid = check_db(user, password).await; 
        
        if is_valid {
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject)
        }
    }

    // 2. Authorize the channel opening
    async fn channel_open_session(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    // 3. Spawn the Sandbox on command execution
    async fn exec(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command_string = String::from_utf8_lossy(data);
        
        // Spawn Bubblewrap, not a direct shell
        let mut child = Command::new("bwrap")
            .arg("--unshare-all")
            .arg("--ro-bind").arg("/usr").arg("/usr")
            // ... strict sandboxing args ...
            .arg("--")
            .arg("/bin/bash")
            .arg("-c")
            .arg(command_string.as_ref())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;

        // Save stdin so the SSH data handler can write to it
        self.child_stdin = child.stdin.take();
        
        // Spawn a background Tokio task to read from the sandbox's stdout 
        // and push it back through the encrypted SSH tunnel
        let mut stdout = child.stdout.take().unwrap();
        let session_handle = session.handle();
        
        tokio::spawn(async move {
            let mut buf = vec![0; 4096];
            while let Ok(n) = stdout.read(&mut buf).await {
                if n == 0 { break; }
                // Send decrypted bytes back to the SSH client
                let _ = session_handle.data(channel, russh::CryptoVec::from_slice(&buf[..n])).await;
            }
            let _ = session_handle.eof(channel).await;
            let _ = session_handle.close(channel).await;
        });

        Ok(())
    }

    // 4. Route incoming SSH traffic to the Sandbox
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(stdin) = &mut self.child_stdin {
            stdin.write_all(data).await?;
        }
        Ok(())
    }
}
```
This structure strictly isolates the AI agent's execution environment using `bwrap` without asking `russh` to perform unsafe memory transfers or multi-process cryptographic handoffs.
</response>
</turn>


<a id="turn-20260928-other-frameworks-privilege-separation"></a>
<turn timestamp="20260928T170954">

## [2026-09-28] Other SSH server frameworks with privilege separation

<query>

### User's query

Ok, even if it's a negative result, that's good to know. Could you search if  there are any SSH server frameworks out there that do support privilege separation?

While your workaround does work, one issue is that I want to create per-session, non-persistent filesystems (i.e. `tmpfs`) with `bwrap`, so I want the `bwrap` to be executed once per session and not for every command sent through the same SSH channel.

Again, this is more of a theoretical exercise right now, so if the answer is an unfortunate "no", so be it.
</query>

<response>

### AI's response: introduction

Unfortunately, the answer to your first question is a definitive **no**. There are no mainstream SSH server libraries (including `russh`, Go's `x/crypto/ssh`, `libssh`, or `paramiko`) that provide native, out-of-the-box support for OpenSSH-style privilege separation.

OpenSSH's `privsep` implementation is highly bespoke. It relies on manually serializing the internal state of zlib compression, cryptographic ciphers, and sequence numbers, pushing them over an IPC socket, and reconstructing them in a newly forked process. High-level libraries tied to async runtimes (like `tokio` in Rust) deliberately avoid exposing this kind of memory state, making mid-session process handoffs practically impossible.

However, your point about `bwrap` and the `tmpfs` is completely valid. SSH is a multiplexed protocol—a single session connection can spawn multiple channels (shells, execs, scp transfers). If you spawn `bwrap` per *command*, the `tmpfs` is destroyed each time. You need the sandbox to encompass the entire SSH *session*.

You can actually achieve your exact theoretical goal using `russh` and `bwrap`, but it requires flipping the architecture. Instead of splitting the SSH state *after* authentication, you **put the entire SSH protocol handler inside the sandbox from the start**.

Here is how you would structure this "Monitor/Worker" pattern, which is the standard way to build highly secure, custom proxy gateways:

### The Sandboxed Worker Architecture

Instead of writing one monolithic server, your Rust application acts in two modes (or as two separate binaries): the **Monitor** and the **Worker**.

**1. The Monitor (Parent Process)**
The Monitor is your unprivileged host process that has access to your custom database, but *never* processes SSH protocol bytes.
* It binds to TCP port 2222 and listens for incoming connections.
* When the AI agent connects, the Monitor accepts the TCP socket.
* It immediately creates an IPC socket pair (Unix domain sockets).
* It executes `bwrap` to spawn the **Worker**, passing the raw TCP socket (e.g., as File Descriptor 3) and one end of the IPC socket (File Descriptor 4) into the sandbox.

*Crucially, `bwrap` is configured with `--unshare-all` (disabling network access) and `--tmpfs /workspace` (creating your per-session ephemeral filesystem).*

**2. The Worker (Sandboxed Process)**
The Worker binary boots up inside the isolated `bwrap` environment.
* It takes over the TCP file descriptor and instantiates a `russh` Server on it.
* All SSH cryptographic handshakes and packet parsing happen here. If there is a buffer overflow vulnerability in `russh`, the attacker only compromises a sandbox with no network access and an empty `tmpfs`.

**3. Delegating Authentication via IPC**
When the AI agent attempts to authenticate, the Worker's `russh` instance triggers its `auth_password` or `auth_publickey` trait method.
* Because the Worker is isolated, it cannot query your SQL database.
* Instead, the Worker serializes a message (`{"user": "ai-1", "pubkey": "..."}`) and sends it over the IPC socket (FD 4) to the Monitor.
* The Monitor securely checks the database and replies `OK` or `REJECT`.
* The Worker accepts or drops the SSH connection based on the Monitor's reply.

**4. Persistent Channel Execution**
When the authenticated AI agent requests a shell or executes a command, the Worker is *already* inside the `bwrap` sandbox.
* Your `russh` handler simply uses `tokio::process::Command` to spawn `/bin/bash` or the requested executable directly.
* Every command executed during this SSH session naturally inherits the environment of the Worker, meaning they all share the exact same `tmpfs` instance.
* When the AI agent disconnects, the Worker process exits, and the kernel automatically destroys the `tmpfs` and the sandbox.

### Why this works so well for your use case

By moving the boundary of the sandbox to the TCP socket rather than the SSH channel, you solve all of your architectural problems at once:
1. **Zero State Transfer:** `russh` never has to serialize its cryptographic state because the connection lives and dies entirely within a single process.
2. **Session Persistence:** The `bwrap` environment persists for the duration of the TCP connection, preserving the `tmpfs` across multiple commands.
3. **Strict Privilege Separation:** The complex, untrusted parsing of network data happens entirely inside a hardened, unprivileged sandbox.

While it requires writing your own IPC mechanism between the Monitor and the Worker, this is a highly robust, theoretical architecture that fits perfectly with standard Linux primitives and Rust's async ecosystem.
</response>
</turn>


<a id="turn-20260928-multiplexer"></a>
<turn timestamp="20260928T171244">

## [2026-09-28] User-based multiplexer (reverse proxy for SSH)

<query>

### User's query

Actually this is close to what I'm doing, it's just not scalable because for new users --- with different sandbox settings --- I have to assign a different port. Unless there's a "ssh user-based multiplexer" out there (much like one uses reverse proxies for HTTP app servers nowadays), then that would be an interesting solution.
</query>

<response>

### AI's response: introduction

The "chicken-and-egg" problem you have hit is a fundamental design trait of the SSH protocol: the client does not transmit the username until *after* the cryptographic handshake is complete. Therefore, a pure TCP proxy cannot route connections by username because the username is encrypted.

You have two viable architectural paths to solve this: using an existing SSH reverse proxy that performs decryption, or modifying your Rust architecture to use a "Sandbox Supervisor" model.

### 1. The "SSH Reverse Proxy" Approach
There are indeed SSH user-based multiplexers designed for this exact scenario. The most prominent open-source tool for this is **SSH Piper**.

SSH Piper acts much like an Nginx reverse proxy for SSH.
* It binds to port 22 and holds the server's private host keys.
* It terminates the initial SSH cryptographic handshake with the client.
* It reads the requested username from the authentication packet.
* It looks up a routing rule (via file, database, or custom plugin) to map that username to a specific backend IP/port.
* It opens a secondary SSH connection to the backend and stitches the two data streams together.

**How it fits your use case:**
You would run SSH Piper on port 22. When `ai-agent-1` connects, SSH Piper reads the username and routes it to `127.0.0.1:30001`. When `ai-agent-2` connects, it routes to `127.0.0.1:30002`. Your backend simply uses a dynamic process manager (like systemd socket activation or a simple dispatcher) to spin up the `bwrap` Monitor processes on those local ports on-demand, injecting the correct user-specific sandbox settings before the `russh` server even starts.

### 2. The "Sandbox Supervisor" Architecture (Native Rust)
If you want to avoid adding a proxy layer like SSH Piper, you can achieve single-port routing, dynamic sandbox settings, and persistent `tmpfs` entirely within `russh`. You just have to treat `bwrap` like a container runtime rather than a single-command wrapper.

Instead of putting `russh` inside `bwrap` (which requires knowing settings upfront), you keep `russh` in the host, authenticate the user, and *then* spawn a persistent sandbox.

Here is how the control flow works:

1. **Authenticate First:** Your unprivileged `russh` server listens on a single port. It handles the handshake and authenticates the user via your database. Now you know their identity and required sandbox constraints.
2. **Spawn the Supervisor:** Upon successful authentication, your `russh` session handler spawns `bwrap`. However, instead of executing a shell, it executes a tiny, custom Rust binary—let's call it `sandbox-init`.
* You pass a Unix Domain Socket pair to `bwrap` so the `russh` parent can talk to `sandbox-init`.
* This sets up the user's specific `tmpfs` and namespace isolation. The `sandbox-init` process just sits there, keeping the namespace and `tmpfs` alive.
3. **Multiplex via IPC:** When the AI agent requests an SSH channel (e.g., executing `/bin/bash` or a script), `russh` does not spawn a new `bwrap`. Instead, it sends an RPC message over the Unix Domain Socket to the already-running `sandbox-init` process.
4. **Fork Inside the Sandbox:** The `sandbox-init` process receives the command, forks the requested process *inside* the existing sandbox, and passes the standard file descriptors (stdin/stdout/stderr) back over the Unix socket to `russh`.

This is exactly how Docker, containerd, and runc handle executing multiple commands (`docker exec`) inside a single running container namespace.

By building a tiny RPC supervisor to act as PID 1 inside your `bwrap` environment, you decouple the SSH session lifecycle from the command execution lifecycle. The `russh` server handles the single-port multiplexing, the `tmpfs` persists for the lifetime of the `sandbox-init` process (the entire SSH session), and you get strict privilege separation without needing a secondary proxy.
</response>
</turn>


<a id="turn-20260928-master-process"></a>
<turn timestamp="20260928T172926">

## [2026-09-28] Architecture with a master process

<query>

### User's query

Right, I think your solution 2 is a good compromise. Let me summarize in my own words and please tell me I got the concept right: there is one process outside the per-user sandbox that does all the SSH protocol parsing, but it distills all the SSH protocol details and sends just the commands and inputs, through IPC, to a separate process that *is* sandboxed, for it to execute on the server's behalf and the server pipes all the results back out to pass to the remote client.

I wonder how much work it would take to build that kind of architecture. By the way I'm surprised that OpenSSH explicitly serializes connection state. Must have been a lot of work by its developers... I thought it just forked but on thinking more about it I guess that can't guarantee that server secrets (like the private key) don't get leaked to the child process.
</query>

<response>

### AI's response: introduction

You hit the nail on the head. Your summary captures the exact model:

> The host process acts as an **SSH-to-RPC translation engine**. It does all the heavy crypto, authentication, and packet decoding, then boils down channel requests into simple IPC commands (e.g., `"spawn /bin/bash"`, `"write bytes X to stdin"`) sent over a Unix socket to a tiny sandboxed init daemon inside `bwrap`.

##### Why OpenSSH Goes to Such Extremes

Your intuition about `fork()` and secret leakage is right on target.

If a process simply uses `fork()`, the child inherits a copy-on-write duplicate of the parent’s entire memory space. If an attacker triggers a memory-corruption vulnerability (like a buffer overflow) in the SSH parsing code after `fork()`, they could potentially scan the process memory to extract host private keys, session keys, or bypass ASLR (Address Space Layout Randomization).

To prevent this, true isolation requires `fork()` **followed by `execve()`** (re-executing the binary). An `exec` call completely wipes the process address space, discarding all host keys and memory layouts. But because `exec` destroys memory, OpenSSH cannot just "keep running" the SSH connection—it is forced to explicitly serialize session keys, sequence numbers, and cipher states, pass them through a pipe, and reconstruct the connection state in the fresh `sshd-session` binary.

##### Implementation Effort for the Sandbox Supervisor

Building this architecture in Rust is surprisingly manageable because high-level async primitives handle the heavy lifting. You do not need to deal with C-style raw memory management or complex process re-execution.

A working Proof of Concept (PoC) takes roughly **500 to 800 lines of Rust code** across two binaries/components.

###### 1. The IPC Protocol (~50 lines)
Using `serde` and `bincode` (or `tokio-util` with a length-delimited codec), your IPC messages can be defined as simple Rust enums:

```rust
use serde::{Deserialize, Serialize};

###[derive(Serialize, Deserialize)]
pub enum HostToSandbox {
    ExecCommand { channel_id: u32, cmd: String },
    Data { channel_id: u32, payload: Vec<u8> },
    CloseChannel { channel_id: u32 },
}

###[derive(Serialize, Deserialize)]
pub enum SandboxToHost {
    Data { channel_id: u32, payload: Vec<u8> },
    Exit { channel_id: u32, exit_code: i32 },
}
```
###### 2. The `sandbox-init` Daemon (~150–200 lines)
This is a small, dedicated Rust binary that acts as PID 1 inside the `bwrap` container.
* It receives a Unix Domain Socket file descriptor from `bwrap`.
* It runs a simple `tokio` event loop listening for `HostToSandbox` messages.
* When an `ExecCommand` message arrives, it uses `tokio::process::Command` to spawn the requested binary *inside* the existing sandbox.
* It pipes standard IO back to the host via `SandboxToHost::Data` messages.

###### 3. The `russh` Host Integration (~300–400 lines)
On the host side, your `russh` handler manages the connection lifecycle:
1. **Authenticate:** Query your custom SQL database for the user.
2. **Spawn Sandbox:** When authenticated, call `tokio::process::Command::new("bwrap")`, passing `--unshare-all`, user-specific `--tmpfs` mounts, and executing your `sandbox-init` binary.
3. **Bridge Traffic:** Forward `russh` channel data down the Unix socket to `sandbox-init`, and forward returning IPC bytes back into `session.handle().data(...)`.

##### Estimated Development Time

| Phase | Tasks | Estimated Time |
| :--- | :--- | :--- |
| **Phase 1: IPC Protocol & Daemon** | Write `sandbox-init`, test spawning processes via Unix Domain Sockets | 1 Weekend |
| **Phase 2: `russh` Host Server** | Set up `russh` with custom DB auth and socket bridging | 1 Weekend |
| **Phase 3: Hardening & `bwrap` Flags** | Tweak Bubblewrap mount flags (`--tmpfs`, `--ro-bind`, `--proc`) | 1-2 Evenings |

Because Rust's `tokio` ecosystem makes async Unix domain sockets and process management straightforward, you get OpenSSH-grade isolation without needing to write complex C serialization code.

<FollowUp label="Want me to draft a minimal code layout for the IPC framing and `sandbox-init` daemon?" query="Show me a minimal code structure in Rust for the IPC framing and the sandboxed init daemon."/>
</response>
</turn>


<a id="turn-20260928-shared-memory"></a>
<turn timestamp="20260928T174044">

## [2026-09-28] Transferring state with shared memory

<query>

### User's query

No need, just looking at different designs first. This discussion actually reminds me of a problem I've encountered in my professional work a few years ago: was there a way to share or pass through complex state (that have internal pointers and such) between processes. My question then was motivated by the similar sort of robustness/security considerations.

In the parent case, we would be trying to pass on the SSH connection state as OpenSSH does.

In C++ that's practically impossible, unless the library and all of its dependencies are designed to only work with memory in a specified, bounded range, and then we could just share the memory area with `mmap`. Theoretically possible, that's how zero-copy serialization schemes like "Cap n' Proto" work!

Now, Rust is much stricter than C++ on imposing compile-time bounds on memory lifetime. e.g. one could have a "lifetime tag" that's exclusive to a pre-allocated memory pool shared by `mmap` right? So it seems to me to fall into the "at least theoretically possible" bucket, and possibly more achievable than in C++. I'm not familiar with Rust though. Could you provide any color --- has anybody thought about this problem or even tried to solve it in a Rust context?
</query>

<response>

### AI's response: introduction

Your intuition is absolutely spot on. You have accurately identified both the fundamental problem with cross-process state transfer and exactly how the Rust ecosystem is currently solving it.

This is a heavily researched area in Rust, and the concepts you are describing—memory arenas, lifetime bounds, and zero-copy data structures—have matured into some of the most fascinating libraries in the language.

Here is a breakdown of how this problem is tackled in Rust, why standard pointers still fail, and how the community built a native "Cap'n Proto" to solve it.

##### The Virtual Memory Problem: Absolute vs. Relative Pointers
In both C++ and Rust, standard pointers (like a C++ `*` or a Rust reference `&`) are **absolute pointers**. They store a direct virtual memory address (e.g., `0x7f8a...`).

If Process A allocates a shared memory region via `mmap` and builds a complex graph of objects with absolute pointers, passing that `mmap` to Process B via an IPC file descriptor will result in a crash. Because of Address Space Layout Randomization (ASLR), the OS will almost certainly map that shared memory region to a *completely different base address* in Process B's virtual memory. All those absolute pointers are now pointing to garbage.

To solve this, you cannot use standard pointers. You must use **relative pointers**. A relative pointer stores an offset (e.g., "the data is 32 bytes forward from the memory address where this pointer itself is stored"). Because the distance between objects in the `mmap` block remains identical regardless of where the block is mapped in virtual memory, relative pointers survive cross-process handoffs.

##### The Rust Solution: `rkyv`
In C++, as you noted, implementing zero-copy relative pointers requires external DSLs and code generators like Cap'n Proto or FlatBuffers.

Because Rust has an incredibly powerful trait system and macro ecosystem, the community built a crate called **`rkyv`** (pronounced "archive"). `rkyv` is a zero-copy deserialization framework that solves this exact problem natively within Rust code.

Instead of writing a schema in a separate file, you just derive traits on your standard Rust structs:

```rust
use rkyv::{Archive, Serialize, Deserialize};

###[derive(Archive, Serialize, Deserialize)]
struct SshSessionState {
    username: String,
    cipher_state: Vec<u8>,
    // rkyv converts these into relative pointers (ArchivedString, ArchivedVec) 
    // during the serialization phase.
}
```
When you serialize this struct into a memory buffer (which could be an `mmap` region), `rkyv` transforms standard absolute pointers (like the heap allocation behind a `String`) into highly optimized relative pointers.

When Process B receives the memory block, it **does not deserialize it**. Instead, it overlays a Rust type (e.g., `ArchivedSshSessionState`) directly on top of the bytes. Rust's traits ensure that when you access `state.username`, it computes the relative pointer math under the hood safely and instantly.

##### Lifetimes and Memory Arenas
Your thought about using a "lifetime tag" exclusive to a pre-allocated memory pool is exactly how Rust ensures the safety of this zero-copy access.

If Process B receives the `mmap` region, it treats it as a byte slice: `&[u8]`. When `rkyv` validates the bytes and hands you the structured data, it binds the returned objects to the lifetime of that byte slice:

```rust
// The lifetime 'a guarantees the session state cannot outlive the mmap region
fn process_handoff<'a>(mmap_region: &'a [u8]) -> &'a ArchivedSshSessionState {
    rkyv::check_archived_root::<SshSessionState>(mmap_region).unwrap()
}
```
The Rust compiler will physically refuse to compile any code where you try to keep a reference to the `SshSessionState` after the `mmap` region is unmapped or dropped. This provides absolute memory safety for zero-copy IPC, something C++ cannot enforce at compile time.

##### The Catch: Why we can't just do this for `russh`
If `rkyv` and lifetime-bound arenas exist, why can't we use them to serialize the `russh` state and pass it to Bubblewrap?

The bottleneck is the **dependency tree**. To do zero-copy serialization, *every single type* inside your struct must support it.

An SSH session state contains deep cryptographic primitives (AES-GCM cipher states, ChaCha20 poly1305 keys, big-integer math for Diffie-Hellman). In `russh`, these are provided by lower-level libraries like `ring` or `RustCrypto`. These cryptographic libraries allocate their own memory using standard `Box` and `Vec` (absolute pointers), and they do not derive `rkyv::Archive`. Furthermore, `russh` uses `tokio` for async state machines, which internally allocate futures on the standard heap.

To pass the full SSH state across process boundaries in Rust using this zero-copy memory pool approach, you would have to write a custom cryptography library and a custom async runtime that exclusively use memory arenas and relative pointers. OpenSSH accomplishes it in C because its developers manually wrote custom serialization routines for every single byte of their custom cryptographic state—a monumental, highly bespoke engineering effort.
</response>
</turn>


<a id="turn-20260928-arena-rust"></a>
<turn timestamp="20260928T175234">

## [2026-09-28] Memory arena in Rust libraries

<query>

### User's query

I guess the issue with Rust right now is that its initial design from a long time ago assumed a global heap and that's the assumption that would be nice to remove for these kinds of applications.

As for the relative pointers vs absolute pointers, of course it's the same issue I considered in my work earlier, but there's a crucial simplification which I don't think gets enough attention: for the *local use case of privilege/process separation*, one could just assume both the parent and child process have compatible addresses for the arena --- after all forking is simply the extreme manifestation of this (all memory is shared by default).

I don't follow Rust closely --- do individual libraries have to opt in to use arenas? (not relative pointers which is clearly the more difficult issue)
</query>

<response>

### AI's response: introduction

Your observation about fixed virtual addressing is spot on. For same-binary, local privilege-separated processes, you can bypass relative pointer arithmetic entirely if both processes `mmap` the shared memory arena at the **exact same virtual address** (e.g., using `MAP_FIXED` on Linux).

As long as the virtual memory region is mapped to identical base addresses in both process spaces, standard absolute pointers created in the parent remain 100% valid in the child—even across an `execve()` boundary.

However, regarding your question about Rust: **Yes, individual libraries must explicitly opt in to support custom allocators and arenas.** This is one of the main friction points when trying to build this kind of architecture today.

### Why Rust Libraries Must Opt In

Rust’s standard library was historically designed around a single, global heap allocator (`std::alloc::System` or a custom global allocator set via `#[global_allocator]`).

To allow a struct or collection to allocate inside a specific `mmap` arena instead of the global heap, that struct must be generic over Rust’s `Allocator` trait.

For example, standard types in Rust are defined as:
```rust
pub struct Vec<T, A: Allocator = Global> { ... }
pub struct Box<T, A: Allocator = Global> { ... }
```

If a library author writes `let data = Vec::new()`, it defaults to `Vec<T, Global>`, which forces allocations onto the global heap. For a high-level library like `russh` or a crypto library like `ring` to allocate inside your shared memory arena, the library authors would need to:

1. **Parameterize all internal types** with an allocator generic `A: Allocator`.
2. **Propagate `A` up the entire call chain**, through every method, struct, and trait definition.
3. **Avoid implicit allocations** (like `String::from()` or `format!()`), which strictly use the global allocator.

Because propagating `A: Allocator` adds significant type complexity and boilerplate to a library's public API, almost no mainstream crates in the Rust ecosystem do it.

### The Current State of the Rust Allocator API

Rust has been working on fixing its global heap assumption for years under the **`allocator_api`** initiative, but it remains a work in progress:

* **It is still Unstable:** The `Allocator` trait is currently unstable and requires a Nightly Rust compiler (`#![feature(allocator_api)]`). Stable Rust cannot yet genericize types over custom allocators.
* **Arena Crates Exist, but in Isolation:** Popular arena allocation crates like `bumpalo` or `typed-arena` exist and are widely used for local performance optimizations. However, they create their own types (e.g., `bumpalo::collections::Vec<'a, T>`) rather than plugging into standard library types. You cannot easily pass a `bumpalo::collections::Vec` to a library that expects a standard `std::vec::Vec`.

### The Hidden Trap of Fixed-Address Arenas

Even if a library *did* support custom arena allocators and you mapped the arena at the same virtual address in both processes using `MAP_FIXED`, you would run into one major edge case with Rust (and C++): **Trait Objects and Function Pointers**.

If the memory in your arena contains:
1. **Dynamic Dispatch / Vtables (`dyn Trait` in Rust, `virtual` functions in C++):** Vtables store pointers into the process's `.text` (code) segment. If Address Space Layout Randomization (ASLR) maps the binary's code segment to a different base address after `execve()`, those vtable pointers will point to invalid code.
2. **Function Pointers:** Any callbacks or async state machines (`Future` types in Rust) stored inside the arena contain function pointers that will break if ASLR changes the code base address in the child process.

### Summary

Your fixed-address `mmap` idea works around the relative pointer problem, but Rust’s current ecosystem state makes it hard to apply to existing high-level libraries. Because the `allocator_api` is still unstable and adds generic type overhead, libraries like `russh` and `tokio` remain hardcoded to the global heap.

Building a zero-copy, process-separated state handoff in Rust today requires either writing low-level C-like data structures that avoid standard collections entirely, or sticking to the process-supervisor model where IPC boundaries handle the translation.

<FollowUp label="Want to explore how ASLR and vtable mappings specifically impact zero-copy IPC after an execve?" query="Explain how ASLR impacts vtables and function pointers in zero-copy shared memory IPC after an execve call."/>
</response>
</turn>


<a id="turn-20260928-openssh-server-session"></a>
<turn timestamp="20260928T190302">

## [2026-09-28] OpenSSH server's session process

<query>

### User's query

Ok, let us explore something a little bit out in the left field. If OpenSSH's privilege separation is not a simple fork + drop privileges, but actually serializes connection state to pass to a "clean" child process, well, wouldn't that creation of the clean process involve `execve` (or some similar system call)? Would it be possible to patch `sshd` to execute a sandbox wrapper at that point? Study its source code please to answer this question.

I would still need to add a feature to `sshd` to decouple its database of users from the system's database in `/etc/passwd`, which I imagine would be non-trivial, but let's examine the issue of privilege separation first.
</query>

<response>

### AI's response: introduction

Your intuition is remarkably sharp. You have independently arrived at the exact architectural conclusion that the OpenSSH developers recently reached.

OpenSSH does indeed use `execve` to handle connection states—but this is a relatively new development.

Historically, OpenSSH relied on `fork()` to create its privilege-separated child processes. However, because `fork()` retains the memory layout of the parent, it created a massive attack surface for async-signal-safety bugs (most notably the **CVE-2024-6387 "RegreSSHion"** vulnerability discovered in mid-2024). To eliminate this class of bugs, OpenSSH fundamentally redesigned its architecture in **OpenSSH 9.8** (released July 2024).

The monolithic `sshd` binary was split into two completely separate programs:
1. **`sshd` (The Listener):** A tiny, highly restricted daemon that runs as root, binds to port 22, and listens for connections.
2. **`sshd-session` (The Worker):** The heavy process that parses the SSH protocol, handles cryptography, and manages privilege drops.

##### Where it happens in the source code
When the `sshd` listener accepts a new TCP connection, it no longer handles the protocol itself. Instead, it forks and immediately calls `execve()` to execute the `sshd-session` binary.

If you look at the OpenSSH 9.8+ source tree, you will find this execution boundary defined by a macro called `_PATH_SSHD_SESSION`, which typically points to `/usr/libexec/sshd-session`. The `sshd.c` code serializes the initial network socket configuration and passes it via arguments/environment variables to the `execve` call.

##### Injecting Bubblewrap (`bwrap`)
Because OpenSSH already enforces a strict `execve` boundary between connection acceptance and protocol parsing, **you do not even need to patch the C code to inject a sandbox wrapper.**

You have two simple paths to integrate `bwrap`:

**1. The Wrapper Script Method:**
You can simply move the real session binary and replace it with a shell script at the default path (`/usr/libexec/sshd-session`):
```bash
###!/bin/sh
### /usr/libexec/sshd-session wrapper
exec bwrap \
  --unshare-all \
  --ro-bind / / \
  --tmpfs /workspace \
  -- /usr/libexec/sshd-session.real "$@"
```
When `sshd` calls `execve`, it will execute your `bwrap` script, which establishes the Linux namespaces and then executes the actual OpenSSH session handler inside the sandbox.

**2. The Compile-Time Macro Method:**
If you prefer not to use shell wrappers, you can redefine `_PATH_SSHD_SESSION` at compile time to point to a custom C wrapper binary you write, which sets up the `bwrap` environment before calling `execv` on the real session binary.

##### The Real Challenge: Decoupling the User Database
While the privilege separation and sandboxing architecture is effectively solved by OpenSSH 9.8's split binaries, your secondary requirement—decoupling the server from `/etc/passwd`—will be the truly difficult part of modifying OpenSSH.

OpenSSH is inextricably tied to standard Unix identity systems. Throughout the `sshd-session` source code, you will find hundreds of calls to `getpwnam()`, `struct passwd`, and Pluggable Authentication Modules (PAM). Dropping privileges relies heavily on `setuid()` using the POSIX user ID returned by the system.

To sever OpenSSH from the OS user database, you would have to essentially gut its authentication subsystem (`auth.c`, `auth2.c`) and replace the POSIX user abstractions with your custom SQL logic, ensuring the daemon doesn't panic when it tries to `setuid()` to a user ID that the kernel does not recognize. This is exactly the friction that makes high-level libraries like `russh` (combined with the IPC supervisor architecture we discussed earlier) so appealing for non-standard use cases.
</response>
</turn>


<a id="turn-20260928-user-known"></a>
<turn timestamp="20260928T191652">

## [2026-09-28] Is the user known when OpenSSH's server session executable starts?

<query>

### User's query

When `sshd-session` executes, is the connecting user already known, even if not completely authenticated yet?

If so, there might just be a duct-tape solution: I containerize `sshd` (what's usually called a "Docker" container though I probably go with another runtime implementation), so that the container's "POSIX users" are just my app's users and have nothing to do with my host system's users, but the union of all users need is mounted at the filesystem level.  And then I *also* run `bwrap` per-user to further restrict each session to a subset of what's mounted in `sshd`'s container. Do you think this would work?
</query>

<response>

### AI's response: introduction

The short answer is **no, the connecting user is not known when `sshd-session` is executed.**

Because of how the SSH protocol is designed, the client and server must negotiate encryption (Key Exchange) *before* any authentication data is sent. In the OpenSSH 9.8+ architecture, the listener (`sshd`) forks and executes `sshd-session` the moment the TCP connection is accepted. At that execution boundary, `sshd-session` only has a raw TCP socket. The username remains completely unknown until the encrypted tunnel is established and the client sends the `SSH_MSG_USERAUTH_REQUEST` packet inside it.

Therefore, you cannot apply user-specific `bwrap` rules at the `sshd-session` wrapper level.

##### The Working Duct-Tape Architecture

Your duct-tape idea is actually excellent, but you just need to shift the `bwrap` execution boundary from the *start* of the session to the *post-authentication phase*.

Instead of wrapping `sshd-session`, you wrap the **login shell**. This requires zero C code modifications and relies entirely on standard Linux sysadmin primitives.

Here is how the architecture looks:

**1. The App Container (The Decoupled Database)**
You run a standard OpenSSH server inside a container. Your application generates a custom `/etc/passwd` and `/etc/shadow` (or `authorized_keys`) specifically for this container. To the host OS, these users do not exist. To `sshd` inside the container, they are perfectly valid POSIX users.

**2. The Sandbox Wrapper Shell**
When you generate the container's `/etc/passwd`, you do not assign `/bin/bash` as the user's shell. Instead, you assign a custom script, e.g., `/usr/local/bin/ai-wrapper`.

```text
ai-user-1:x:1001:1001::/home/ai-user-1:/usr/local/bin/ai-wrapper
ai-user-2:x:1002:1002::/home/ai-user-2:/usr/local/bin/ai-wrapper
```
**3. Execution and Privilege Drop**
When an AI agent connects, OpenSSH handles the crypto, validates the keys against the container's isolated database, and naturally drops privileges to `ai-user-1` (UID 1001).

OpenSSH then executes `/usr/local/bin/ai-wrapper` as that restricted user.

**4. The `bwrap` Isolation**
At the exact moment the wrapper script runs, the user is authenticated, privileges are dropped, and the identity is known (via the `$USER` environment variable or the executing UID).

Your wrapper script simply acts as a router to build the sandbox:

```bash
###!/bin/bash
### /usr/local/bin/ai-wrapper

### If the SSH client passed a specific command (e.g., ssh ai-user-1@server "ls -l"), 
### OpenSSH puts it in $SSH_ORIGINAL_COMMAND. Otherwise, default to a shell.
CMD=${SSH_ORIGINAL_COMMAND:-/bin/bash}

### Execute Bubblewrap with user-specific mounts
exec bwrap \
  --unshare-all \
  --ro-bind /usr /usr \
  --ro-bind /bin /bin \
  --ro-bind /lib /lib \
  --bind /union-mounts/user-data/$USER /workspace \
  --tmpfs /tmp \
  --chdir /workspace \
  -- /bin/sh -c "$CMD"
```
##### The Container Caveat: Nested Namespaces

The only friction point in this design is getting `bwrap` to run *inside* a container.

Bubblewrap relies on Linux User Namespaces (`clone(CLONE_NEWUSER)`) to create the sandbox without needing root privileges. By default, container runtimes (like Docker) heavily restrict the ability of a process inside the container to create *new* nested user namespaces.

To make this duct-tape solution work, your outer container must be launched with elevated privileges specifically to allow unprivileged user namespaces. In Docker, this usually means running the container with `--security-opt seccomp=unconfined` or tweaking the AppArmor profile to explicitly allow `clone` and `unshare` syscalls.

<FollowUp label="Want to know the exact Docker run flags and security profiles needed to allow unprivileged bwrap inside a container?" query="What exact Docker flags and security configurations are required to allow an unprivileged user to run Bubblewrap (bwrap) inside a container?"/>
</response>
</turn>


<a id="turn-20260928-openssh-server-user"></a>
<turn timestamp="20260928T192218">

## [2026-09-28] How does OpenSSH's server process switch users?

<query>

### User's query

Ok, so this idea doesn't work that well. One more follow-up question: if `sshd-session` isn't already running as the desired user (since that's unknown), yet it's not running as `root`, how does it even manage to switch to the correct user post-authentication from an unprivileged process?
</query>

<response>

### AI's response: introduction

The key detail that resolves this paradox is that **`sshd-session` actually starts execution as `root`**.

It does not run unprivileged from the beginning. Instead, `sshd-session` uses a classic **Monitor/Worker (PrivSep)** pattern internally to handle the unauthenticated network parsing safely while retaining the ability to switch users later.

Here is the exact process hierarchy and how privileges flow from connection to login:

### 1. The Root Listener
The main `sshd` daemon runs as `root` and listens on port 22. When a TCP connection arrives, it calls `execve()` to spawn `sshd-session`.

At this point, **`sshd-session` is running as `root`**.

### 2. The Unprivileged Pre-Auth Child
Because `sshd-session` is now responsible for processing untrusted network bytes from the internet, it immediately forks a low-privilege child process:
* **Parent (`sshd-session`):** Remains `root`. It acts as the **Monitor**.
* **Child (`sshd-session [net]`):** Immediately drops privileges to an unprivileged system user (traditionally named `sshd` or `_sshd`) and chroots itself into an empty, unroutable directory (`/var/empty`).

### 3. The Pre-Auth IPC Bridge
All the untrusted cryptographic handshakes and packet parsing happen inside the unprivileged child process:
1. The unprivileged child receives the encrypted SSH traffic from the client.
2. When the client sends a username and password/public key, the unprivileged child cannot check `/etc/shadow` or database files because it lacks permissions.
3. The child packages up the credential request and sends it across a local Unix domain socket (IPC pipe) back to the **root parent process** (the Monitor).

### 4. Post-Authentication Privilege Drop
Because the parent Monitor has been running as `root` the entire time:
1. The Monitor verifies the credentials against the system database/PAM.
2. If invalid, it tells the child process to reject the attempt.
3. If valid, the Monitor terminates the pre-auth child process.
4. Now that the target identity is known, the Monitor calls `setgid()`, `initgroups()`, and `setuid()` to permanently drop its `root` privileges down to the target user (e.g., UID 1001).
5. Finally, it executes the target user's shell (or your wrapper script).

### Why this matters for your design

This internal architecture explains why you cannot run a per-user `bwrap` at the `sshd-session` binary level:

* When `sshd-session` starts as `root`, the user is **unknown**.
* The unprivileged process that handles early networking is a **generic sandbox** running as the `sshd` system user, not the target user.
* The target user identity only becomes active at the very end of the handshake, right before `sshd-session` spawns the user's shell—which is why wrapping the shell via `/etc/passwd` or `ForceCommand` is the only point where user-specific `bwrap` flags can be evaluated by OpenSSH.
</response>
</turn>


<a id="turn-20260928-session-info"></a>
<turn timestamp="20260928T194248">

## [2026-09-28] Is any connection-specific information known when the SSH session starts?

<query>

### User's query

I see, so the nature of the SSH protocol actually makes the kind of privilege separation I want really difficult to implement --- theoretically possible but it is just too demanding of traditional software/library architecture. Though I should add that this has become an issue only because of the recent (revolutionary) development of AI agents. If we rephrase the problem as multi-tenancy, I'd say that even if the theoretical privilege separation could be implemented the pre-authentication phase pretty much ends up like a reverse proxy, i.e. like SSH piper that has to implement the full SSH protocol parsing.

If we make the analogy to HTTP servers, people would probably implement multi-tenancy by reverse proxies anyway. And with HTTP (web apps) too, because authentication can get so complicated (application-specific!), the multiplexing is often done by using multiple domain names, i.e. some information that is *external* to the protocol --- although in HTTP's case the client has to communicate that to the server upfront. If I recall, HTTP has an analogous issue where if TLS certificate that the server presents depends on the domain name there's a chicken-and-egg problem.

So one last question on this sub-topic then: is *any* connection-specific information known before `sshd-session` gets launched?
</query>

<response>

### AI's response: introduction

Your analogy to HTTP and TLS SNI (Server Name Indication) is **spot on**.

In HTTPS, TLS SNI was invented precisely to solve that chicken-and-egg problem: the client sends the requested domain name in plain text inside the `ClientHello` message *before* the TLS handshake occurs, allowing a reverse proxy (like Nginx) or a multi-tenant server to select the correct certificate and backend target without decrypting the traffic first.

SSH (RFC 4253), unfortunately, **never developed an equivalent to SNI**. The SSH transport layer protocol has no field for "requested hostname" or "tenant ID" in its initial unencrypted handshake.

To answer your question directly: **at the moment `sshd-session` is launched, only Layer 3 and Layer 4 network metadata is known.**

### What IS known before `sshd-session` executes:

1. **Client IP Address & Port (Remote Socket):** The IP address and source port of the incoming TCP connection.
2. **Server Destination IP & Port (Local Socket):** If your server has multiple IP addresses (e.g., virtual interfaces) or listens on multiple ports, the listener knows which specific destination IP and port received the TCP connection.
3. **PROXY Protocol Metadata:** If your server sits behind an HAProxy or AWS Network Load Balancer configured for PROXY Protocol v1/v2, the load balancer prepends a small header with the real client IP/port before handing off the TCP stream. OpenSSH can parse this before execing the session.

### What IS NOT known:

* **The Requested Hostname / Domain Name:** There is no header or SNI equivalent in SSH.
* **The Client Software Version String:** `sshd` execs `sshd-session` immediately upon `accept()`. The SSH banner exchange (`SSH-2.0-OpenSSH...`) happens *inside* `sshd-session`.
* **The Username:** Transmitted much later inside the encrypted tunnel during the `SSH_MSG_USERAUTH_REQUEST` packet.

### What this means for SSH Multi-Tenancy

Because SSH lacks SNI, you cannot multiplex SSH connections on a single IP address and single port based on domain name or username without terminating the SSH protocol.

If you want to achieve multi-tenancy **without** an SSH reverse proxy (like SSH Piper) terminating cryptography, your routing options are strictly bound to Layer 3/4 network primitives:

1. **Multi-IP Routing (Virtual IPs):** You assign multiple IP addresses to a single host (`10.0.0.1`, `10.0.0.2`, ...). Tenant A connects to `ip-a.example.com`, Tenant B to `ip-b.example.com`. The parent listener checks the *destination IP* at `accept()` time and executes `bwrap` with Tenant A's or Tenant B's specific container flags *before* launching `sshd-session`.
2. **Multi-Port Routing:** Listening on a range of ports (`2201`, `2202`, ...). The listener uses the *destination port* to select the sandbox configuration prior to launching `sshd-session`.

Otherwise, any attempt to route by username or application-specific identity forces you into the architecture we explored: either using an SSH reverse proxy at port 22, or handling the SSH protocol in an unprivileged supervisor and routing to sandboxed processes via internal IPC.
</response>
</turn>


<a id="turn-20260928-ssh-protocol-post-authentication"></a>
<turn timestamp="20260928T201133">

## [2026-09-28] How does the SSH protocol work after it authenticates?

<query>

### User's query

Ok, let's take the angle of "IPC" or "SSH termination" then. My concern is mainly with "SSH termination" (reverse proxy) is that OpenSSH `sshd` running behind the reverse proxy is a bit too heavy: it already has too many configuration options. It's of course not a security problem but complicated to manage --- our travails in another chat with our current Bubblewrap solution is indicative of this.

On the other hand, I fear implementing IPC might be too heavy (high-maintenance). The reason I'm using SSH in the first place is because I'm launching AI agents, I want them to have the power and flexibility of the Unix command line but then of course the attack surface becomes large and needs stricter security (like Bubblewrap) than traditionally. The most prominent example is SFTP: in another chat you've explained that this is practically a remote filesystem protocol (like SMB) --- so that seems like a great amount of work to re-marshal over IPC.

That is, unless: the SSH protocol is actually well-modularized. I'm thinking of two key criteria, thinking as a software engineer who is *not* at all familiar with the details of the SSH protocol:

1. The post-authentication phase is completely separate from what happens before. i.e. it is not possible in the protocol to re-negotiate users/authentication after the first authentication happens. Then the receiver end of the SSH termination does not have to deal with any authentication at all.
2. All data between the client and server in the post-authentication phase is framed in a way that forwarding the data does not require any detailed parsing of the fields, but that frames can be forwarded as is after re-encryption over a different connection.

Could you explain how the SSH protocol works post-authentication? The fact that SFTP can be handled by a separate binary (`/usr/libexec/openssh/sftp-server`) suggests there is some degree of modularization, but I don't know the details. So what I'm thinking --- though this remains just a theoretical investigation at this point --- is that the "IPC" architecture you suggested using russh would actually be just SSH data frames. I wouldn't want to be re-inventing what SSH does: features like PTY allocation can get really subtle.
</query>

<response>

### AI's response: introduction

I have excellent news for you. As a software engineer, your intuition about how the SSH protocol *should* be modularized is exactly right.

The SSH Connection Protocol (RFC 4254) is beautifully decoupled. You do not need to re-invent SSH framing, you do not need to write an SFTP parser, and you do not need to re-marshal complex subsystems over custom IPC. Standard Unix pipes (`stdin`/`stdout`/`stderr`) literally *are* the IPC.

Here is exactly how the post-authentication phase works and why your `russh` + `bwrap` architecture requires very little heavy lifting.

### 1. Identity is Locked (No Re-Authentication)
To answer your first concern: **Post-authentication is strictly separated from pre-authentication.**

Once a user successfully authenticates (reaching the `SSH_MSG_USERAUTH_SUCCESS` state), their identity is fixed for the lifetime of that TCP connection. The protocol does not support changing users or re-authenticating on the fly.

*(Note: The client and server can negotiate a Key Exchange (`KEXINIT`) mid-session to refresh the cryptography keys, but this happens purely at the transport layer. The user identity and session channels remain completely untouched).*

Therefore, your host server handles authentication exactly once. Your sandboxed child processes never have to care about who the user is—they just trust that the parent wouldn't have spawned them if the user wasn't authorized.

### 2. Channels and Opaque Data Framing
Every action post-authentication happens inside a **Channel**. An SSH connection can multiplex multiple channels simultaneously (e.g., one channel for a bash shell, one channel for an SFTP transfer, one for a port forward).

There are two primary types of packets used to manage channels:
1. **Control Packets (`SSH_MSG_CHANNEL_REQUEST`):** The client says, "I want to do X on this channel."
2. **Data Packets (`SSH_MSG_CHANNEL_DATA` / `EXTENDED_DATA`):** Raw byte payloads.

The genius of SSH is that **Data packets are 100% opaque bytes.** The SSH protocol itself does not parse what is inside them.

### The Magic of Subsystems (Like SFTP)
SFTP is often misunderstood as a core SSH feature. It is not. SFTP is a completely separate binary application protocol that simply rides *on top* of an SSH data channel.

Here is what happens when a client wants an SFTP session:
1. The client opens a channel.
2. The client sends a `CHANNEL_REQUEST` with the type `"subsystem"` and the name `"sftp"`.
3. OpenSSH looks at its `sshd_config` file and sees: `Subsystem sftp /usr/libexec/openssh/sftp-server`.
4. OpenSSH spawns that binary as a child process.
5. **The Bridge:** OpenSSH takes every `CHANNEL_DATA` packet it receives from the client, strips off the encryption, and writes the raw bytes directly to the `sftp-server`'s `stdin`. When `sftp-server` writes to its `stdout`, OpenSSH wraps those bytes in a `CHANNEL_DATA` packet, encrypts them, and sends them to the client.

**OpenSSH has zero SFTP parsing code inside the daemon.** It is literally just piping standard I/O to a child process.

### How this works in `russh` + `bwrap`
If you use `russh` as your host-level server, `russh` does all the RFC 4254 framing for you. It exposes simple trait methods like `pty_request`, `exec`, and `subsystem`.

If an AI agent requests an SFTP subsystem, your `russh` server handles it identically to a bash shell execution:
1. `russh` triggers your `subsystem` trait callback with the name `"sftp"`.
2. You spawn `bwrap` via `tokio::process::Command`. You configure `bwrap` to execute `/usr/libexec/sftp-server` (or a Rust-based SFTP binary) inside the sandbox, passing in standard pipes (`Stdio::piped()`).
3. You spawn a background Tokio task that loops: reading from `russh`'s data stream and writing to `bwrap`'s `stdin`, and reading `bwrap`'s `stdout` and writing it back to `russh`'s `session.data()`.

You do not need to parse a single SFTP packet. You just pipe the opaque bytes into the sandbox.

### What about PTYs (Pseudo-Terminals)?
PTY allocation is similarly delegated to the host OS.

When a client wants an interactive shell, they send a `"pty-req"` request. `russh` triggers your `pty_request` callback, handing you the requested terminal dimensions (rows/cols) and terminal modes.

In Rust, you don't implement the complex TTY line disciplines yourself. You just use standard Linux syscalls (or a crate like `pty-process`) to ask the Linux kernel to create a Master/Slave PTY pair.
1. You pass the Slave PTY file descriptor into `bwrap` as its standard input/output.
2. You read/write from the Master PTY file descriptor in your `russh` host process, forwarding the bytes as standard `CHANNEL_DATA`.
3. If the client resizes their terminal window, they send a `"window-change"` request. `russh` gives you this event, and you just issue a standard `TIOCSWINSZ` ioctl syscall to the Master PTY file descriptor.

### Summary
Your fear of high-maintenance IPC is resolved by the design of SSH itself. You do not need to build custom IPC serialization to pass SSH data into `bwrap`.

Because `russh` completely handles the SSH framing (window sizes, packet chunking, MACs, encryption), your host process acts as a simple bridge. You turn SSH requests into `bwrap` process executions, and you bridge the unencrypted SSH `CHANNEL_DATA` directly into standard OS Unix pipes (`stdin`/`stdout`). The sandboxed child processes (`/bin/bash` or `sftp-server`) handle their respective application logic without ever knowing they are talking over a network.
</response>
</turn>


<a id="turn-20260928-russh-implementation-breakdown"></a>
<turn timestamp="20260928T203115">

## [2026-09-28] High-level breakdown of implementation with russh

<query>

### User's query

Ok, let me refine my earlier query then.

Let's say hypothetically I wanted to have a SSH server that implements almost all the post-authentication features that OpenSSH does: PTY allocation, SFTP, port-forwarding (the same sort of features AI agents might want to adequately develop software). On the other hand, for authentication, I'd rip out pretty much everything OpenSSH does now and just work off a flat file, no system/library calls for traditional Unix user/group management.

Then:

- If everything was in one process, i.e. no privilege separation, how long would it take to implement using russh?
- And, if we split the above process down the middle, so that post-authentication, the "monitor" process forwards all SSH frames to/from a "session" process launched with `bwrap`, and the "session" process or child processes under it does all the SSH data parsing, how long would this architecture take to implement with russh?
</query>

<response>

### AI's response: introduction

Here is a realistic engineering breakdown of both architectures.

Assuming you are an experienced software engineer comfortable with asynchronous programming (though new to Rust), here is how the timelines and complexities map out using `russh` and the `tokio` async ecosystem.

### Scenario A: Single-Process (No Privilege Separation)
**Estimated Time: 1 to 2 Weeks**

If you drop the `bwrap` isolation and run everything in a single process, `russh` does 90% of the heavy lifting. The implementation becomes a straightforward exercise in gluing Rust crates together.

*   **Authentication (1-2 days):** Completely trivial. You implement the `auth_password` or `auth_publickey` traits in `russh`, read your flat file, and return `Auth::Accept`.
*   **PTY & Shell Allocation (3-4 days):** This is the hardest part of Scenario A. You cannot just use `tokio::process::Command` because standard pipes do not provide terminal emulation (handling Ctrl+C, window resizing, etc.). You must use a crate like `pty-process` or `nix` to issue Linux `openpty` and `forkpty` syscalls, then bridge the resulting Master PTY file descriptor to the `russh` encrypted data stream.
*   **SFTP (1 day):** `russh` triggers a `subsystem` request. You spawn `/usr/libexec/openssh/sftp-server` (or a Rust equivalent) as a standard subprocess and pipe its stdin/stdout directly to `russh`.
*   **Port Forwarding (2-3 days):** When the AI agent requests a direct TCP forward, `russh` gives you the target IP and port. You use `tokio::net::TcpStream::connect()` and spawn a background task to copy bytes between the TCP socket and the SSH channel.

**Verdict:** Highly achievable for a solo developer. The friction comes strictly from learning Linux PTY ioctls, not from the SSH protocol.

### Scenario B: Split-Process (Monitor + Sandboxed Session)
**Estimated Time: 4 to 6 Weeks**

This architecture requires building what is effectively a custom distributed systems bridge.

Because `russh` handles the monolithic SSH state (Transport + Connection layers), your Monitor process must do **all** the SSH parsing. The Monitor then distills those semantic SSH events (PTY, SFTP, TCP) and sends them to the `sandbox-init` daemon running inside `bwrap`.

The massive leap in complexity comes from **Multiplexing**. An AI agent might open a shell, start an SFTP transfer, and open two port forwards *simultaneously* over a single SSH connection. You must get all four data streams in and out of a single `bwrap` sandbox.

Here is where the time goes:

*   **The IPC Multiplexing Trap (2-3 weeks):** If you try to send the data for all four channels over a single Unix domain socket, you have to write a custom framing protocol (e.g., `[Channel_ID (4 bytes)][Data_Length (4 bytes)][Payload]`) to ensure data doesn't get mixed up. You end up accidentally re-inventing SSH's framing layer.
*   **The `SCM_RIGHTS` Optimization (Alternative to Multiplexing):** You can skip custom framing by using a POSIX feature called `SCM_RIGHTS` (passing file descriptors over a Unix socket). When the Monitor gets a new SSH channel, it creates a socket pair (`socketpair()`). It keeps one end, and sends the other end to the `sandbox-init` daemon via `SCM_RIGHTS`. Now the Monitor and the Sandbox have a dedicated pipe for *just* that channel. Getting this right in async Rust takes about a week of intense debugging.
*   **Remote Execution Proxying (1 week):** The Monitor must serialize PTY resize events and window-change requests, send them over the control IPC, and the `sandbox-init` daemon must apply them to the target process.
*   **Network Namespace Translation (1 week):** If `bwrap` uses `--unshare-net`, port forwarding gets tricky. If the AI agent asks to forward a port to `google.com`, the sandboxed daemon cannot reach the internet. The Monitor must handle the TCP connection on the host network, and then pipe the raw TCP bytes down into the sandbox via the IPC bridge.

**Verdict:** This is a serious software engineering project. It is essentially writing a lightweight container runtime (like `containerd`) specifically tailored for SSH protocol semantics.

### The Pragmatic Recommendation

If your goal is to safely sandbox AI agents with robust command-line tooling, **Scenario B is the correct architectural choice**, but you should drastically reduce the scope of your IPC layer.

Instead of writing a custom IPC daemon in Rust, look into **systemd-nspawn** or **LXD/Incus** containers for the per-session sandbox, and use their native APIs to execute commands and attach file descriptors. If you must use `bwrap`, implement the `SCM_RIGHTS` socket-passing method from the start to avoid writing a complex data multiplexer.
</response>
</turn>


<a id="turn-20260928-ssh-parsing"></a>
<turn timestamp="20260928T203847">

## [2026-09-28] Forwarding, then parsing SSH frames separately

<query>

### User's query

It is not possible to just forward SSH frames from the monitor process to the session process, after the encryption is peeled off, for the IPC protocol? The monitor process needs to parse the channel signaling?
</query>

<response>

### AI's response: introduction

Your idea is conceptually brilliant—it is exactly how modern proxies handle TLS termination for HTTP/2 (strip the encryption, forward the multiplexed HTTP/2 frames to the backend).

Theoretically, the SSH protocol is layered perfectly to support this:
1. **RFC 4253 (Transport Layer):** Handles encryption and MAC.
2. **RFC 4252 (User Auth Layer):** Handles passwords/keys.
3. **RFC 4254 (Connection Layer):** Handles channels, PTYs, exec, and SFTP.

If you could just strip the RFC 4253 crypto and forward the raw RFC 4254 connection frames, your Monitor would be incredibly simple.

However, **practically, you cannot do this with `russh` (or almost any other off-the-shelf SSH library).**

Here is why this specific "frame forwarding" architecture hits a brick wall in implementation, and why translating trait calls to IPC is actually the easier path.

### 1. Libraries are Monolithic State Machines
High-level SSH libraries are not designed as modular pipelines where you can tap into the middle. `russh`, Go's `x/crypto/ssh`, and `libssh` all treat the Transport and Connection layers as a single, heavily intertwined state machine.

When `russh` decrypts a packet from the network, it does not hand you the raw decrypted byte frame. It immediately reads the first byte (the SSH Message Type), looks at its internal state, and consumes the packet.
* If it sees an `SSH_MSG_CHANNEL_REQUEST` with the string `"pty-req"`, it parses the terminal dimensions out of the binary payload itself.
* It then invokes the `pty_request()` method on your Rust `Handler` trait.

To get the raw, decrypted SSH frames out of `russh` so you could forward them over IPC, you would literally have to fork the library, delete its entire Connection layer (RFC 4254) implementation, and write an escape hatch to yield the decrypted bytes.

### 2. You Would Have to Write a Second SSH Parser
Even if you successfully hacked `russh` to give you the raw decrypted frames, you now have a new problem: your sandboxed child process receives a stream of raw RFC 4254 SSH frames.

Because standard libraries assume they are handling the *entire* protocol (including crypto), there is no library you can import into your sandboxed process that *only* parses the Connection layer. You would have to manually write the binary parser in Rust to decode SSH strings, integers, channel IDs, and message types to figure out if the agent is asking for a PTY or sending data.

### 3. The Flow Control Nightmare
SSH has built-in flow control (Window Sizes) handled at the Connection layer. If an AI agent sends a massive file over SFTP, the Connection layer tells the Transport layer, "My channel window is full, stop acknowledging TCP packets."

If you split the Transport layer (in the Monitor) and the Connection layer (in the Sandbox) across an IPC boundary, the Monitor doesn't know when to throttle the TCP socket because the window size state lives inside the Sandbox. Synchronizing flow control across processes is notoriously difficult and prone to deadlocks.

### Why the RPC/IPC approach is actually much easier

While building an IPC layer sounds heavy, it is vastly easier than dealing with raw SSH frames because **`russh` does all the binary parsing and flow control for you.**

When you use the architecture from my previous answer (translating `russh` events to IPC), you are taking advantage of the fact that `russh` has already translated complex, highly-specific SSH binary frames into clean Rust types.

Instead of trying to forward an `SSH_MSG_CHANNEL_REQUEST` binary frame, `russh` just calls your function:
```rust
async fn pty_request(&mut self, channel: ChannelId, col_width: u32, row_height: u32, ...)
```

At this point, you don't need to know anything about the SSH protocol. You just send a dead-simple JSON or bincode message over your Unix socket to your sandbox:
`{"action": "allocate_pty", "channel": 1, "cols": 80, "rows": 24}`

**To summarize:** You cannot easily forward raw decrypted SSH frames because libraries do not expose that boundary, and even if they did, you would have to write a custom binary parser in the sandbox. Letting `russh` parse the connection signaling and translating those clean Rust function calls into simple IPC commands is significantly less work and much easier to maintain.
</response>
</turn>


<a id="turn-20260929-sshpiper"></a>
<turn timestamp="20260929T075047">

## [2026-09-29] Multiplexing with sshpiper

<query>

### User's query

Ok, that's probably enough info I need on a russh-based solution. It looks like [sshpiper](https://github.com/tg123/sshpiper) would be easier to work with for my needs. Though as I know nothing about golang programming, if I need to customize it I would totally need AI assistance.

Since sshpiper's purpose is to be a reverse proxy, I'm thinking it already does minimal parsing of RFC 4254 data. (Though I hope it would understand flow control.) Then what I'd want it to do is to execute a specific command for each user, namely to launch Bubblewrap (`bwrap`) running `sshd` in "inetd mode", while "piping" all SSH communication.

So `sshd` does not listen or even communicate through a socket but just through `stdin` and `stdout`. And then I make `sshd`'s authentication be "no-op" (method: none, passwordless authentication: yes).

Would this work? I'm already using a `bwrap`-sandboxed `sshd` today so that is a known working piece. As I said earlier, I just want to be more scalable as I add more users with different sandbox settings.

I don't need a sophisticated database for sshpiper; a flat YAML file listing the users, their keys, and associated command would do. If sshpiper's code need to be customized, or a plugin needs to be implemented to do what I want, how long would it take?
</query>

<response>

### AI's response: introduction

Your proposed architecture—using `sshpiper` to authenticate, and then having it spawn and pipe directly to `bwrap sshd -i` with authentication disabled—is structurally excellent. Running `sshd` in inetd mode (`-i`) is the historically standard way to handle exactly this kind of pre-routed, stream-based connection.

However, implementing this natively in `sshpiper` hits a specific architectural hurdle due to how the project was recently redesigned, but it is highly achievable.

Here is the breakdown of how it would work, what needs to be customized, and how long it would take.

### The Catch: `sshpiper`'s v1 Plugin Architecture
Out of the box, `sshpiper`'s existing `yaml` plugin maps users to network endpoints (e.g., `127.0.0.1:2222`). It does not natively support mapping a user to a local shell command.

Furthermore, `sshpiper` recently moved to a gRPC-based plugin architecture. Plugins run as separate processes and simply return routing configuration (like the upstream IP and port) back to the main `sshpiperd` daemon. Because of this strict IPC boundary, a plugin **cannot** spawn a local process and hand the live `stdin`/`stdout` pipes back to the main proxy.

### The Customization Path (Go Programming)
To make `sshpiper` pipe directly to `bwrap`, you would not write a plugin; you would need to patch the core `sshpiperd` proxy engine.

You would modify `sshpiperd`'s connection dialer to recognize a custom URI scheme (e.g., `cmd://bwrap...`) returned by your YAML file.
1. When `sshpiperd` sees `cmd://`, instead of calling `net.Dial("tcp", target)`, it uses Go's `os/exec` package to spawn your command.
2. Because Go relies heavily on duck-typing, you can take the `StdinPipe()` and `StdoutPipe()` of the spawned process and wrap them into a small custom struct that implements Go's `net.Conn` interface.
3. You hand that fake network connection back to `sshpiper`'s internal SSH engine, and it handles the rest completely unaware that it's talking to a local process instead of a TCP socket.

**Time Estimate:** Even with zero Go experience, an AI agent could guide you through this customization rapidly. Wrapping pipes into a `net.Conn` takes about 50 lines of boilerplate Go code. Finding the dialer in the `sshpiper` codebase, injecting the bypass, and testing the `bwrap` integration would take a solid **2 to 4 days** of tinkering.

### The "Zero-Code" Alternative (Highly Recommended)
If you want to use the standard `sshpiper` release without writing a single line of Go, you can achieve your exact goal using a classic Unix utility: **`socat`**.

Instead of making `sshpiper` spawn the process, you use `socat` as an inetd-style listener to bridge the TCP-to-Pipe gap:

1. **The Target Service:** For each user, you run a lightweight background service using `socat`. For example, for User A on port 22001:
```bash
socat TCP-LISTEN:22001,bind=127.0.0.1,reuseaddr,fork EXEC:"bwrap --unshare-all ... -- /usr/sbin/sshd -i"
```
2. **The `sshpiper` Config:** You use the standard, unmodified `sshpiper` `yaml` plugin. Your flat YAML file simply maps the users to their dedicated `socat` ports:
```yaml
userA:
upstream: 127.0.0.1:22001
userB:
upstream: 127.0.0.1:22002
```

When `sshpiper` authenticates User A, it routes the traffic to `127.0.0.1:22001`. `socat` receives the TCP connection, immediately `forks` a new `bwrap` sandbox, executes `sshd -i`, and pipes the TCP bytes seamlessly into the sandbox's `stdin`/`stdout`.

This architecture gives you the strict, per-session Bubblewrap isolation you want, the flat-file user management you requested, and completely avoids the need to maintain a custom fork of `sshpiper`.
</response>
</turn>


<a id="turn-20260929-sshpiper-inetd"></a>
<turn timestamp="20260929T081544">

## [2026-09-29] Bringing up the listening server fronted by sshpiper

<query>

### User's query

Thank you.

I'm trying to get away from running multiple background services --- even if they use minimal resources --- it's more about administrative load to manage them for me. But, if I were to write a plug-in (and if it's gRPC, that means I can use any language with gRPC bindings, right?), could I have the plug-in *dynamically* bring up the listening side corresponding to the TCP url it hands back to sshpiper?

Or I could run one "internal inetd" because that's basically what I'm doing. If I use this latter approach, can I even use the unmodified `yaml` plugin to do the user-to-port multiplexing? Also, is there a "minimal inetd" implementation without heavy config that a non-root user can run? Systemd (which is what I'm using for my sandboxed `sshd`) is too heavy in the sense that each additional "service" requires defining a `.service` and `.socket` file with a lot of boilerplate content. I just want one flat file: mapping port → command to execute.
</query>

<response>

### AI's response: introduction

Yes, you are absolutely on the right track. Both of these approaches solve the administrative overhead problem beautifully, and they require exactly zero patching of `sshpiper`'s C/Go source code.

Here is the breakdown of how both approaches work, confirming your assumptions.

### Approach 1: The Dynamic gRPC Plugin (Zero Background Services)
Yes, because `sshpiper` v1 uses standard gRPC for its plugins, **you can write the plugin in any language you want** (Python, Rust, Node.js, etc.) by simply generating the bindings from their `.proto` file.

This approach allows you to achieve true "on-demand" sandboxing with absolutely no idle background listeners:

1. **The Request:** An AI agent connects as `ai-user-2`. `sshpiper` suspends the connection and sends a gRPC `FindUpstream(username="ai-user-2")` request to your custom Python plugin.
2. **The Dynamic Spin-up:** Your Python script looks up the user's `bwrap` command in your YAML file. It finds an available ephemeral port (e.g., `127.0.0.1:43912`).
3. **The Listener:** The script immediately uses `subprocess.Popen` to spawn a one-off `socat` listener on that port that wraps the `bwrap sshd -i` command.
4. **The Handoff:** Your plugin returns `127.0.0.1:43912` back to `sshpiper` via gRPC.
5. **The Connection:** `sshpiper` connects to that ephemeral port. `socat` accepts the connection, spawns the sandboxed `sshd`, and bridges the traffic.
6. **The Cleanup:** When the AI agent disconnects, `sshpiper` drops the TCP connection. `socat` detects the EOF, the `bwrap` sandbox shuts down, and all resources vanish.

You only run *one* background service: the tiny Python gRPC server. Everything else is spun up dynamically.

### Approach 2: The "Micro-inetd" (Using the unmodified YAML plugin)
If you do not want to deal with gRPC protocol buffers, you can use `sshpiper`'s default `yaml` plugin. As you noted, the `yaml` plugin requires the upstream TCP addresses to be static, so you need *something* listening on those ports.

You asked if there is a minimal, non-root `inetd` implementation that just reads a flat file. Classic `xinetd` exists, but its configuration is archaic and it expects to run as root.

However, because you are just mapping a TCP socket to `stdin`/`stdout`, **you can write a complete "micro-inetd" in about 35 lines of Python**. It is vastly simpler than managing systemd `.socket` and `.service` units.

Here is exactly what that single background script looks like:

```python
import asyncio
import yaml
import subprocess

async def handle_connection(reader, writer, command):
    # Spawn the sandboxed sshd in inetd mode
    process = subprocess.Popen(
        command, shell=True,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    
    # Bridge the TCP socket to the process stdin/stdout
    async def pump(src, dst):
        while data := await src.read(4096):
            dst.write(data)
            if hasattr(dst, 'drain'): await dst.drain()
        if hasattr(dst, 'close'): dst.close()
        
    # Run bidirectional forwarding
    loop = asyncio.get_running_loop()
    await asyncio.gather(
        pump(reader, process.stdin),
        pump(loop.connect_read_pipe(asyncio.StreamReader, process.stdout)[0], writer)
    )

async def main():
    # Load your flat mapping file
    with open("users.yaml") as f:
        config = yaml.safe_load(f)
        
    servers = []
    # Start a socket listener for every user in the flat file
    for user, data in config.items():
        port = data['local_port']
        cmd = data['bwrap_command'] # e.g., "bwrap --unshare-all ... /usr/sbin/sshd -i"
        
        server = await asyncio.start_server(
            lambda r, w, c=cmd: handle_connection(r, w, c), 
            '127.0.0.1', port
        )
        servers.append(server)

    await asyncio.gather(*(s.serve_forever() for s in servers))

asyncio.run(main())
```
### Which should you choose?
*   **Go with Approach 2 (Micro-inetd)** if you want to get this running this afternoon. You use the unmodified `sshpiper` release, the `yaml` plugin, and run that tiny Python script as your single background routing service. It consumes essentially zero RAM while idle.
*   **Go with Approach 1 (gRPC Plugin)** if you have hundreds or thousands of users and do not want to pre-allocate a massive block of static TCP ports. It is slightly more work to compile the `.proto` bindings, but it is the most robust, dynamically scalable architecture possible.
</response>
</turn>


