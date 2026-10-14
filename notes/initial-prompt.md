/ssh I have a remote machine with a large variety of development tools installed, and equipped with ample CPU and memory. I want you to connect to that machine, called "steve-sandbox", using the SSH skill Note that the host is sandboxed, with network connectivity for downloading from certain package repositories only. 

I have in mind a somewhat ambitious project to implement an SSH server in Rust with *privilege separation* of sessions.  The only open-source implementation of an SSH server supporting privilege separation, that I know of, is, of course, OpenSSH.

What I'd like to have is a SSH server that runs sessions in sandboxes, so that I can safely let AI agents connect and work inside (without having to approve their commands manually).  [Bubblewrap](https://github.com/containers/bubblewrap) (the `bwrap` command) would do the sandboxing on Linux, and the sandboxing parameters may change depending on the connecting user account.  At the same time, I want to selectively share my files with my agents.  All this selective sharing is better and more easily done with unprivileged namespaces than provisioning traditional Unix user accounts (which requires elevating to the super-user).  

So I want my SSH server to work off "app-level" users, as in most database servers, web services, etc.  OpenSSH's `sshd` carries a lot of (what I'd consider) baggage for system-level user accounts.  Furthermore, when run in unprivileged mode it only allows a single user to log in.

One could run multiple `sshd` instances, one for each sandbox, but having the different users (AI agents) be multiplexed based on the user name, connecting to a single server port, is much easier to manage when considering network firewalls, etc.

User-based multiplexing could be accomplished by fronting all those `sshd` instances behind [sshpiper](https://github.com/tg123/sshpiper).  I'm fairly confident that solution would work, but managing all those server instances is more administratively difficult than I desire.

So I've been considering implementing my own custom SSH multiplexer that can launch the sandboxed sessions directly.  Please take a quick look at the below transcripts of chats I had with another LLM: (in the directory `/home/steve/dev/shion/notes/`)

  - [Implementation of user-based multiplexing of SSH servers](ssh-server-multiplexing.md)
  - [Implementing a SSH3 server with privilege separation](ssh3-server.md)

To summarize, complexities in the SSH protocol and its implementing libraries (like “russh” in Rust) make privilege separation more difficult than expected.  Yet, conceptually it shouldn't be that hard: if we look at the so-called “SSH3” protocol, which outsources what traditional SSH does on its own to the more general QUIC and HTTP/3 protocol stacks, it becomes a lot more straightforward.  

I know what I'm trying to do is over-kill, but please consider it to be an exercise in coding in Rust if nothing else.  I'm an experienced C++ programmer but just a beginner in Rust, and seeing you code this kind of low-level software will help me learn.  (If I were younger, I'd probably spend a few years learning it all from “first principles”, but nowadays I don't have that luxury; perhaps modern AI technology can help me make up for that.)

The design is outlined at the end of the second transcript.  The major problem I see with it is that “SSH3” is experimental and I don't completely trust even the reference implementation, especially since the original author has abandoned it for a few years.  At least there's a [community-maintained fork](https://github.com/h4sh5/sshoq), though it's also not clear how much it has diverged from the [IETF draft of the specification](https://datatracker.ietf.org/doc/draft-michel-remote-terminal-http3/) which itself has expired.

So one thing I would change for our initial design would be to continue using the original SSH2 protocol for now.  So the “front-end” process would speak SSH2 using the russh library, but forward the SSH-channel requests to the session process using the ssh3 wire format.  So when the session process is completely brought up, we could switch the “front-end” to speak SSH3 (the HTTP/3 + QUIC-based protocol) if we desire.

As for for the multiplexing of channels from the “front-end” process to the session process, I would avoid the approach of Unix domain sockets as suggested in the transcript. Instead, we could use the [async-smux crate in Rust](https://github.com/black-binary/async-smux) to multiplex the streams with lightweight 8-byte headers.  That has a few advantages:

  - It is more portable, should we want to port this software to Windows.
  - The session process could be easily adapted to run on a remote machine.
  - It uses less kernel resources — file descriptors.

Do you understand what I am getting at?

If so, we could start from the session process first, which would contain key logic like executing shell commands and opening pseudo-terminals.  Could you come up with a design?

Please use the directory `/home/steve/dev/shion` for all the code.  (It's not initialized as a Rust project yet.)  Code name for this project: “shion”.

If you want to take a look at an SSH3 implementation, I checked out “sshoq” at `/home/steve/dev/sshoq`.

