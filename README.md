*Work in progress*

Shion is an implementation of an [Secure Shell (SSH)](https://en.wikipedia.org/wiki/Secure_Shell) server, 
intended for clients that are AI agents, all running under one designated unprivileged user on the host
system.

The client sessions may be sandboxed with wrapper programs like [Bubblewrap](https://github.com/containers/bubblewrap).
The sandboxing parameters are customizable, and can be switched on the user name of the connecting client.
So, AI agents may work on different projects, and have sandboxes provisioned for them per project or 
per role.

With OpenSSH, such an architecture can only be implemented by running multiple `sshd` instances, one
for each sandbox user.  Furthermore, unless those `sshd` instances are fronted by an SSH multiplexer 
like [sshpiper](https://github.com/tg123/sshpiper), they will need to be assigned different network
ports.  

And even if sshpiper is used, managing the port assignments and lifetimes of those internal `sshd` 
instances may be more administratively complex than desired.  For example, if you decide to use
[systemd](https://en.wikipedia.org/wiki/Systemd) to manage them, each `sshd` instance needs
its own `.service` and `.socket` definition, just to implement socket activation for sshpiper,
yet not have idle `sshd` instances linger forever — as sshpiper does not natively support 
launching SSH servers on demand.

Shion, on the other hand, is more lightweight: you can configure what command line is used to
launch a sandboxed session process, whenever it is neeeded.

