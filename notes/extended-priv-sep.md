# Even more rigorous privilege separation

Currently, the threat model for Shion is that the front-end server processes hostile
network input, but runs no user code.  Since Shion is written in Rust, that is already
fairly safe, but we might want even higher assurance that some kind of unsoundness
in the Rust implementation could not compromise credentials, allow escape from the
sandboxed session, or allow manipulation under whatever “real” user that the front-end
server is running as.

Note that the front-end server cannot be very strictly sandboxed itself because it
needs permissions to launch sandboxes for the union of all users.

So we might want to consider additional privilege separation on the front end.
Although not a primary use case, that will be particularly pertinent if Shion 
is to used as a SSH server for “real” (system-level) user accounts in the manner of 
traditional SSH: the front-end would need to run as `root` just to be
able to switch to the desired user.

We could implement the additional privilege separation similarly to what OpenSSH
does, as follows.  Let's call the initial process that is started as the “master process”.
Below, we'll use the term “privileged” below to mean “unsandboxed” (if running as
a single host user) or “running as root” (if Shion can switch between system-level users).

  1. First, on start up, the master process forks itself:
    - The parent remains privileged, but does not read any hostile network input directly.  
    - The child becomes the front-end that handles hostile network input.
  2. The child gets a Unix domain socket, one end of of the `socketpair` inherited from the master process, to communicate with the latter.
  3. The parent reads the necessary configuration, such as the accepted credentials and sandbox parameters.  
    - The configuration is considered trusted input given by the administrator.
  4. On each network connection that the front-end accepts, it further forks a child process to handle it.  
    - This is purely to prevent credentials for different clients from mixing in the same process.  
    - That grandchild inherits the control socket from the master process.
  5. As the connecting client tries to authenticate, the grandchild validates credentials with the master process.  
    - The master process treats the other end of its control socket as hostile.
  6. When validation is successful, the master process hands out a token (an integer handle) to the grandchild process.
  7. The grandchild process can use the token to use the (sandboxed) session program pre-configured for the connecting user.  
    - Furthermore, it will supply the socket which maps to `shion-session`'s connection (currently wired as stdin/stdout).
  8. The master process will launch a sandboxed `shion-session` on behalf of the grandchild and wire it up.
  9. If we want a single `shion-session` process to work with multiple network connections, since there are now could be multiple grandchildren processes, `shion-session` will have to extended to process additional streams in its `tokio` reactor loop.
  10. The master process still manages the lifetime of all the (sandboxed) `shion-session` processes.

With this model:

  - The front-end process can be sandboxed too, to the absolute minimum needed to handle network connections.
  - Compromising the front-end process does not gain any privileges beyond what can be obtained by normal operation from the client's supplied credentials.
  - The only untrusted input to the master process is the client's credentials during authentication, which can be rigorouly validated.
