//! The carrier: one bidirectional byte stream made from stdin and stdout.
//!
//! The front-end will probably hand us one end of a `socketpair` as both
//! fds, but we don't assume that. Any pipe, socket, FIFO, tty or even a
//! regular file works, so the process can be driven from a shell for
//! testing (`shion-session … < requests.bin > responses.bin`). The
//! `shion-fd` crate explains why we don't use `tokio::io::stdin()`.

use std::fs::File;
use std::io;
use std::os::fd::AsFd;

use shion_fd::{BoxedRead, BoxedWrite};
use tokio::io::Join;

/// stdin and stdout joined into one `AsyncRead + AsyncWrite` value, which is
/// the shape async-smux wants.
///
/// The halves are boxed (run-time polymorphism) because their concrete
/// types depend on the actual "files" passed in as stdin/stdout: see
/// [`shion_fd::duplex`].
pub type Carrier = Join<BoxedRead, BoxedWrite>;

/// Takes over stdin and stdout as the carrier.
///
/// Afterwards fd 0 reads from `/dev/null` and fd 1 is a copy of stderr, so a
/// stray `println!` (ours or a library's) ends up in the log instead of
/// corrupting the protocol stream. Must be called from inside a tokio
/// runtime.
///
/// # Errors
/// If the fds can't be duplicated or redirected.
pub fn from_stdio() -> io::Result<Carrier> {
    // `try_clone_to_owned` is `dup` with `O_CLOEXEC`, so child processes
    // never inherit the carrier.
    let input = io::stdin().as_fd().try_clone_to_owned()?;
    let output = io::stdout().as_fd().try_clone_to_owned()?;

    rustix::stdio::dup2_stdin(File::open("/dev/null")?)?;
    rustix::stdio::dup2_stdout(io::stderr())?;

    let (reader, writer) = shion_fd::duplex(input, output)?;
    Ok(tokio::io::join(reader, writer))
}
