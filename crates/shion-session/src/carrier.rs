//! The carrier: one bidirectional byte stream made from stdin and stdout.
//!
//! The front-end will probably hand us one end of a `socketpair` as both
//! fds, but we don't assume that. Any pipe, socket, FIFO, tty or even a
//! regular file works, so the process can be driven from a shell for
//! testing (`shion-session … < requests.bin > responses.bin`).
//!
//! `tokio::io::stdin()` would be the obvious choice, but tokio implements
//! it with a blocking `read` on a helper thread that can't be cancelled, so
//! shutting the runtime down can hang until more input arrives. Instead,
//! fds that support readiness polling (everything except regular files) are
//! registered with tokio's reactor through [`AsyncFd`]. Regular files never
//! block indefinitely, so they can safely use `tokio::fs::File`, which does
//! use the blocking thread pool.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use rustix::fs::OFlags;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, Join, ReadBuf};

pub type BoxedRead = Box<dyn AsyncRead + Send + Unpin>;
pub type BoxedWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// stdin and stdout joined into one `AsyncRead + AsyncWrite` value, which is
/// the shape async-smux wants.
///
/// We require run-time polymorphism for `BoxedRead` and `BoxedWrite`.
/// The concrete type of each half depends on the actual "files" that are 
/// passed in to the session process's stdin/stdout. 
/// 
/// The concrete type is:
/// 
///   - `FdStream` for file descriptors that support non-blocking operation and polling.
///   - `tokio::fs::File` for regular files.
/// 
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

    let reader: BoxedRead = match FdStream::new(input)? {
        Ok(stream) => Box::new(stream),
        Err(fd) => Box::new(tokio::fs::File::from_std(File::from(fd))),
    };
    let writer: BoxedWrite = match FdStream::new(output)? {
        Ok(stream) => Box::new(stream),
        Err(fd) => Box::new(tokio::fs::File::from_std(File::from(fd))),
    };
    Ok(tokio::io::join(reader, writer))
}

/// A non-blocking fd driven by tokio's reactor (epoll).
#[derive(Debug)]
struct FdStream {
    fd: AsyncFd<OwnedFd>,
    /// File status flags before we set `O_NONBLOCK`, restored on drop.
    /// `O_NONBLOCK` belongs to the *open file description*, which is shared
    /// with whoever gave us the fd (say, an interactive shell's tty), so we
    /// put it back the way we found it.
    original_flags: OFlags,
}

impl FdStream {
    /// Wraps `fd`, or gives it back (`Ok(Err(fd))`) if epoll doesn't
    /// support it, as with regular files.
    ///
    /// The nested `Result` separates "real error" (outer) from "this fd
    /// needs a different strategy" (inner).
    fn new(fd: OwnedFd) -> io::Result<Result<Self, OwnedFd>> {
        let original_flags = rustix::fs::fcntl_getfl(&fd)?;
        rustix::fs::fcntl_setfl(&fd, original_flags | OFlags::NONBLOCK)?;
        // `unsafe` because the reactor keeps using the raw fd number, which
        // would go wrong if the wrapped object closed or swapped its fd
        // behind tokio's back. (Tokio 1.53 deprecated the safe `try_new`
        // for exactly that reason.) The workspace denies `unsafe_code`, so
        // this one block has to opt out explicitly, and clippy requires the
        // SAFETY comment.
        #[allow(unsafe_code)]
        // SAFETY: `OwnedFd` owns a valid, open fd, never closes or replaces
        // it except on drop, and `as_raw_fd` always returns the same number.
        let registered = unsafe { AsyncFd::register(fd) };
        match registered {
            Ok(fd) => Ok(Ok(Self { fd, original_flags })),
            // On failure we get the fd back, still owned, and can fall back
            // to something else.
            Err(e) => {
                let (fd, err) = e.into_parts();
                rustix::fs::fcntl_setfl(&fd, original_flags)?;
                if err.kind() == io::ErrorKind::PermissionDenied {
                    Ok(Err(fd)) // epoll refuses regular files with EPERM
                } else {
                    Err(err)
                }
            }
        }
    }
}

impl Drop for FdStream {
    fn drop(&mut self) {
        // Best effort: nothing useful to do if this fails during teardown.
        let _ = rustix::fs::fcntl_setfl(self.fd.get_ref(), self.original_flags);
    }
}

// The standard readiness pattern: wait until epoll says the fd is ready,
// try the syscall, and if it says EAGAIN after all, `try_io` clears the
// readiness flag and we go round again.

impl AsyncRead for FdStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|fd| Ok(rustix::io::read(fd.get_ref(), &mut *unfilled)?)) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => {}
            }
        }
    }
}

impl AsyncWrite for FdStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;
            match guard.try_io(|fd| Ok(rustix::io::write(fd.get_ref(), data)?)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => {}
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Nothing is buffered in user space.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The fd is closed when the FdStream is dropped. (For a socket we
        // could `shutdown(SHUT_WR)` here, but we don't assume a socket.)
        Poll::Ready(Ok(()))
    }
}
