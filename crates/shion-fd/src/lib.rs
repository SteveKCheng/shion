//! Non-blocking file descriptors driven by tokio's reactor (epoll).
//!
//! Tokio's own `stdin()`/`stdout()` do blocking I/O on a helper thread that
//! can't be cancelled, so shutting the runtime down can hang until more
//! input arrives. Instead, fds that support readiness polling (pipes,
//! sockets, FIFOs, ttys, pty masters: everything except regular files) are
//! registered with the reactor through [`AsyncFd`]. Regular files never
//! block indefinitely, so [`reader`] and [`writer`] fall back to
//! `tokio::fs::File` for them, which uses the blocking thread pool.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use rustix::fs::OFlags;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub type BoxedRead = Box<dyn AsyncRead + Send + Unpin>;
pub type BoxedWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// Wraps any readable fd. Must be called from inside a tokio runtime.
///
/// We need run-time polymorphism (a `Box<dyn …>`) because the concrete type
/// depends on what the fd turns out to be:
///
///   - [`FdStream`] for fds that support non-blocking operation and polling.
///   - `tokio::fs::File` for regular files.
///
/// # Errors
/// If the fd's flags can't be read or changed, or registration fails for a
/// reason other than the fd being a regular file.
pub fn reader(fd: OwnedFd) -> io::Result<BoxedRead> {
    Ok(match FdStream::new(fd)? {
        Ok(stream) => Box::new(stream),
        Err(fd) => Box::new(tokio::fs::File::from_std(File::from(fd))),
    })
}

/// Wraps any writable fd. See [`reader`].
///
/// # Errors
/// As for [`reader`].
pub fn writer(fd: OwnedFd) -> io::Result<BoxedWrite> {
    Ok(match FdStream::new(fd)? {
        Ok(stream) => Box::new(stream),
        Err(fd) => Box::new(tokio::fs::File::from_std(File::from(fd))),
    })
}

/// Wraps an input fd and an output fd, which may share one open file
/// description.
///
/// Prefer this to separate [`reader`] and [`writer`] calls for stdin and
/// stdout. They often share one *open file description* (a terminal, or
/// one end of a `socketpair` passed as both), and with it the `O_NONBLOCK`
/// flag. Two [`FdStream`]s on it would each remember the flags they found,
/// and whichever was created second would "restore" `O_NONBLOCK` when
/// dropped, leaving, say, your shell's terminal non-blocking. So in that
/// case we wrap only `input`, which must be open for both reading and
/// writing, and split it.
///
/// # Errors
/// As for [`reader`].
pub fn duplex(mut input: OwnedFd, output: OwnedFd) -> io::Result<(BoxedRead, BoxedWrite)> {
    if same_description(&input, &output)? && is_read_write(&input)? {
        match FdStream::new(input)? {
            Ok(stream) => {
                drop(output); // a duplicate we don't need
                let (r, w) = tokio::io::split(stream);
                return Ok((Box::new(r), Box::new(w)));
            }
            Err(fd) => input = fd, // a regular file: no flags to worry about
        }
    }
    Ok((reader(input)?, writer(output)?))
}

/// Whether two fds share one open file description.
fn same_description(a: &OwnedFd, b: &OwnedFd) -> io::Result<bool> {
    #[cfg(target_os = "linux")]
    match kcmp_file(a, b) {
        Ok(same) => return Ok(same),
        // ENOSYS: a kernel built without `kcmp`. EPERM: blocked by a
        // seccomp filter, as in Docker's default profile. Fall back.
        Err(e) if matches!(e.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) => {}
        Err(e) => return Err(e),
    }
    // Same file, which is a weaker test: fds sharing a description always
    // refer to the same file, so it never misses a shared description, but
    // it also matches separate opens of one file. Then we'd use `input` for
    // output too, which works (it's open read-write) but ignores any status
    // flags of `output`'s own description, such as `O_APPEND`.
    let (a, b) = (rustix::fs::fstat(a)?, rustix::fs::fstat(b)?);
    Ok((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino))
}

/// Asks the kernel whether two of our fds share an open file description,
/// with `kcmp(KCMP_FILE)`. Linux-only, and with no wrapper in glibc or
/// rustix, so we make the raw system call through the `libc` crate.
#[cfg(target_os = "linux")]
fn kcmp_file(a: &OwnedFd, b: &OwnedFd) -> io::Result<bool> {
    use std::os::fd::AsRawFd;

    /// From `<linux/kcmp.h>`, which the `libc` crate doesn't cover.
    const KCMP_FILE: libc::c_long = 0;

    // `syscall` is variadic and the kernel reads every argument as a full
    // register, so pass them all as `c_long`. An `i32` passed as a C
    // variadic argument may leave the register's upper half undefined.
    let pid = libc::c_long::from(rustix::process::getpid().as_raw_nonzero().get());
    let (a, b) = (
        libc::c_long::from(a.as_raw_fd()),
        libc::c_long::from(b.as_raw_fd()),
    );
    #[allow(unsafe_code)]
    // SAFETY: `kcmp` only compares kernel objects. It takes no pointers,
    // so it can't touch our memory, and the arguments match its
    // signature, `kcmp(pid, pid, type, idx1, idx2)`. A stale fd number
    // would only make it fail with EBADF, and the borrows keep both open.
    let result = unsafe { libc::syscall(libc::SYS_kcmp, pid, pid, KCMP_FILE, a, b) };
    // 0 means equal. 1 and 2 order unequal objects, which `kcmp` offers so
    // callers can sort them.
    match result {
        -1 => Err(io::Error::last_os_error()),
        r => Ok(r == 0),
    }
}

fn is_read_write(fd: &OwnedFd) -> io::Result<bool> {
    Ok(rustix::fs::fcntl_getfl(fd)? & OFlags::RWMODE == OFlags::RDWR)
}

/// Adapts a file descriptor for async I/O in tokio's reactor.
///
/// Implements both `AsyncRead` and `AsyncWrite`; whether both work depends
/// on the FD. To read and write from different tasks, use
/// `tokio::io::split`.
///
/// The non-blocking flag `O_NONBLOCK` is set on the file descriptor,
/// and then restored on dropping `FdStream`.
///
/// However, do note that `O_NONBLOCK` belongs to the *open file description*,
/// which is shared between cloned FDs.  In shion, the target file descriptors
/// are either owned by the session process, or for the stdin/stdout of the
/// session process, which can only be reasonably assumed to be solely used
/// by the session process. (stdin and stdout are passing binary data so any
/// process trying to read/write to them at the same time will surely corrupt
/// the data.)  
///
/// In case the session process is run from the terminal, etc., restoring the
/// original file status is mostly about being nice: if the session process
/// crashes, it is not guaranteed to restore the flags.
#[derive(Debug)]
pub struct FdStream {
    fd: AsyncFd<OwnedFd>,

    /// File status flags before `O_NONBLOCK` is set; restored on drop.
    original_flags: OFlags,
}

impl FdStream {
    /// Wraps `fd`, or gives it back (`Ok(Err(fd))`) if epoll doesn't
    /// support it, as with regular files. Must be called from inside a
    /// tokio runtime.
    ///
    /// The nested `Result` separates "real error" (outer) from "this fd
    /// needs a different strategy" (inner).
    ///
    /// # Errors
    /// If the fd's flags can't be read or changed, or registration fails for
    /// a reason other than the fd being a regular file.
    pub fn new(fd: OwnedFd) -> io::Result<Result<Self, OwnedFd>> {
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn pipe_roundtrip_and_flags_restored() {
        let (r, w) = rustix::pipe::pipe().unwrap();
        let r2 = r.try_clone().unwrap(); // shares the open file description
        let mut reader = reader(r).unwrap();
        let mut writer = writer(w).unwrap();
        assert!(
            rustix::fs::fcntl_getfl(&r2)
                .unwrap()
                .contains(OFlags::NONBLOCK)
        );

        writer.write_all(b"hello").await.unwrap();
        drop(writer);
        let mut got = Vec::new();
        reader.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello");

        drop(reader);
        assert!(
            !rustix::fs::fcntl_getfl(&r2)
                .unwrap()
                .contains(OFlags::NONBLOCK)
        );
    }

    #[tokio::test]
    async fn duplex_shares_one_fd_and_restores_flags() {
        let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let theirs = OwnedFd::from(theirs);
        let watch = theirs.try_clone().unwrap();
        let (mut r, mut w) = duplex(theirs.try_clone().unwrap(), theirs).unwrap();
        assert!(
            rustix::fs::fcntl_getfl(&watch)
                .unwrap()
                .contains(OFlags::NONBLOCK)
        );

        w.write_all(b"ping").await.unwrap();
        let mut ours = tokio::net::UnixStream::from_std({
            ours.set_nonblocking(true).unwrap();
            ours
        })
        .unwrap();
        let mut got = [0; 4];
        ours.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        ours.write_all(b"pong").await.unwrap();
        r.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"pong");

        // Dropped in creation order: the case that went wrong with two
        // separate `FdStream`s.
        drop(r);
        drop(w);
        assert!(
            !rustix::fs::fcntl_getfl(&watch)
                .unwrap()
                .contains(OFlags::NONBLOCK)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn kcmp_tells_descriptions_apart() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let first = OwnedFd::from(file.reopen().unwrap());
        let dup = first.try_clone().unwrap(); // same description
        let second = OwnedFd::from(file.reopen().unwrap()); // a new one
        match kcmp_file(&first, &second) {
            Ok(same) => assert!(!same),
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) => {
                eprintln!("kcmp unavailable ({e}); skipping");
                return;
            }
            Err(e) => panic!("kcmp: {e}"),
        }
        assert!(kcmp_file(&first, &dup).unwrap());
        assert!(same_description(&first, &dup).unwrap());
        assert!(!same_description(&first, &second).unwrap());
    }

    #[tokio::test]
    async fn regular_files_fall_back() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"data").unwrap();
        let fd = OwnedFd::from(file.reopen().unwrap());
        assert!(FdStream::new(fd.try_clone().unwrap()).unwrap().is_err());
        let mut got = Vec::new();
        reader(fd).unwrap().read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"data");
    }
}
