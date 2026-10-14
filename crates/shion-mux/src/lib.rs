//! async-smux plumbing shared by the shion front-end and session process.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_smux::MuxStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// What async-smux needs from a carrier. (async-smux names this
/// `TokioConn`, but doesn't export it; any type with these traits
/// qualifies.)
pub trait Carrier: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> Carrier for T {}

/// A smux stream that can be closed through `tokio_util`'s `Framed`.
///
/// Works around a bug in async-smux 0.4.0: once `poll_shutdown` has queued
/// the FIN, `poll_flush` fails with `BrokenPipe` ("stream tx is already
/// closed"). `Framed::poll_close` calls flush and then shutdown, and when
/// shutdown returns `Pending` (while the FIN is still being written) the
/// whole sequence is polled again, so the flush fails. This wrapper
/// remembers that shutdown has started and treats a later flush as "keep
/// shutting down", which is what flushing a half-closed stream should do.
pub struct Stream<T: Carrier> {
    inner: MuxStream<T>,
    shutting_down: bool,
}

// Written by hand because `MuxStream` doesn't implement `Debug`.
impl<T: Carrier> fmt::Debug for Stream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream")
            .field("id", &self.id())
            .field("shutting_down", &self.shutting_down)
            .finish_non_exhaustive()
    }
}

impl<T: Carrier> From<MuxStream<T>> for Stream<T> {
    fn from(inner: MuxStream<T>) -> Self {
        Self {
            inner,
            shutting_down: false,
        }
    }
}

impl<T: Carrier> Stream<T> {
    /// The smux stream ID (odd for client-opened streams, even for
    /// server-opened ones).
    pub fn id(&self) -> u32 {
        self.inner.get_stream_id()
    }
}

// `MuxStream` is `Unpin`, so `Stream` is too, and `get_mut` on the pinned
// reference is allowed. Pinning only matters for types that point into
// themselves (like most `async` blocks), which these don't.

impl<T: Carrier> AsyncRead for Stream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: Carrier> AsyncWrite for Stream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.shutting_down {
            // Flushes the queued frames, FIN included, and returns Ok.
            Pin::new(&mut this.inner).poll_shutdown(cx)
        } else {
            Pin::new(&mut this.inner).poll_flush(cx)
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.shutting_down = true;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_smux::MuxBuilder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Flushing after shutdown must succeed, as it does for TCP streams.
    /// With a bare `MuxStream` the flush fails.
    #[tokio::test]
    async fn flush_after_shutdown_succeeds() {
        let (a, b) = tokio::io::duplex(64);
        let (connector, _acceptor_a, worker_a) = MuxBuilder::client().with_connection(a).build();
        let (_connector_b, mut acceptor, worker_b) =
            MuxBuilder::server().with_connection(b).build();
        tokio::spawn(worker_a);
        tokio::spawn(worker_b);

        let mut stream = Stream::from(connector.connect().unwrap());
        stream.write_all(b"hello").await.unwrap();
        stream.shutdown().await.unwrap();
        stream.flush().await.unwrap();

        let mut peer = acceptor.accept().await.unwrap();
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"hello");
    }
}
