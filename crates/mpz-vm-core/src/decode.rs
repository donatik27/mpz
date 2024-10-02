use std::{
    future::Future,
    ops::Range,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{channel::oneshot, FutureExt};
use mpz_memory_core::Slice;

/// Decode operation.
#[derive(Debug)]
pub struct DecodeOp<T> {
    pub slice: Slice,
    pub chan: Option<oneshot::Sender<T>>,
}

impl<T> DecodeOp<T> {
    /// Sends the data.
    pub fn send(&mut self, data: T) -> Result<(), DecodeError> {
        if let Some(chan) = self.chan.take() {
            _ = chan.send(data);
        } else {
            return Err(DecodeError);
        }

        Ok(())
    }
}

/// Future which will resolve to a value when it is ready.
#[derive(Debug)]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct DecodeFuture<T> {
    chan: oneshot::Receiver<T>,
}

impl<T> DecodeFuture<T> {
    /// Creates a new decode future.
    #[doc(hidden)]
    pub fn new(slice: Slice) -> (Self, DecodeOp<T>) {
        let (chan, recv) = oneshot::channel();

        (
            Self { chan: recv },
            DecodeOp {
                slice,
                chan: Some(chan),
            },
        )
    }

    /// Tries to receive the value, returning `None` if the value is not ready.
    pub fn try_recv(&mut self) -> Result<Option<T>, DecodeError> {
        self.chan.try_recv().map_err(|_| DecodeError)
    }
}

impl<T> Future for DecodeFuture<T> {
    type Output = Result<T, DecodeError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        self.chan.poll_unpin(cx).map_err(|_| DecodeError)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("decode operation was dropped.")]
pub struct DecodeError;
