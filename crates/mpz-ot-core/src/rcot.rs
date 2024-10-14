use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::{channel::oneshot, FutureExt};

use crate::TransferId;

/// Output the sender receives from the random COT functionality.
#[derive(Debug)]
pub struct RCOTSenderOutput<T> {
    /// Transfer id.
    pub id: TransferId,
    /// Random keys.
    pub keys: Vec<T>,
}

/// Random correlated oblivious transfer sender.
pub trait RCOTSender<T> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Allocates `count` RCOTs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of available RCOTs.
    fn available(&self) -> usize;

    /// Returns the global correlation key, `delta`.
    fn delta(&self) -> T;

    /// Returns preprocessed RCOTs, if available.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of preprocessed RCOTs to try to consume.
    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<T>, Self::Error>;

    /// Returns a future which will yield RCOTs once they are ready.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of RCOTs to send.
    fn queue_send_rcot(&mut self, count: usize) -> Result<RCOTSendFuture<T>, Self::Error>;
}

/// Sender channel of [`RCOTSendFuture`].
#[derive(Debug)]
pub(crate) struct RCOTSendPending<T> {
    count: usize,
    chan: oneshot::Sender<RCOTSenderOutput<T>>,
}

impl<T> RCOTSendPending<T>
where
    T: Send + 'static,
{
    /// Returns the number of RCOTs to send.
    pub(crate) fn count(&self) -> usize {
        self.count
    }

    /// Sends the output.
    pub(crate) fn send(self, output: RCOTSenderOutput<T>) {
        let _ = self.chan.send(output);
    }
}

/// Future returned by [`RCOTSender::send_random_correlated`].
#[must_use = "futures do nothing unless you `.await` or poll them"]
#[derive(Debug)]
pub struct RCOTSendFuture<T> {
    chan: oneshot::Receiver<RCOTSenderOutput<T>>,
}

impl<T> RCOTSendFuture<T> {
    /// Creates a new RCOT send future.
    pub(crate) fn new(count: usize) -> (RCOTSendPending<T>, Self) {
        let (sender, receiver) = oneshot::channel();

        (
            RCOTSendPending {
                count,
                chan: sender,
            },
            RCOTSendFuture { chan: receiver },
        )
    }

    /// Attempts to receive the output, returning `None` if not ready.
    pub fn try_recv(&mut self) -> Result<Option<RCOTSenderOutput<T>>, RCOTSendFutureError> {
        match self
            .chan
            .try_recv()
            .map_err(|_| RCOTSendFutureError { _private: () })?
        {
            Some(output) => Ok(Some(output)),
            None => Ok(None),
        }
    }
}

impl<T> Future for RCOTSendFuture<T>
where
    T: Send + 'static,
{
    type Output = Result<RCOTSenderOutput<T>, RCOTSendFutureError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.chan
            .poll_unpin(cx)
            .map_err(|_| RCOTSendFutureError { _private: () })
    }
}

/// Error for [`RCOTSendFuture`].
#[derive(Debug, thiserror::Error)]
#[error("failed to send RCOT: protocol error occurred or it was cancelled")]
pub struct RCOTSendFutureError {
    _private: (),
}

/// Output the receiver receives from the random COT functionality.
#[derive(Debug)]
pub struct RCOTReceiverOutput<T, U> {
    /// Transfer id.
    pub id: TransferId,
    /// Choice bits.
    pub choices: Vec<T>,
    /// Chosen messages.
    pub msgs: Vec<U>,
}

/// Random correlated oblivious transfer receiver.
pub trait RCOTReceiver<T, U> {
    /// Error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Allocates `count` RCOTs for preprocessing.
    fn alloc(&mut self, count: usize) -> Result<(), Self::Error>;

    /// Returns the number of available RCOTs.
    fn available(&self) -> usize;

    /// Returns preprocessed RCOTs, if available.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of preprocessed RCOTs to try to consume.
    fn try_recv_rcot(&mut self, count: usize) -> Result<RCOTReceiverOutput<T, U>, Self::Error>;

    /// Returns a future which will yield RCOTs once they are ready.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of RCOTs to receive.
    fn queue_recv_rcot(&mut self, count: usize) -> Result<RCOTRecvFuture<T, U>, Self::Error>;
}

/// Sender channel of [`RCOTRecvFuture`].
#[derive(Debug)]
pub(crate) struct RCOTRecvPending<T, U> {
    count: usize,
    chan: oneshot::Sender<RCOTReceiverOutput<T, U>>,
}

impl<T, U> RCOTRecvPending<T, U>
where
    T: Send + 'static,
    U: Send + 'static,
{
    /// Returns the number of RCOTs to receive.
    pub(crate) fn count(&self) -> usize {
        self.count
    }

    /// Sends the output.
    pub(crate) fn send(self, output: RCOTReceiverOutput<T, U>) {
        let _ = self.chan.send(output);
    }
}

/// Future returned by [`RCOTReceiver::recv_random_correlated`].
#[must_use = "futures do nothing unless you `.await` or poll them"]
#[derive(Debug)]
pub struct RCOTRecvFuture<T, U> {
    chan: oneshot::Receiver<RCOTReceiverOutput<T, U>>,
}

impl<T, U> RCOTRecvFuture<T, U> {
    /// Creates a new RCOT receive future.
    pub(crate) fn new(count: usize) -> (RCOTRecvPending<T, U>, Self) {
        let (sender, receiver) = oneshot::channel();

        (
            RCOTRecvPending {
                count,
                chan: sender,
            },
            RCOTRecvFuture { chan: receiver },
        )
    }

    /// Attempts to receive the output, returning `None` if not ready.
    pub fn try_recv(&mut self) -> Result<Option<RCOTReceiverOutput<T, U>>, RCOTRecvFutureError> {
        match self
            .chan
            .try_recv()
            .map_err(|_| RCOTRecvFutureError { _private: () })?
        {
            Some(output) => Ok(Some(output)),
            None => Ok(None),
        }
    }
}

impl<T, U> Future for RCOTRecvFuture<T, U>
where
    T: Send + 'static,
    U: Send + 'static,
{
    type Output = Result<RCOTReceiverOutput<T, U>, RCOTRecvFutureError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.chan
            .poll_unpin(cx)
            .map_err(|_| RCOTRecvFutureError { _private: () })
    }
}

/// Error for [`RCOTRecvFuture`].
#[derive(Debug, thiserror::Error)]
#[error("failed to receive RCOT: protocol error occurred or it was cancelled")]
pub struct RCOTRecvFutureError {
    _private: (),
}
