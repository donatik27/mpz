//! Implementations of oblivious transfer protocols.

#![deny(
    unsafe_code,
    missing_docs,
    unused_imports,
    unused_must_use,
    unreachable_pub,
    clippy::all
)]

pub mod chou_orlandi;
#[cfg(any(test, feature = "ideal"))]
pub mod ideal;
pub mod kos;

use async_trait::async_trait;

pub use mpz_ot_core::{
    COTReceiverOutput, COTSenderOutput, OTReceiverOutput, OTSenderOutput, RCOTReceiverOutput,
    RCOTSenderOutput, ROTReceiverOutput, ROTSenderOutput, TransferId,
};

/// An oblivious transfer error.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum OTError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("context error: {0}")]
    Context(#[from] mpz_common::ContextError),
    #[error("mutex error: {0}")]
    Mutex(#[from] mpz_common::sync::MutexError),
    #[error("sender error: {0}")]
    SenderError(Box<dyn std::error::Error + Send + Sync>),
    #[error("receiver error: {0}")]
    ReceiverError(Box<dyn std::error::Error + Send + Sync>),
}

/// An oblivious transfer protocol that needs to perform a one-time setup.
#[async_trait]
pub trait OTSetup<Ctx> {
    /// Runs any one-time setup for the protocol.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    async fn setup(&mut self, ctx: &mut Ctx) -> Result<(), OTError>;
}

/// An oblivious transfer sender.
#[async_trait]
pub trait OTSender<Ctx, T> {
    /// Obliviously transfers the messages to the receiver.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `msgs` - The messages to obliviously transfer.
    async fn send(&mut self, ctx: &mut Ctx, msgs: &[T]) -> Result<OTSenderOutput, OTError>;
}

/// A correlated oblivious transfer sender.
#[async_trait]
pub trait COTSender<Ctx, T> {
    /// Returns the correlation, `delta`.
    fn delta(&self) -> T;

    /// Obliviously transfers the correlated messages to the receiver.
    ///
    /// Returns the `0`-bit messages that were obliviously transferred.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `count` - The number of correlated messages to obliviously transfer.
    async fn send_correlated(
        &mut self,
        ctx: &mut Ctx,
        msgs: &[T],
    ) -> Result<COTSenderOutput<T>, OTError>;
}

/// A random OT sender.
#[async_trait]
pub trait RandomOTSender<Ctx, T> {
    /// Outputs pairs of random messages.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `count` - The number of pairs of random messages to output.
    async fn send_random(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<ROTSenderOutput<T>, OTError>;
}

/// A random correlated oblivious transfer sender.
#[async_trait]
pub trait RandomCOTSender<Ctx, T> {
    /// Obliviously transfers the correlated messages to the receiver.
    ///
    /// Returns the `0`-bit messages that were obliviously transferred.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `count` - The number of correlated messages to obliviously transfer.
    async fn send_random_correlated(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<RCOTSenderOutput<T>, OTError>;
}

/// An oblivious transfer receiver.
#[async_trait]
pub trait OTReceiver<Ctx, T, U> {
    /// Obliviously receives data from the sender.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `choices` - The choices made by the receiver.
    async fn receive(
        &mut self,
        ctx: &mut Ctx,
        choices: &[T],
    ) -> Result<OTReceiverOutput<U>, OTError>;
}

/// A correlated oblivious transfer receiver.
#[async_trait]
pub trait COTReceiver<Ctx, T, U> {
    /// Obliviously receives correlated messages from the sender.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `choices` - The choices made by the receiver.
    async fn receive_correlated(
        &mut self,
        ctx: &mut Ctx,
        choices: &[T],
    ) -> Result<COTReceiverOutput<U>, OTError>;
}

/// A random OT receiver.
#[async_trait]
pub trait RandomOTReceiver<Ctx, T, U> {
    /// Outputs the choice bits and the corresponding messages.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `count` - The number of random messages to receive.
    async fn receive_random(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<ROTReceiverOutput<T, U>, OTError>;
}

/// A random correlated oblivious transfer receiver.
#[async_trait]
pub trait RandomCOTReceiver<Ctx, T, U> {
    /// Obliviously receives correlated messages with random choices.
    ///
    /// Returns a tuple of the choices and the messages, respectively.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The thread context.
    /// * `count` - The number of correlated messages to obliviously receive.
    async fn receive_random_correlated(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<RCOTReceiverOutput<T, U>, OTError>;
}
