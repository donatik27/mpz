use std::mem;

use async_trait::async_trait;
use itybity::IntoBitIterator;
use mpz_cointoss as cointoss;
use mpz_common::{Allocate, Context, Preprocess};
use mpz_core::{prg::Prg, Block};
use mpz_ot_core::{
    kos::{
        msgs::{SenderPayload, StartExtend},
        pad_ot_count, receiver_state as state, Receiver as ReceiverCore, ReceiverConfig,
        ReceiverKeys, CSP,
    },
    OTReceiverOutput, ROTReceiverOutput,
};

use enum_try_as_inner::EnumTryAsInner;
use rand::{
    distributions::{Distribution, Standard},
    thread_rng, Rng,
};
use rand_core::{OsRng, SeedableRng};
use serio::{stream::IoStreamExt as _, SinkExt as _};
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

use super::{ReceiverError, EXTEND_CHUNK_SIZE};
use crate::{OTError, OTReceiver, OTSender, OTSetup, RandomOTReceiver};

#[derive(Debug, EnumTryAsInner)]
#[derive_err(Debug)]
pub(crate) enum State {
    Initialized(Box<ReceiverCore<state::Initialized>>),
    Extension(Box<ReceiverCore<state::Extension>>),
    Error,
}

/// KOS receiver.
#[derive(Debug)]
pub struct Receiver<BaseOT> {
    state: State,
    base: BaseOT,
    alloc: usize,
}

impl<BaseOT> Receiver<BaseOT>
where
    BaseOT: Send,
{
    /// Creates a new receiver.
    ///
    /// # Arguments
    ///
    /// * `config` - The receiver's configuration
    pub fn new(config: ReceiverConfig, base: BaseOT) -> Self {
        Self {
            state: State::Initialized(Box::new(ReceiverCore::new(config))),
            base,
            alloc: 0,
        }
    }

    /// The number of remaining OTs which can be consumed.
    pub fn remaining(&self) -> Result<usize, ReceiverError> {
        Ok(self.state.try_as_extension()?.remaining())
    }

    /// Returns the provided number of keys.
    pub(crate) fn take_keys(&mut self, count: usize) -> Result<ReceiverKeys, ReceiverError> {
        self.state
            .try_as_extension_mut()?
            .keys(count)
            .map_err(ReceiverError::from)
    }

    /// Performs OT extension.
    ///
    /// # Arguments
    ///
    /// * `sink` - The sink to send messages to the sender
    /// * `stream` - The stream to receive messages from the sender
    /// * `count` - The number of OTs to extend
    pub async fn extend<Ctx: Context>(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<(), ReceiverError> {
        let mut ext_receiver =
            std::mem::replace(&mut self.state, State::Error).try_into_extension()?;

        let count = pad_ot_count(count);

        // Extend the OTs.
        let (mut ext_receiver, extend) = Backend::spawn(move || {
            ext_receiver
                .extend(count)
                .map(|extend| (ext_receiver, extend))
        })
        .await?;

        // Send the extend message and cointoss commitment.
        ctx.io_mut().feed(StartExtend { count }).await?;
        for extend in extend.into_chunks(EXTEND_CHUNK_SIZE) {
            ctx.io_mut().feed(extend).await?;
        }
        ctx.io_mut().flush().await?;

        // Sample chi_seed with coin-toss.
        let seed = thread_rng().gen();
        let chi_seed = cointoss::cointoss_sender(ctx, vec![seed]).await?[0];

        // Compute consistency check.
        let (ext_receiver, check) = Backend::spawn(move || {
            ext_receiver
                .check(chi_seed)
                .map(|check| (ext_receiver, check))
        })
        .await?;

        // Send correlation check value.
        ctx.io_mut().send(check).await?;

        self.state = State::Extension(ext_receiver);

        Ok(())
    }
}

#[async_trait]
impl<Ctx, BaseOT> OTSetup<Ctx> for Receiver<BaseOT>
where
    Ctx: Context,
    BaseOT: OTSetup<Ctx> + OTSender<Ctx, [Block; 2]> + Send,
{
    async fn setup(&mut self, ctx: &mut Ctx) -> Result<(), OTError> {
        if self.state.is_extension() {
            return Ok(());
        }

        let ext_receiver = std::mem::replace(&mut self.state, State::Error)
            .try_into_initialized()
            .map_err(ReceiverError::from)?;

        self.base.setup(ctx).await?;

        let seeds: [[Block; 2]; CSP] = std::array::from_fn(|_| OsRng.gen());

        // Send seeds to sender
        self.base.send(ctx, &seeds).await?;

        let ext_receiver = ext_receiver.setup(seeds);

        self.state = State::Extension(Box::new(ext_receiver));

        Ok(())
    }
}

impl<BaseOT> Allocate for Receiver<BaseOT> {
    fn alloc(&mut self, count: usize) {
        self.alloc += count;
    }
}

#[async_trait]
impl<Ctx, BaseOT> Preprocess<Ctx> for Receiver<BaseOT>
where
    Ctx: Context,
    BaseOT: OTSetup<Ctx> + OTSender<Ctx, [Block; 2]> + Send,
{
    type Error = OTError;

    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<(), OTError> {
        if self.state.is_initialized() {
            self.setup(ctx).await?;
        }

        let count = mem::take(&mut self.alloc);
        if count == 0 {
            return Ok(());
        }

        self.extend(ctx, count).await.map_err(OTError::from)
    }
}

#[async_trait]
impl<Ctx, BaseOT> OTReceiver<Ctx, bool, Block> for Receiver<BaseOT>
where
    Ctx: Context,
    BaseOT: Send,
{
    async fn receive(
        &mut self,
        ctx: &mut Ctx,
        choices: &[bool],
    ) -> Result<OTReceiverOutput<Block>, OTError> {
        let receiver = self
            .state
            .try_as_extension_mut()
            .map_err(ReceiverError::from)?;

        let mut receiver_keys = receiver.keys(choices.len()).map_err(ReceiverError::from)?;

        let choices = choices.into_lsb0_vec();
        let derandomize = receiver_keys
            .derandomize(&choices)
            .map_err(ReceiverError::from)?;

        // Send derandomize message
        ctx.io_mut().send(derandomize).await?;

        // Receive payload
        let payload: SenderPayload = ctx.io_mut().expect_next().await?;
        let id = payload.id;

        let received = Backend::spawn(move || {
            receiver_keys
                .decrypt_blocks(payload)
                .map_err(ReceiverError::from)
        })
        .await?;

        Ok(OTReceiverOutput { id, msgs: received })
    }
}

#[async_trait]
impl<Ctx, T, BaseOT> RandomOTReceiver<Ctx, bool, T> for Receiver<BaseOT>
where
    Ctx: Context,
    Standard: Distribution<T>,
    BaseOT: Send,
{
    async fn receive_random(
        &mut self,
        _ctx: &mut Ctx,
        count: usize,
    ) -> Result<ROTReceiverOutput<bool, T>, OTError> {
        let receiver = self
            .state
            .try_as_extension_mut()
            .map_err(ReceiverError::from)?;

        let keys = receiver.keys(count).map_err(ReceiverError::from)?;
        let id = keys.id();
        let (choices, keys) = keys.take_choices_and_keys();

        let msgs = keys.into_iter().map(|k| Prg::from_seed(k).gen()).collect();

        Ok(ROTReceiverOutput { id, choices, msgs })
    }
}

#[async_trait]
impl<Ctx, const N: usize, BaseOT> OTReceiver<Ctx, bool, [u8; N]> for Receiver<BaseOT>
where
    Ctx: Context,
    BaseOT: Send,
{
    async fn receive(
        &mut self,
        ctx: &mut Ctx,
        choices: &[bool],
    ) -> Result<OTReceiverOutput<[u8; N]>, OTError> {
        let receiver = self
            .state
            .try_as_extension_mut()
            .map_err(ReceiverError::from)?;

        let mut receiver_keys = receiver.keys(choices.len()).map_err(ReceiverError::from)?;

        let choices = choices.into_lsb0_vec();
        let derandomize = receiver_keys
            .derandomize(&choices)
            .map_err(ReceiverError::from)?;

        // Send derandomize message
        ctx.io_mut().send(derandomize).await?;

        // Receive payload
        let payload: SenderPayload = ctx.io_mut().expect_next().await?;
        let id = payload.id;

        let received = Backend::spawn(move || {
            receiver_keys
                .decrypt_bytes(payload)
                .map_err(ReceiverError::from)
        })
        .await?;

        Ok(OTReceiverOutput { id, msgs: received })
    }
}
