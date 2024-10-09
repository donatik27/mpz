use async_trait::async_trait;

use itybity::BitIterable;
use mpz_common::Context;
use mpz_core::Block;
use mpz_ot_core::chou_orlandi::{
    msgs::SenderPayload, receiver_state as state, Receiver as ReceiverCore, ReceiverConfig,
};

use enum_try_as_inner::EnumTryAsInner;
use rand::Rng;
use rand_core::OsRng;
use serio::{stream::IoStreamExt as _, SinkExt as _};
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

use crate::{OTError, OTReceiver, OTReceiverOutput, OTSetup};

use super::ReceiverError;

#[derive(Debug, EnumTryAsInner)]
#[derive_err(Debug)]
pub(crate) enum State {
    Initialized {
        config: ReceiverConfig,
        seed: Option<[u8; 32]>,
    },
    Setup(Box<ReceiverCore<state::Setup>>),
    Error,
}

/// Chou-Orlandi receiver.
#[derive(Debug)]
pub struct Receiver {
    state: State,
}

impl Default for Receiver {
    fn default() -> Self {
        Self {
            state: State::Initialized {
                config: ReceiverConfig::default(),
                seed: None,
            },
        }
    }
}

impl Receiver {
    /// Creates a new receiver.
    ///
    /// # Arguments
    ///
    /// * `config` - The receiver's configuration
    pub fn new(config: ReceiverConfig) -> Self {
        Self {
            state: State::Initialized { config, seed: None },
        }
    }

    /// Creates a new receiver with the provided RNG seed.
    ///
    /// # Arguments
    ///
    /// * `config` - The receiver's configuration
    /// * `seed` - The RNG seed used to generate the receiver's keys.
    pub fn new_with_seed(config: ReceiverConfig, seed: [u8; 32]) -> Self {
        Self {
            state: State::Initialized {
                config,
                seed: Some(seed),
            },
        }
    }
}

#[async_trait]
impl<Ctx: Context> OTSetup<Ctx> for Receiver {
    async fn setup(&mut self, ctx: &mut Ctx) -> Result<(), OTError> {
        if self.state.is_setup() {
            return Ok(());
        }

        let (config, seed) = std::mem::replace(&mut self.state, State::Error)
            .try_into_initialized()
            .map_err(ReceiverError::from)?;

        let seed = seed.unwrap_or_else(|| OsRng.gen());

        let sender_setup = ctx.io_mut().expect_next().await?;
        let receiver =
            Backend::spawn(move || ReceiverCore::new_with_seed(config, seed).setup(sender_setup))
                .await;

        self.state = State::Setup(Box::new(receiver));

        Ok(())
    }
}

#[async_trait]
impl<Ctx, T> OTReceiver<Ctx, T, Block> for Receiver
where
    Ctx: Context,
    T: BitIterable + Send + Sync + Clone + 'static,
{
    async fn receive(
        &mut self,
        ctx: &mut Ctx,
        choices: &[T],
    ) -> Result<OTReceiverOutput<Block>, OTError> {
        let mut receiver = std::mem::replace(&mut self.state, State::Error)
            .try_into_setup()
            .map_err(ReceiverError::from)?;

        let choices = choices.to_vec();
        let (mut receiver, receiver_payload) = Backend::spawn(move || {
            let payload = receiver.receive_random(&choices);
            (receiver, payload)
        })
        .await;

        ctx.io_mut().send(receiver_payload).await?;

        let sender_payload: SenderPayload = ctx.io_mut().expect_next().await?;
        let id = sender_payload.id;

        let (receiver, msgs) = Backend::spawn(move || {
            receiver
                .receive(sender_payload)
                .map(|msgs| (receiver, msgs))
        })
        .await
        .map_err(ReceiverError::from)?;

        self.state = State::Setup(receiver);

        Ok(OTReceiverOutput { id, msgs })
    }
}
