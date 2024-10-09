use crate::{chou_orlandi::SenderError, OTError, OTSender, OTSenderOutput, OTSetup};

use async_trait::async_trait;
use mpz_common::Context;
use mpz_core::Block;
use mpz_ot_core::chou_orlandi::{sender_state as state, Sender as SenderCore, SenderConfig};
use serio::{stream::IoStreamExt, SinkExt as _};
use utils_aio::non_blocking_backend::{Backend, NonBlockingBackend};

use enum_try_as_inner::EnumTryAsInner;

#[derive(Debug, EnumTryAsInner)]
#[derive_err(Debug)]
pub(crate) enum State {
    Initialized(SenderCore<state::Initialized>),
    Setup(SenderCore<state::Setup>),
    Error,
}

/// Chou-Orlandi sender.
#[derive(Debug)]
pub struct Sender {
    state: State,
}

impl Default for Sender {
    fn default() -> Self {
        Self {
            state: State::Initialized(SenderCore::new(SenderConfig::default())),
        }
    }
}

impl Sender {
    /// Creates a new Sender
    ///
    /// # Arguments
    ///
    /// * `config` - The sender's configuration
    pub fn new(config: SenderConfig) -> Self {
        Self {
            state: State::Initialized(SenderCore::new(config)),
        }
    }

    /// Creates a new Sender with the provided RNG seed
    ///
    /// # Arguments
    ///
    /// * `config` - The sender's configuration
    /// * `seed` - The RNG seed used to generate the sender's keys
    pub fn new_with_seed(config: SenderConfig, seed: [u8; 32]) -> Self {
        Self {
            state: State::Initialized(SenderCore::new_with_seed(config, seed)),
        }
    }
}

#[async_trait]
impl<Ctx: Context> OTSetup<Ctx> for Sender {
    async fn setup(&mut self, ctx: &mut Ctx) -> Result<(), OTError> {
        if self.state.is_setup() {
            return Ok(());
        }

        let sender = std::mem::replace(&mut self.state, State::Error)
            .try_into_initialized()
            .map_err(SenderError::from)?;

        let (msg, sender) = sender.setup();

        ctx.io_mut().send(msg).await?;

        self.state = State::Setup(sender);

        Ok(())
    }
}

#[async_trait]
impl<Ctx: Context> OTSender<Ctx, [Block; 2]> for Sender {
    async fn send(
        &mut self,
        ctx: &mut Ctx,
        input: &[[Block; 2]],
    ) -> Result<OTSenderOutput, OTError> {
        let mut sender = std::mem::replace(&mut self.state, State::Error)
            .try_into_setup()
            .map_err(SenderError::from)?;

        let receiver_payload = ctx.io_mut().expect_next().await?;

        let input = input.to_vec();
        let (sender, payload) = Backend::spawn(move || {
            sender
                .send(&input, receiver_payload)
                .map(|payload| (sender, payload))
        })
        .await
        .map_err(SenderError::from)?;

        let id = payload.id;

        ctx.io_mut().send(payload).await?;

        self.state = State::Setup(sender);

        Ok(OTSenderOutput { id })
    }
}
