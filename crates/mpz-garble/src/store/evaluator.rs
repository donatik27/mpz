use core::fmt;

use mpz_common::{scoped, Context};
use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use mpz_garble_core::store::{EvaluatorStore as Core, EvaluatorStoreError as CoreError};
use mpz_memory_core::{correlated::Mac, Slice};
use mpz_ot::{COTReceiver, COTReceiverOutput};
use mpz_vm_core::DecodeFuture;
use serio::{stream::IoStreamExt, SinkExt};

type Error = EvaluatorStoreError;
type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Default)]
pub struct EvaluatorStore {
    inner: Core,
}

impl EvaluatorStore {
    /// Returns whether the MACs are set for a slice.
    pub fn is_set_macs(&self, slice: Slice) -> bool {
        self.inner.is_set_macs(slice)
    }

    /// Returns whether the data is set for a slice.
    pub fn is_set_data(&self, slice: Slice) -> bool {
        self.inner.is_set_data(slice)
    }

    pub fn try_get_macs(&self, slice: Slice) -> Result<&[Mac]> {
        self.inner.try_get_macs(slice).map_err(Error::from)
    }

    pub fn alloc(&mut self, len: usize) -> Slice {
        self.inner.alloc(len)
    }

    pub fn set_output(&mut self, slice: Slice, macs: &[Mac]) -> Result<()> {
        self.inner.try_set_macs(slice, macs).map_err(Error::from)
    }

    pub fn assign_public(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.inner.assign_public(slice, data).map_err(Error::from)
    }

    pub fn assign_private(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.inner.assign_private(slice, data).map_err(Error::from)
    }

    pub fn assign_blind(&mut self, slice: Slice) -> Result<()> {
        self.inner.assign_blind(slice).map_err(Error::from)
    }

    pub fn decode(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.inner.decode(slice).map_err(Error::from)
    }

    pub async fn commit<Ctx, OT>(&mut self, ctx: &mut Ctx, ot: &mut OT) -> Result<()>
    where
        Ctx: Context,
        OT: COTReceiver<Ctx, bool, Block> + Send,
    {
        if self.inner.wants_assign() {
            let (receive, ot_choices) = self.inner.execute_assign()?;

            if !ot_choices.is_empty() {
                let (payload, COTReceiverOutput { msgs: macs, .. }) = ctx
                    .try_join(
                        scoped!(move |ctx| {
                            ctx.io_mut().expect_next().await.map_err(Error::from)
                        }),
                        scoped!(move |ctx| {
                            ot.receive_correlated(ctx, &ot_choices)
                                .await
                                .map_err(Error::from)
                        }),
                    )
                    .await??;

                receive.receive(payload, Mac::from_blocks(macs))?;
            } else {
                let payload = ctx.io_mut().expect_next().await?;
                receive.receive(payload, Vec::default())?;
            }
        }

        if self.inner.wants_key_bits() {
            let key_bits = ctx.io_mut().expect_next().await?;
            self.inner.receive_key_bits(key_bits)?;
        }

        if self.inner.wants_decode() {
            let payload = self.inner.send_macs()?;
            ctx.io_mut().send(payload).await?;
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub struct EvaluatorStoreError {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl fmt::Display for EvaluatorStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("evaluator store error: ")?;

        match self.kind {
            ErrorKind::Io => f.write_str("io error")?,
            ErrorKind::Core => f.write_str("core error")?,
            ErrorKind::Ot => f.write_str("ot error")?,
            ErrorKind::Context => f.write_str("context error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
enum ErrorKind {
    Io,
    Core,
    Ot,
    Context,
}

impl From<CoreError> for EvaluatorStoreError {
    fn from(err: CoreError) -> Self {
        Self {
            kind: ErrorKind::Core,
            source: Some(Box::new(err)),
        }
    }
}

impl From<std::io::Error> for EvaluatorStoreError {
    fn from(err: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            source: Some(Box::new(err)),
        }
    }
}

impl From<mpz_ot::OTError> for EvaluatorStoreError {
    fn from(err: mpz_ot::OTError) -> Self {
        Self {
            kind: ErrorKind::Ot,
            source: Some(Box::new(err)),
        }
    }
}

impl From<mpz_common::ContextError> for EvaluatorStoreError {
    fn from(err: mpz_common::ContextError) -> Self {
        Self {
            kind: ErrorKind::Context,
            source: Some(Box::new(err)),
        }
    }
}
