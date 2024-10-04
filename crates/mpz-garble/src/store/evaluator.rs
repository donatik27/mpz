use core::fmt;

use mpz_common::{scoped, Context};
use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use mpz_garble_core::store::{
    EvaluatorStore as Core, EvaluatorStoreError as CoreError, EvaluatorSync, GeneratorSync,
};
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

    /// Sets the slice as public.
    pub fn configure_public(&mut self, slice: Slice) -> Result<()> {
        self.inner.configure_public(slice).map_err(Error::from)
    }

    /// Sets the slice as private.
    pub fn configure_private(&mut self, slice: Slice) -> Result<()> {
        self.inner.configure_private(slice).map_err(Error::from)
    }

    /// Sets the slice as blind.
    pub fn configure_blind(&mut self, slice: Slice) -> Result<()> {
        self.inner.configure_blind(slice).map_err(Error::from)
    }

    pub fn assign(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.inner.assign(slice, data).map_err(Error::from)
    }

    pub fn commit(&mut self, slice: Slice) -> Result<()> {
        self.inner.commit(slice).map_err(Error::from)
    }

    pub fn decode(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.inner.decode(slice).map_err(Error::from)
    }

    pub async fn sync<Ctx, OT>(&mut self, ctx: &mut Ctx, ot: &mut OT) -> Result<()>
    where
        Ctx: Context,
        OT: COTReceiver<Ctx, bool, Block> + Send,
    {
        let mut msg = EvaluatorSync::default();

        if self.inner.wants_prove_macs() {
            msg.macs = Some(self.inner.prove_macs()?);
        }

        let receive = if self.inner.wants_oblivious_transfer() {
            let receive = self.inner.oblivious_transfer()?;
            msg.idx_ot = Some(receive.idx().clone());
            Some(receive)
        } else {
            None
        };

        let expected_idx_ot = receive.as_ref().map(|r| r.idx()).cloned();

        let (msg, _) = ctx
            .try_join(
                scoped!(move |ctx| {
                    let msg: GeneratorSync = ctx.io_mut().expect_next().await?;

                    if msg.idx_ot != expected_idx_ot {
                        assert_eq!(msg.idx_ot, expected_idx_ot);
                    }

                    Ok::<_, Error>(msg)
                }),
                scoped!(move |ctx| {
                    ctx.io_mut().send(msg).await?;

                    if let Some(receive) = receive {
                        let choices = receive.choices();
                        let COTReceiverOutput { msgs: macs, .. } =
                            ot.receive_correlated(ctx, &choices).await?;
                        receive.receive(Mac::from_blocks(macs))?;
                    }

                    Ok(())
                }),
            )
            .await??;

        let GeneratorSync { macs, key_bits, .. } = msg;

        if let Some(payload) = macs {
            self.inner.receive_macs(payload)?;
        }

        if let Some(payload) = key_bits {
            self.inner.receive_key_bits(payload)?;
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
