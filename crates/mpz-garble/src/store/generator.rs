use mpz_common::{scoped, Context};
use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use mpz_garble_core::store::{
    EvaluatorSync, GeneratorStore as Core, GeneratorStoreError as CoreError, GeneratorSync,
    OTKeyPayload,
};
use mpz_memory_core::{
    correlated::{Delta, Key},
    Slice,
};
use mpz_ot::COTSender;
use mpz_vm_core::DecodeFuture;
use serio::{stream::IoStreamExt, SinkExt};

type Error = GeneratorStoreError;
type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub struct GeneratorStore {
    inner: Core,
}

impl GeneratorStore {
    /// Creates a new generator store.
    pub fn new(seed: [u8; 16], delta: Delta) -> Self {
        Self {
            inner: Core::new(seed, delta),
        }
    }

    /// Returns delta.
    pub fn delta(&self) -> &Delta {
        self.inner.delta()
    }

    /// Returns whether the keys are set for a slice.
    pub fn is_set_keys(&self, slice: Slice) -> bool {
        self.inner.is_set_keys(slice)
    }

    /// Returns whether the keys are assigned for a slice.
    pub fn is_assigned_keys(&self, slice: Slice) -> bool {
        self.inner.is_assigned_keys(slice)
    }

    /// Returns whether the data is set for a slice.
    pub fn is_set_data(&self, slice: Slice) -> bool {
        self.inner.is_set_data(slice)
    }

    pub fn try_get_keys(&self, slice: Slice) -> Result<&[Key]> {
        self.inner.try_get_keys(slice).map_err(Error::from)
    }

    /// Allocates memory for a value.
    pub fn alloc(&mut self, len: usize) -> Slice {
        self.inner.alloc(len)
    }

    /// Allocates uninitialized memory for output values of a circuit.
    pub fn alloc_output(&mut self, len: usize) -> Slice {
        self.inner.alloc_output(len)
    }

    /// Sets keys which were allocated with
    /// [`alloc_output`](Self::alloc_output).
    pub fn set_output(&mut self, slice: Slice, keys: &[Key]) -> Result<()> {
        self.inner.set_output(slice, keys).map_err(Error::from)
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

    /// Assigns data to memory.
    pub fn assign(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.inner.assign(slice, data).map_err(Error::from)
    }

    pub fn commit(&mut self, slice: Slice) -> Result<()> {
        self.inner.commit(slice).map_err(Error::from)
    }

    /// Buffers a decoding operation, returning a future which will resolve to
    /// the value when it is ready.
    pub fn decode(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.inner.decode(slice).map_err(Error::from)
    }

    /// Synchronizes the memory.
    ///
    /// This executes all ready assignment and decoding operations.
    pub async fn sync<Ctx, OT>(&mut self, ctx: &mut Ctx, ot: &mut OT) -> Result<()>
    where
        Ctx: Context,
        OT: COTSender<Ctx, Block> + Send,
    {
        // COT sender must use same delta.
        if &ot.delta() != self.inner.delta().as_block() {
            todo!()
        }

        let mut msg = GeneratorSync::default();

        if self.inner.wants_commit() {
            msg.macs = Some(self.inner.send_macs()?)
        }

        let ot_payload = if self.inner.wants_oblivious_transfer() {
            let payload = self.inner.oblivious_transfer()?;
            msg.idx_ot = Some(payload.idx.clone());
            Some(payload)
        } else {
            None
        };

        if self.inner.wants_send_key_bits() {
            msg.key_bits = Some(self.inner.send_key_bits()?)
        }

        let expected_idx_ot = ot_payload.as_ref().map(|p| p.idx.clone());

        ctx.try_join(
            scoped!(move |ctx| ctx.io_mut().send(msg).await.map_err(Error::from)),
            scoped!(move |ctx| {
                let EvaluatorSync { idx_ot, macs } = ctx.io_mut().expect_next().await?;

                if idx_ot != expected_idx_ot {
                    assert_eq!(idx_ot, expected_idx_ot);
                }

                if let Some(payload) = ot_payload {
                    ot.send_correlated(ctx, Key::as_blocks(&payload.keys))
                        .await?;
                }

                if let Some(macs) = macs {
                    self.inner.verify_macs(macs)?;
                }

                Ok(())
            }),
        )
        .await??;

        Ok(())
    }
}

/// Error for [`GeneratorStore`].
#[derive(Debug, thiserror::Error)]
#[error("generator store error: {0}")]
pub struct GeneratorStoreError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("core error: {0}")]
    Core(#[from] CoreError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("OT error: {0}")]
    Ot(#[from] mpz_ot::OTError),
    #[error("context error: {0}")]
    Context(#[from] mpz_common::ContextError),
}

impl From<CoreError> for GeneratorStoreError {
    fn from(err: CoreError) -> Self {
        Self(ErrorRepr::Core(err))
    }
}

impl From<std::io::Error> for GeneratorStoreError {
    fn from(err: std::io::Error) -> Self {
        Self(ErrorRepr::Io(err))
    }
}

impl From<mpz_ot::OTError> for GeneratorStoreError {
    fn from(err: mpz_ot::OTError) -> Self {
        Self(ErrorRepr::Ot(err))
    }
}

impl From<mpz_common::ContextError> for GeneratorStoreError {
    fn from(err: mpz_common::ContextError) -> Self {
        Self(ErrorRepr::Context(err))
    }
}
