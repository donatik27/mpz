use mpz_common::{scoped, Context};
use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use mpz_garble_core::store::{GeneratorStore as Core, GeneratorStoreError as CoreError};
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

    /// Assigns a public value.
    pub fn assign_public(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.inner.assign_public(slice, data).map_err(Error::from)
    }

    /// Assigns a private value.
    pub fn assign_private(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.inner.assign_private(slice, data).map_err(Error::from)
    }

    /// Assigns a blind value.
    pub fn assign_blind(&mut self, slice: Slice) -> Result<()> {
        self.inner.assign_blind(slice).map_err(Error::from)
    }

    /// Buffers a decoding operation, returning a future which will resolve to
    /// the value when it is ready.
    pub fn decode(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.inner.decode(slice).map_err(Error::from)
    }

    /// Commits the memory.
    ///
    /// This executes all ready assignment and decoding operations.
    pub async fn commit<Ctx, OT>(&mut self, ctx: &mut Ctx, ot: &mut OT) -> Result<()>
    where
        Ctx: Context,
        OT: COTSender<Ctx, Block> + Send,
    {
        // COT sender must use same delta.
        if &ot.delta() != self.inner.delta().as_block() {
            todo!()
        }

        if self.inner.wants_assign() {
            let (payload, ot_keys) = self.inner.execute_assign()?;

            if !ot_keys.is_empty() {
                ctx.try_join(
                    scoped!(move |ctx| ctx.io_mut().send(payload).await.map_err(Error::from)),
                    scoped!(move |ctx| ot
                        .send_correlated(ctx, Key::as_blocks(&ot_keys))
                        .await
                        .map_err(Error::from)),
                )
                .await??;
            } else {
                ctx.io_mut().send(payload).await?;
            }
        }

        if self.inner.wants_send_key_bits() {
            let key_bits = self.inner.send_key_bits()?;
            ctx.io_mut().send(key_bits).await?;
        }

        if self.inner.wants_verify_data() {
            let payload = ctx.io_mut().expect_next().await?;
            self.inner.verify_macs(payload)?;
        }

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
