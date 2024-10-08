use std::mem;

use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use mpz_memory_core::{
    correlated::{Delta, Key, KeyStore, KeyStoreError},
    store::{BitStore, StoreError},
    DecodeFuture, DecodeOp, Slice,
};
use utils::filter_drain::FilterDrain;

use crate::store::{AssignPayload, DecodePayload, MacPayload};

type Error = VerifierStoreError;
type Result<T> = core::result::Result<T, Error>;
type Range = core::ops::Range<usize>;
type RangeSet = utils::range::RangeSet<usize>;

#[derive(Debug)]
pub struct VerifierStore {
    key_store: KeyStore,
    data_store: BitStore,
    idx_public: RangeSet,
    buffer_assign: Vec<Range>,
    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl VerifierStore {
    /// Creates a new verifier store.
    pub fn new(delta: Delta) -> Self {
        Self {
            key_store: KeyStore::new(delta),
            data_store: BitStore::new(),
            idx_public: RangeSet::default(),
            buffer_assign: Vec::new(),
            buffer_decode: Vec::new(),
        }
    }

    /// Returns delta.
    pub fn delta(&self) -> &Delta {
        self.key_store.delta()
    }

    /// Returns whether the store wants to assign values.
    pub fn wants_assign(&self) -> bool {
        !self.buffer_assign.is_empty()
    }

    /// Returns whether the store wants to verify data.
    pub fn wants_verify_data(&self) -> bool {
        self.buffer_decode
            .iter()
            .any(|op| self.key_store.is_set(op.slice))
    }

    /// Allocates memory.
    pub fn alloc(&mut self, len: usize) -> Slice {
        self.key_store.alloc(len);
        self.data_store.alloc(len)
    }

    /// Allocates uninitialized memory for outputs of a circuit.
    pub fn alloc_output(&mut self, len: usize) -> Slice {
        self.key_store.alloc(len);
        self.data_store.alloc(len)
    }

    /// Sets the output keys for a circuit.
    pub fn set_output(&mut self, slice: Slice, keys: &[Key]) -> Result<()> {
        self.key_store.try_set(slice, keys).map_err(Error::from)
    }

    /// Assigns public data.
    pub fn assign_public(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.key_store.try_set_public(slice, data)?;
        self.data_store.try_set(slice, data)?;

        Ok(())
    }

    /// Assigns blind data.
    pub fn assign_blind(&mut self, slice: Slice, keys: &[Key]) -> Result<()> {
        self.key_store.try_set(slice, keys)?;

        self.buffer_assign.push(slice.to_range());

        Ok(())
    }

    /// Buffers a decoding operation, returning a future which will resolve to
    /// the value when it is ready.
    pub fn decode(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        let (fut, op) = DecodeFuture::new(slice);

        self.buffer_decode.push(op);

        Ok(fut)
    }

    /// Executes assignment operations.
    ///
    /// Returns the payload to send to the prover as well as the keys to send
    /// using oblivious transfer.
    pub fn execute_assign(&mut self, payload: AssignPayload) -> Result<()> {
        let idx_expected = RangeSet::from(mem::take(&mut self.buffer_assign));

        let AssignPayload { idx, adjust } = payload;

        if idx != idx_expected {
            todo!()
        }

        let mut i = 0;
        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.key_store.adjust(slice, &adjust[i..i + slice.len()])?;
            i += slice.len();
        }

        Ok(())
    }

    /// Verifies a proof of MACs from the prover.
    ///
    /// Resolves corresponding decode operations.
    pub fn verify_data(&mut self, payload: MacPayload) -> Result<()> {
        let MacPayload {
            idx,
            mut bits,
            proof,
        } = payload;

        self.key_store.verify(&idx, &mut bits, proof)?;

        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.data_store.try_set(slice, &bits)?;
        }

        Ok(())
    }

    pub fn execute_decode(&mut self) -> Result<()> {
        for mut op in self
            .buffer_decode
            .filter_drain(|op| self.data_store.is_set(op.slice))
        {
            let data = self
                .data_store
                .try_get(op.slice)
                .expect("data should be set");
            op.send(data.to_bitvec()).unwrap();
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("verifier store error: {0}")]
pub struct VerifierStoreError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("key store error: {0}")]
    KeyStore(#[from] KeyStoreError),
    #[error("data store error: {0}")]
    Store(#[from] StoreError),
}

impl From<KeyStoreError> for VerifierStoreError {
    fn from(err: KeyStoreError) -> Self {
        Self(ErrorRepr::KeyStore(err))
    }
}

impl From<StoreError> for VerifierStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}
