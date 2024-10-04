use std::mem;

use mpz_core::{
    bitvec::{BitSlice, BitVec},
    prg::Prg,
};
use mpz_memory_core::{
    correlated::{Delta, Key, KeyStore, KeyStoreError},
    store::{BitStore, StoreError},
    view::View,
    AssignKind, Slice,
};
use mpz_vm_core::{AssignOp, DecodeFuture, DecodeOp};
use rand::Rng;
use utils::{
    filter_drain::FilterDrain,
    range::{Difference, Disjoint, Intersection, Subset, Union},
};

use crate::store::{KeyBitPayload, MacPayload, MacProof, OTKeyPayload};

type Error = GeneratorStoreError;
type Result<T> = core::result::Result<T, Error>;
type RangeSet = utils::range::RangeSet<usize>;

#[derive(Debug)]
pub struct GeneratorStore {
    prg: Prg,
    key_store: KeyStore,
    data_store: BitStore,
    view: View,

    /// Ranges which are computed outputs.
    idx_outputs: RangeSet,
    /// Ranges for which commitment is pending.
    idx_pending_commit: RangeSet,
    /// Ranges which have been committed.
    idx_committed: RangeSet,
    /// Ranges for which key bits have been sent.
    idx_key_bits: RangeSet,
    /// Ranges for which key bits are pending.
    idx_pending_key_bits: RangeSet,
    /// Ranges which have already been decoded.
    idx_decoded: RangeSet,
    /// Ranges for which we are waiting for MACs to decode.
    idx_pending_decode: RangeSet,

    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl GeneratorStore {
    /// Creates a new generator store.
    pub fn new(seed: [u8; 16], delta: Delta) -> Self {
        Self {
            prg: Prg::new_with_seed(seed),
            key_store: KeyStore::new(delta),
            data_store: BitStore::new(),
            view: View::default(),
            idx_outputs: RangeSet::default(),
            idx_pending_commit: RangeSet::default(),
            idx_committed: RangeSet::default(),
            idx_key_bits: RangeSet::default(),
            idx_pending_key_bits: RangeSet::default(),
            idx_decoded: RangeSet::default(),
            idx_pending_decode: RangeSet::default(),
            buffer_decode: Vec::new(),
        }
    }

    /// Returns delta.
    pub fn delta(&self) -> &Delta {
        self.key_store.delta()
    }

    /// Returns whether all the keys are set.
    pub fn is_set_keys(&self, slice: Slice) -> bool {
        self.key_store.is_set(slice)
    }

    /// Returns whether the keys are assigned for a slice.
    pub fn is_assigned_keys(&self, slice: Slice) -> bool {
        self.key_store.is_used(slice)
    }

    /// Returns whether the data is set for a slice.
    pub fn is_set_data(&self, slice: Slice) -> bool {
        self.data_store.is_set(slice)
    }

    /// Returns `true` if the store wants to commit.
    pub fn wants_commit(&self) -> bool {
        !self.idx_pending_commit.is_empty()
    }

    /// Returns `true` if the store wants to send MACs via oblivious transfer.
    pub fn wants_oblivious_transfer(&self) -> bool {
        !self
            .idx_pending_commit
            .intersection(self.view.blind())
            .is_empty()
    }

    /// Returns `true` if the store wants to send key bits.
    pub fn wants_send_key_bits(&self) -> bool {
        !self
            .idx_pending_key_bits
            .intersection(self.key_store.set_ranges())
            .is_empty()
    }

    /// Returns `true` if the store wants to verify data.
    pub fn wants_verify_data(&self) -> bool {
        !self.idx_pending_decode.is_empty()
    }

    pub fn try_get_keys(&self, slice: Slice) -> Result<&[Key]> {
        self.key_store.try_get(slice).map_err(Error::from)
    }

    /// Allocates memory for a value.
    pub fn alloc(&mut self, len: usize) -> Slice {
        let keys = (0..len).map(|_| self.prg.gen()).collect::<Vec<_>>();
        self.view.alloc(len);
        self.key_store.alloc_with(&keys);
        self.data_store.alloc(len)
    }

    /// Allocates uninitialized memory for output values.
    pub fn alloc_output(&mut self, len: usize) -> Slice {
        self.view.alloc(len);
        self.key_store.alloc(len);
        let slice = self.data_store.alloc(len);
        self.idx_outputs = self.idx_outputs.union(&slice.to_range());
        slice
    }

    /// Sets the output keys for a circuit.
    pub fn set_output(&mut self, slice: Slice, keys: &[Key]) -> Result<()> {
        self.key_store.try_set(slice, keys).map_err(Error::from)
    }

    /// Configures the slice as public.
    pub fn configure_public(&mut self, slice: Slice) -> Result<()> {
        if self.view.is_set_any(slice) {
            todo!("view is already set");
        }

        self.view.set_public(slice);

        Ok(())
    }

    /// Configures the slice as private.
    pub fn configure_private(&mut self, slice: Slice) -> Result<()> {
        if self.view.is_set_any(slice) {
            todo!("view is already set");
        }

        self.view.set_private(slice);

        Ok(())
    }

    /// Configures the slice as blind.
    pub fn configure_blind(&mut self, slice: Slice) -> Result<()> {
        if self.view.is_set_any(slice) {
            todo!("view is already set");
        }

        self.view.set_blind(slice);

        Ok(())
    }

    /// Assigns data to memory.
    pub fn assign(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        if !self.view.is_visible(slice) {
            todo!("memory not configured as visible");
        }

        self.data_store.try_set(slice, data)?;

        Ok(())
    }

    /// Commits the slice.
    pub fn commit(&mut self, slice: Slice) -> Result<()> {
        let range = slice.to_range();
        if !range.is_disjoint(&self.idx_committed) {
            todo!("slice already committed");
        }

        self.idx_pending_commit = range.union(&self.idx_pending_commit);

        Ok(())
    }

    /// Returns a future which will resolve to the value when it is decoded.
    pub fn decode(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        let (fut, mut op) = DecodeFuture::new(slice);

        // If data is already decoded, send it immediately.
        if let Ok(data) = self.data_store.try_get(slice) {
            op.send(data.to_bitvec()).unwrap();
        } else {
            self.buffer_decode.push(op);
        }

        let range = slice.to_range();

        // Determine which key bits haven't been sent yet then mark them pending.
        let idx_not_sent = range.difference(&self.idx_key_bits);
        if !idx_not_sent.is_empty() {
            // Add it to pending.
            self.idx_pending_key_bits = self.idx_pending_key_bits.union(&idx_not_sent);
        }

        // Determine which MACs we need to receive then mark them pending.
        let idx_not_decoded = range.difference(&self.idx_decoded);
        if !idx_not_decoded.is_empty() {
            // Add it to pending.
            self.idx_pending_decode = self.idx_pending_decode.union(&idx_not_decoded);
        }

        Ok(fut)
    }

    /// Sends pending MACs to the evaluator.
    pub fn send_macs(&mut self) -> Result<MacPayload> {
        let idx = self.idx_pending_commit.intersection(self.view.visible());

        let mut macs = Vec::with_capacity(idx.len());
        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            let data = self.data_store.try_get(slice).expect("data should be set");
            macs.extend(self.key_store.authenticate(slice, data)?);
        }

        self.idx_pending_commit = self.idx_pending_commit.difference(&idx);

        Ok(MacPayload { idx, macs })
    }

    /// Sends pending MACs to the evaluator using oblivious transfer.
    pub fn oblivious_transfer(&mut self) -> Result<OTKeyPayload> {
        let idx = self.idx_pending_commit.intersection(self.view.blind());

        let mut keys = Vec::with_capacity(idx.len());
        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);

            // Store protects against keys being transferred multiple times.
            let keys_ = self.key_store.oblivious_transfer(slice)?;

            keys.extend_from_slice(keys_);
        }

        self.idx_pending_commit = self.idx_pending_commit.difference(&idx);

        Ok(OTKeyPayload { idx, keys })
    }

    /// Sends pending key bits to the evaluator.
    pub fn send_key_bits(&mut self) -> Result<KeyBitPayload> {
        let idx = mem::take(&mut self.idx_pending_key_bits);

        let mut key_bits = BitVec::new();
        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            key_bits.extend(self.key_store.try_get_bits(slice)?);
        }

        Ok(KeyBitPayload { idx, key_bits })
    }

    /// Verifies a proof of MACs from the evaluator.
    ///
    /// Resolves corresponding decode operations.
    pub fn verify_macs(&mut self, payload: MacProof) -> Result<()> {
        let MacProof {
            idx,
            mut bits,
            proof,
        } = payload;

        if !idx.is_subset(&self.idx_pending_decode) {
            todo!("unexpected decode payload");
        }

        self.key_store.verify(&idx, &mut bits, proof)?;

        let mut i = 0;
        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.data_store.try_set(slice, &bits[i..i + slice.len()])?;
            i += slice.len();
        }

        self.idx_pending_decode = self.idx_pending_decode.difference(&idx);
        self.idx_decoded = self.idx_decoded.union(&idx);

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

/// Error for [`GeneratorStore`].
#[derive(Debug, thiserror::Error)]
#[error("generator store error: {}", .0)]
pub struct GeneratorStoreError(ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error(transparent)]
    KeyStore(KeyStoreError),
    #[error(transparent)]
    Store(StoreError),
}

impl From<KeyStoreError> for GeneratorStoreError {
    fn from(err: KeyStoreError) -> Self {
        Self(ErrorRepr::KeyStore(err))
    }
}

impl From<StoreError> for GeneratorStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}
