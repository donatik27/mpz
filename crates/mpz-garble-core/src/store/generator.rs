use std::mem;

use mpz_core::{
    bitvec::{BitSlice, BitVec},
    prg::Prg,
};
use mpz_memory_core::{
    correlated::{Delta, Key, KeyStore, KeyStoreError},
    store::{BitStore, StoreError},
    AssignKind, Size, Slice,
};
use mpz_vm_core::{AssignOp, DecodeFuture, DecodeOp};
use rand::Rng;
use utils::{
    filter_drain::FilterDrain,
    range::{Difference, Intersection, Subset, Union},
};

use crate::store::{AssignPayload, DecodePayload, MacPayload};

type Error = GeneratorStoreError;
type Result<T> = core::result::Result<T, Error>;
type RangeSet = utils::range::RangeSet<usize>;

#[derive(Debug)]
pub struct GeneratorStore {
    prg: Prg,
    key_store: KeyStore,
    data_store: BitStore,

    /// Ranges which are computed outputs.
    idx_outputs: RangeSet,
    /// Ranges for which key bits have been sent.
    idx_key_bits: RangeSet,
    /// Ranges for which key bits are pending.
    idx_pending_key_bits: RangeSet,
    /// Ranges which have already been decoded.
    idx_decoded: RangeSet,
    /// Ranges for which we are waiting for MACs to decode.
    idx_pending_decode: RangeSet,

    buffer_assign: Vec<AssignOp>,
    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl GeneratorStore {
    /// Creates a new generator store.
    pub fn new(seed: [u8; 16], delta: Delta) -> Self {
        Self {
            prg: Prg::new_with_seed(seed),
            key_store: KeyStore::new(delta),
            data_store: BitStore::new(),
            idx_outputs: RangeSet::default(),
            idx_key_bits: RangeSet::default(),
            idx_pending_key_bits: RangeSet::default(),
            idx_decoded: RangeSet::default(),
            idx_pending_decode: RangeSet::default(),
            buffer_assign: Vec::new(),
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

    /// Returns whether the store wants to assign values.
    pub fn wants_assign(&self) -> bool {
        !self.buffer_assign.is_empty()
    }

    /// Returns whether the store wants to send key bits.
    pub fn wants_send_key_bits(&self) -> bool {
        !self
            .idx_pending_key_bits
            .intersection(self.key_store.set_ranges())
            .is_empty()
    }

    /// Returns whether the store wants to verify data.
    pub fn wants_verify_data(&self) -> bool {
        !self.idx_pending_decode.is_empty()
    }

    pub fn try_get_keys(&self, slice: Slice) -> Result<&[Key]> {
        self.key_store.try_get(slice).map_err(Error::from)
    }

    /// Allocates memory for a value.
    pub fn alloc(&mut self, len: usize) -> Slice {
        let keys = (0..len).map(|_| self.prg.gen()).collect::<Vec<_>>();
        self.key_store.alloc_with(&keys);
        self.data_store.alloc(len)
    }

    /// Allocates uninitialized memory for output values.
    pub fn alloc_output(&mut self, len: usize) -> Slice {
        self.key_store.alloc(len);
        let slice = self.data_store.alloc(len);
        self.idx_outputs = self.idx_outputs.union(&slice.to_range());
        slice
    }

    /// Sets the output keys for a circuit.
    pub fn set_output(&mut self, slice: Slice, keys: &[Key]) -> Result<()> {
        self.key_store.try_set(slice, keys).map_err(Error::from)
    }

    /// Assigns public data.
    pub fn assign_public(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.data_store.try_set(slice, data)?;

        self.buffer_assign.push(AssignOp {
            slice,
            kind: AssignKind::Public,
        });

        Ok(())
    }

    /// Assigns private data.
    pub fn assign_private(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.data_store.try_set(slice, data)?;

        self.buffer_assign.push(AssignOp {
            slice,
            kind: AssignKind::Private,
        });

        Ok(())
    }

    /// Assigns blind data.
    pub fn assign_blind(&mut self, slice: Slice) -> Result<()> {
        self.buffer_assign.push(AssignOp {
            slice,
            kind: AssignKind::Blind,
        });

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

    /// Executes assignment operations.
    ///
    /// Returns the payload to send to the evaluator as well as the keys to send
    /// using oblivious transfer.
    pub fn execute_assign(&mut self) -> Result<(AssignPayload, Vec<Key>)> {
        self.buffer_assign.sort_by_key(|op| op.slice.ptr());

        let mut idx_direct = Vec::new();
        let mut idx_oblivious = Vec::new();
        for op in mem::take(&mut self.buffer_assign) {
            match op.kind {
                AssignKind::Public | AssignKind::Private => {
                    idx_direct.push(op.slice.to_range());
                }
                AssignKind::Blind => {
                    idx_oblivious.push(op.slice.to_range());
                }
            }
        }

        let idx_direct = RangeSet::from(idx_direct);
        let idx_oblivious = RangeSet::from(idx_oblivious);

        let mut keys = Vec::new();
        for range in idx_oblivious.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            keys.extend_from_slice(self.key_store.oblivious_transfer(slice)?);
        }

        let mut macs = Vec::new();
        for range in idx_direct.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            let data = self.data_store.try_get(slice).expect("data should be set");
            macs.extend(self.key_store.authenticate(slice, data)?);
        }

        Ok((
            AssignPayload {
                idx_direct,
                idx_oblivious,
                macs,
            },
            keys,
        ))
    }

    pub fn send_key_bits(&mut self) -> Result<DecodePayload> {
        let idx = mem::take(&mut self.idx_pending_key_bits);

        let mut key_bits = BitVec::new();
        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            key_bits.extend(self.key_store.try_get_bits(slice)?);
        }

        Ok(DecodePayload { idx, key_bits })
    }

    /// Verifies a proof of MACs from the evaluator.
    ///
    /// Resolves corresponding decode operations.
    pub fn verify_macs(&mut self, payload: MacPayload) -> Result<()> {
        let MacPayload {
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
            self.data_store.try_set(slice, &bits[i..i + slice.size()])?;
            i += slice.size();
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
