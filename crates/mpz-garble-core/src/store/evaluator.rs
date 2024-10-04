use std::mem;

use mpz_core::bitvec::{BitSlice, BitVec};
use mpz_memory_core::{
    correlated::{Mac, MacStore, MacStoreError},
    store::{BitStore, StoreError},
    view::View,
    AssignKind, Slice,
};
use mpz_vm_core::{AssignOp, DecodeFuture, DecodeOp};
use utils::{
    filter_drain::FilterDrain,
    range::{Difference, Disjoint, Intersection, Subset, Union},
};

use crate::store::{KeyBitPayload, MacPayload, MacProof};

type Error = EvaluatorStoreError;
type Result<T> = core::result::Result<T, Error>;
type RangeSet = utils::range::RangeSet<usize>;

#[derive(Debug, Default)]
pub struct EvaluatorStore {
    mac_store: MacStore,
    key_bit_store: BitStore,
    data_store: BitStore,
    view: View,

    /// Ranges for which commitment is pending.
    idx_pending_commit: RangeSet,
    /// Ranges which have been committed.
    idx_committed: RangeSet,
    /// Ranges for which key bits have been received.
    idx_key_bits: RangeSet,
    /// Ranges for which key bits are pending.
    idx_pending_key_bits: RangeSet,
    /// Ranges which have already been decoded.
    idx_decoded: RangeSet,
    /// Ranges for which we are waiting to send MACs.
    idx_pending_decode: RangeSet,

    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl EvaluatorStore {
    /// Allocates uninitialized memory for a value.
    pub fn alloc(&mut self, len: usize) -> Slice {
        self.view.alloc(len);
        self.mac_store.alloc(len);
        self.key_bit_store.alloc(len);
        self.data_store.alloc(len)
    }

    /// Returns whether the MACs are set for a slice.
    pub fn is_set_macs(&self, slice: Slice) -> bool {
        self.mac_store.is_set(slice)
    }

    /// Returns whether the data is set for a slice.
    pub fn is_set_data(&self, slice: Slice) -> bool {
        self.data_store.is_set(slice)
    }

    /// Returns `true` if the store is ready to receive MACs.
    pub fn wants_commit(&self) -> bool {
        !self.idx_pending_commit.is_empty()
    }

    /// Returns `true` if the store is ready to receive MACs using oblivious
    /// transfer.
    pub fn wants_oblivious_transfer(&self) -> bool {
        !self
            .idx_pending_commit
            .intersection(self.view.private())
            .is_empty()
    }

    /// Returns `true` if the store is ready to receive key bits.
    pub fn wants_key_bits(&self) -> bool {
        !self
            .idx_pending_key_bits
            .intersection(self.mac_store.set_ranges())
            .is_empty()
    }

    /// Returns `true` if the store is ready to prove MACs.
    pub fn wants_prove_macs(&self) -> bool {
        !self
            .idx_pending_decode
            .intersection(self.mac_store.set_ranges())
            .is_empty()
    }

    pub fn try_get_macs(&self, slice: Slice) -> Result<&[Mac]> {
        self.mac_store.try_get(slice).map_err(Error::from)
    }

    pub fn try_set_macs(&mut self, slice: Slice, macs: &[Mac]) -> Result<()> {
        self.mac_store.try_set(slice, macs).map_err(Error::from)
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

        // Determine which key bits we need to receive then mark them pending.
        let idx_not_received = range.difference(&self.idx_key_bits);
        if !idx_not_received.is_empty() {
            // Add it to pending.
            self.idx_pending_key_bits = self.idx_pending_key_bits.union(&idx_not_received);
        }

        // Determine which MACs we need to send then mark them pending.
        let idx_not_decoded = range.difference(&self.idx_decoded);
        if !idx_not_decoded.is_empty() {
            // Add it to pending.
            self.idx_pending_decode = self.idx_pending_decode.union(&idx_not_decoded);
        }

        Ok(fut)
    }

    /// Receives MACs from the generator.
    pub fn receive_macs(&mut self, payload: MacPayload) -> Result<()> {
        let MacPayload { idx, macs } = payload;

        let expected_idx = self.idx_pending_commit.difference(self.view.private());

        if idx != expected_idx {
            assert_eq!(idx, expected_idx);
        }

        let mut i = 0;
        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);

            // Store protects against MACs being overwritten.
            self.mac_store.try_set(slice, &macs[i..i + slice.len()])?;

            i += slice.len();
        }

        self.idx_pending_commit = self.idx_pending_commit.difference(&idx);
        self.decode_macs();

        Ok(())
    }

    /// Receives MACs from the generator using oblivious transfer.
    pub fn oblivious_transfer(&mut self) -> Result<ObliviousTransfer<'_>> {
        let idx = self.idx_pending_commit.intersection(self.view.private());

        Ok(ObliviousTransfer { store: self, idx })
    }

    /// Receives key bits from the generator.
    pub fn receive_key_bits(&mut self, payload: KeyBitPayload) -> Result<()> {
        let KeyBitPayload { idx, key_bits } = payload;

        if !idx.is_subset(&self.idx_pending_key_bits) {
            todo!("unexpected key bits");
        }

        let mut i = 0;
        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            let key_bits = &key_bits[i..i + slice.len()];

            self.key_bit_store.try_set(slice, key_bits)?;

            i += slice.len();
        }

        self.idx_pending_key_bits = self.idx_pending_key_bits.difference(&idx);
        self.decode_macs();

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

    /// Proves MACs to the generator.
    pub fn prove_macs(&mut self) -> Result<MacProof> {
        let idx = self
            .idx_pending_decode
            .intersection(self.mac_store.set_ranges());

        let (bits, proof) = self.mac_store.prove(&idx)?;

        self.idx_pending_decode = self.idx_pending_decode.difference(&idx);
        self.idx_decoded = self.idx_decoded.union(&idx);

        Ok(MacProof { idx, bits, proof })
    }

    /// Decodes all data which is not set but we have the MACs and key bits.
    pub fn decode_macs(&mut self) {
        let idx = self
            .mac_store
            .set_ranges()
            .intersection(self.key_bit_store.set_ranges())
            .difference(self.data_store.set_ranges());

        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            let mac_bits = self
                .mac_store
                .try_get_bits(slice)
                .expect("macs should be set");
            let mut data = self
                .key_bit_store
                .try_get(slice)
                .expect("key bits should be set")
                .to_bitvec();
            data.iter_mut()
                .zip(mac_bits)
                .for_each(|(mut bit, mac_bit)| {
                    *bit ^= mac_bit;
                });
            self.data_store
                .try_set(slice, &data)
                .expect("data should not be set");
        }

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
    }
}

#[must_use]
pub struct ObliviousTransfer<'a> {
    store: &'a mut EvaluatorStore,
    idx: RangeSet,
}

impl ObliviousTransfer<'_> {
    /// Returns the ranges for which oblivious transfer is being performed.
    pub fn idx(&self) -> &RangeSet {
        &self.idx
    }

    /// Returns the choices for oblivious transfer.
    pub fn choices(&self) -> Vec<bool> {
        let mut choices: Vec<_> = Vec::with_capacity(self.idx.len());
        for range in self.idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            choices.extend(
                self.store
                    .data_store
                    .try_get(slice)
                    .expect("data should be set")
                    .iter()
                    .by_vals(),
            );
        }

        choices
    }

    /// Receives the MACs from the oblivious transfer.
    pub fn receive(self, macs: Vec<Mac>) -> Result<()> {
        if macs.len() != self.idx.len() {
            todo!()
        }

        let mut i = 0;
        for range in self.idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.store
                .mac_store
                .try_set(slice, &macs[i..i + slice.len()])?;
            i += slice.len();
        }

        self.store.idx_pending_commit = self.store.idx_pending_commit.difference(&self.idx);

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("evaluator store error")]
pub struct EvaluatorStoreError {}

impl From<MacStoreError> for EvaluatorStoreError {
    fn from(err: MacStoreError) -> Self {
        todo!()
    }
}

impl From<StoreError> for EvaluatorStoreError {
    fn from(err: StoreError) -> Self {
        todo!()
    }
}
