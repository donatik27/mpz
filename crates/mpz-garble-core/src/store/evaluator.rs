use std::mem;

use mpz_core::bitvec::{BitSlice, BitVec};
use mpz_memory_core::{
    correlated::{Mac, MacStore, MacStoreError},
    store::{BitStore, StoreError},
    view::View,
    AssignKind, Size, Slice,
};
use mpz_vm_core::{AssignOp, DecodeFuture, DecodeOp};
use utils::{
    filter_drain::FilterDrain,
    range::{Difference, Intersection, Subset, Union},
};

use crate::store::{AssignPayload, DecodePayload, MacPayload};

type Error = EvaluatorStoreError;
type Result<T> = core::result::Result<T, Error>;
type RangeSet = utils::range::RangeSet<usize>;

#[derive(Debug, Default)]
pub struct EvaluatorStore {
    view: View,
    mac_store: MacStore,
    key_bit_store: BitStore,
    data_store: BitStore,

    /// Ranges for which key bits have been received.
    idx_key_bits: RangeSet,
    /// Ranges for which key bits are pending.
    idx_pending_key_bits: RangeSet,
    /// Ranges which have already been decoded.
    idx_decoded: RangeSet,
    /// Ranges for which we are waiting to send MACs.
    idx_pending_decode: RangeSet,

    buffer_assign: Vec<AssignOp>,
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

    pub fn wants_assign(&self) -> bool {
        !self.buffer_assign.is_empty()
    }

    pub fn wants_key_bits(&self) -> bool {
        !self
            .idx_pending_key_bits
            .intersection(self.mac_store.set_ranges())
            .is_empty()
    }

    pub fn wants_decode(&self) -> bool {
        !self.idx_pending_decode.is_empty()
    }

    pub fn try_get_macs(&self, slice: Slice) -> Result<&[Mac]> {
        self.mac_store.try_get(slice).map_err(Error::from)
    }

    pub fn try_set_macs(&mut self, slice: Slice, macs: &[Mac]) -> Result<()> {
        self.mac_store.try_set(slice, macs).map_err(Error::from)
    }

    pub fn assign_public(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.data_store.try_set(slice, data)?;
        self.view.set_public(slice);

        self.buffer_assign.push(AssignOp {
            slice,
            kind: AssignKind::Public,
        });

        Ok(())
    }

    pub fn assign_private(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.data_store.try_set(slice, data)?;
        self.view.set_private(slice);

        self.buffer_assign.push(AssignOp {
            slice,
            kind: AssignKind::Private,
        });

        Ok(())
    }

    pub fn assign_blind(&mut self, slice: Slice) -> Result<()> {
        self.view.set_blind(slice);

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

    /// Executes assignment operations.
    ///
    /// Returns a receiver for the assignment payload and the choices for
    /// oblivious transfer.
    pub fn execute_assign(&mut self) -> Result<(ReceiveAssign<'_>, Vec<bool>)> {
        self.buffer_assign.sort_by_key(|op| op.slice.ptr());

        let mut idx_direct = Vec::new();
        let mut idx_oblivious = Vec::new();
        for op in mem::take(&mut self.buffer_assign) {
            match op.kind {
                AssignKind::Public | AssignKind::Blind => {
                    idx_direct.push(op.slice.to_range());
                }
                AssignKind::Private => {
                    idx_oblivious.push(op.slice.to_range());
                }
            }
        }

        let idx_direct = RangeSet::from(idx_direct);
        let idx_oblivious = RangeSet::from(idx_oblivious);

        let mut choices = Vec::new();
        for range in idx_oblivious.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            choices.extend(
                self.data_store
                    .try_get(slice)
                    .expect("data should be set")
                    .iter()
                    .by_vals(),
            );
        }

        Ok((
            ReceiveAssign {
                store: self,
                idx_direct,
                idx_oblivious,
            },
            choices,
        ))
    }

    /// Receives key bits from the generator.
    pub fn receive_key_bits(&mut self, payload: DecodePayload) -> Result<()> {
        let DecodePayload { idx, key_bits } = payload;

        if !idx.is_subset(&self.idx_pending_key_bits) {
            todo!("unexpected key bits");
        }

        let mut i = 0;
        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            let key_bits = &key_bits[i..i + slice.size()];

            self.key_bit_store.try_set(slice, key_bits)?;

            i += slice.size();
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

    /// Executes ready decode operations.
    ///
    /// Returns MAC proof to send to the generator.
    pub fn send_macs(&mut self) -> Result<MacPayload> {
        let idx = self
            .idx_pending_decode
            .intersection(self.mac_store.set_ranges());

        let (bits, proof) = self.mac_store.prove(&idx)?;

        self.idx_pending_decode = self.idx_pending_decode.difference(&idx);
        self.idx_decoded = self.idx_decoded.union(&idx);

        Ok(MacPayload { idx, bits, proof })
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
    }
}

#[must_use]
pub struct ReceiveAssign<'a> {
    store: &'a mut EvaluatorStore,
    idx_direct: RangeSet,
    idx_oblivious: RangeSet,
}

impl ReceiveAssign<'_> {
    /// Receives the MACs from the generator.
    ///
    /// # Arguments
    ///
    /// * `payload` - Assignment payload.
    /// * `oblivious` - MACs received via oblivious transfer.
    pub fn receive(self, payload: AssignPayload, oblivious_macs: Vec<Mac>) -> Result<()> {
        let AssignPayload {
            idx_direct,
            idx_oblivious,
            macs,
        } = payload;

        if self.idx_direct != idx_direct {
            todo!()
        } else if self.idx_oblivious != idx_oblivious {
            todo!()
        }

        if oblivious_macs.len() != idx_oblivious.len() {
            todo!()
        }

        let mut i = 0;
        for range in idx_direct.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.store
                .mac_store
                .try_set(slice, &macs[i..i + slice.size()])?;
            i += slice.size();
        }

        i = 0;
        for range in idx_oblivious.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.store
                .mac_store
                .try_set(slice, &oblivious_macs[i..i + slice.size()])?;
            i += slice.size();
        }

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
