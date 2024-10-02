use std::mem;

use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use mpz_memory_core::{
    correlated::{Mac, MacStore, MacStoreError},
    store::{BitStore, StoreError},
    AssignKind, Size, Slice,
};
use mpz_vm_core::{AssignOp, DecodeFuture, DecodeOp};
use utils::{
    filter_drain::FilterDrain,
    range::{Difference, Union},
};

use crate::store::{AssignPayload, DecodePayload, MacPayload};

type Error = ProverStoreError;
type Result<T> = core::result::Result<T, Error>;
type Range = core::ops::Range<usize>;
type RangeSet = utils::range::RangeSet<usize>;

#[derive(Debug, Default)]
pub struct ProverStore {
    mac_store: MacStore,
    data_store: BitStore,
    idx_public: RangeSet,
    buffer_assign: Vec<(Range, BitVec)>,
    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl ProverStore {
    /// Allocates uninitialized memory.
    pub fn alloc(&mut self, len: usize) -> Slice {
        self.mac_store.alloc(len);
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

    pub fn wants_decode(&self) -> bool {
        self.buffer_decode
            .iter()
            .any(|op| self.mac_store.is_set(op.slice))
    }

    pub fn try_get_macs(&self, slice: Slice) -> Result<&[Mac]> {
        self.mac_store.try_get(slice).map_err(Error::from)
    }

    pub fn set_macs(&mut self, slice: Slice, macs: &[Mac]) -> Result<()> {
        self.mac_store.try_set(slice, macs).map_err(Error::from)
    }

    pub fn assign_public(&mut self, slice: Slice, data: &BitSlice) -> Result<()> {
        self.mac_store.try_set_public(slice, data)?;
        self.data_store.try_set(slice, data)?;

        self.idx_public = self.idx_public.union(&slice.to_range());

        Ok(())
    }

    pub fn assign_private(
        &mut self,
        slice: Slice,
        data: &BitSlice,
        masks: &BitSlice,
        macs: &[Mac],
    ) -> Result<()> {
        self.data_store.try_set(slice, data)?;
        self.mac_store.try_set(slice, macs)?;
        self.mac_store.adjust(slice, data)?;

        let mut adjust = masks.to_bitvec();
        adjust ^= data;

        self.buffer_assign.push((slice.to_range(), adjust));

        Ok(())
    }

    pub fn decode(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        let (fut, op) = DecodeFuture::new(slice);

        self.buffer_decode.push(op);

        Ok(fut)
    }

    /// Executes assignment operations.
    ///
    /// Returns payload to send to the verifier.
    pub fn execute_assign(&mut self) -> Result<AssignPayload> {
        let mut ops = mem::take(&mut self.buffer_assign);
        ops.sort_by_key(|(range, _)| range.start);

        let mut idx = Vec::new();
        let mut adjust = BitVec::new();
        for (range, adjust_) in ops {
            idx.push(range);
            adjust.extend_from_bitslice(&adjust_);
        }

        Ok(AssignPayload {
            idx: RangeSet::from(idx),
            adjust,
        })
    }

    /// Executes ready decode operations.
    ///
    /// Returns MAC proof to send to the verifier.
    pub fn execute_decode(&mut self) -> Result<MacPayload> {
        let mut idx = RangeSet::from(
            self.buffer_decode
                .filter_drain(|op| {
                    if let Ok(data) = self.data_store.try_get(op.slice) {
                        op.send(data.to_bitvec())
                            .expect("channel should not be closed");

                        true
                    } else {
                        false
                    }
                })
                .map(|op| op.slice.to_range())
                .collect::<Vec<_>>(),
        );

        // Only prove the private indices.
        idx = idx.difference(&self.idx_public);

        let (bits, proof) = self.mac_store.prove(&idx)?;

        Ok(MacPayload { idx, bits, proof })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("prover store error")]
pub struct ProverStoreError {}

impl From<MacStoreError> for ProverStoreError {
    fn from(err: MacStoreError) -> Self {
        todo!()
    }
}

impl From<StoreError> for ProverStoreError {
    fn from(err: StoreError) -> Self {
        todo!()
    }
}
