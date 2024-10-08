use std::mem;

use mpz_core::bitvec::{BitSlice, BitVec};
use mpz_memory_core::{
    binary::Binary,
    correlated::{Mac, MacStore, MacStoreError},
    store::{BitStore, StoreError},
    view::View,
    DecodeError, DecodeFuture, DecodeOp, Memory, Slice, View as ViewTrait,
};
use utils::{
    filter_drain::FilterDrain,
    range::{Difference, Disjoint, Intersection},
};

use crate::store::{DecodeState, FlushState, InputState, OutputState, ProverFlush, VerifierFlush};

type Error = ProverStoreError;
type Result<T> = core::result::Result<T, Error>;
type Range = core::ops::Range<usize>;
type RangeSet = utils::range::RangeSet<usize>;

#[derive(Debug, Default)]
pub struct ProverStore {
    mac_store: MacStore,
    data_store: BitStore,
    view: View,
    input_state: InputState,
    output_state: OutputState,
    decode_state: DecodeState,
    flush_state: FlushState,

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

    pub fn wants_flush(&mut self) -> bool {
        todo!()
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

        self.idx_public |= slice.to_range();

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

impl Memory<Binary> for ProverStore {
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.view.alloc(size);
        self.mac_store.alloc(size);
        let slice = self.data_store.alloc(size);

        let range = slice.to_range();
        self.input_state.uncommitted |= &range;
        self.input_state.all |= &range;

        Ok(slice)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<()> {
        if !self.view.is_visible(slice) {
            return Err(ErrorRepr::AssignedBlind { slice }.into());
        } else if !slice.to_range().is_disjoint(&self.output_state.all) {
            return Err(ErrorRepr::AssignedOutput { slice }.into());
        }

        self.data_store.try_set(slice, &data)?;

        Ok(())
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        // Make sure visibility is set.
        if !self.view.is_set(slice) {
            return Err(ErrorRepr::VisibilityNotSet { slice }.into());
        } else if !slice.to_range().is_disjoint(&self.output_state.all) {
            return Err(ErrorRepr::CommitOutput { slice }.into());
        }

        let range = slice.to_range();

        // Make sure all visible ranges are assigned.
        let visible = range.intersection(self.view.visible());
        for range in visible.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            if !self.data_store.is_set(slice) {
                return Err(ErrorRepr::NotAssigned { slice }.into());
            }
        }

        self.input_state.uncommitted -= &range;
        self.input_state.pending |= &range;

        Ok(())
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        let (fut, mut op) = DecodeFuture::new(slice);

        // If data is already decoded, send it immediately.
        if let Ok(data) = self.data_store.try_get(slice) {
            op.send(data.to_bitvec())?;
        } else {
            self.buffer_decode.push(op);
        }

        self.decode_state.all |= slice.to_range();

        Ok(fut)
    }
}

impl ViewTrait for ProverStore {
    type Error = Error;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        if self.view.is_set_any(slice) {
            return Err(ErrorRepr::VisibilityAlreadySet { slice }.into());
        } else if !slice.to_range().is_disjoint(&self.output_state.all) {
            return Err(ErrorRepr::VisibilityOutput { slice }.into());
        }

        self.view.set_public(slice);

        Ok(())
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        if self.view.is_set_any(slice) {
            return Err(ErrorRepr::VisibilityAlreadySet { slice }.into());
        } else if !slice.to_range().is_disjoint(&self.output_state.all) {
            return Err(ErrorRepr::VisibilityOutput { slice }.into());
        }

        self.view.set_private(slice);

        Ok(())
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        todo!("cannot mark blind")
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ProverStoreError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error(transparent)]
    MacStore(MacStoreError),
    #[error(transparent)]
    Store(StoreError),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error("visibility not set for slice: {slice}")]
    VisibilityNotSet { slice: Slice },
    #[error("visibility already set for slice: {slice}")]
    VisibilityAlreadySet { slice: Slice },
    #[error("attempted to set visibility for output: {slice}")]
    VisibilityOutput { slice: Slice },
    #[error("attempted to commit visible memory which is not assigned: {slice}")]
    NotAssigned { slice: Slice },
    #[error("attempted to assign to blind memory: {slice}")]
    AssignedBlind { slice: Slice },
    #[error("attempted to assign to an output: {slice}")]
    AssignedOutput { slice: Slice },
    #[error("attempted to commit output, only inputs can be committed: {slice}")]
    CommitOutput { slice: Slice },
    #[error("evaluator flush index mismatch: expected {expected:?}, got {actual:?}")]
    FlushIdx {
        expected: FlushState,
        actual: FlushState,
    },
}

impl From<MacStoreError> for ProverStoreError {
    fn from(err: MacStoreError) -> Self {
        Self(ErrorRepr::MacStore(err))
    }
}

impl From<StoreError> for ProverStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<DecodeError> for ProverStoreError {
    fn from(err: DecodeError) -> Self {
        Self(ErrorRepr::Decode(err))
    }
}
