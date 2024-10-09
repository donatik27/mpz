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
    range::{Difference, Disjoint, Intersection, Subset},
};

use crate::store::{DecodeState, FlushState, InputState, OutputState, ProverFlush, VerifierFlush};

type Error = ProverStoreError;
type Result<T> = core::result::Result<T, Error>;
type Range = core::ops::Range<usize>;
type RangeSet = utils::range::RangeSet<usize>;

#[derive(Debug, Default)]
pub struct ProverStore {
    mac_store: MacStore,
    mask_store: BitStore,
    data_store: BitStore,
    view: View,
    input_state: InputState,
    output_state: OutputState,
    decode_state: DecodeState,
    flush_state: FlushState,
    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl ProverStore {
    /// Returns whether the MACs are set for a slice.
    pub fn is_set_macs(&self, slice: Slice) -> bool {
        self.mac_store.is_set(slice)
    }

    /// Returns whether the data is set for a slice.
    pub fn is_set_data(&self, slice: Slice) -> bool {
        self.data_store.is_set(slice)
    }

    /// Returns whether the data is committed.
    pub fn is_committed(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.input_state.complete)
    }

    pub fn try_get_macs(&self, slice: Slice) -> Result<&[Mac]> {
        self.mac_store.try_get(slice).map_err(Error::from)
    }

    /// Sets the MACs for input data.
    pub fn set_input_macs(
        &mut self,
        slice: Slice,
        mask_bits: &BitSlice,
        macs: &[Mac],
    ) -> Result<()> {
        self.mac_store.try_set(slice, macs)?;
        self.mask_store.try_set(slice, mask_bits)?;

        Ok(())
    }

    pub fn set_output_macs(&mut self, slice: Slice, macs: &[Mac]) -> Result<()> {
        self.mac_store.try_set(slice, macs).map_err(Error::from)
    }

    pub fn wants_flush(&mut self) -> bool {
        let wants_decode =
            (self.decode_state.all.clone() - &self.decode_state.complete) - self.view.public();

        self.flush_state.commit = self.input_state.pending.clone() - self.view.public();
        self.flush_state.prove = (self.input_state.complete.clone()
            // Can commit and prove simulatenously.
            | &self.flush_state.commit
            | &self.output_state.complete)
            & wants_decode;

        !self.flush_state.is_empty()
    }

    pub fn flush(&mut self) -> Result<(ReceiveFlush<'_>, ProverFlush)> {
        let mut adjust = BitVec::with_capacity(self.flush_state.commit.len());
        let mut i = 0;
        for range in self.flush_state.commit.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);

            let data = self.data_store.try_get(slice)?;
            self.mac_store.adjust(slice, data)?;

            adjust.extend_from_bitslice(data);

            // Apply masks to the data.
            let masks = self.mask_store.try_get(slice)?;
            adjust[i..i + slice.len()] ^= masks;

            i += slice.len();
        }

        let (mac_bits, proof) = self.mac_store.prove(&self.flush_state.prove)?;

        let flush = ProverFlush {
            state: self.flush_state.clone(),
            adjust,
            mac_bits,
            proof,
        };

        Ok((ReceiveFlush { store: self }, flush))
    }

    fn flush_decode(&mut self) -> Result<()> {
        for mut op in self
            .buffer_decode
            .filter_drain(|op| self.data_store.is_set(op.slice))
        {
            let data = self.data_store.try_get(op.slice)?;
            op.send(data.to_bitvec())?;
        }

        Ok(())
    }
}

#[must_use]
pub struct ReceiveFlush<'a> {
    store: &'a mut ProverStore,
}

impl ReceiveFlush<'_> {
    pub fn receive(self, flush: VerifierFlush) -> Result<()> {
        let VerifierFlush { state } = flush;

        if state != self.store.flush_state {
            return Err(ErrorRepr::FlushState {
                expected: self.store.flush_state.clone(),
                actual: state,
            }
            .into());
        }

        self.store.input_state.pending -= &state.commit;
        self.store.input_state.complete |= &state.commit;
        self.store.decode_state.complete |= &state.prove;

        self.store.flush_state.clear();
        self.store.flush_decode()?;

        Ok(())
    }
}

impl Memory<Binary> for ProverStore {
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.view.alloc(size);
        self.mac_store.alloc(size);
        self.mask_store.alloc(size);
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

impl ViewTrait<Binary> for ProverStore {
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
    #[error("verifier flush state mismatch: expected {expected:?}, got {actual:?}")]
    FlushState {
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
