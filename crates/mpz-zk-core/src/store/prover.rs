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
    pub fn alloc_output(&mut self, size: usize) -> Slice {
        self.view.alloc(size);
        self.mac_store.alloc(size);
        self.mask_store.alloc(size);
        let slice = self.data_store.alloc(size);

        let range = slice.to_range();
        self.output_state.all |= &range;

        slice
    }

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

    pub fn set_output_macs(&mut self, slice: Slice, macs: &[Mac]) -> Result<()> {
        self.mac_store.try_set(slice, macs)?;

        let data = BitVec::from_iter(macs.iter().map(|mac| mac.pointer()));
        self.data_store.try_set(slice, &data)?;

        self.flush_decode()?;

        self.flush_state.prove |=
            (slice.to_range() & &self.decode_state.all) - &self.decode_state.complete;

        Ok(())
    }

    /// Returns the number of MACs the store wants.
    pub fn wants_macs(&self) -> usize {
        ((self.input_state.all.clone() - self.mac_store.set_ranges()) - self.view.public()).len()
    }

    /// Returns `true` if the store wants a flush.
    pub fn wants_flush(&self) -> bool {
        !self.flush_state.is_empty()
    }

    /// Receives MACs from the verifier.
    pub fn receive_macs(&mut self) -> Result<ReceiveMacs<'_>> {
        let ranges =
            (self.input_state.all.clone() - self.mac_store.set_ranges()) - self.view.public();
        Ok(ReceiveMacs {
            store: self,
            ranges,
        })
    }

    pub fn flush(&mut self) -> Result<(ReceiveFlush<'_>, ProverFlush)> {
        // Commit MACs.
        let mut adjust = BitVec::with_capacity(self.flush_state.commit.len());
        let mut i = 0;
        for range in self.flush_state.commit.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);

            let data = self.data_store.try_get(slice)?;
            adjust.extend_from_bitslice(data);

            // Apply masks to the data.
            let masks = self.mask_store.try_get(slice)?;
            adjust[i..i + slice.len()] ^= masks;

            i += slice.len();
        }

        let mac_proof = if !self.flush_state.prove.is_empty() {
            Some(self.mac_store.prove(&self.flush_state.prove)?)
        } else {
            None
        };

        let flush = ProverFlush {
            state: self.flush_state.clone(),
            adjust,
            mac_proof,
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
pub struct ReceiveMacs<'a> {
    store: &'a mut ProverStore,
    ranges: RangeSet,
}

impl<'a> ReceiveMacs<'a> {
    /// Receives MACs from the verifier.
    ///
    /// # Panics
    ///
    /// Panics if the number of masks does not match the number of MACs.
    pub fn receive(self, masks: &BitSlice, macs: &[Mac]) -> Result<()> {
        assert_eq!(masks.len(), macs.len());

        if masks.len() != self.ranges.len() {
            todo!()
        }

        let mut i = 0;
        for range in self.ranges.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);

            self.store
                .mask_store
                .try_set(slice, &masks[i..i + slice.len()])?;
            self.store
                .mac_store
                .try_set(slice, &macs[i..i + slice.len()])?;

            let data = self.store.data_store.try_get(slice)?;
            self.store.mac_store.adjust(slice, data)?;

            i += slice.len();
        }

        self.store.flush_state.prove |= self.ranges.clone() & &self.store.decode_state.all;

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

        self.input_state.all |= slice.to_range();

        Ok(slice)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<()> {
        if !self.view.is_visible(slice) {
            return Err(ErrorRepr::AssignedBlind { slice }.into());
        } else if !slice.to_range().is_disjoint(&self.output_state.all) {
            return Err(ErrorRepr::AssignedOutput { slice }.into());
        }

        self.data_store.try_set(slice, &data)?;

        // For public data, set MACs.
        let public = slice.to_range() & self.view.public();
        for range in public.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);

            let data = self.data_store.try_get(slice)?;
            self.mac_store.try_set_public(slice, data)?;
        }
        self.input_state.complete |= public;

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

        self.flush_state.commit |= range.difference(&self.input_state.complete);

        Ok(())
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>> {
        self.data_store
            .try_get(slice)
            .map(|data| Some(data.to_bitvec()))
            .map_err(Error::from)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        let (fut, mut op) = DecodeFuture::new(slice);

        // If data is already decoded, send it immediately.
        if let Ok(data) = self.data_store.try_get(slice) {
            op.send(data.to_bitvec())?;
        } else {
            self.buffer_decode.push(op);
        }

        let range = slice.to_range();

        // Prove ranges which have MACs set and are not yet proven.
        self.flush_state.prove |=
            range.difference(&self.decode_state.complete) & self.mac_store.set_ranges();
        self.decode_state.all |= range;

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

#[cfg(test)]
mod tests {
    use itybity::IntoBitIterator;
    use mpz_memory_core::{binary::U8, Array, MemoryExt, ToRaw, ViewExt};

    use super::*;

    #[test]
    fn test_assign() {
        let mut store = ProverStore::default();

        let a: Array<U8, 16> = store.alloc().unwrap();
        store.mark_private(a).unwrap();
        store.assign(a, [42u8; 16]).unwrap();

        let data = store.data_store.try_get(a.to_raw()).unwrap();

        assert_eq!(
            data.to_bitvec(),
            BitVec::<u32>::from_iter([42u8; 16].into_iter_lsb0())
        );
    }
}
