use mpz_core::bitvec::BitVec;
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

use crate::store::{
    DecodeState, EvaluatorFlush, FlushState, GeneratorFlush, InputState, MacProof, OutputState,
};

type Error = EvaluatorStoreError;
type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Default)]
pub struct EvaluatorStore {
    mac_store: MacStore,
    key_bit_store: BitStore,
    data_store: BitStore,
    view: View,
    input_state: InputState,
    decode_state: DecodeState,
    output_state: OutputState,
    flush_state: FlushState,

    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl EvaluatorStore {
    pub fn alloc_output(&mut self, size: usize) -> Slice {
        self.view.alloc(size);
        self.mac_store.alloc(size);
        self.key_bit_store.alloc(size);
        let slice = self.data_store.alloc(size);

        let range = slice.to_range();
        self.output_state.uninit |= &range;
        self.output_state.all |= range;

        slice
    }

    /// Returns whether the MACs are set for a slice.
    pub fn is_set_macs(&self, slice: Slice) -> bool {
        self.mac_store.is_set(slice)
    }

    /// Returns whether the slice is committed.
    pub fn is_committed(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.input_state.complete)
    }

    /// Returns the MACs for a slice.
    pub fn try_get_macs(&self, slice: Slice) -> Result<&[Mac]> {
        self.mac_store.try_get(slice).map_err(Error::from)
    }

    /// Sets the MACs for a slice corresponding to output.
    pub fn set_output(&mut self, slice: Slice, macs: &[Mac]) -> Result<()> {
        self.mac_store.try_set(slice, macs)?;

        self.output_state.uninit -= slice.to_range();
        self.output_state.preprocessed -= slice.to_range();
        self.output_state.complete |= slice.to_range();

        Ok(())
    }

    /// Marks an output as preprocessed.
    pub fn mark_output(&mut self, slice: Slice) {
        self.output_state.uninit -= slice.to_range();
        self.output_state.preprocessed |= slice.to_range();
    }

    /// Updates the flush state and returns `true` if the store wants to flush.
    pub fn wants_flush(&mut self) -> bool {
        // Receive MACs directly except for private data.
        self.flush_state.macs = self.input_state.pending.clone() - self.view.private();
        // Receive MACs using OT for private data.
        self.flush_state.ot = self.input_state.pending.clone() & self.view.private();

        let private_inputs = self.input_state.all.clone() & self.view.private();
        let blind_inputs = self.input_state.all.clone() & self.view.blind();
        let initialized_outputs = self.output_state.all.clone() - &self.output_state.uninit;
        let executed_outputs = &self.output_state.complete;
        let received_key_bits = &self.decode_state.key_bits;
        let wants_decode = self.decode_state.all.clone() - &self.decode_state.complete;

        // Receive key bits for blind inputs and initialized outputs.
        self.flush_state.key_bits =
            ((blind_inputs | initialized_outputs) - received_key_bits) & &wants_decode;
        // Send MAC proofs for private inputs and executed outputs.
        self.flush_state.decode =
            (private_inputs | (executed_outputs.clone() & received_key_bits)) & wants_decode;

        !self.flush_state.is_empty()
    }

    /// Flushes pending operations.
    ///
    /// Returns the flush receiver, message and choices if oblivious transfer
    /// is required.
    pub fn flush(&mut self) -> Result<(ReceiveFlush<'_>, EvaluatorFlush, Vec<bool>)> {
        let idx = self.flush_state.clone();

        // Collect the choices for oblivious transfer.
        let mut choices: Vec<_> = Vec::with_capacity(idx.ot.len());
        for range in idx.ot.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            choices.extend(self.data_store.try_get(slice)?.iter().by_vals());
        }

        // Prove decoded MACs to the generator.
        let mac_proof = if !idx.decode.is_empty() {
            let (bits, proof) = self.mac_store.prove(&idx.decode)?;

            Some(MacProof { bits, proof })
        } else {
            None
        };

        let flush = EvaluatorFlush { idx, mac_proof };

        Ok((ReceiveFlush { store: self }, flush, choices))
    }

    /// Flushes decode operations.
    pub fn flush_decode(&mut self) -> Result<()> {
        self.decode_macs()?;

        for mut op in self
            .buffer_decode
            .filter_drain(|op| self.data_store.is_set(op.slice))
        {
            let data = self.data_store.try_get(op.slice)?;
            op.send(data.to_bitvec())?;
        }

        Ok(())
    }

    /// Decodes all data which is not set but we have the MACs and key bits.
    fn decode_macs(&mut self) -> Result<()> {
        let idx = self
            .mac_store
            .set_ranges()
            .intersection(self.key_bit_store.set_ranges())
            .difference(self.data_store.set_ranges());

        for range in idx.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            let mac_bits = self.mac_store.try_get_bits(slice)?;
            let mut data = self.key_bit_store.try_get(slice)?.to_bitvec();
            data.iter_mut()
                .zip(mac_bits)
                .for_each(|(mut bit, mac_bit)| {
                    *bit ^= mac_bit;
                });
            self.data_store.try_set(slice, &data)?;
        }

        Ok(())
    }
}

#[must_use]
pub struct ReceiveFlush<'a> {
    store: &'a mut EvaluatorStore,
}

impl ReceiveFlush<'_> {
    /// Receives the MACs from the oblivious transfer.
    pub fn receive(self, flush: GeneratorFlush, ot_macs: Vec<Mac>) -> Result<()> {
        let GeneratorFlush {
            idx,
            macs,
            key_bits,
        } = flush;

        // Ensure the generators flush is consistent.
        if idx != self.store.flush_state {
            return Err(ErrorRepr::FlushIdx {
                expected: self.store.flush_state.clone(),
                actual: idx,
            }
            .into());
        }

        // Receive the MACs.
        let mut i = 0;
        for range in idx.macs.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.store
                .mac_store
                .try_set(slice, &macs[i..i + slice.len()])?;
            i += slice.len();
        }

        // Receive the OT MACs.
        i = 0;
        for range in idx.ot.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.store
                .mac_store
                .try_set(slice, &ot_macs[i..i + slice.len()])?;
            i += slice.len();
        }

        // Receive the key bits.
        i = 0;
        for range in idx.key_bits.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.store
                .key_bit_store
                .try_set(slice, &key_bits[i..i + slice.len()])?;
            i += slice.len();
        }

        self.store.flush_state.clear();
        self.store.flush_decode()?;

        self.store.input_state.pending -= &idx.macs;
        self.store.input_state.pending -= &idx.ot;
        self.store.input_state.complete |= &idx.macs;
        self.store.input_state.complete |= &idx.ot;

        self.store.decode_state.key_bits |= &idx.key_bits;
        self.store.decode_state.complete |= &idx.decode;

        Ok(())
    }
}

impl Memory<Binary> for EvaluatorStore {
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.view.alloc(size);
        self.mac_store.alloc(size);
        self.key_bit_store.alloc(size);
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

impl ViewTrait for EvaluatorStore {
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
        if self.view.is_set_any(slice) {
            return Err(ErrorRepr::VisibilityAlreadySet { slice }.into());
        } else if !slice.to_range().is_disjoint(&self.output_state.all) {
            return Err(ErrorRepr::VisibilityOutput { slice }.into());
        }

        self.view.set_blind(slice);

        Ok(())
    }
}

/// Error for [`EvaluatorStore`].
#[derive(Debug, thiserror::Error)]
#[error("evaluator store error: {}", .0)]
pub struct EvaluatorStoreError(#[from] ErrorRepr);

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

impl From<MacStoreError> for EvaluatorStoreError {
    fn from(err: MacStoreError) -> Self {
        Self(ErrorRepr::MacStore(err))
    }
}

impl From<StoreError> for EvaluatorStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<DecodeError> for EvaluatorStoreError {
    fn from(err: DecodeError) -> Self {
        Self(ErrorRepr::Decode(err))
    }
}
