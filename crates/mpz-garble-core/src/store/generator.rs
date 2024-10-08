use mpz_core::{bitvec::BitVec, prg::Prg};
use mpz_memory_core::{
    binary::Binary,
    correlated::{Delta, Key, KeyStore, KeyStoreError},
    store::{BitStore, StoreError},
    view::View,
    DecodeError, DecodeFuture, DecodeOp, Memory, Slice, View as ViewTrait,
};
use rand::Rng;
use utils::{
    filter_drain::FilterDrain,
    range::{Disjoint, Intersection, Subset},
};

use crate::store::{
    DecodeState, EvaluatorFlush, FlushState, GeneratorFlush, InputState, MacProof, OutputState,
};

type Error = GeneratorStoreError;
type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub struct GeneratorStore {
    prg: Prg,
    key_store: KeyStore,
    data_store: BitStore,
    view: View,
    input_state: InputState,
    decode_state: DecodeState,
    output_state: OutputState,
    flush_state: FlushState,

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
            input_state: InputState::default(),
            decode_state: DecodeState::default(),
            output_state: OutputState::default(),
            flush_state: FlushState::default(),
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

    /// Returns whether the slice is committed.
    pub fn is_committed(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.input_state.complete)
    }

    /// Returns keys if they are set.
    ///
    /// # Security
    ///
    /// **Never** use this method to transfer MACs to the evaluator.
    pub fn try_get_keys(&self, slice: Slice) -> Result<&[Key]> {
        self.key_store.try_get(slice).map_err(Error::from)
    }

    /// Allocates uninitialized memory for output values.
    pub fn alloc_output(&mut self, len: usize) -> Slice {
        self.view.alloc(len);
        self.key_store.alloc(len);
        let slice = self.data_store.alloc(len);

        let range = slice.to_range();
        self.output_state.uninit |= &range;
        self.output_state.all |= range;

        slice
    }

    /// Sets the keys for output data.
    pub fn set_output(&mut self, slice: Slice, keys: &[Key]) -> Result<()> {
        self.key_store.try_set(slice, keys)?;

        self.output_state.uninit -= slice.to_range();
        self.output_state.preprocessed |= slice.to_range();

        Ok(())
    }

    /// Marks an output as executed.
    ///
    /// This indicates that both parties have *executed* the call which produces
    /// this output.
    pub fn mark_output(&mut self, slice: Slice) {
        let range = slice.to_range();
        self.output_state.preprocessed -= &range;
        self.output_state.complete |= range;
    }

    /// Updates the flush state and returns `true` if the store wants to flush.
    pub fn wants_flush(&mut self) -> bool {
        // Send MACs for visible data.
        self.flush_state.macs = self.input_state.pending.clone() & self.view.visible();
        // Send MACs using OT for blind data.
        self.flush_state.ot = self.input_state.pending.clone() & self.view.blind();

        let private_inputs = self.input_state.all.clone() & self.view.private();
        let blind_inputs = self.input_state.all.clone() & self.view.blind();
        let initialized_outputs = self.output_state.all.clone() - &self.output_state.uninit;
        let executed_outputs = &self.output_state.complete;
        let sent_key_bits = &self.decode_state.key_bits;
        let wants_decode = self.decode_state.all.clone() - &self.decode_state.complete;

        // Send evaluator key bits for private inputs and initialized outputs.
        self.flush_state.key_bits =
            ((private_inputs | initialized_outputs) - sent_key_bits) & &wants_decode;
        // Expect MAC proofs for blind inputs and executed outputs.
        self.flush_state.decode =
            (blind_inputs | (executed_outputs.clone() & sent_key_bits)) & wants_decode;

        !self.flush_state.is_empty()
    }

    /// Flushes pending operations.
    ///
    /// Returns the flush receiver, message and the keys if oblivious transfer
    /// is required.
    pub fn flush(&mut self) -> Result<(ReceiveFlush<'_>, GeneratorFlush, Vec<Key>)> {
        let idx = self.flush_state.clone();

        // Collect MACs.
        let mut macs = Vec::with_capacity(idx.macs.len());
        for range in idx.macs.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            let data = self.data_store.try_get(slice)?;
            macs.extend(self.key_store.authenticate(slice, data)?);
        }

        // Collect keys for OT.
        let mut keys = Vec::with_capacity(idx.ot.len());
        for range in idx.ot.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            keys.extend_from_slice(self.key_store.oblivious_transfer(slice)?);
        }

        // Collect key bits.
        let mut key_bits = BitVec::with_capacity(idx.key_bits.len());
        for range in idx.key_bits.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            key_bits.extend(self.key_store.try_get_bits(slice)?);
        }

        let flush = GeneratorFlush {
            state: idx,
            macs,
            key_bits,
        };

        Ok((ReceiveFlush { store: self }, flush, keys))
    }

    /// Flushes decode operations.
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
    store: &'a mut GeneratorStore,
}

impl ReceiveFlush<'_> {
    /// Receives a flush from the evaluator.
    pub fn receive(self, flush: EvaluatorFlush) -> Result<()> {
        let EvaluatorFlush {
            state: idx,
            mac_proof: macs,
        } = flush;

        // Ensure the evaluators flush is consistent.
        if idx != self.store.flush_state {
            return Err(ErrorRepr::FlushIdx {
                expected: self.store.flush_state.clone(),
                actual: idx,
            }
            .into());
        }

        // Verify MACs and store the data.
        if let Some(MacProof { mut bits, proof }) = macs {
            self.store.key_store.verify(&idx.decode, &mut bits, proof)?;

            let mut i = 0;
            for range in idx.decode.iter_ranges() {
                let slice = Slice::from_range_unchecked(range);
                self.store
                    .data_store
                    .try_set(slice, &bits[i..i + slice.len()])?;
                i += slice.len();
            }
        }

        self.store.input_state.pending -= &idx.macs;
        self.store.input_state.pending -= &idx.ot;
        self.store.input_state.complete |= &idx.macs;
        self.store.input_state.complete |= &idx.ot;

        self.store.decode_state.key_bits |= &idx.key_bits;
        self.store.decode_state.complete |= &idx.decode;

        self.store.flush_state.clear();
        self.store.flush_decode()?;

        Ok(())
    }
}

impl Memory<Binary> for GeneratorStore {
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        let keys = (0..size).map(|_| self.prg.gen()).collect::<Vec<_>>();
        self.view.alloc(size);
        self.key_store.alloc_with(&keys);
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

impl ViewTrait for GeneratorStore {
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

/// Error for [`GeneratorStore`].
#[derive(Debug, thiserror::Error)]
#[error("generator store error: {}", .0)]
pub struct GeneratorStoreError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error(transparent)]
    KeyStore(KeyStoreError),
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

impl From<DecodeError> for GeneratorStoreError {
    fn from(err: DecodeError) -> Self {
        Self(ErrorRepr::Decode(err))
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    fn new() -> GeneratorStore {
        let mut rng = StdRng::seed_from_u64(0);
        GeneratorStore::new([0; 16], Delta::random(&mut rng))
    }

    #[test]
    fn test_gen_store_commit_without_visibility() {
        let mut store = new();
        let slice = store.alloc_raw(1).unwrap();
        let err = store.commit_raw(slice).unwrap_err();
        matches!(err.0, ErrorRepr::VisibilityNotSet { .. });
    }

    #[test]
    fn test_gen_store_commit_without_assign() {
        let mut store = new();
        let slice = store.alloc_raw(1).unwrap();
        store.mark_public_raw(slice).unwrap();
        let err = store.commit_raw(slice).unwrap_err();
        matches!(err.0, ErrorRepr::NotAssigned { .. });

        let slice = store.alloc_raw(1).unwrap();
        store.mark_private_raw(slice).unwrap();
        let err = store.commit_raw(slice).unwrap_err();
        matches!(err.0, ErrorRepr::NotAssigned { .. });
    }

    #[test]
    fn test_gen_store_commit_twice_is_ok() {
        let mut store = new();
        let slice = store.alloc_raw(1).unwrap();
        store.mark_blind_raw(slice).unwrap();
        store.commit_raw(slice).unwrap();
        assert!(store.commit_raw(slice).is_ok());
    }

    #[test]
    fn test_gen_store_visibility_already_set() {
        let mut store = new();
        let slice = store.alloc_raw(1).unwrap();
        store.mark_public_raw(slice).unwrap();
        let err = store.mark_public_raw(slice).unwrap_err();
        matches!(err.0, ErrorRepr::VisibilityAlreadySet { .. });

        let slice = store.alloc_raw(1).unwrap();
        store.mark_private_raw(slice).unwrap();
        let err = store.mark_private_raw(slice).unwrap_err();
        matches!(err.0, ErrorRepr::VisibilityAlreadySet { .. });

        let slice = store.alloc_raw(1).unwrap();
        store.mark_blind_raw(slice).unwrap();
        let err = store.mark_blind_raw(slice).unwrap_err();
        matches!(err.0, ErrorRepr::VisibilityAlreadySet { .. });
    }

    #[test]
    fn test_gen_store_nothing_to_flush() {
        let mut store = new();
        assert!(!store.wants_flush());
    }

    #[test]
    fn test_gen_store_commit_wants_flush() {
        let mut store = new();
        let slice = store.alloc_raw(1).unwrap();
        store.commit_raw(slice).unwrap();
        assert!(store.wants_flush());
    }

    #[test]
    fn test_gen_store_flush_pending_output() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut store = new();
        let slice = store.alloc_output(1);
        _ = store.decode_raw(slice).unwrap();

        assert!(!store.wants_flush());

        store.set_output(slice, &[rng.gen()]).unwrap();

        let (_, flush, _) = store.flush().unwrap();

        assert!(
            !flush.state.key_bits.is_empty(),
            "should want to flush key bits"
        );
        assert!(
            flush.state.decode.is_empty(),
            "should not be set until after marked ready"
        );

        store.mark_output(slice);

        assert!(store.wants_flush());
    }
}
