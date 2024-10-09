use std::mem;

use mpz_core::{
    bitvec::{BitSlice, BitVec},
    Block,
};
use mpz_memory_core::{
    binary::Binary,
    correlated::{Delta, Key, KeyStore, KeyStoreError},
    store::{BitStore, StoreError},
    view::View,
    DecodeError, DecodeFuture, DecodeOp, Memory, Slice, View as ViewTrait,
};
use utils::{
    filter_drain::FilterDrain,
    range::{Disjoint, Subset},
};

use crate::store::{DecodeState, FlushState, InputState, OutputState, ProverFlush, VerifierFlush};

type Error = VerifierStoreError;
type Result<T> = core::result::Result<T, Error>;
type Range = core::ops::Range<usize>;
type RangeSet = utils::range::RangeSet<usize>;

#[derive(Debug)]
pub struct VerifierStore {
    key_store: KeyStore,
    data_store: BitStore,
    view: View,
    input_state: InputState,
    output_state: OutputState,
    decode_state: DecodeState,
    flush_state: FlushState,
    buffer_decode: Vec<DecodeOp<BitVec>>,
}

impl VerifierStore {
    /// Creates a new verifier store.
    pub fn new(delta: Delta) -> Self {
        Self {
            key_store: KeyStore::new(delta),
            data_store: BitStore::new(),
            view: View::default(),
            input_state: InputState::default(),
            output_state: OutputState::default(),
            decode_state: DecodeState::default(),
            flush_state: FlushState::default(),
            buffer_decode: Vec::new(),
        }
    }

    /// Returns delta.
    pub fn delta(&self) -> &Delta {
        self.key_store.delta()
    }

    /// Returns whether the data is committed.
    pub fn is_committed(&self, slice: Slice) -> bool {
        slice.to_range().is_subset(&self.input_state.complete)
    }

    pub fn try_get_keys(&self, slice: Slice) -> Result<&[Key]> {
        self.key_store.try_get(slice).map_err(Error::from)
    }

    pub fn set_input_keys(&mut self, slice: Slice, keys: &[Key]) -> Result<()> {
        self.key_store.try_set(slice, keys).map_err(Error::from)
    }

    /// Sets the output keys for a circuit.
    pub fn set_output_keys(&mut self, slice: Slice, keys: &[Key]) -> Result<()> {
        self.key_store.try_set(slice, keys).map_err(Error::from)
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

    pub fn flush(&mut self) -> Result<(ReceiveFlush<'_>, VerifierFlush)> {
        let flush = VerifierFlush {
            state: self.flush_state.clone(),
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
    store: &'a mut VerifierStore,
}

impl ReceiveFlush<'_> {
    pub fn receive(self, flush: ProverFlush) -> Result<()> {
        let ProverFlush {
            state,
            adjust,
            mac_bits,
            proof,
        } = flush;

        if state != self.store.flush_state {
            return Err(ErrorRepr::FlushState {
                expected: self.store.flush_state.clone(),
                actual: state,
            }
            .into());
        }

        // Adjust keys.
        let mut i = 0;
        for range in state.commit.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.store
                .key_store
                .adjust(slice, &adjust[i..i + slice.len()])?;
            i += slice.len();
        }

        // Verify MAC proofs.
        let mut bits = mac_bits;
        self.store
            .key_store
            .verify(&state.prove, &mut bits, proof)?;
        for range in state.prove.iter_ranges() {
            let slice = Slice::from_range_unchecked(range);
            self.store.data_store.try_set(slice, &bits)?;
        }

        self.store.input_state.pending -= &state.commit;
        self.store.input_state.complete |= &state.commit;
        self.store.decode_state.complete |= &state.prove;

        self.store.flush_state.clear();
        self.store.flush_decode()?;

        Ok(())
    }
}

impl Memory<Binary> for VerifierStore {
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.view.alloc(size);
        self.key_store.alloc(size);
        let slice = self.data_store.alloc(size);

        let range = slice.to_range();
        self.input_state.uncommitted |= &range;
        self.input_state.all |= &range;

        Ok(slice)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<()> {
        if !self.view.is_public(slice) {
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
        let visible = range.clone() & self.view.visible();
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

impl ViewTrait<Binary> for VerifierStore {
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
        todo!("can not mark private")
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

#[derive(Debug, thiserror::Error)]
#[error("verifier store error: {0}")]
pub struct VerifierStoreError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("key store error: {0}")]
    KeyStore(#[from] KeyStoreError),
    #[error("data store error: {0}")]
    Store(#[from] StoreError),
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
    #[error("prover flush index mismatch: expected {expected:?}, got {actual:?}")]
    FlushState {
        expected: FlushState,
        actual: FlushState,
    },
}

impl From<KeyStoreError> for VerifierStoreError {
    fn from(err: KeyStoreError) -> Self {
        Self(ErrorRepr::KeyStore(err))
    }
}

impl From<StoreError> for VerifierStoreError {
    fn from(err: StoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<DecodeError> for VerifierStoreError {
    fn from(err: DecodeError) -> Self {
        Self(ErrorRepr::Decode(err))
    }
}
