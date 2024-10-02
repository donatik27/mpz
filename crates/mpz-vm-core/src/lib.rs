mod decode;

pub use decode::{DecodeFuture, DecodeOp};

use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_memory_core::{AssignKind, Size, Slice};

#[derive(Debug, Clone)]
pub struct AssignOp {
    /// Memory slice.
    pub slice: Slice,
    /// Assign kind.
    pub kind: AssignKind,
}

#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("input count mismatch: expected {expected}, got {actual}")]
    InputCount { expected: usize, actual: usize },
    #[error("input length mismatch: input {idx} expected {expected}, got {actual}")]
    InputLength {
        idx: usize,
        expected: usize,
        actual: usize,
    },
}

#[derive(Debug, Clone)]
pub struct Call {
    circ: Arc<Circuit>,
    inputs: Vec<Slice>,
}

impl Call {
    /// Creates a new call.
    pub fn new(circ: Arc<Circuit>, inputs: Vec<Slice>) -> Result<Self, CallError> {
        if circ.inputs().len() != inputs.len() {
            return Err(CallError::InputCount {
                expected: circ.inputs().len(),
                actual: inputs.len(),
            });
        }

        for (idx, (circ_input, input)) in circ.inputs().iter().zip(&inputs).enumerate() {
            if circ_input.len() != input.size() {
                return Err(CallError::InputLength {
                    idx,
                    expected: circ_input.len(),
                    actual: input.size(),
                });
            }
        }

        Ok(Self { circ, inputs })
    }

    /// Returns the circuit.
    pub fn circ(&self) -> &Circuit {
        &self.circ
    }

    /// Returns the inputs.
    pub fn inputs(&self) -> &[Slice] {
        &self.inputs
    }

    /// Consumes the call and returns the circuit and inputs.
    pub fn into_parts(self) -> (Arc<Circuit>, Vec<Slice>) {
        (self.circ, self.inputs)
    }
}
