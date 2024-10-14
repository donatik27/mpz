use std::mem;

use blake3::Hasher;
use cfg_if::cfg_if;
use mpz_circuits::{types::BinaryRepr, Circuit, Gate};
use mpz_core::{bitvec::BitVec, Block};
use mpz_memory_core::correlated::{Delta, Key};

type GateIter<'a> = std::slice::Iter<'a, Gate>;
type Result<T> = core::result::Result<T, VerifierError>;

pub struct Verifier {
    buffer: Vec<Key>,
    delta: Delta,
    check: Check,
}

impl Verifier {
    /// Creates a new verifier.
    pub fn new(delta: Delta) -> Self {
        Self {
            buffer: Vec::new(),
            delta,
            check: Check::default(),
        }
    }

    /// Returns `true` if there are gates to check.
    pub fn wants_check(&self) -> bool {
        self.check.wants_check()
    }

    pub fn execute<'a>(
        &'a mut self,
        circ: &'a Circuit,
        input_keys: &'a [Key],
        gate_keys: &'a [Key],
    ) -> Result<VerifierConsumer<'a, GateIter<'a>>> {
        if input_keys.len() != circ.input_len() {
            todo!()
        } else if gate_keys.len() != circ.and_count() {
            todo!()
        }

        self.check.reserve(circ.and_count());

        // Expand the buffer to fit the circuit
        if circ.feed_count() > self.buffer.len() {
            self.buffer.resize(circ.feed_count(), Default::default());
        }

        let mut inputs = input_keys.into_iter();
        for input in circ.inputs() {
            for (node, key) in input.iter().zip(inputs.by_ref()) {
                self.buffer[node.id()] = *key;
            }
        }

        Ok(VerifierConsumer {
            buffer: &mut self.buffer,
            gate_keys,
            delta: self.delta,
            gates: circ.gates().iter(),
            outputs: circ.outputs(),
            counter: 0,
            and_count: circ.and_count(),
            complete: false,
            check: &mut self.check,
        })
    }

    /// Executes the consistency check.
    pub fn check(&mut self, mask_w: Block) -> Verify<'_> {
        let w = self.check.execute(self.delta.as_block(), mask_w);

        Verify {
            check: &mut self.check,
            delta: self.delta.as_block(),
            w,
        }
    }
}

pub struct VerifierConsumer<'a, I> {
    buffer: &'a mut [Key],
    gate_keys: &'a [Key],
    delta: Delta,
    gates: I,
    outputs: &'a [BinaryRepr],
    counter: usize,
    and_count: usize,
    complete: bool,

    check: &'a mut Check,
}

impl<'a, I> VerifierConsumer<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    /// Returns `true` if the evaluator wants more encrypted gates.
    #[inline]
    pub fn wants_gates(&self) -> bool {
        self.counter != self.and_count
    }

    /// Processes the next gate in the circuit.
    #[inline]
    pub fn next(&mut self, adjust: bool) {
        while let Some(gate) = self.gates.next() {
            match gate {
                Gate::Xor {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let x = self.buffer[node_x.id()];
                    let y = self.buffer[node_y.id()];
                    self.buffer[node_z.id()] = x + y;
                }
                Gate::And {
                    x: node_x,
                    y: node_y,
                    z: node_z,
                } => {
                    let key_x = self.buffer[node_x.id()];
                    let key_y = self.buffer[node_y.id()];
                    let mut key_z = self.gate_keys[self.counter];

                    key_z.adjust(adjust, &self.delta);

                    self.buffer[node_z.id()] = key_z;
                    self.check.push(key_x, key_y, key_z, adjust);
                    self.counter += 1;

                    // If we have more AND gates to evaluate, return.
                    if self.wants_gates() {
                        return;
                    }
                }
                Gate::Inv {
                    x: node_x,
                    z: node_z,
                } => {
                    let mut x = self.buffer[node_x.id()];
                    x.adjust(true, &self.delta);
                    self.buffer[node_z.id()] = x;
                }
            }
        }

        self.complete = true;
    }

    pub fn finish(mut self) -> Result<Vec<Key>> {
        if self.wants_gates() {
            todo!()
        }

        // If there were 0 AND gates in the circuit, we need to evaluate the "free"
        // gates now.
        if !self.complete {
            self.next(Default::default());
        }

        let outputs = self
            .outputs
            .iter()
            .flat_map(|output| output.iter().map(|node| self.buffer[node.id()]))
            .collect();

        Ok(outputs)
    }
}

#[derive(Default)]
struct Check {
    transcript: Hasher,
    keys: Vec<[Block; 3]>,
    adjust: BitVec<u8>,
}

impl Check {
    /// Reserves capacity for at least `n` AND gates.
    fn reserve(&mut self, n: usize) {
        self.keys.reserve(n);
        self.adjust.reserve(n);
    }

    /// Pushes the keys for the next AND gate.
    fn push(&mut self, x: Key, y: Key, z: Key, adjust: bool) {
        self.keys.push([x.into(), y.into(), z.into()]);
        self.adjust.push(adjust);
    }

    /// Returns `true` if there are gates to check.
    fn wants_check(&self) -> bool {
        !self.keys.is_empty()
    }

    /// Records the `U` and `V` terms received from the prover.
    fn record_terms(&mut self, u: Block, v: Block) {
        self.transcript.update(&u.to_bytes());
        self.transcript.update(&v.to_bytes());
    }

    /// Executes the verifier check, returning `W` defined in Step 7.c.
    fn execute(&mut self, delta: &Block, mask_w: Block) -> Block {
        self.transcript.update(self.adjust.as_raw_slice());

        // TODO: Consider using a PRG instead so computing the coefficients
        // can be done in parallel.
        let mut chi = Block::try_from(&self.transcript.finalize().as_bytes()[..16])
            .expect("block should be 16 bytes");
        let mut chis = Vec::with_capacity(self.keys.len());
        chis.push(chi);
        for _ in 1..self.keys.len() {
            chi = chi.gfmul(chi);
            chis.push(chi);
        }

        #[inline]
        fn compute_term([x, y, z]: [Block; 3], chi: Block, delta: &Block) -> Block {
            let b = x.gfmul(y) ^ delta.gfmul(z);
            b.gfmul(chi)
        }

        let keys = mem::take(&mut self.keys);
        cfg_if! {
            if #[cfg(all(feature = "rayon", not(feature = "force-st")))] {
                use rayon::prelude::*;

                let mut w = keys
                    .into_par_iter()
                    .zip(chis)
                    .map(|(keys, chi)| compute_term(keys, chi, delta))
                    .reduce(
                        || Block::ZERO,
                        |w_0, w_1| w_0 ^ w_1,
                    );
            } else {
                let mut w = macs
                    .into_iter()
                    .zip(chis)
                    .map(|(keys, chi)| compute_term(keys, chi, delta))
                    .fold(
                        Block::ZERO,
                        |w_0, w_1| w_0 ^ w_1,
                    );
            }
        }

        w ^= mask_w;

        self.adjust.clear();

        w
    }
}

/// Verifier consistency check, returned by [`Verifier::check`].
#[must_use = "verifier consistency check must be completed"]
pub struct Verify<'a> {
    check: &'a mut Check,
    delta: &'a Block,
    w: Block,
}

impl Verify<'_> {
    /// Verifies the `U` and `V` terms received from the prover, completing
    /// the consistency check.
    pub fn verify(self, u: Block, v: Block) -> Result<()> {
        self.check.record_terms(u, v);

        if self.w != u ^ self.delta.gfmul(v) {
            // todo
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("verifier error")]
pub struct VerifierError {}
