use std::mem;

use blake3::Hasher;
use cfg_if::cfg_if;
use mpz_circuits::{types::BinaryRepr, Circuit, Gate};
use mpz_core::{bitvec::BitVec, Block};
use mpz_memory_core::correlated::Mac;

type Result<T> = core::result::Result<T, ProverError>;

#[derive(Debug, Default)]
pub struct Prover {
    buffer: Vec<Mac>,
    check: Check,
}

impl Prover {
    /// Returns `true` if there are gates to check.
    pub fn wants_check(&self) -> bool {
        self.check.wants_check()
    }

    pub fn execute<'a>(
        &'a mut self,
        circ: &'a Circuit,
        input_macs: &'a [Mac],
        gate_masks: &'a [bool],
        gate_macs: &'a [Mac],
    ) -> Result<ProverIter<'a, std::slice::Iter<'a, Gate>>> {
        if input_macs.len() != circ.input_len() {
            todo!()
        } else if gate_masks.len() != circ.and_count() {
            todo!()
        } else if gate_macs.len() != circ.and_count() {
            todo!()
        }

        self.check.reserve(circ.and_count());

        // Expand the buffer to fit the circuit
        if circ.feed_count() > self.buffer.len() {
            self.buffer.resize(circ.feed_count(), Default::default());
        }

        let mut inputs = input_macs.into_iter();
        for input in circ.inputs() {
            for (node, mac) in input.iter().zip(inputs.by_ref()) {
                self.buffer[node.id()] = *mac;
            }
        }

        Ok(ProverIter {
            buffer: &mut self.buffer,
            gate_masks,
            gate_macs,
            gates: circ.gates().iter(),
            outputs: circ.outputs(),
            counter: 0,
            and_count: circ.and_count(),
            complete: false,
            check: &mut self.check,
        })
    }

    /// Executes the consistency check.
    pub fn check(&mut self, mask_u: Block, mask_v: Block) -> (Block, Block) {
        self.check.execute(mask_u, mask_v)
    }
}

pub struct ProverIter<'a, I> {
    buffer: &'a mut [Mac],
    gate_masks: &'a [bool],
    gate_macs: &'a [Mac],
    gates: I,
    outputs: &'a [BinaryRepr],
    counter: usize,
    and_count: usize,
    complete: bool,

    check: &'a mut Check,
}

impl<'a, I> ProverIter<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    /// Returns `true` if there are more gates to process.
    #[inline]
    pub fn has_gates(&self) -> bool {
        self.counter != self.and_count
    }

    pub fn finish(mut self) -> Result<Vec<Mac>> {
        if self.has_gates() {
            todo!();
        }

        // Finish computing any "free" gates.
        if !self.complete {
            assert_eq!(self.next(), None);
        }

        let outputs = self
            .outputs
            .iter()
            .flat_map(|output| output.iter().map(|node| self.buffer[node.id()]))
            .collect();

        Ok(outputs)
    }
}

impl<'a, I> Iterator for ProverIter<'a, I>
where
    I: Iterator<Item = &'a Gate>,
{
    type Item = bool;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(gate) = self.gates.next() {
            match gate {
                Gate::Xor { x, y, z } => {
                    let mac_x = self.buffer[x.id()];
                    let mac_y = self.buffer[y.id()];
                    self.buffer[z.id()] = mac_x + mac_y;
                }
                Gate::And { x, y, z } => {
                    let mac_x = self.buffer[x.id()];
                    let mac_y = self.buffer[y.id()];
                    let mut mac_z = self.gate_macs[self.counter];

                    let w_z = mac_x.pointer() & mac_y.pointer();
                    mac_z.set_pointer(w_z);

                    let adjust = self.gate_masks[self.counter] ^ w_z;

                    self.buffer[z.id()] = mac_z;
                    self.check.push(mac_x, mac_y, mac_z, adjust);
                    self.counter += 1;

                    // If we have processed all AND gates, we can compute
                    // the rest of the "free" gates.
                    if !self.has_gates() {
                        assert!(self.next().is_none());

                        self.complete = true;
                    }

                    return Some(adjust);
                }
                Gate::Inv { x, z } => {
                    let mut mac = self.buffer[x.id()];
                    mac.set_pointer(!mac.pointer());
                    self.buffer[z.id()] = mac;
                }
            }
        }

        None
    }
}

#[derive(Debug, Default)]
struct Check {
    transcript: Hasher,
    macs: Vec<[Block; 3]>,
    adjust: BitVec<u8>,
}

impl Check {
    /// Reserves capacity for at least `n` AND gates.
    fn reserve(&mut self, n: usize) {
        self.macs.reserve(n);
        self.adjust.reserve(n);
    }

    /// Pushes the MACs for the next AND gate.
    #[inline]
    fn push(&mut self, x: Mac, y: Mac, z: Mac, adjust: bool) {
        self.macs.push([x.into(), y.into(), z.into()]);
        self.adjust.push(adjust);
    }

    /// Returns `true` if there are gates to check.
    #[inline]
    fn wants_check(&self) -> bool {
        !self.macs.is_empty()
    }

    /// Executes the prover check, returning `U` and `V` defined in Step 7.b.
    fn execute(&mut self, mask_u: Block, mask_v: Block) -> (Block, Block) {
        self.transcript.update(self.adjust.as_raw_slice());

        // TODO: Consider using a PRG instead so computing the coefficients
        // can be done in parallel.
        let mut chi = Block::try_from(&self.transcript.finalize().as_bytes()[..16])
            .expect("block should be 16 bytes");
        let mut chis = Vec::with_capacity(self.macs.len());
        chis.push(chi);
        for _ in 1..self.macs.len() {
            chi = chi.gfmul(chi);
            chis.push(chi);
        }

        #[inline]
        fn compute_terms([x, y, z]: [Block; 3], chi: Block) -> (Block, Block) {
            let u = x.gfmul(y).gfmul(chi);

            let a_10 = if x.lsb() { y } else { Block::ZERO };
            let a_11 = if y.lsb() { x } else { Block::ZERO };
            let v = (a_10 ^ a_11 ^ z).gfmul(chi);

            (u, v)
        }

        let macs = mem::take(&mut self.macs);
        cfg_if! {
            if #[cfg(all(feature = "rayon", not(feature = "force-st")))] {
                use rayon::prelude::*;

                let (mut u, mut v) = macs
                    .into_par_iter()
                    .zip(chis)
                    .map(|(macs, chi)| compute_terms(macs, chi))
                    .reduce(
                        || (Block::ZERO, Block::ZERO),
                        |(u_0, v_0), (u_1, v_1)| (u_0 ^ u_1, v_0 ^ v_1),
                    );
            } else {
                let (mut u, mut v) = macs
                    .into_iter()
                    .zip(chis)
                    .map(|(macs, chi)| compute_terms(macs, chi))
                    .fold(
                        (Block::ZERO, Block::ZERO),
                        |(u_0, v_0), (u_1, v_1)| (u_0 ^ u_1, v_0 ^ v_1),
                    );
            }
        }

        u ^= mask_u;
        v ^= mask_v;

        self.transcript.update(&u.to_bytes());
        self.transcript.update(&v.to_bytes());

        self.adjust.clear();

        (u, v)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("prover error")]
pub struct ProverError {}
