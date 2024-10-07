mod evaluator;
mod generator;

use blake3::Hash;
pub use evaluator::{EvaluatorStore, EvaluatorStoreError};
pub use generator::{GeneratorStore, GeneratorStoreError};

use mpz_core::bitvec::BitVec;
use mpz_memory_core::correlated::Mac;
use serde::{Deserialize, Serialize};
use utils::range::RangeSet;

#[derive(Debug, Default)]
pub struct InputState {
    /// Ranges which are allocated but not committed.
    uncommitted: RangeSet<usize>,
    /// Ranges which are pending commitment.
    pending: RangeSet<usize>,
    /// Ranges which are fully committed in both parties views.
    complete: RangeSet<usize>,
    /// All input ranges.
    all: RangeSet<usize>,
}

#[derive(Debug, Default)]
pub struct OutputState {
    /// Output ranges which are allocated but not initialized.
    uninit: RangeSet<usize>,
    /// Output ranges which are preprocessed but not executed.
    preprocessed: RangeSet<usize>,
    /// Output ranges which are executed.
    complete: RangeSet<usize>,
    /// All output ranges.
    all: RangeSet<usize>,
}

#[derive(Debug, Default)]
pub struct DecodeState {
    /// Ranges which have key bits sent.
    key_bits: RangeSet<usize>,
    /// Ranges which have already been decoded.
    complete: RangeSet<usize>,
    /// Ranges which have been pushed. This makes sure we don't get duplicates
    /// in different states.
    all: RangeSet<usize>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlushState {
    /// Ranges for which the generator is to send MACs.
    macs: RangeSet<usize>,
    /// Ranges for which the generator is to send MACs using oblivious
    /// transfer.
    ot: RangeSet<usize>,
    /// Ranges for which the generator is to send key bits for decoding.
    key_bits: RangeSet<usize>,
    /// Ranges for which the evaluator is to prove MACs for decoding.
    decode: RangeSet<usize>,
}

impl FlushState {
    /// Returns `true` if the flush state is empty.
    pub fn is_empty(&self) -> bool {
        self.macs.is_empty()
            && self.ot.is_empty()
            && self.key_bits.is_empty()
            && self.decode.is_empty()
    }

    /// Clears the flush state.
    pub fn clear(&mut self) {
        std::mem::take(self);
    }
}

/// Flush message sent by the generator.
#[derive(Debug, Serialize, Deserialize)]
#[serde(try_from = "validation::GeneratorFlushUnchecked")]
pub struct GeneratorFlush {
    /// Flush index.
    idx: FlushState,
    /// MACs sent directly to the evaluator.
    macs: Vec<Mac>,
    /// Key bits for decoding.
    key_bits: BitVec,
}

/// Flush message sent by the evaluator.
#[derive(Debug, Serialize, Deserialize)]
#[serde(try_from = "validation::EvaluatorFlushUnchecked")]
pub struct EvaluatorFlush {
    /// Flush index.
    idx: FlushState,
    /// Proof of MACs for decoding.
    mac_proof: Option<MacProof>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MacProof {
    bits: BitVec,
    proof: Hash,
}

mod validation {
    use super::*;

    #[derive(Debug, Deserialize)]
    pub(super) struct GeneratorFlushUnchecked {
        pub idx: FlushState,
        pub macs: Vec<Mac>,
        pub key_bits: BitVec,
    }

    impl TryFrom<GeneratorFlushUnchecked> for GeneratorFlush {
        type Error = String;

        fn try_from(value: GeneratorFlushUnchecked) -> Result<Self, Self::Error> {
            let GeneratorFlushUnchecked {
                idx,
                macs,
                key_bits,
            } = value;

            if idx.macs.len().saturating_sub(idx.ot.len()) != macs.len() {
                return Err("generator sent flush with invalid number of MACs".to_string());
            }

            if idx.key_bits.len() != key_bits.len() {
                return Err("generator sent flush with invalid number of key bits".to_string());
            }

            Ok(GeneratorFlush {
                idx,
                macs,
                key_bits,
            })
        }
    }

    #[derive(Debug, Deserialize)]
    pub(super) struct EvaluatorFlushUnchecked {
        pub idx: FlushState,
        pub macs: Option<MacProof>,
    }

    impl TryFrom<EvaluatorFlushUnchecked> for EvaluatorFlush {
        type Error = String;

        fn try_from(value: EvaluatorFlushUnchecked) -> Result<Self, Self::Error> {
            let EvaluatorFlushUnchecked { idx, macs } = value;

            if idx.decode.len() != macs.as_ref().map_or(0, |m| m.bits.len()) {
                return Err("evaluator sent flush with invalid number of MACs".to_string());
            }

            Ok(EvaluatorFlush {
                idx,
                mac_proof: macs,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use mpz_memory_core::{
        binary::U8,
        correlated::{Delta, Key},
        Array, MemoryExt, ViewExt,
    };
    use mpz_ot_core::{ideal::cot::IdealCOT, COTReceiverOutput};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    #[test]
    fn test_store_decode() {
        let mut cot = IdealCOT::default();
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        cot.set_delta(delta.into_inner());

        let mut gen = GeneratorStore::new(rng.gen(), delta);
        let mut ev = EvaluatorStore::default();

        let val_a = [0u8; 16];
        let val_b = [42u8; 16];
        let val_c = [69u8; 16];

        let ref_a_gen: Array<U8, 16> = gen.alloc().unwrap();
        gen.mark_public(ref_a_gen).unwrap();
        let ref_b_gen: Array<U8, 16> = gen.alloc().unwrap();
        gen.mark_private(ref_b_gen).unwrap();
        let ref_c_gen: Array<U8, 16> = gen.alloc().unwrap();
        gen.mark_blind(ref_c_gen).unwrap();

        let ref_a_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_public(ref_a_ev).unwrap();
        let ref_b_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_blind(ref_b_ev).unwrap();
        let ref_c_ev: Array<U8, 16> = ev.alloc().unwrap();
        ev.mark_private(ref_c_ev).unwrap();

        gen.assign(ref_a_gen, val_a).unwrap();
        gen.assign(ref_b_gen, val_b).unwrap();

        ev.assign(ref_a_ev, val_a).unwrap();
        ev.assign(ref_c_ev, val_c).unwrap();

        gen.commit(ref_a_gen).unwrap();
        gen.commit(ref_b_gen).unwrap();
        gen.commit(ref_c_gen).unwrap();

        ev.commit(ref_a_ev).unwrap();
        ev.commit(ref_b_ev).unwrap();
        ev.commit(ref_c_ev).unwrap();

        assert!(gen.wants_flush());
        assert!(ev.wants_flush());

        let (gen_receive, gen_flush, keys) = gen.flush().unwrap();
        let (ev_receive, ev_flush, choices) = ev.flush().unwrap();

        assert_eq!(keys.len(), choices.len());

        let (_, COTReceiverOutput { msgs: macs, .. }) =
            cot.correlated(Key::as_blocks(&keys).to_vec(), choices);

        gen_receive.receive(ev_flush).unwrap();
        ev_receive
            .receive(gen_flush, Mac::from_blocks(macs))
            .unwrap();

        let mut fut_a_gen = gen.decode(ref_a_gen).unwrap();
        let mut fut_b_gen = gen.decode(ref_b_gen).unwrap();
        let mut fut_c_gen = gen.decode(ref_c_gen).unwrap();

        let mut fut_a_ev = ev.decode(ref_a_ev).unwrap();
        let mut fut_b_ev = ev.decode(ref_b_ev).unwrap();
        let mut fut_c_ev = ev.decode(ref_c_ev).unwrap();

        assert!(gen.wants_flush());
        assert!(ev.wants_flush());

        let (gen_receive, gen_flush, keys) = gen.flush().unwrap();
        assert!(keys.is_empty());
        let (ev_receive, ev_flush, choices) = ev.flush().unwrap();
        assert!(choices.is_empty());

        gen_receive.receive(ev_flush).unwrap();
        ev_receive.receive(gen_flush, Vec::default()).unwrap();

        let (val_a_gen, val_b_gen, val_c_gen) = (
            fut_a_gen.try_recv().unwrap().unwrap(),
            fut_b_gen.try_recv().unwrap().unwrap(),
            fut_c_gen.try_recv().unwrap().unwrap(),
        );

        let (val_a_ev, val_b_ev, val_c_ev) = (
            fut_a_ev.try_recv().unwrap().unwrap(),
            fut_b_ev.try_recv().unwrap().unwrap(),
            fut_c_ev.try_recv().unwrap().unwrap(),
        );

        assert_eq!(val_a_gen, val_a_ev);
        assert_eq!(val_b_gen, val_b_ev);
        assert_eq!(val_c_gen, val_c_ev);
        assert_eq!(val_a_gen, val_a);
        assert_eq!(val_b_gen, val_b);
        assert_eq!(val_c_gen, val_c);
    }

    // #[test]
    // fn test_store_gen_wants_assign_public() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut
    // rng));

    //     let a = gen.alloc(128);
    //     gen.set_public(a).unwrap();

    //     gen.assign(a, &BitVec::from_iter((0..128).map(|_|
    // rng.gen::<bool>())))         .unwrap();

    //     assert!(gen.wants_assign());
    // }

    // #[test]
    // fn test_store_gen_wants_assign_private() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut
    // rng));

    //     let a = gen.alloc(128);
    //     gen.set_private(a).unwrap();

    //     gen.assign(a, &BitVec::from_iter((0..128).map(|_|
    // rng.gen::<bool>())))         .unwrap();

    //     assert!(gen.wants_assign());
    // }

    // #[test]
    // fn test_store_gen_wants_assign_blind() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut
    // rng));

    //     let a = gen.alloc(128);
    //     gen.set_blind(a).unwrap();

    //     assert!(gen.wants_assign());
    // }

    // #[test]
    // fn test_store_gen_does_not_want_assign() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let gen = GeneratorStore::new(rng.gen(), Delta::random(&mut rng));

    //     assert!(!gen.wants_assign());
    // }

    // #[test]
    // fn test_store_ev_wants_assign_public() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut ev = EvaluatorStore::default();

    //     let a = ev.alloc(128);
    //     ev.set_public(a).unwrap();

    //     ev.assign(a, &BitVec::from_iter((0..128).map(|_| rng.gen::<bool>())))
    //         .unwrap();

    //     assert!(ev.wants_assign());
    // }

    // #[test]
    // fn test_store_ev_wants_assign_private() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut ev = EvaluatorStore::default();

    //     let a = ev.alloc(128);
    //     ev.set_private(a).unwrap();

    //     ev.assign(a, &BitVec::from_iter((0..128).map(|_| rng.gen::<bool>())))
    //         .unwrap();

    //     assert!(ev.wants_assign());
    // }

    // #[test]
    // fn test_store_ev_wants_assign_blind() {
    //     let mut ev = EvaluatorStore::default();

    //     let a = ev.alloc(128);
    //     ev.set_blind(a).unwrap();

    //     assert!(ev.wants_assign());
    // }

    // #[test]
    // fn test_store_ev_does_not_want_assign() {
    //     let ev = EvaluatorStore::default();

    //     assert!(!ev.wants_assign());
    // }

    // #[test]
    // fn test_store_gen_wants_send_key_bits() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut
    // rng));

    //     let a = gen.alloc(128);

    //     _ = gen.decode(a).unwrap();

    //     assert!(gen.wants_send_key_bits());
    // }

    // #[test]
    // fn test_store_gen_does_not_want_send_key_bits_uninit() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut
    // rng));

    //     let a = gen.alloc_output(128);

    //     _ = gen.decode(a).unwrap();

    //     assert!(!gen.wants_send_key_bits());
    // }

    // #[test]
    // fn test_store_ev_wants_key_bits() {
    //     let mut ev = EvaluatorStore::default();

    //     let a = ev.alloc(128);

    //     ev.try_set_macs(a, &[Mac::default(); 128]).unwrap();

    //     _ = ev.decode(a).unwrap();

    //     assert!(ev.wants_key_bits());
    // }

    // #[test]
    // fn test_store_ev_does_not_want_key_bits_uninit() {
    //     let mut ev = EvaluatorStore::default();

    //     let a = ev.alloc(128);

    //     _ = ev.decode(a).unwrap();

    //     assert!(!ev.wants_key_bits());
    // }

    // #[test]
    // fn test_store_gen_wants_decode() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut
    // rng));

    //     let a = gen.alloc(128);
    //     _ = gen.decode(a).unwrap();

    //     assert!(gen.wants_verify_data());
    // }

    // #[test]
    // fn test_store_gen_does_not_want_decode_uninit() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut
    // rng));

    //     _ = gen.alloc(128);

    //     assert!(!gen.wants_verify_data());
    // }

    // #[test]
    // fn test_store_ev_wants_decode() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut ev = EvaluatorStore::default();
    //     let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut
    // rng));

    //     let a = gen.alloc(128);
    //     _ = gen.decode(a).unwrap();
    //     let payload = gen.send_key_bits().unwrap();

    //     let a = ev.alloc(128);
    //     ev.try_set_macs(a, &[Mac::default(); 128]).unwrap();
    //     ev.receive_key_bits(payload).unwrap();
    //     _ = ev.decode(a).unwrap();

    //     assert!(ev.wants_decode());
    // }

    // #[test]
    // fn test_store_ev_does_not_want_decode_uninit() {
    //     let mut ev = EvaluatorStore::default();

    //     _ = ev.alloc(128);

    //     assert!(!ev.wants_decode());
    // }
}
