mod evaluator;
mod generator;

use blake3::Hash;
pub use evaluator::{EvaluatorStore, EvaluatorStoreError, ReceiveAssign};
pub use generator::{GeneratorStore, GeneratorStoreError};

use mpz_core::{bitvec::BitVec, Block};
use mpz_memory_core::correlated::Mac;
use serde::{Deserialize, Serialize};
use utils::range::RangeSet;

#[derive(Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct AssignPayload {
    idx_direct: RangeSet<usize>,
    idx_oblivious: RangeSet<usize>,
    macs: Vec<Mac>,
}

#[derive(Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct DecodePayload {
    idx: RangeSet<usize>,
    key_bits: BitVec,
}

#[derive(Serialize, Deserialize)]
#[serde(try_from = "validation::MacPayloadUnchecked")]
#[allow(missing_docs)]
pub struct MacPayload {
    idx: RangeSet<usize>,
    bits: BitVec,
    proof: Hash,
}

mod validation {
    use super::*;

    #[derive(Serialize, Deserialize)]
    pub(super) struct MacPayloadUnchecked {
        idx: RangeSet<usize>,
        bits: BitVec,
        proof: Hash,
    }

    impl TryFrom<MacPayloadUnchecked> for MacPayload {
        type Error = String;

        fn try_from(value: MacPayloadUnchecked) -> Result<Self, Self::Error> {
            let MacPayloadUnchecked { idx, bits, proof } = value;

            if idx.len() != bits.len() {
                return Err(format!(
                    "index and bits length mismatch: {} != {}",
                    idx.len(),
                    bits.len()
                ));
            }

            Ok(MacPayload { idx, bits, proof })
        }
    }
}

#[cfg(test)]
mod tests {
    use mpz_core::bitvec::BitVec;
    use mpz_memory_core::correlated::{Delta, Key};
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

        let val_a = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
        let val_b = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
        let val_c = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));

        let ref_a_gen = gen.alloc(128);
        let ref_b_gen = gen.alloc(128);
        let ref_c_gen = gen.alloc(128);

        let ref_a_ev = ev.alloc(128);
        let ref_b_ev = ev.alloc(128);
        let ref_c_ev = ev.alloc(128);

        gen.assign_public(ref_a_gen, &val_a).unwrap();
        gen.assign_private(ref_b_gen, &val_b).unwrap();
        gen.assign_blind(ref_c_gen).unwrap();

        ev.assign_public(ref_a_ev, &val_a).unwrap();
        ev.assign_blind(ref_b_ev).unwrap();
        ev.assign_private(ref_c_ev, &val_c).unwrap();

        let (payload, keys) = gen.execute_assign().unwrap();
        let (receive, choices) = ev.execute_assign().unwrap();

        let (_, COTReceiverOutput { msgs: macs, .. }) =
            cot.correlated(Key::as_blocks(&keys).to_vec(), choices);

        receive.receive(payload, Mac::from_blocks(macs)).unwrap();

        let mut fut_a_gen = gen.decode(ref_a_gen).unwrap();
        let mut fut_b_gen = gen.decode(ref_b_gen).unwrap();
        let mut fut_c_gen = gen.decode(ref_c_gen).unwrap();

        let mut fut_a_ev = ev.decode(ref_a_ev).unwrap();
        let mut fut_b_ev = ev.decode(ref_b_ev).unwrap();
        let mut fut_c_ev = ev.decode(ref_c_ev).unwrap();

        let payload = gen.send_key_bits().unwrap();
        ev.receive_key_bits(payload).unwrap();
        ev.decode_macs();
        let payload = ev.send_macs().unwrap();
        gen.verify_macs(payload).unwrap();

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

    #[test]
    fn test_store_gen_wants_assign_public() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut rng));

        let a = gen.alloc(128);

        gen.assign_public(a, &BitVec::from_iter((0..128).map(|_| rng.gen::<bool>())))
            .unwrap();

        assert!(gen.wants_assign());
    }

    #[test]
    fn test_store_gen_wants_assign_private() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut rng));

        let a = gen.alloc(128);

        gen.assign_private(a, &BitVec::from_iter((0..128).map(|_| rng.gen::<bool>())))
            .unwrap();

        assert!(gen.wants_assign());
    }

    #[test]
    fn test_store_gen_wants_assign_blind() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut rng));

        let a = gen.alloc(128);

        gen.assign_blind(a).unwrap();

        assert!(gen.wants_assign());
    }

    #[test]
    fn test_store_gen_does_not_want_assign() {
        let mut rng = StdRng::seed_from_u64(0);
        let gen = GeneratorStore::new(rng.gen(), Delta::random(&mut rng));

        assert!(!gen.wants_assign());
    }

    #[test]
    fn test_store_ev_wants_assign_public() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut ev = EvaluatorStore::default();

        let a = ev.alloc(128);

        ev.assign_public(a, &BitVec::from_iter((0..128).map(|_| rng.gen::<bool>())))
            .unwrap();

        assert!(ev.wants_assign());
    }

    #[test]
    fn test_store_ev_wants_assign_private() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut ev = EvaluatorStore::default();

        let a = ev.alloc(128);

        ev.assign_private(a, &BitVec::from_iter((0..128).map(|_| rng.gen::<bool>())))
            .unwrap();

        assert!(ev.wants_assign());
    }

    #[test]
    fn test_store_ev_wants_assign_blind() {
        let mut ev = EvaluatorStore::default();

        let a = ev.alloc(128);

        ev.assign_blind(a).unwrap();

        assert!(ev.wants_assign());
    }

    #[test]
    fn test_store_ev_does_not_want_assign() {
        let ev = EvaluatorStore::default();

        assert!(!ev.wants_assign());
    }

    #[test]
    fn test_store_gen_wants_send_key_bits() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut rng));

        let a = gen.alloc(128);

        _ = gen.decode(a).unwrap();

        assert!(gen.wants_send_key_bits());
    }

    #[test]
    fn test_store_gen_does_not_want_send_key_bits_uninit() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut rng));

        let a = gen.alloc_output(128);

        _ = gen.decode(a).unwrap();

        assert!(!gen.wants_send_key_bits());
    }

    #[test]
    fn test_store_ev_wants_key_bits() {
        let mut ev = EvaluatorStore::default();

        let a = ev.alloc(128);

        ev.try_set_macs(a, &[Mac::default(); 128]).unwrap();

        _ = ev.decode(a).unwrap();

        assert!(ev.wants_key_bits());
    }

    #[test]
    fn test_store_ev_does_not_want_key_bits_uninit() {
        let mut ev = EvaluatorStore::default();

        let a = ev.alloc(128);

        _ = ev.decode(a).unwrap();

        assert!(!ev.wants_key_bits());
    }

    #[test]
    fn test_store_gen_wants_decode() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut rng));

        let a = gen.alloc(128);
        _ = gen.decode(a).unwrap();

        assert!(gen.wants_verify_data());
    }

    #[test]
    fn test_store_gen_does_not_want_decode_uninit() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut rng));

        _ = gen.alloc(128);

        assert!(!gen.wants_verify_data());
    }

    #[test]
    fn test_store_ev_wants_decode() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut ev = EvaluatorStore::default();
        let mut gen = GeneratorStore::new(rng.gen(), Delta::random(&mut rng));

        let a = gen.alloc(128);
        _ = gen.decode(a).unwrap();
        let payload = gen.send_key_bits().unwrap();

        let a = ev.alloc(128);
        ev.try_set_macs(a, &[Mac::default(); 128]).unwrap();
        ev.receive_key_bits(payload).unwrap();
        _ = ev.decode(a).unwrap();

        assert!(ev.wants_decode());
    }

    #[test]
    fn test_store_ev_does_not_want_decode_uninit() {
        let mut ev = EvaluatorStore::default();

        _ = ev.alloc(128);

        assert!(!ev.wants_decode());
    }
}
