mod prover;
mod verifier;

pub use prover::{ProverStore, ProverStoreError};
pub use verifier::{VerifierStore, VerifierStoreError};

use blake3::Hash;
use mpz_core::bitvec::BitVec;
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
    /// Output ranges which are executed.
    complete: RangeSet<usize>,
    /// All output ranges.
    all: RangeSet<usize>,
}

#[derive(Debug, Default)]
pub struct DecodeState {
    /// Ranges which have already been decoded.
    complete: RangeSet<usize>,
    /// All ranges which are to be decoded.
    all: RangeSet<usize>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FlushState {
    /// Ranges which the Prover is to commit.
    commit: RangeSet<usize>,
    /// Ranges which the Verifier is to prove.
    prove: RangeSet<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProverFlush {
    state: FlushState,
    adjust: BitVec,
    mac_bits: BitVec,
    proof: Hash,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifierFlush {
    state: FlushState,
}

#[cfg(test)]
mod tests {
    use mpz_core::bitvec::BitVec;
    use mpz_memory_core::correlated::{Delta, Key};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    #[test]
    fn test_store() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let mut verifier = VerifierStore::new(delta);
        let mut prover = ProverStore::default();

        let val_a = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
        let val_b = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));

        let keys_a = (0..128).map(|_| rng.gen()).collect::<Vec<Key>>();
        let masks_a = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
        let macs_a = keys_a
            .iter()
            .zip(&masks_a)
            .map(|(key, bit)| key.auth(*bit, &delta))
            .collect::<Vec<_>>();

        let ref_a_verifier = verifier.alloc(128);
        let ref_b_verifier = verifier.alloc(128);

        let ref_a_prover = prover.alloc(128);
        let ref_b_prover = prover.alloc(128);

        verifier.assign_blind(ref_a_verifier, &keys_a).unwrap();
        verifier.assign_public(ref_b_verifier, &val_b).unwrap();

        prover
            .assign_private(ref_a_prover, &val_a, &masks_a, &macs_a)
            .unwrap();
        prover.assign_public(ref_b_prover, &val_b).unwrap();

        let payload = prover.execute_assign().unwrap();
        verifier.execute_assign(payload).unwrap();

        let mut fut_a_verifier = verifier.decode(ref_a_verifier).unwrap();
        let mut fut_b_verifier = verifier.decode(ref_b_verifier).unwrap();

        let _ = prover.decode(ref_a_prover).unwrap();
        let _ = prover.decode(ref_b_prover).unwrap();

        let payload = prover.execute_decode().unwrap();
        verifier.verify_data(payload).unwrap();
        verifier.execute_decode().unwrap();

        let (val_a_verifier, val_b_verifier) = (
            fut_a_verifier.try_recv().unwrap().unwrap(),
            fut_b_verifier.try_recv().unwrap().unwrap(),
        );

        assert_eq!(val_a_verifier, val_a);
        assert_eq!(val_b_verifier, val_b);
    }

    // #[test]
    // fn test_store_verifier_wants_assign_public() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut verifier = VerifierStore::new(Delta::random(&mut rng));

    //     let a = verifier.alloc(128);

    //     verifier
    //         .assign_public(a, &BitVec::from_iter((0..128).map(|_|
    // rng.gen::<bool>())))         .unwrap();

    //     assert!(verifier.wants_assign());
    // }

    // #[test]
    // fn test_store_verifier_wants_assign_blind() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut verifier = VerifierStore::new(Delta::random(&mut rng));

    //     let a = verifier.alloc(128);

    //     verifier.assign_blind(a).unwrap();

    //     assert!(verifier.wants_assign());
    // }

    // #[test]
    // fn test_store_verifier_does_not_want_assign() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let verifier = VerifierStore::new(Delta::random(&mut rng));

    //     assert!(!verifier.wants_assign());
    // }

    // #[test]
    // fn test_store_prover_wants_assign_public() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut prover = ProverStore::default();

    //     let a = prover.alloc(128);

    //     prover
    //         .assign_public(a, &BitVec::from_iter((0..128).map(|_|
    // rng.gen::<bool>())))         .unwrap();

    //     assert!(prover.wants_assign());
    // }

    // #[test]
    // fn test_store_prover_wants_assign_private() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut prover = ProverStore::default();

    //     let a = prover.alloc(128);

    //     prover
    //         .assign_private(a, &BitVec::from_iter((0..128).map(|_|
    // rng.gen::<bool>())))         .unwrap();

    //     assert!(prover.wants_assign());
    // }

    // #[test]
    // fn test_store_prover_does_not_want_assign() {
    //     let prover = ProverStore::default();

    //     assert!(!prover.wants_assign());
    // }

    // #[test]
    // fn test_store_verifier_wants_decode() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut verifier = VerifierStore::new(Delta::random(&mut rng));

    //     let a = verifier.alloc(128);
    //     _ = verifier.decode(a).unwrap();

    //     assert!(verifier.wants_verify_data());
    // }

    // #[test]
    // fn test_store_verifier_does_not_want_decode_uninit() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut verifier = VerifierStore::new(Delta::random(&mut rng));

    //     _ = verifier.alloc(128);

    //     assert!(!verifier.wants_verify_data());
    // }

    // #[test]
    // fn test_store_prover_wants_decode() {
    //     let mut rng = StdRng::seed_from_u64(0);
    //     let mut prover = ProverStore::default();
    //     let mut verifier = VerifierStore::new(Delta::random(&mut rng));

    //     let a = verifier.alloc(128);
    //     _ = verifier.decode(a).unwrap();
    //     let payload = verifier.send_key_bits().unwrap();

    //     let a = prover.alloc(128);
    //     prover.set_macs(&[a], &[Block::default(); 128]).unwrap();
    //     prover.receive_key_bits(payload).unwrap();
    //     _ = prover.decode(a).unwrap();

    //     assert!(prover.wants_decode());
    // }

    // #[test]
    // fn test_store_prover_does_not_want_decode_uninit() {
    //     let mut prover = ProverStore::default();

    //     _ = prover.alloc(128);

    //     assert!(!prover.wants_decode());
    // }
}
