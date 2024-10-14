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
    /// Ranges which are fully committed in both parties views.
    complete: RangeSet<usize>,
    /// All input ranges.
    all: RangeSet<usize>,
}

#[derive(Debug, Default)]
pub struct OutputState {
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

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlushState {
    /// Ranges which the Prover is to commit.
    commit: RangeSet<usize>,
    /// Ranges which the Verifier is to prove.
    prove: RangeSet<usize>,
}

impl FlushState {
    /// Returns `true` if the state is empty.
    pub fn is_empty(&self) -> bool {
        self.commit.is_empty() && self.prove.is_empty()
    }

    /// Clears the flush state.
    pub fn clear(&mut self) {
        self.commit.clear();
        self.prove.clear();
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProverFlush {
    state: FlushState,
    adjust: BitVec,
    mac_proof: Option<(BitVec, Hash)>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifierFlush {
    state: FlushState,
}

#[cfg(test)]
mod tests {
    use mpz_core::bitvec::BitVec;
    use mpz_memory_core::{
        binary::U8,
        correlated::{Delta, Key},
        Array, MemoryExt, ViewExt,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    #[test]
    fn test_store() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let mut verifier = VerifierStore::new(delta);
        let mut prover = ProverStore::default();

        let keys = (0..128).map(|_| rng.gen()).collect::<Vec<Key>>();
        let masks = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
        let macs = keys
            .iter()
            .zip(&masks)
            .map(|(key, bit)| key.auth(*bit, &delta))
            .collect::<Vec<_>>();

        let a_v: Array<U8, 16> = verifier.alloc().unwrap();
        let b_v: Array<U8, 16> = verifier.alloc().unwrap();

        let a_p: Array<U8, 16> = prover.alloc().unwrap();
        let b_p: Array<U8, 16> = prover.alloc().unwrap();

        verifier.mark_public(a_v).unwrap();
        verifier.mark_blind(b_v).unwrap();
        verifier.assign(a_v, [42u8; 16]).unwrap();
        verifier.commit(a_v).unwrap();
        verifier.commit(b_v).unwrap();

        prover.mark_public(a_p).unwrap();
        prover.mark_private(b_p).unwrap();
        prover.assign(a_p, [42u8; 16]).unwrap();
        prover.assign(b_p, [69u8; 16]).unwrap();
        prover.commit(a_p).unwrap();
        prover.commit(b_p).unwrap();

        let mut b_v = verifier.decode(b_v).unwrap();
        let _ = prover.decode(b_p).unwrap();

        assert!(verifier.wants_keys());
        assert!(prover.wants_macs());

        let recv_v = verifier.receive_keys().unwrap();
        let rec_p = prover.receive_macs().unwrap();

        assert_eq!(recv_v.count(), rec_p.count());

        recv_v.receive(&keys).unwrap();
        rec_p.receive(&masks, &macs).unwrap();

        assert!(verifier.wants_flush());
        assert!(prover.wants_flush());

        let (recv_v, flush_v) = verifier.flush().unwrap();
        let (recv_p, flush_p) = prover.flush().unwrap();

        recv_v.receive(flush_p).unwrap();
        recv_p.receive(flush_v).unwrap();

        let b_v = b_v.try_recv().unwrap().unwrap();

        assert_eq!(b_v, [69u8; 16]);
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
