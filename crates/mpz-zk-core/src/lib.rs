mod prover;
pub mod store;
mod verifier;

pub use prover::{Prover, ProverError};
pub use verifier::{Verifier, VerifierError};

#[cfg(test)]
mod tests {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use mpz_circuits::circuits::AES128;
    use mpz_core::{bitvec::BitVec, Block};
    use mpz_memory_core::{
        binary::{Binary, U8},
        correlated::{Delta, Key, Mac},
        Array, FromRaw, MemoryExt, ToRaw, ViewExt,
    };
    use mpz_ot_core::{
        ideal::rcot::IdealRCOT,
        rcot::{RCOTReceiverOutput, RCOTSenderOutput},
    };
    use rand::{rngs::StdRng, SeedableRng};

    use crate::store::{ProverStore, VerifierStore};

    use super::*;

    fn expected_aes(key: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
        let cipher = aes::Aes128::new_from_slice(&key).unwrap();

        let mut msg = msg.into();
        cipher.encrypt_block(&mut msg);

        msg.into()
    }

    #[test]
    fn test_zk() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let key = [42u8; 16];
        let msg = [69u8; 16];
        let expected_ct = expected_aes(key, msg);

        let mut rcot = IdealRCOT::new(Block::ZERO, delta.into_inner());

        let mut prover_store = ProverStore::default();
        let mut verifier_store = VerifierStore::new(delta);

        let key_p: Array<U8, 16> = prover_store.alloc().unwrap();
        let msg_p: Array<U8, 16> = prover_store.alloc().unwrap();
        let ct_p = <Array<U8, 16> as FromRaw<Binary>>::from_raw(prover_store.alloc_output(128));

        let key_v: Array<U8, 16> = verifier_store.alloc().unwrap();
        let msg_v: Array<U8, 16> = verifier_store.alloc().unwrap();
        let ct_v = <Array<U8, 16> as FromRaw<Binary>>::from_raw(verifier_store.alloc_output(128));

        prover_store.mark_private(key_p).unwrap();
        prover_store.mark_public(msg_p).unwrap();

        verifier_store.mark_blind(key_v).unwrap();
        verifier_store.mark_public(msg_v).unwrap();

        prover_store.assign(key_p, key).unwrap();
        prover_store.assign(msg_p, msg).unwrap();
        prover_store.commit(key_p).unwrap();
        prover_store.commit(msg_p).unwrap();

        verifier_store.assign(msg_v, msg).unwrap();
        verifier_store.commit(key_v).unwrap();
        verifier_store.commit(msg_v).unwrap();

        let mut out_p = prover_store.decode(ct_p).unwrap();
        let mut out_v = verifier_store.decode(ct_v).unwrap();

        assert!(prover_store.wants_macs());
        assert!(verifier_store.wants_keys());

        let recv_p = prover_store.receive_macs().unwrap();
        let recv_v = verifier_store.receive_keys().unwrap();

        assert_eq!(recv_p.count(), recv_v.count());

        rcot.alloc(recv_p.count());
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput { keys, .. },
            RCOTReceiverOutput {
                choices: masks,
                msgs: macs,
                ..
            },
        ) = rcot.transfer(recv_p.count()).unwrap();

        recv_p
            .receive(&BitVec::from_iter(masks), &Mac::from_blocks(macs))
            .unwrap();
        recv_v.receive(&Key::from_blocks(keys)).unwrap();

        assert!(prover_store.wants_flush());
        assert!(verifier_store.wants_flush());

        let (recv_p, flush_p) = prover_store.flush().unwrap();
        let (recv_v, flush_v) = verifier_store.flush().unwrap();

        recv_p.receive(flush_v).unwrap();
        recv_v.receive(flush_p).unwrap();

        let mut prover = Prover::default();
        let mut verifier = Verifier::new(delta);

        let mut input_macs = Vec::new();
        input_macs.extend_from_slice(prover_store.try_get_macs(key_p.to_raw()).unwrap());
        input_macs.extend_from_slice(prover_store.try_get_macs(msg_p.to_raw()).unwrap());

        let mut input_keys = Vec::new();
        input_keys.extend_from_slice(verifier_store.try_get_keys(key_v.to_raw()).unwrap());
        input_keys.extend_from_slice(verifier_store.try_get_keys(msg_v.to_raw()).unwrap());

        rcot.alloc(AES128.and_count());
        rcot.flush().unwrap();
        let (
            RCOTSenderOutput {
                keys: gate_keys, ..
            },
            RCOTReceiverOutput {
                choices: gate_masks,
                msgs: gate_macs,
                ..
            },
        ) = rcot.transfer(AES128.and_count()).unwrap();
        let gate_keys = Key::from_blocks(gate_keys);
        let gate_macs = Mac::from_blocks(gate_macs);

        let mut prover_iter = prover
            .execute(&AES128, &input_macs, &gate_masks, &gate_macs)
            .unwrap();
        let mut verifier_consumer = verifier.execute(&AES128, &input_keys, &gate_keys).unwrap();

        for adjust in prover_iter.by_ref() {
            verifier_consumer.next(adjust);
        }

        let output_macs = prover_iter.finish().unwrap();
        let output_keys = verifier_consumer.finish().unwrap();

        prover_store
            .set_output_macs(ct_p.to_raw(), &output_macs)
            .unwrap();
        verifier_store
            .set_output_keys(ct_v.to_raw(), &output_keys)
            .unwrap();

        assert!(prover_store.wants_flush());
        assert!(verifier_store.wants_flush());

        let (recv_p, flush_p) = prover_store.flush().unwrap();
        let (recv_v, flush_v) = verifier_store.flush().unwrap();

        recv_p.receive(flush_v).unwrap();
        recv_v.receive(flush_p).unwrap();

        let out_p = out_p.try_recv().unwrap().unwrap();
        let out_v = out_v.try_recv().unwrap().unwrap();

        assert_eq!(out_p, expected_ct);
        assert_eq!(out_v, expected_ct);
    }
}
