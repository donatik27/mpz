mod evaluator;
mod generator;

pub use evaluator::Evaluator;
pub use generator::Generator;

#[cfg(test)]
mod tests {
    use mpz_circuits::circuits::AES128;
    use mpz_common::executor::test_st_executor;
    use mpz_core::bitvec::BitVec;
    use mpz_memory_core::correlated::Delta;
    use mpz_ot::ideal::cot::ideal_cot_with_delta;
    use mpz_vm::{Alloc, AssignBlind, AssignPrivate, Callable, Decode, Preprocess, Synchronize};
    use mpz_vm_core::Call;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    #[tokio::test]
    async fn test_semihonest() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (cot_send, cot_recv) = ideal_cot_with_delta(delta.into_inner());

        let key = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
        let msg = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));

        let mut gen = Generator::new(cot_send, [0u8; 16], delta);
        let mut ev = Evaluator::new(cot_recv);

        let (gen_out, ev_out) = futures::join!(
            async {
                let key_ref = gen.alloc_raw(128).unwrap();
                let msg_ref = gen.alloc_raw(128).unwrap();
                let circ = AES128.clone();

                let ciphertext_ref = gen
                    .call_raw(Call::new(circ, vec![key_ref, msg_ref]).unwrap())
                    .unwrap();

                let ciphertext = gen.decode_raw(ciphertext_ref).unwrap();

                gen.assign_private_raw(key_ref, key).unwrap();
                gen.assign_blind_raw(msg_ref).unwrap();
                gen.sync(&mut ctx_a).await.unwrap();

                ciphertext.await.unwrap()
            },
            async {
                let key_ref = ev.alloc_raw(128).unwrap();
                let msg_ref = ev.alloc_raw(128).unwrap();
                let circ = AES128.clone();

                let ciphertext_ref = ev
                    .call_raw(Call::new(circ, vec![key_ref, msg_ref]).unwrap())
                    .unwrap();

                let ciphertext = ev.decode_raw(ciphertext_ref).unwrap();

                ev.assign_blind_raw(key_ref).unwrap();
                ev.assign_private_raw(msg_ref, msg).unwrap();
                ev.sync(&mut ctx_b).await.unwrap();

                ciphertext.await.unwrap()
            }
        );

        assert_eq!(gen_out, ev_out);
    }

    #[tokio::test]
    async fn test_semihonest_nothing_to_do() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (cot_send, cot_recv) = ideal_cot_with_delta(delta.into_inner());

        let mut gen = Generator::new(cot_send, [0u8; 16], delta);
        let mut ev = Evaluator::new(cot_recv);

        futures::try_join!(gen.sync(&mut ctx_a), ev.sync(&mut ctx_b)).unwrap();
    }

    #[tokio::test]
    async fn test_semihonest_preprocess() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (cot_send, cot_recv) = ideal_cot_with_delta(delta.into_inner());

        let key = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
        let msg = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));

        let mut gen = Generator::new(cot_send, [0u8; 16], delta);
        let mut ev = Evaluator::new(cot_recv);

        let (gen_out, ev_out) = futures::join!(
            async {
                let key_ref = gen.alloc_raw(128).unwrap();
                let msg_ref = gen.alloc_raw(128).unwrap();
                let circ = AES128.clone();

                let ciphertext_ref = gen
                    .call_raw(Call::new(circ, vec![key_ref, msg_ref]).unwrap())
                    .unwrap();

                let ciphertext = gen.decode_raw(ciphertext_ref).unwrap();

                gen.preprocess(&mut ctx_a).await.unwrap();

                gen.assign_private_raw(key_ref, key).unwrap();
                gen.assign_blind_raw(msg_ref).unwrap();

                gen.sync(&mut ctx_a).await.unwrap();

                ciphertext.await.unwrap()
            },
            async {
                let key_ref = ev.alloc_raw(128).unwrap();
                let msg_ref = ev.alloc_raw(128).unwrap();
                let circ = AES128.clone();

                let ciphertext_ref = ev
                    .call_raw(Call::new(circ, vec![key_ref, msg_ref]).unwrap())
                    .unwrap();

                let ciphertext = ev.decode_raw(ciphertext_ref).unwrap();

                ev.preprocess(&mut ctx_b).await.unwrap();

                ev.assign_blind_raw(key_ref).unwrap();
                ev.assign_private_raw(msg_ref, msg).unwrap();

                ev.sync(&mut ctx_b).await.unwrap();

                ciphertext.await.unwrap()
            }
        );

        assert_eq!(gen_out, ev_out);
    }
}
