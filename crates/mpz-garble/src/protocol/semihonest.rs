mod evaluator;
mod generator;

pub use evaluator::Evaluator;
pub use generator::Generator;

#[cfg(test)]
mod tests {
    use mpz_circuits::circuits::AES128;
    use mpz_common::executor::test_st_executor;
    use mpz_memory_core::{binary::U8, correlated::Delta, Array};
    use mpz_ot::ideal::cot::ideal_cot_with_delta;
    use mpz_vm::prelude::*;
    use mpz_vm_core::Call;
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[tokio::test]
    async fn test_semihonest() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (cot_send, cot_recv) = ideal_cot_with_delta(delta.into_inner());

        let key = [0u8; 16];
        let msg = [42u8; 16];

        let mut gen = Generator::new(cot_send, [0u8; 16], delta);
        let mut ev = Evaluator::new(cot_recv);

        let (gen_out, ev_out) = futures::join!(
            async {
                let key_ref = gen.alloc::<Array<U8, 16>>().unwrap();
                let msg_ref = gen.alloc::<Array<U8, 16>>().unwrap();
                let circ = AES128.clone();

                gen.configure_private(key_ref).unwrap();
                gen.configure_blind(msg_ref).unwrap();

                let ciphertext_ref = gen
                    .call(Call::new(circ).arg(key_ref).arg(msg_ref).build().unwrap())
                    .unwrap();

                let ciphertext = gen.decode::<Array<U8, 16>>(ciphertext_ref).unwrap();

                gen.assign(key_ref, key).unwrap();
                gen.commit(key_ref).unwrap();
                gen.commit(msg_ref).unwrap();
                gen.sync(&mut ctx_a).await.unwrap();

                ciphertext.await.unwrap()
            },
            async {
                let key_ref = ev.alloc::<Array<U8, 16>>().unwrap();
                let msg_ref = ev.alloc::<Array<U8, 16>>().unwrap();
                let circ = AES128.clone();

                ev.configure_blind(key_ref).unwrap();
                ev.configure_private(msg_ref).unwrap();

                let ciphertext_ref = ev
                    .call(Call::new(circ).arg(key_ref).arg(msg_ref).build().unwrap())
                    .unwrap();

                let ciphertext = ev.decode::<Array<U8, 16>>(ciphertext_ref).unwrap();

                ev.assign(msg_ref, msg).unwrap();
                ev.commit(key_ref).unwrap();
                ev.commit(msg_ref).unwrap();
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

        let key = [0u8; 16];
        let msg = [42u8; 16];

        let mut gen = Generator::new(cot_send, [0u8; 16], delta);
        let mut ev = Evaluator::new(cot_recv);

        let (gen_out, ev_out) = futures::join!(
            async {
                let key_ref = gen.alloc::<Array<U8, 16>>().unwrap();
                let msg_ref = gen.alloc::<Array<U8, 16>>().unwrap();
                let circ = AES128.clone();

                gen.configure_private(key_ref).unwrap();
                gen.configure_blind(msg_ref).unwrap();

                let ciphertext_ref = gen
                    .call(Call::new(circ).arg(key_ref).arg(msg_ref).build().unwrap())
                    .unwrap();

                let ciphertext = gen.decode::<Array<U8, 16>>(ciphertext_ref).unwrap();

                gen.preprocess(&mut ctx_a).await.unwrap();

                gen.assign(key_ref, key).unwrap();

                gen.sync(&mut ctx_a).await.unwrap();

                ciphertext.await.unwrap()
            },
            async {
                let key_ref = ev.alloc::<Array<U8, 16>>().unwrap();
                let msg_ref = ev.alloc::<Array<U8, 16>>().unwrap();
                let circ = AES128.clone();

                ev.configure_blind(key_ref).unwrap();
                ev.configure_private(msg_ref).unwrap();

                let ciphertext_ref = ev
                    .call(Call::new(circ).arg(key_ref).arg(msg_ref).build().unwrap())
                    .unwrap();

                let ciphertext = ev.decode::<Array<U8, 16>>(ciphertext_ref).unwrap();

                ev.preprocess(&mut ctx_b).await.unwrap();

                ev.assign(msg_ref, msg).unwrap();

                ev.sync(&mut ctx_b).await.unwrap();

                ciphertext.await.unwrap()
            }
        );

        assert_eq!(gen_out, ev_out);
    }
}
