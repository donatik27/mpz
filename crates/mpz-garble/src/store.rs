mod evaluator;
mod generator;

pub use evaluator::{EvaluatorStore, EvaluatorStoreError};
pub use generator::{GeneratorStore, GeneratorStoreError};

#[cfg(test)]
mod tests {
    use mpz_common::executor::test_st_executor;
    use mpz_core::bitvec::BitVec;
    use mpz_memory_core::correlated::Delta;
    use mpz_ot::ideal::cot::ideal_cot_with_delta;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use super::*;

    #[tokio::test]
    async fn test_store() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta: Delta = rng.gen();

        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut cot_sender, mut cot_receiver) = ideal_cot_with_delta(delta.into_inner());

        let val_a = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
        let val_b = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
        let val_c = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));

        let expected_values = (val_a.clone(), val_b.clone(), val_c.clone());

        let (gen_values, ev_values) = futures::join!(
            async {
                let mut store = GeneratorStore::new([0u8; 16], delta);

                let ref_a = store.alloc(128);
                let ref_b = store.alloc(128);
                let ref_c = store.alloc(128);

                store.assign_public(ref_a, &val_a).unwrap();
                store.assign_private(ref_b, &val_b).unwrap();
                store.assign_blind(ref_c).unwrap();

                let val_a = store.decode(ref_a).unwrap();
                let val_b = store.decode(ref_b).unwrap();
                let val_c = store.decode(ref_c).unwrap();

                store.commit(&mut ctx_a, &mut cot_sender).await.unwrap();

                futures::try_join!(val_a, val_b, val_c).unwrap()
            },
            async {
                let mut store = EvaluatorStore::default();

                let ref_a = store.alloc(128);
                let ref_b = store.alloc(128);
                let ref_c = store.alloc(128);

                store.assign_public(ref_a, &val_a).unwrap();
                store.assign_blind(ref_b).unwrap();
                store.assign_private(ref_c, &val_c).unwrap();

                let val_a = store.decode(ref_a).unwrap();
                let val_b = store.decode(ref_b).unwrap();
                let val_c = store.decode(ref_c).unwrap();

                store.commit(&mut ctx_b, &mut cot_receiver).await.unwrap();

                futures::try_join!(val_a, val_b, val_c).unwrap()
            }
        );

        assert_eq!(gen_values, expected_values);
        assert_eq!(ev_values, expected_values);
    }
}
