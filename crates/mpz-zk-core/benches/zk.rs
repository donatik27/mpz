use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use mpz_circuits::circuits::AES128;
use mpz_core::Block;
use mpz_memory_core::correlated::Delta;
use mpz_ot_core::{ideal::cot::IdealCOT, test::assert_cot, RCOTReceiverOutput, RCOTSenderOutput};
use mpz_zk_core::{Prover, Verifier};
use rand::{rngs::StdRng, Rng, SeedableRng};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("zk-core");

    group.throughput(Throughput::Bytes(16));
    group.bench_function("aes128", |b| {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);
        let mut cot = IdealCOT::new(rng.gen(), delta.into_inner());

        let (
            RCOTSenderOutput { msgs: keys, .. },
            RCOTReceiverOutput {
                choices,
                msgs: macs,
                ..
            },
        ) = cot.random_correlated(AES128.input_len() + AES128.and_count());

        let input_keys = &keys[..AES128.input_len()];
        let gate_keys = &keys[AES128.input_len()..];
        let input_macs = &macs[..AES128.input_len()];
        let gate_masks = &choices[AES128.input_len()..];
        let gate_macs = &macs[AES128.input_len()..];

        let mut prover = Prover::default();
        let mut verifier = Verifier::new(delta);

        b.iter(|| {
            let mut prover_iter = prover
                .execute(&AES128, input_macs, gate_masks, gate_macs)
                .unwrap();
            let mut verifier_consumer = verifier.execute(&AES128, &input_keys, &gate_keys).unwrap();

            for adjust in prover_iter.by_ref() {
                verifier_consumer.next(adjust);
            }

            let output_macs = prover_iter.finish().unwrap();
            let output_keys = verifier_consumer.finish().unwrap();

            let (u, v) = prover.check(Block::ZERO, Block::ZERO);
            verifier.check(Block::ZERO).verify(u, v).unwrap();

            black_box((output_macs, output_keys))
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
