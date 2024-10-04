use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use mpz_circuits::circuits::AES128;
use mpz_common::executor::{test_mt_executor, test_st_executor};
use mpz_garble::protocol::semihonest::{Evaluator, Generator};
use mpz_memory_core::{binary::*, correlated::Delta, Array};
use mpz_ot::ideal::cot::ideal_cot_with_delta;
use mpz_vm::prelude::*;
use rand::{rngs::StdRng, SeedableRng};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("semihonest");
    let rt = tokio::runtime::Runtime::new().unwrap();

    group.throughput(Throughput::Bytes(16));
    group.bench_function("aes", |b| {
        b.to_async(&rt).iter(|| async {
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

                    let ciphertext_ref = gen
                        .call(Call::new(circ).arg(key_ref).arg(msg_ref).build().unwrap())
                        .unwrap();

                    let ciphertext = gen.decode::<Array<U8, 16>>(ciphertext_ref).unwrap();

                    gen.assign_private(key_ref, key).unwrap();
                    gen.assign_blind(msg_ref).unwrap();
                    gen.sync(&mut ctx_a).await.unwrap();

                    ciphertext.await.unwrap()
                },
                async {
                    let key_ref = ev.alloc::<Array<U8, 16>>().unwrap();
                    let msg_ref = ev.alloc::<Array<U8, 16>>().unwrap();
                    let circ = AES128.clone();

                    let ciphertext_ref = ev
                        .call(Call::new(circ).arg(key_ref).arg(msg_ref).build().unwrap())
                        .unwrap();

                    let ciphertext = ev.decode::<Array<U8, 16>>(ciphertext_ref).unwrap();

                    ev.assign_blind(key_ref).unwrap();
                    ev.assign_private(msg_ref, msg).unwrap();
                    ev.sync(&mut ctx_b).await.unwrap();

                    ciphertext.await.unwrap()
                }
            );

            black_box((gen_out, ev_out));
        })
    });

    group.throughput(Throughput::Bytes(16 * 256));
    group.bench_function("aes/batched", |b| {
        b.to_async(&rt).iter(|| async {
            let mut rng = StdRng::seed_from_u64(0);
            let (mut exec_gen, mut exec_ev) = test_mt_executor(8);
            let mut ctx_gen = exec_gen.new_thread().await.unwrap();
            let mut ctx_ev = exec_ev.new_thread().await.unwrap();

            let delta = Delta::random(&mut rng);
            let (cot_send, cot_recv) = ideal_cot_with_delta(delta.into_inner());

            let mut gen = Generator::new(cot_send, [0u8; 16], delta);
            let mut ev = Evaluator::new(cot_recv);

            let key = [0u8; 16];
            let msg = [42u8; 16];

            futures::join!(
                async {
                    let key_ref = gen.alloc::<Array<U8, 16>>().unwrap();
                    gen.assign_private(key_ref, key).unwrap();

                    for _ in 0..256 {
                        let msg_ref = gen.alloc::<Array<U8, 16>>().unwrap();
                        let circ = AES128.clone();

                        gen.assign_blind(msg_ref).unwrap();

                        let ciphertext_ref = gen
                            .call(Call::new(circ).arg(key_ref).arg(msg_ref).build().unwrap())
                            .unwrap();

                        _ = gen.decode::<Array<U8, 16>>(ciphertext_ref).unwrap();
                    }

                    gen.sync(&mut ctx_gen).await.unwrap();
                },
                async {
                    let key_ref = ev.alloc::<Array<U8, 16>>().unwrap();
                    ev.assign_blind(key_ref).unwrap();

                    for _ in 0..256 {
                        let msg_ref = ev.alloc::<Array<U8, 16>>().unwrap();
                        let circ = AES128.clone();

                        ev.assign_private(msg_ref, msg).unwrap();

                        let ciphertext_ref = ev
                            .call(Call::new(circ).arg(key_ref).arg(msg_ref).build().unwrap())
                            .unwrap();

                        _ = ev.decode::<Array<U8, 16>>(ciphertext_ref).unwrap();
                    }

                    ev.sync(&mut ctx_ev).await.unwrap();
                }
            );
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
