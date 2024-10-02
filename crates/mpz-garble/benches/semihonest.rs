use criterion::{black_box, criterion_group, criterion_main, Criterion};

use mpz_circuits::circuits::AES128;
use mpz_common::executor::{test_mt_executor, test_st_executor};
use mpz_core::bitvec::BitVec;
use mpz_garble::protocol::semihonest::{Evaluator, Generator};
use mpz_memory_core::correlated::Delta;
use mpz_ot::ideal::cot::ideal_cot_with_delta;
use mpz_vm::{Alloc, AssignBlind, AssignPrivate, Callable, Decode, Synchronize};
use mpz_vm_core::Call;
use rand::{rngs::StdRng, Rng, SeedableRng};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("semihonest");

    let rt = tokio::runtime::Runtime::new().unwrap();
    group.bench_function("aes", |b| {
        b.to_async(&rt).iter(|| async {
            let mut rng = StdRng::seed_from_u64(0);
            let (mut ctx_gen, mut ctx_ev) = test_st_executor(8);

            let delta = Delta::random(&mut rng);
            let (cot_send, cot_recv) = ideal_cot_with_delta(delta.into_inner());

            let mut gen = Generator::new(cot_send, [0u8; 16], delta);
            let mut ev = Evaluator::new(cot_recv);

            let key = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
            let msg = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));

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
                    gen.sync(&mut ctx_gen).await.unwrap();

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
                    ev.sync(&mut ctx_ev).await.unwrap();

                    ciphertext.await.unwrap()
                }
            );

            black_box((gen_out, ev_out));
        })
    });

    group.bench_function("aes/256", |b| {
        b.to_async(&rt).iter(|| async {
            let mut rng = StdRng::seed_from_u64(0);
            let (mut exec_gen, mut exec_ev) = test_mt_executor(8);
            let mut ctx_gen = exec_gen.new_thread().await.unwrap();
            let mut ctx_ev = exec_ev.new_thread().await.unwrap();

            let delta = Delta::random(&mut rng);
            let (cot_send, cot_recv) = ideal_cot_with_delta(delta.into_inner());

            let mut gen = Generator::new(cot_send, [0u8; 16], delta);
            let mut ev = Evaluator::new(cot_recv);

            let key = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));
            let msg = BitVec::from_iter((0..128).map(|_| rng.gen::<bool>()));

            futures::join!(
                async {
                    let key_ref = gen.alloc_raw(128).unwrap();
                    gen.assign_private_raw(key_ref, key).unwrap();

                    for _ in 0..256 {
                        let msg_ref = gen.alloc_raw(128).unwrap();
                        let circ = AES128.clone();

                        gen.assign_blind_raw(msg_ref).unwrap();

                        let ciphertext_ref = gen
                            .call_raw(Call::new(circ, vec![key_ref, msg_ref]).unwrap())
                            .unwrap();

                        _ = gen.decode_raw(ciphertext_ref).unwrap();
                    }

                    gen.sync(&mut ctx_gen).await.unwrap();
                },
                async {
                    let key_ref = ev.alloc_raw(128).unwrap();
                    ev.assign_blind_raw(key_ref).unwrap();

                    for _ in 0..256 {
                        let msg_ref = ev.alloc_raw(128).unwrap();
                        let circ = AES128.clone();

                        ev.assign_private_raw(msg_ref, msg.clone()).unwrap();

                        let ciphertext_ref = ev
                            .call_raw(Call::new(circ, vec![key_ref, msg_ref]).unwrap())
                            .unwrap();

                        _ = ev.decode_raw(ciphertext_ref).unwrap();
                    }

                    ev.sync(&mut ctx_ev).await.unwrap();
                }
            );
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
