mod prover;
pub mod store;
mod verifier;

pub use prover::{Prover, ProverError};
pub use verifier::{Verifier, VerifierError};

#[cfg(test)]
mod tests {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use itybity::{FromBitIterator, ToBits};
    use mpz_circuits::circuits::AES128;
    use mpz_core::{
        bitvec::{BitSlice, BitVec},
        Block,
    };
    use mpz_memory_core::correlated::{Delta, Key, Mac};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    use crate::store::{ProverStore, VerifierStore};

    use super::*;

    fn expected_aes(input: impl IntoIterator<Item = bool>) -> BitVec {
        let mut input = input.into_iter();

        let key = <[u8; 16]>::from_lsb0_iter(input.by_ref());
        let msg = <[u8; 16]>::from_lsb0_iter(input.by_ref());

        let cipher = aes::Aes128::new_from_slice(&key).unwrap();

        let mut msg = msg.into();
        cipher.encrypt_block(&mut msg);

        BitVec::from_iter(<[u8; 16]>::from(msg).iter_lsb0())
    }

    #[test]
    fn test_zk() {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let key_count = AES128.input_len() + AES128.and_count();

        let mut keys = (0..key_count).map(|_| rng.gen()).collect::<Vec<Key>>();
        let masks = (0..key_count)
            .map(|_| rng.gen::<bool>())
            .collect::<Vec<_>>();
        let mut macs = keys
            .iter()
            .zip(&masks)
            .map(|(key, mask)| key.auth(*mask, &delta))
            .collect::<Vec<_>>();

        let input_data = BitVec::<u32>::from_iter(
            (0..AES128.input_len())
                .map(|_| rng.gen::<bool>())
                .collect::<Vec<bool>>(),
        );

        let mut adjust = BitVec::from_iter(masks[..AES128.input_len()].iter().copied());
        adjust ^= &input_data;

        keys[..AES128.input_len()]
            .iter_mut()
            .zip(adjust)
            .for_each(|(key, bit)| key.adjust(bit, &delta));
        macs[..AES128.input_len()]
            .iter_mut()
            .zip(&input_data)
            .for_each(|(mac, bit)| mac.set_pointer(*bit));

        let mut prover = Prover::default();
        let mut verifier = Verifier::new(delta);

        let mut prover_iter = prover
            .execute(
                &AES128,
                &macs[..AES128.input_len()],
                &masks[AES128.input_len()..],
                &macs[AES128.input_len()..],
            )
            .unwrap();
        let mut verifier_consumer = verifier
            .execute(
                &AES128,
                &keys[..AES128.input_len()],
                &keys[AES128.input_len()..],
            )
            .unwrap();

        for adjust in prover_iter.by_ref() {
            verifier_consumer.next(adjust);
        }

        let output_macs = prover_iter.finish().unwrap();
        let output_keys = verifier_consumer.finish().unwrap();

        let ciphertext = BitVec::<u32>::from_iter(output_macs.iter().map(Mac::pointer));
        let expected = expected_aes(input_data.iter().by_vals());

        assert_eq!(ciphertext, expected);
    }
}
