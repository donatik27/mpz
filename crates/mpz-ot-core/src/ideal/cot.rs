//! Ideal Correlated Oblivious Transfer functionality.

use mpz_core::{prg::Prg, Block};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{COTReceiverOutput, COTSenderOutput, RCOTReceiverOutput, RCOTSenderOutput, TransferId};

/// The ideal COT functionality.
#[derive(Debug)]
pub struct IdealCOT {
    delta: Block,
    transfer_id: TransferId,
    counter: usize,
    prg: Prg,
}

impl IdealCOT {
    /// Creates a new ideal OT functionality.
    ///
    /// # Arguments
    ///
    /// * `seed` - The seed for the PRG.
    /// * `delta` - The correlation.
    pub fn new(seed: Block, delta: Block) -> Self {
        IdealCOT {
            delta,
            transfer_id: TransferId::default(),
            counter: 0,
            prg: Prg::from_seed(seed),
        }
    }

    /// Returns the correlation, delta.
    pub fn delta(&self) -> Block {
        self.delta
    }

    /// Sets the correlation, delta.
    pub fn set_delta(&mut self, delta: Block) {
        self.delta = delta;
    }

    /// Returns the current transfer id.
    pub fn transfer_id(&self) -> TransferId {
        self.transfer_id
    }

    /// Returns the number of OTs executed.
    pub fn count(&self) -> usize {
        self.counter
    }

    /// Executes random correlated oblivious transfers.
    ///
    /// The functionality deals random choices to the receiver, along with the corresponding messages.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of COTs to execute.
    pub fn random_correlated(
        &mut self,
        count: usize,
    ) -> (RCOTSenderOutput<Block>, RCOTReceiverOutput<bool, Block>) {
        let mut msgs = vec![Block::ZERO; count];
        let mut choices = vec![false; count];

        self.prg.random_blocks(&mut msgs);
        self.prg.random_bools(&mut choices);

        let chosen: Vec<Block> = msgs
            .iter()
            .zip(choices.iter())
            .map(|(&q, &r)| if r { q ^ self.delta } else { q })
            .collect();

        self.counter += count;
        let id = self.transfer_id.next();

        (
            RCOTSenderOutput { id, msgs },
            RCOTReceiverOutput {
                id,
                choices,
                msgs: chosen,
            },
        )
    }

    /// Executes correlated oblivious transfers with choices provided by the receiver.
    ///
    /// # Arguments
    ///
    /// * `choices` - The choices made by the receiver.
    pub fn correlated(
        &mut self,
        msgs: Vec<Block>,
        choices: Vec<bool>,
    ) -> (COTSenderOutput<Block>, COTReceiverOutput<Block>) {
        assert_eq!(msgs.len(), choices.len());

        let mut received = msgs.clone();
        received.iter_mut().zip(choices).for_each(|(msg, choice)| {
            if choice {
                *msg ^= self.delta
            }
        });

        self.counter += msgs.len();
        let id = self.transfer_id.next();

        (
            COTSenderOutput { id, msgs },
            COTReceiverOutput { id, msgs: received },
        )
    }
}

impl Default for IdealCOT {
    fn default() -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        Self::new(rng.gen(), rng.gen())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test::assert_cot;

    #[test]
    fn test_ideal_rcot() {
        let mut ideal = IdealCOT::default();

        let (
            RCOTSenderOutput { msgs, .. },
            RCOTReceiverOutput {
                choices,
                msgs: received,
                ..
            },
        ) = ideal.random_correlated(100);

        assert_cot(ideal.delta(), &choices, &msgs, &received)
    }

    #[test]
    fn test_ideal_cot() {
        let mut ideal = IdealCOT::default();

        let mut rng = ChaCha8Rng::seed_from_u64(0);
        let msgs = Block::random_vec(&mut rng, 100);
        let mut choices = vec![false; 100];
        rng.fill(&mut choices[..]);

        let (COTSenderOutput { msgs, .. }, COTReceiverOutput { msgs: received, .. }) =
            ideal.correlated(msgs, choices.clone());

        assert_cot(ideal.delta(), &choices, &msgs, &received)
    }
}
