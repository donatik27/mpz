//! Ideal Correlated Oblivious Transfer functionality.

use mpz_core::{prg::Prg, Block};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    rcot::{RCOTReceiverOutput, RCOTSenderOutput},
    COTReceiverOutput, COTSenderOutput, TransferId,
};

/// The ideal COT functionality.
#[derive(Debug)]
pub struct IdealCOT {
    delta: Block,
    sender_transfer_id: TransferId,
    receiver_transfer_id: TransferId,
    count_sender: usize,
    count_receiver: usize,
    prg: Prg,
    keys: Vec<Block>,
    msgs: Vec<Block>,
    choices: Vec<bool>,
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
            sender_transfer_id: TransferId::default(),
            receiver_transfer_id: TransferId::default(),
            count_sender: 0,
            count_receiver: 0,
            prg: Prg::from_seed(seed),
            keys: Vec::new(),
            msgs: Vec::new(),
            choices: Vec::new(),
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

    /// Preprocesses `count` random COTs.
    fn preprocess(&mut self, count: usize) {
        self.keys
            .resize_with(self.keys.len() + count, || self.prg.gen());
        self.msgs.resize(self.msgs.len() + count, Block::ZERO);
        self.choices
            .resize_with(self.choices.len() + count, || self.prg.gen());

        let start = self.msgs.len() - count;
        self.msgs[start..]
            .iter_mut()
            .zip(&self.keys[self.keys.len() - count..])
            .zip(&self.choices[self.choices.len() - count..])
            .for_each(|((msg, key), choice)| *msg = if *choice { *key ^ self.delta } else { *key });
    }

    /// Returns the number of preprocessed COTs available for the sender.
    fn available_sender(&self) -> usize {
        self.keys.len() - self.count_sender
    }

    /// Returns the number of preprocessed COTs available for the receiver.
    fn available_receiver(&self) -> usize {
        self.choices.len() - self.count_receiver
    }

    /// Sends preprocessed random correlated oblivious transfers.
    pub fn send_random_correlated(&mut self, count: usize) -> RCOTSenderOutput<Block> {
        if count > self.available_sender() {
            self.preprocess(count - self.available_sender());
        }

        let keys = self.keys[self.count_sender..self.count_sender + count].to_vec();

        let id = self.sender_transfer_id.next();
        self.count_sender += count;

        RCOTSenderOutput { id, keys }
    }

    /// Receives preprocessed random correlated oblivious transfers.
    ///
    /// # Panics
    ///
    /// Panics if `count` is greater than the number of preprocessed OTs.
    pub fn receive_random_correlated(&mut self, count: usize) -> RCOTReceiverOutput<bool, Block> {
        if count > self.available_receiver() {
            self.preprocess(count - self.available_receiver());
        }

        let choices = self.choices[self.count_receiver..self.count_receiver + count].to_vec();
        let msgs = self.msgs[self.count_receiver..self.count_receiver + count].to_vec();

        let id = self.receiver_transfer_id.next();
        self.count_receiver += count;

        RCOTReceiverOutput { id, choices, msgs }
    }

    /// Executes random correlated oblivious transfers.
    ///
    /// The functionality deals random choices to the receiver, along with the
    /// corresponding messages.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of COTs to execute.
    pub fn random_correlated(
        &mut self,
        count: usize,
    ) -> (RCOTSenderOutput<Block>, RCOTReceiverOutput<bool, Block>) {
        (
            self.send_random_correlated(count),
            self.receive_random_correlated(count),
        )
    }

    /// Executes correlated oblivious transfers with choices provided by the
    /// receiver.
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

        (
            COTSenderOutput {
                id: self.sender_transfer_id.next(),
                msgs,
            },
            COTReceiverOutput {
                id: self.receiver_transfer_id.next(),
                msgs: received,
            },
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
            RCOTSenderOutput { keys: msgs, .. },
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
