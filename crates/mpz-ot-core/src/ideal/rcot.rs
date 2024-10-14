//! Ideal Random Correlated Oblivious Transfer functionality.

//! Ideal Correlated Oblivious Transfer functionality.

use std::mem;

use mpz_core::{prg::Prg, Block};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    rcot::{
        RCOTReceiver, RCOTReceiverOutput, RCOTRecvFuture, RCOTRecvPending, RCOTSendFuture,
        RCOTSendPending, RCOTSender, RCOTSenderOutput,
    },
    TransferId,
};

type Error = IdealRCOTError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Default)]
struct SenderState {
    alloc: usize,
    transfer_id: TransferId,
    available: usize,
    current: usize,
    counts: Vec<usize>,
    queue: Vec<RCOTSendPending<Block>>,
}

#[derive(Debug, Default)]
struct ReceiverState {
    alloc: usize,
    transfer_id: TransferId,
    available: usize,
    current: usize,
    counts: Vec<usize>,
    queue: Vec<RCOTRecvPending<bool, Block>>,
}

/// Ideal RCOT functionality.
#[derive(Debug)]
pub struct IdealRCOT {
    delta: Block,
    prg: Prg,

    sender_state: SenderState,
    receiver_state: ReceiverState,

    keys: Vec<Block>,
    msgs: Vec<Block>,
    choices: Vec<bool>,
}

impl IdealRCOT {
    /// Creates a new ideal RCOT functionality.
    ///
    /// # Arguments
    ///
    /// * `seed` - Seed for the PRG.
    /// * `delta` - Global correlation key.
    pub fn new(seed: Block, delta: Block) -> Self {
        IdealRCOT {
            delta,
            prg: Prg::from_seed(seed),
            sender_state: SenderState::default(),
            receiver_state: ReceiverState::default(),
            keys: Vec::new(),
            msgs: Vec::new(),
            choices: Vec::new(),
        }
    }

    /// Allocates `count` random correlated OTs.
    pub fn alloc(&mut self, count: usize) {
        self.sender_state.alloc += count;
        self.receiver_state.alloc += count;
    }

    /// Transfers `count` random correlated OTs.
    pub fn transfer(
        &mut self,
        count: usize,
    ) -> Result<(RCOTSenderOutput<Block>, RCOTReceiverOutput<bool, Block>)> {
        Ok((self.try_send_rcot(count)?, self.try_recv_rcot(count)?))
    }

    /// Flushes pending operations.
    pub fn flush(&mut self) -> Result<()> {
        if self.sender_state.current != self.receiver_state.current {
            todo!()
        } else if self.sender_state.alloc != self.receiver_state.alloc {
            todo!()
        }

        let start = self.keys.len();
        let count = self.sender_state.alloc;

        self.keys
            .resize_with(self.keys.len() + count, || self.prg.gen());
        self.msgs.resize(self.msgs.len() + count, Block::ZERO);
        self.choices
            .resize_with(self.choices.len() + count, || self.prg.gen());

        self.msgs[start..]
            .iter_mut()
            .zip(&self.keys[start..])
            .zip(&self.choices[start..])
            .for_each(|((msg, key), choice)| *msg = if *choice { *key ^ self.delta } else { *key });

        for pending in mem::take(&mut self.sender_state.queue) {
            let count = pending.count();
            pending.send(self.try_send_rcot(count)?);
        }

        for pending in mem::take(&mut self.receiver_state.queue) {
            let count = pending.count();
            pending.send(self.try_recv_rcot(count)?);
        }

        self.sender_state.alloc = 0;
        self.sender_state.available += count;

        self.receiver_state.alloc = 0;
        self.receiver_state.available += count;

        Ok(())
    }
}

impl RCOTSender<Block> for IdealRCOT {
    type Error = Error;

    fn alloc(&mut self, count: usize) -> Result<()> {
        self.sender_state.alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.sender_state.available
    }

    fn delta(&self) -> Block {
        self.delta
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>> {
        if count > self.sender_state.available {
            return Err(ErrorRepr::InsufficientPreprocessed {
                wanted: count,
                got: self.sender_state.available,
            }
            .into());
        }

        let id = self.sender_state.transfer_id.next();

        self.sender_state.counts.push(count);
        if let Some(receiver_count) = self
            .receiver_state
            .counts
            .get(self.sender_state.counts.len())
        {
            // Make sure both parties are expecting the same number of RCOTs.
            if count != *receiver_count {
                return Err(ErrorRepr::CountMismatch {
                    id,
                    sender: count,
                    receiver: *receiver_count,
                }
                .into());
            }
        }

        let keys = self.keys[self.sender_state.current..self.sender_state.current + count].to_vec();
        self.sender_state.current += count;
        self.sender_state.available -= count;

        Ok(RCOTSenderOutput { id, keys })
    }

    fn queue_send_rcot(&mut self, count: usize) -> Result<RCOTSendFuture<Block>> {
        let (send, recv) = RCOTSendFuture::new(count);

        if self.sender_state.available >= count {
            let output = self.try_send_rcot(count)?;
            send.send(output);
        } else {
            RCOTSender::alloc(self, count)?;
            self.sender_state.queue.push(send);
        }

        Ok(recv)
    }
}

impl RCOTReceiver<bool, Block> for IdealRCOT {
    type Error = Error;

    fn alloc(&mut self, count: usize) -> Result<()> {
        self.receiver_state.alloc += count;
        Ok(())
    }

    fn available(&self) -> usize {
        self.receiver_state.available
    }

    fn try_recv_rcot(&mut self, count: usize) -> Result<RCOTReceiverOutput<bool, Block>> {
        if count > self.receiver_state.available {
            return Err(ErrorRepr::InsufficientPreprocessed {
                wanted: count,
                got: self.receiver_state.available,
            }
            .into());
        }

        let id = self.receiver_state.transfer_id.next();

        self.receiver_state.counts.push(count);
        if let Some(sender_count) = self
            .sender_state
            .counts
            .get(self.receiver_state.counts.len())
        {
            // Make sure both parties are expecting the same number of RCOTs.
            if count != *sender_count {
                return Err(ErrorRepr::CountMismatch {
                    id,
                    sender: *sender_count,
                    receiver: count,
                }
                .into());
            }
        }

        let choices =
            self.choices[self.receiver_state.current..self.receiver_state.current + count].to_vec();
        let msgs =
            self.msgs[self.receiver_state.current..self.receiver_state.current + count].to_vec();
        self.receiver_state.current += count;
        self.receiver_state.available -= count;

        Ok(RCOTReceiverOutput { id, choices, msgs })
    }

    fn queue_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<crate::rcot::RCOTRecvFuture<bool, Block>> {
        let (send, recv) = RCOTRecvFuture::new(count);

        if self.receiver_state.available >= count {
            let output = self.try_recv_rcot(count)?;
            send.send(output);
        } else {
            RCOTReceiver::alloc(self, count)?;
            self.receiver_state.queue.push(send);
        }

        Ok(recv)
    }
}

impl Default for IdealRCOT {
    fn default() -> Self {
        let mut rng = ChaCha8Rng::seed_from_u64(0);
        Self::new(rng.gen(), rng.gen())
    }
}

/// Error for [`IdealRCOT`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct IdealRCOTError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("insufficient preprocessed RCOTs: {wanted} > {got}")]
    InsufficientPreprocessed { wanted: usize, got: usize },
    #[error("count mismatch in transfer {id}: sender: {sender}, receiver: {receiver}")]
    CountMismatch {
        id: TransferId,
        sender: usize,
        receiver: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test::assert_cot;

    #[test]
    fn test_ideal_rcot() {
        let mut ideal = IdealRCOT::default();

        ideal.alloc(100);
        ideal.flush().unwrap();

        let (
            RCOTSenderOutput { keys: msgs, .. },
            RCOTReceiverOutput {
                choices,
                msgs: received,
                ..
            },
        ) = ideal.transfer(100).unwrap();

        assert_cot(ideal.delta(), &choices, &msgs, &received)
    }
}
