//! Ideal functionality for random correlated oblivious transfer.

use async_trait::async_trait;

use mpz_common::{
    ideal::{ideal_f2p, Alice, Bob},
    Context, Flush,
};
use mpz_core::Block;
use mpz_ot_core::{
    ideal::rcot::IdealRCOT,
    rcot::{RCOTReceiver, RCOTReceiverOutput, RCOTSender, RCOTSenderOutput},
};

use crate::{OTError, RandomCOTReceiver, RandomCOTSender};

fn flush(f: &mut IdealRCOT, _: (), _: ()) -> ((), ()) {
    f.flush().unwrap();
    ((), ())
}

/// Returns an ideal RCOT sender and receiver with a specific delta value.
pub fn ideal_rcot(seed: Block, delta: Block) -> (IdealRCOTSender, IdealRCOTReceiver) {
    let rcot = IdealRCOT::new(seed, delta);
    let (alice, bob) = ideal_f2p(rcot);
    (IdealRCOTSender(alice), IdealRCOTReceiver(bob))
}

/// Ideal COT sender.
#[derive(Debug, Clone)]
pub struct IdealRCOTSender(Alice<IdealRCOT>);

impl RCOTSender<Block> for IdealRCOTSender {
    type Error = OTError;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        RCOTSender::alloc(&mut (*self.0.get()), count).map_err(|e| OTError::SenderError(e.into()))
    }

    fn available(&self) -> usize {
        RCOTSender::available(&(*self.0.get()))
    }

    fn delta(&self) -> Block {
        RCOTSender::delta(&(*self.0.get()))
    }

    fn try_send_rcot(&mut self, count: usize) -> Result<RCOTSenderOutput<Block>, Self::Error> {
        RCOTSender::try_send_rcot(&mut (*self.0.get()), count)
            .map_err(|e| OTError::SenderError(e.into()))
    }

    fn queue_send_rcot(
        &mut self,
        count: usize,
    ) -> Result<mpz_ot_core::rcot::RCOTSendFuture<Block>, Self::Error> {
        RCOTSender::queue_send_rcot(&mut (*self.0.get()), count)
            .map_err(|e| OTError::SenderError(e.into()))
    }
}

#[async_trait]
impl<Ctx> Flush<Ctx> for IdealRCOTSender
where
    Ctx: Context,
{
    type Error = OTError;

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(self.0.call(ctx, (), flush).await)
    }
}

#[async_trait]
impl<Ctx: Context> RandomCOTSender<Ctx, Block> for IdealRCOTSender {
    async fn send_random_correlated(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<RCOTSenderOutput<Block>, OTError> {
        let available = RCOTSender::available(&(*self.0.get()));
        if count > available {
            self.0.get_mut().alloc(count);
            self.0.call(ctx, (), flush).await;
        }

        Ok(self.0.get_mut().try_send_rcot(count).unwrap())
    }
}

/// Ideal COT receiver.
#[derive(Debug, Clone)]
pub struct IdealRCOTReceiver(Bob<IdealRCOT>);

impl RCOTReceiver<bool, Block> for IdealRCOTReceiver {
    type Error = OTError;

    fn alloc(&mut self, count: usize) -> Result<(), Self::Error> {
        RCOTReceiver::alloc(&mut (*self.0.get()), count)
            .map_err(|e| OTError::ReceiverError(e.into()))
    }

    fn available(&self) -> usize {
        RCOTReceiver::available(&(*self.0.get()))
    }

    fn try_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, Self::Error> {
        RCOTReceiver::try_recv_rcot(&mut (*self.0.get()), count)
            .map_err(|e| OTError::ReceiverError(e.into()))
    }

    fn queue_recv_rcot(
        &mut self,
        count: usize,
    ) -> Result<mpz_ot_core::rcot::RCOTRecvFuture<bool, Block>, Self::Error> {
        RCOTReceiver::queue_recv_rcot(&mut (*self.0.get()), count)
            .map_err(|e| OTError::ReceiverError(e.into()))
    }
}

#[async_trait]
impl<Ctx> Flush<Ctx> for IdealRCOTReceiver
where
    Ctx: Context,
{
    type Error = OTError;

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<(), OTError> {
        Ok(self.0.call(ctx, (), flush).await)
    }
}

#[async_trait]
impl<Ctx: Context> RandomCOTReceiver<Ctx, bool, Block> for IdealRCOTReceiver {
    async fn receive_random_correlated(
        &mut self,
        ctx: &mut Ctx,
        count: usize,
    ) -> Result<RCOTReceiverOutput<bool, Block>, OTError> {
        let available = RCOTReceiver::available(&(*self.0.get()));
        if count > available {
            self.0.get_mut().alloc(count);
            self.0.call(ctx, (), flush).await;
        }

        Ok(self.0.get_mut().try_recv_rcot(count).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpz_common::executor::test_st_executor;
    use mpz_ot_core::{rcot::RCOTSender, test::assert_cot};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[tokio::test]
    async fn test_ideal_rcot() {
        let mut rng = StdRng::seed_from_u64(0);
        let (mut ctx_a, mut ctx_b) = test_st_executor(8);
        let (mut alice, mut bob) = ideal_rcot(rng.gen(), rng.gen());

        let delta = alice.delta();
        let count = 10;

        let (
            RCOTSenderOutput {
                id: id_a,
                keys: sender_msgs,
            },
            RCOTReceiverOutput {
                id: id_b,
                choices,
                msgs: receiver_msgs,
            },
        ) = tokio::try_join!(
            alice.send_random_correlated(&mut ctx_a, count),
            bob.receive_random_correlated(&mut ctx_b, count)
        )
        .unwrap();

        assert_eq!(id_a, id_b);
        assert_eq!(count, sender_msgs.len());
        assert_eq!(count, receiver_msgs.len());
        assert_eq!(count, choices.len());
        assert_cot(delta, &choices, &sender_msgs, &receiver_msgs);
    }
}
