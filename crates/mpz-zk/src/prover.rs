use async_trait::async_trait;
use mpz_common::{scoped, Context, ContextError, Flush};
use mpz_core::{bitvec::BitVec, Block};
use mpz_ot::{RCOTReceiver, RCOTReceiverOutput};
use mpz_vm_core::{
    memory::{binary::Binary, correlated::Mac, DecodeFuture, Memory, Slice, View},
    Call, Execute, Vm,
};
use mpz_zk_core::{
    store::{ProverStore, ProverStoreError},
    Prover as Core, ProverError as CoreError,
};
use serio::{stream::IoStreamExt, SinkExt};
use utils::filter_drain::FilterDrain;

type Error = ProverError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
pub struct Prover<OT> {
    store: ProverStore,
    ot: OT,
    callstack: Vec<(Call, Slice)>,
}

impl<OT> Prover<OT> {
    /// Creates a new prover.
    pub fn new(ot: OT) -> Self {
        Self {
            store: ProverStore::default(),
            ot,
            callstack: Vec::default(),
        }
    }
}

#[async_trait]
impl<Ctx, OT> Execute<Ctx> for Prover<OT>
where
    Ctx: Context,
    OT: RCOTReceiver<bool, Block> + Flush<Ctx> + Send + 'static,
{
    type Error = Error;

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<()> {
        let wants_macs = self.store.wants_macs();
        if wants_macs > 0 {
            if self.ot.available() < wants_macs {
                self.preprocess(ctx).await?;
            }

            let recv = self.store.receive_macs()?;
            let RCOTReceiverOutput {
                msgs: macs,
                choices: masks,
                ..
            } = self.ot.try_recv_rcot(wants_macs).map_err(Error::ot)?;
            let masks = BitVec::from_iter(masks);
            let macs = Mac::from_blocks(macs);
            recv.receive(&masks, &macs)?;
        }

        while self.store.wants_flush() {
            let (recv, flush) = self.store.flush()?;
            ctx.io_mut().send(flush).await?;
            let flush = ctx.io_mut().expect_next().await?;
            recv.receive(flush)?;
        }

        Ok(())
    }

    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<()> {
        self.ot.flush(ctx).await.map_err(Error::ot)?;

        Ok(())
    }

    async fn execute(&mut self, ctx: &mut Ctx) -> Result<()> {
        self.preprocess(ctx).await.map_err(Error::ot)?;

        while !self.callstack.is_empty() {
            let ready_calls: Vec<_> = self
                .callstack
                .filter_drain(|(call, _)| {
                    call.inputs()
                        .iter()
                        .all(|input| self.store.is_committed(*input))
                })
                .map(|(call, output)| {
                    let input_macs = call
                        .inputs()
                        .iter()
                        .flat_map(|input| {
                            self.store.try_get_macs(*input).expect("macs should be set")
                        })
                        .copied()
                        .collect::<Vec<_>>();
                    let (circ, _) = call.into_parts();
                    (circ, input_macs, output)
                })
                .collect();

            if ready_calls.is_empty() {
                break;
            }

            let gate_count = ready_calls
                .iter()
                .map(|(circ, _, _)| circ.and_count())
                .sum();

            let RCOTReceiverOutput {
                choices: gate_masks,
                msgs: gate_macs,
                ..
            } = self.ot.try_recv_rcot(gate_count).map_err(Error::ot)?;

            let gate_macs = Mac::from_blocks(gate_macs);
            let outputs = ctx
                .blocking(scoped!(move |ctx| {
                    let mut prover = Core::default();
                    let mut outputs = Vec::with_capacity(ready_calls.len());
                    let mut i = 0;
                    for (circ, input_macs, output) in ready_calls {
                        let mut iter = prover.execute(
                            &circ,
                            &input_macs,
                            &gate_masks[i..i + circ.and_count()],
                            &gate_macs[i..i + circ.and_count()],
                        )?;

                        while iter.has_gates() {
                            let adjust: BitVec<u32> = BitVec::from_iter(iter.by_ref().take(8000));
                            ctx.io_mut().send(adjust).await?;
                        }

                        let output_macs = iter.finish()?;
                        outputs.push((output, output_macs));
                        i += circ.and_count();
                    }

                    let check = prover.check(Block::ZERO, Block::ZERO);

                    ctx.io_mut().send(check).await?;

                    Ok::<_, Error>(outputs)
                }))
                .await??;

            for (output, output_macs) in outputs {
                self.store.set_output_macs(output, &output_macs)?;
            }
        }

        Ok(())
    }
}

impl<OT> Vm<Binary> for Prover<OT>
where
    OT: RCOTReceiver<bool, Block>,
{
    type Error = Error;

    fn call_raw(&mut self, call: Call) -> Result<Slice> {
        let output = self.store.alloc_output(call.circ().output_len());

        self.ot.alloc(call.circ().and_count()).map_err(Error::ot)?;
        self.callstack.push((call, output));

        Ok(output)
    }
}

impl<OT> Memory<Binary> for Prover<OT> {
    type Error = Error;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.store.alloc_raw(size).map_err(Error::from)
    }

    fn assign_raw(&mut self, slice: Slice, data: BitVec) -> Result<()> {
        self.store.assign_raw(slice, data).map_err(Error::from)
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.commit_raw(slice).map_err(Error::from)
    }

    fn get_raw(&self, slice: Slice) -> Result<Option<BitVec>> {
        self.store.get_raw(slice).map_err(Error::from)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.store.decode_raw(slice).map_err(Error::from)
    }
}

impl<OT> View<Binary> for Prover<OT>
where
    OT: RCOTReceiver<bool, Block>,
{
    type Error = Error;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_public_raw(slice).map_err(Error::from)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_private_raw(slice)?;

        self.ot.alloc(slice.len()).map_err(Error::ot)?;

        Ok(())
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        let res = self.store.mark_blind_raw(slice);

        debug_assert!(res.is_err());

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ProverError(#[from] ErrorRepr);

impl ProverError {
    fn ot<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Ot(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error(transparent)]
    Store(#[from] ProverStoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error("oblivious transfer error: {0}")]
    Ot(Box<dyn std::error::Error + Send + Sync>),
}

impl From<CoreError> for ProverError {
    fn from(err: CoreError) -> Self {
        Self(ErrorRepr::Core(err))
    }
}

impl From<ProverStoreError> for ProverError {
    fn from(err: ProverStoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<std::io::Error> for ProverError {
    fn from(err: std::io::Error) -> Self {
        Self(ErrorRepr::Io(err))
    }
}

impl From<ContextError> for ProverError {
    fn from(err: ContextError) -> Self {
        Self(ErrorRepr::Context(err))
    }
}
