use async_trait::async_trait;
use mpz_common::{scoped, Context, ContextError};
use mpz_core::{bitvec::BitVec, Block};
use mpz_ot::{COTReceiver, OTError, RCOTReceiverOutput, RandomCOTReceiver};
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
    OT: RandomCOTReceiver<Ctx, bool, Block> + Send + 'static,
{
    type Error = Error;

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<()> {
        while self.store.wants_flush() {
            let (recv, flush) = self.store.flush()?;
            ctx.io_mut().send(flush).await?;
            let flush = ctx.io_mut().expect_next().await?;
            recv.receive(flush)?;
        }

        Ok(())
    }

    async fn preprocess(&mut self, _ctx: &mut Ctx) -> Result<()> {
        // Nothing to do.
        Ok(())
    }

    async fn execute(&mut self, ctx: &mut Ctx) -> Result<()> {
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
            } = self.ot.receive_random_correlated(ctx, gate_count).await?;

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

impl<OT> Vm<Binary> for Prover<OT> {
    type Error = Error;

    fn call_raw(&mut self, call: Call) -> Result<Slice> {
        let output = self.alloc_raw(call.circ().output_len())?;
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

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.store.decode_raw(slice).map_err(Error::from)
    }
}

impl<OT> View<Binary> for Prover<OT> {
    type Error = Error;

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_public_raw(slice).map_err(Error::from)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_private_raw(slice).map_err(Error::from)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_blind_raw(slice).map_err(Error::from)
    }
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct ProverError(#[from] ErrorRepr);

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
    #[error(transparent)]
    Ot(#[from] OTError),
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

impl From<OTError> for ProverError {
    fn from(err: OTError) -> Self {
        Self(ErrorRepr::Ot(err))
    }
}
