use async_trait::async_trait;
use mpz_common::{scoped, Context, ContextError};
use mpz_core::{bitvec::BitVec, Block};
use mpz_ot::{OTError, RCOTSenderOutput, RandomCOTSender};
use mpz_vm_core::{
    memory::{
        binary::Binary,
        correlated::{Delta, Key},
        DecodeFuture, Memory, Slice, View,
    },
    Call, Execute, Vm,
};
use mpz_zk_core::{
    store::{VerifierStore, VerifierStoreError},
    Verifier as Core, VerifierError as CoreError,
};
use serio::{stream::IoStreamExt, SinkExt};
use utils::filter_drain::FilterDrain;

type Error = VerifierError;
type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
pub struct Verifier<OT> {
    store: VerifierStore,
    ot: OT,
    callstack: Vec<(Call, Slice)>,
}

impl<OT> Verifier<OT> {
    /// Creates a new prover.
    pub fn new(delta: Delta, ot: OT) -> Self {
        Self {
            store: VerifierStore::new(delta),
            ot,
            callstack: Vec::default(),
        }
    }
}

#[async_trait]
impl<Ctx, OT> Execute<Ctx> for Verifier<OT>
where
    Ctx: Context,
    OT: RandomCOTSender<Ctx, Block> + Send + 'static,
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
                    let input_keys = call
                        .inputs()
                        .iter()
                        .flat_map(|input| {
                            self.store.try_get_keys(*input).expect("keys should be set")
                        })
                        .copied()
                        .collect::<Vec<_>>();
                    let (circ, _) = call.into_parts();
                    (circ, input_keys, output)
                })
                .collect();

            if ready_calls.is_empty() {
                break;
            }

            let gate_count = ready_calls
                .iter()
                .map(|(circ, _, _)| circ.and_count())
                .sum();

            let RCOTSenderOutput {
                msgs: gate_keys, ..
            } = self.ot.send_random_correlated(ctx, gate_count).await?;

            let delta = *self.store.delta();
            let gate_keys = Key::from_blocks(gate_keys);
            let outputs = ctx
                .blocking(scoped!(move |ctx| {
                    let mut verifier = Core::new(delta);
                    let mut outputs = Vec::with_capacity(ready_calls.len());
                    let mut i = 0;
                    for (circ, input_keys, output) in ready_calls {
                        let mut consumer = verifier.execute(
                            &circ,
                            &input_keys,
                            &gate_keys[i..i + circ.and_count()],
                        )?;

                        while consumer.wants_gates() {
                            let adjust: BitVec = ctx.io_mut().expect_next().await?;
                            for bit in adjust {
                                consumer.next(bit);
                            }
                        }

                        let output_macs = consumer.finish()?;
                        outputs.push((output, output_macs));
                        i += circ.and_count();
                    }

                    let verify = verifier.check(Block::ZERO);
                    let (u, v) = ctx.io_mut().expect_next().await?;

                    verify.verify(u, v)?;

                    Ok::<_, Error>(outputs)
                }))
                .await??;

            for (output, output_keys) in outputs {
                self.store.set_output_keys(output, &output_keys)?;
            }
        }

        Ok(())
    }
}

impl<OT> Vm<Binary> for Verifier<OT> {
    type Error = Error;

    fn call_raw(&mut self, call: Call) -> Result<Slice> {
        let output = self.alloc_raw(call.circ().output_len())?;
        self.callstack.push((call, output));
        Ok(output)
    }
}

impl<OT> Memory<Binary> for Verifier<OT> {
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

impl<OT> View<Binary> for Verifier<OT> {
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
pub struct VerifierError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error(transparent)]
    Core(#[from] CoreError),
    #[error(transparent)]
    Store(#[from] VerifierStoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    Ot(#[from] OTError),
}

impl From<CoreError> for VerifierError {
    fn from(err: CoreError) -> Self {
        Self(ErrorRepr::Core(err))
    }
}

impl From<VerifierStoreError> for VerifierError {
    fn from(err: VerifierStoreError) -> Self {
        Self(ErrorRepr::Store(err))
    }
}

impl From<std::io::Error> for VerifierError {
    fn from(err: std::io::Error) -> Self {
        Self(ErrorRepr::Io(err))
    }
}

impl From<ContextError> for VerifierError {
    fn from(err: ContextError) -> Self {
        Self(ErrorRepr::Context(err))
    }
}

impl From<OTError> for VerifierError {
    fn from(err: OTError) -> Self {
        Self(ErrorRepr::Ot(err))
    }
}
