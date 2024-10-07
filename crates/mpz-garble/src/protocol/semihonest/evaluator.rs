use std::sync::Arc;

use async_trait::async_trait;
use hashbrown::HashMap;
use mpz_circuits::Circuit;
use mpz_common::{cpu::CpuBackend, scoped, Context};
use mpz_core::{bitvec::BitVec, Block};
use mpz_garble_core::{
    evaluate_garbled_circuits,
    store::{EvaluatorStore, EvaluatorStoreError},
    GarbledCircuit, Mac,
};
use mpz_memory_core::{binary::Binary, DecodeFuture, Memory, Slice};
use mpz_ot::COTReceiver;
use mpz_vm_core::{Call, Execute, Vm};
use serio::{stream::IoStreamExt, SinkExt};
use utils::{
    filter_drain::FilterDrain,
    range::{Disjoint, RangeSet},
};

use crate::evaluator::{evaluate, receive_garbled_circuit};

type Result<T, E = EvaluatorError> = core::result::Result<T, E>;
type Error = EvaluatorError;

#[derive(Debug)]
pub struct Evaluator<OT> {
    ot: OT,
    store: EvaluatorStore,
    call_stack: Vec<(Call, Slice)>,
    preprocessed: HashMap<Slice, (Call, GarbledCircuit)>,
}

impl<OT> Evaluator<OT> {
    /// Creates a new generator.
    pub fn new(ot: OT) -> Self {
        Self {
            ot,
            store: EvaluatorStore::default(),
            call_stack: Vec::new(),
            preprocessed: HashMap::new(),
        }
    }
}

impl<OT> Memory<Binary> for Evaluator<OT> {
    type Error = EvaluatorError;

    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        self.store.alloc_raw(size).map_err(Error::from)
    }

    fn mark_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_public_raw(slice).map_err(Error::from)
    }

    fn mark_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_private_raw(slice).map_err(Error::from)
    }

    fn mark_blind_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.mark_blind_raw(slice).map_err(Error::from)
    }

    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.commit_raw(slice).map_err(Error::from)
    }

    fn assign_raw(&mut self, slice: Slice, value: BitVec) -> Result<()> {
        self.store.assign_raw(slice, value).map_err(Error::from)
    }

    fn decode_raw(&mut self, slice: Slice) -> Result<DecodeFuture<BitVec>> {
        self.store.decode_raw(slice).map_err(Error::from)
    }
}

impl<OT> Vm<Binary> for Evaluator<OT> {
    type Error = Error;

    fn call_raw(&mut self, call: Call) -> std::result::Result<Slice, <Self as Vm<Binary>>::Error> {
        let output = self.store.alloc_output(call.circ().output_len());
        self.call_stack.push((call, output));
        Ok(output)
    }
}

#[async_trait]
impl<Ctx, OT> Execute<Ctx> for Evaluator<OT>
where
    Ctx: Context,
    OT: COTReceiver<Ctx, bool, Block> + Send,
{
    type Error = Error;

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<()> {
        while self.store.wants_flush() {
            let ot = &mut self.ot;
            let (recv, flush, ot_choices) = self.store.flush()?;
            if !ot_choices.is_empty() {
                let (flush, macs) = ctx
                    .try_join(
                        scoped!(move |ctx| {
                            ctx.io_mut().send(flush).await?;
                            let flush = ctx.io_mut().expect_next().await?;
                            Ok(flush)
                        }),
                        scoped!(move |ctx| {
                            ot.receive_correlated(ctx, &ot_choices)
                                .await
                                .map_err(Error::from)
                        }),
                    )
                    .await??;

                recv.receive(flush, Mac::from_blocks(macs.msgs))?;
            } else {
                ctx.io_mut().send(flush).await?;
                let flush = ctx.io_mut().expect_next().await?;
                recv.receive(flush, Vec::default())?;
            }
        }

        Ok(())
    }

    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<()> {
        while !self.call_stack.is_empty() {
            let mut idx_outputs = RangeSet::default();
            let ready_calls = self
                .call_stack
                // Extract calls which have no dependencies on other prior calls.
                .filter_drain(|(call, output)| {
                    if call
                        .inputs()
                        .iter()
                        .all(|input| input.to_range().is_disjoint(&idx_outputs))
                    {
                        idx_outputs |= output.to_range();
                        true
                    } else {
                        false
                    }
                })
                .collect::<Vec<_>>();

            let outputs = ctx
                .blocking_map_unordered(
                    scoped!(move |ctx, call| {
                        let (call, output): (Call, Slice) = call;
                        let result = receive_garbled_circuit(ctx, call.circ(), false).await;
                        (call, output, result)
                    }),
                    ready_calls,
                    Some(|(call, _): &(Call, _)| call.circ().and_count()),
                )
                .await
                .unwrap();

            for (call, output, result) in outputs {
                let garbled_circuit = result.unwrap();
                self.preprocessed.insert(output, (call, garbled_circuit));
                self.store.mark_output(output)?;
            }
        }

        Ok(())
    }

    async fn execute(&mut self, ctx: &mut Ctx) -> Result<()> {
        while !self.preprocessed.is_empty() {
            let (output_refs, ready_calls): (Vec<_>, Vec<_>) = self
                .preprocessed
                .extract_if(|_, (call, _)| {
                    call.inputs()
                        .iter()
                        .all(|input| self.store.is_set_macs(*input))
                })
                .map(|(output, (call, garbled_circuit))| {
                    let input_macs = call
                        .inputs()
                        .iter()
                        .flat_map(|input| {
                            self.store.try_get_macs(*input).expect("macs should be set")
                        })
                        .copied()
                        .collect::<Vec<_>>();
                    (output, (call.into_parts().0, input_macs, garbled_circuit))
                })
                .unzip();

            if ready_calls.is_empty() {
                break;
            }

            let outputs = CpuBackend::blocking(|| evaluate_garbled_circuits(ready_calls))
                .await
                .unwrap();

            for (output_ref, output) in output_refs.into_iter().zip(outputs) {
                self.store
                    .set_output(output_ref, &output.outputs)
                    .map_err(Error::from)?;
                self.store.mark_output(output_ref)?;
            }

            self.store.flush_decode()?;
        }

        while !self.call_stack.is_empty() {
            let ready_calls = self
                .call_stack
                .filter_drain(|(call, _)| {
                    call.inputs()
                        .iter()
                        .all(|input| self.store.is_set_macs(*input))
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
                .collect::<Vec<_>>();

            if ready_calls.is_empty() {
                break;
            }

            let outputs = ctx
                .blocking_map_unordered(
                    scoped!(move |ctx, call| {
                        let (circ, input_macs, output_ref) = call;
                        let result = evaluate(ctx, circ, input_macs).await;
                        (output_ref, result)
                    }),
                    ready_calls,
                    Some(|(circ, _, _): &(Arc<Circuit>, _, _)| circ.and_count()),
                )
                .await
                .unwrap();

            for (output_ref, result) in outputs {
                let output = result.unwrap();
                self.store
                    .set_output(output_ref, &output.outputs)
                    .map_err(Error::from)?;
            }

            self.store.flush_decode()?;
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
#[error("evaluator error")]
pub struct EvaluatorError {}

impl From<EvaluatorStoreError> for EvaluatorError {
    fn from(value: EvaluatorStoreError) -> Self {
        todo!()
    }
}

impl From<mpz_ot::OTError> for EvaluatorError {
    fn from(value: mpz_ot::OTError) -> Self {
        todo!()
    }
}

impl From<std::io::Error> for EvaluatorError {
    fn from(value: std::io::Error) -> Self {
        todo!()
    }
}

impl From<mpz_common::ContextError> for EvaluatorError {
    fn from(value: mpz_common::ContextError) -> Self {
        todo!()
    }
}
