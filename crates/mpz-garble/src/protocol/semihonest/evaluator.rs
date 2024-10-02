use std::sync::Arc;

use async_trait::async_trait;
use hashbrown::HashMap;
use mpz_circuits::Circuit;
use mpz_common::{cpu::CpuBackend, scoped, Context};
use mpz_core::{bitvec::BitVec, Block};
use mpz_garble_core::{evaluate_garbled_circuits, GarbledCircuit};
use mpz_memory_core::Slice;
use mpz_ot::COTReceiver;
use mpz_vm::{
    Alloc, AssignBlind, AssignPrivate, AssignPublic, Callable, Commit, Decode, Execute, Preprocess,
    Synchronize, VmError,
};
use mpz_vm_core::{Call, DecodeFuture};
use utils::{
    filter_drain::FilterDrain,
    range::{Disjoint, RangeSet, Union},
};

use crate::{
    evaluator::{evaluate, receive_garbled_circuit},
    store::EvaluatorStore,
};

type Result<T> = core::result::Result<T, VmError>;

#[derive(Debug)]
pub struct Evaluator<OT> {
    store: EvaluatorStore,
    ot: OT,

    call_stack: Vec<(Call, Slice)>,
    preprocessed: HashMap<Slice, (Call, GarbledCircuit)>,
}

impl<OT> Evaluator<OT> {
    /// Creates a new generator.
    pub fn new(ot: OT) -> Self {
        Self {
            store: EvaluatorStore::default(),
            ot,
            call_stack: Vec::new(),
            preprocessed: HashMap::new(),
        }
    }
}

impl<OT> Alloc for Evaluator<OT> {
    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        Ok(self.store.alloc(size))
    }
}

impl<OT> AssignPublic for Evaluator<OT> {
    type Value = BitVec;

    fn assign_public_raw(&mut self, slice: Slice, value: Self::Value) -> Result<()> {
        self.store
            .assign_public(slice, &value)
            .map_err(VmError::memory)
    }
}

impl<OT> AssignPrivate for Evaluator<OT> {
    type Value = BitVec;

    fn assign_private_raw(&mut self, slice: Slice, value: Self::Value) -> Result<()> {
        self.store
            .assign_private(slice, &value)
            .map_err(VmError::memory)
    }
}

impl<OT> AssignBlind for Evaluator<OT> {
    fn assign_blind_raw(&mut self, raw: Slice) -> Result<()> {
        self.store.assign_blind(raw).map_err(VmError::memory)
    }
}

impl<OT> Callable for Evaluator<OT> {
    fn call_raw(&mut self, call: Call) -> Result<Slice> {
        let output = self.store.alloc(call.circ().output_len());
        self.call_stack.push((call, output));
        Ok(output)
    }
}

impl<OT> Decode for Evaluator<OT> {
    type Value = BitVec;

    fn decode_raw(&mut self, raw: Slice) -> Result<DecodeFuture<Self::Value>> {
        self.store.decode(raw).map_err(VmError::memory)
    }
}

#[async_trait]
impl<Ctx, OT> Commit<Ctx> for Evaluator<OT>
where
    Ctx: Context,
    OT: COTReceiver<Ctx, bool, Block> + Send,
{
    async fn commit(&mut self, ctx: &mut Ctx) -> Result<()> {
        self.store
            .commit(ctx, &mut self.ot)
            .await
            .map_err(VmError::memory)
    }
}

#[async_trait]
impl<Ctx, OT> Preprocess<Ctx> for Evaluator<OT>
where
    Ctx: Context,
    OT: Send,
{
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
                        idx_outputs = idx_outputs.union(&output.to_range());
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
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<Ctx, OT> Execute<Ctx> for Evaluator<OT>
where
    Ctx: Context,
    OT: Send,
{
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
                    .map_err(VmError::memory)?;
            }
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
                    .map_err(VmError::memory)?;
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<Ctx, OT> Synchronize<Ctx> for Evaluator<OT>
where
    Ctx: Context,
    OT: COTReceiver<Ctx, bool, Block> + Send,
{
    async fn sync(&mut self, ctx: &mut Ctx) -> Result<()> {
        self.commit(ctx).await?;
        self.execute(ctx).await?;
        self.commit(ctx).await?;

        Ok(())
    }
}
