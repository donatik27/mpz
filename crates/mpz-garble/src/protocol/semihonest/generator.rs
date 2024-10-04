use std::sync::Arc;

use async_trait::async_trait;
use mpz_circuits::Circuit;
use mpz_common::{scoped, Context};
use mpz_core::{bitvec::BitVec, Block};
use mpz_garble_core::GeneratorOutput;
use mpz_memory_core::{binary::Binary, correlated::Delta, MemoryType, Slice};
use mpz_ot::COTSender;
use mpz_vm::{
    Alloc, Assign, Callable, Commit, Decode, Execute, Memory, MemorySync, Preprocess, Result,
    Synchronize, View, VmError,
};
use mpz_vm_core::{Call, DecodeFuture};
use rand::Rng;
use utils::filter_drain::FilterDrain;

use crate::{generator::generate, store::GeneratorStore};

#[derive(Debug)]
pub struct Generator<OT> {
    store: GeneratorStore,
    ot: OT,

    call_stack: Vec<(Call, Slice)>,
}

impl<OT> Generator<OT> {
    /// Creates a new generator.
    pub fn new(ot: OT, seed: [u8; 16], delta: Delta) -> Self {
        Self {
            store: GeneratorStore::new(seed, delta),
            ot,
            call_stack: Vec::new(),
        }
    }
}

impl<OT> Memory for Generator<OT> {
    type MemoryType = Binary;
}

impl<OT> Alloc for Generator<OT> {
    fn alloc_raw(&mut self, size: usize) -> Result<Slice> {
        Ok(self.store.alloc(size))
    }
}

impl<OT> View for Generator<OT> {
    fn configure_public_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.configure_public(slice).map_err(VmError::memory)
    }

    fn configure_private_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.configure_private(slice).map_err(VmError::memory)
    }

    fn configure_blind_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.configure_blind(slice).map_err(VmError::memory)
    }
}

impl<OT> Assign for Generator<OT> {
    fn assign_raw(&mut self, slice: Slice, value: BitVec) -> Result<()> {
        self.store.assign(slice, &value).map_err(VmError::memory)
    }
}

impl<OT> Commit for Generator<OT> {
    fn commit_raw(&mut self, slice: Slice) -> Result<()> {
        self.store.commit(slice).map_err(VmError::memory)
    }
}

impl<OT> Callable for Generator<OT> {
    fn call(&mut self, call: Call) -> Result<Slice> {
        let output = self.store.alloc_output(call.circ().output_len());
        self.call_stack.push((call, output));
        Ok(output)
    }
}

impl<OT> Decode for Generator<OT> {
    fn decode_raw(&mut self, raw: Slice) -> Result<DecodeFuture<BitVec>> {
        self.store.decode(raw).map_err(VmError::memory)
    }
}

#[async_trait]
impl<Ctx, OT> MemorySync<Ctx> for Generator<OT>
where
    Ctx: Context,
    OT: COTSender<Ctx, Block> + Send,
{
    async fn sync_memory(&mut self, ctx: &mut Ctx) -> Result<()> {
        self.store
            .sync(ctx, &mut self.ot)
            .await
            .map_err(VmError::memory)
    }
}

#[async_trait]
impl<Ctx, OT> Preprocess<Ctx> for Generator<OT>
where
    Ctx: Context,
    OT: Send,
{
    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<()> {
        let delta = *self.store.delta();
        while !self.call_stack.is_empty() {
            let ready_calls = self
                .call_stack
                .filter_drain(|(call, _)| {
                    call.inputs()
                        .iter()
                        .all(|input| self.store.is_set_keys(*input))
                })
                .map(|(call, output)| {
                    let input_macs = call
                        .inputs()
                        .iter()
                        .flat_map(|input| {
                            self.store.try_get_keys(*input).expect("keys should be set")
                        })
                        .copied()
                        .collect::<Vec<_>>();
                    (call.into_parts().0, input_macs, output)
                })
                .collect::<Vec<_>>();

            let outputs = ctx
                .blocking_map_unordered(
                    scoped!(move |ctx, call| {
                        let (circ, input_macs, output_ref) = call;
                        let output = generate(ctx, circ, delta, input_macs).await;
                        (output_ref, output)
                    }),
                    ready_calls,
                    Some(|(circ, _, _): &(Arc<Circuit>, _, _)| circ.and_count()),
                )
                .await
                .unwrap();

            for (output_ref, result) in outputs {
                let GeneratorOutput {
                    outputs: output_macs,
                    ..
                } = result.unwrap();
                self.store.set_output(output_ref, &output_macs).unwrap();
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<Ctx, OT> Execute<Ctx> for Generator<OT>
where
    Ctx: Context,
    OT: Send,
{
    async fn execute(&mut self, ctx: &mut Ctx) -> Result<()> {
        let delta = *self.store.delta();
        while !self.call_stack.is_empty() {
            let ready_calls = self
                .call_stack
                .filter_drain(|(call, _)| {
                    call.inputs().iter().all(|input| {
                        self.store.is_set_keys(*input) && self.store.is_assigned_keys(*input)
                    })
                })
                .map(|(call, output)| {
                    let input_macs = call
                        .inputs()
                        .iter()
                        .flat_map(|input| {
                            self.store.try_get_keys(*input).expect("keys should be set")
                        })
                        .copied()
                        .collect::<Vec<_>>();
                    (call.into_parts().0, input_macs, output)
                })
                .collect::<Vec<_>>();

            if ready_calls.is_empty() {
                break;
            }

            let outputs = ctx
                .blocking_map_unordered(
                    scoped!(move |ctx, call| {
                        let (circ, input_macs, output_ref) = call;
                        let output = generate(ctx, circ, delta, input_macs).await;
                        (output_ref, output)
                    }),
                    ready_calls,
                    Some(|(circ, _, _): &(Arc<Circuit>, _, _)| circ.and_count()),
                )
                .await
                .unwrap();

            for (output_ref, result) in outputs {
                let GeneratorOutput {
                    outputs: output_macs,
                    ..
                } = result.unwrap();
                self.store.set_output(output_ref, &output_macs).unwrap();
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<Ctx, OT> Synchronize<Ctx> for Generator<OT>
where
    Ctx: Context,
    OT: COTSender<Ctx, Block> + Send,
{
    async fn sync(&mut self, ctx: &mut Ctx) -> Result<()> {
        self.sync_memory(ctx).await?;
        self.execute(ctx).await?;
        self.sync_memory(ctx).await?;

        Ok(())
    }
}
