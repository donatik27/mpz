use std::sync::Arc;

use async_trait::async_trait;
use mpz_circuits::Circuit;
use mpz_common::{scoped, Context};
use mpz_core::{bitvec::BitVec, Block};
use mpz_garble_core::{
    store::{GeneratorStore, GeneratorStoreError},
    Key,
};
use mpz_memory_core::{binary::Binary, correlated::Delta, DecodeFuture, Memory, Slice};
use mpz_ot::COTSender;
use mpz_vm_core::{Call, Execute, Vm};
use serio::{stream::IoStreamExt, SinkExt};
use utils::filter_drain::FilterDrain;

use crate::generator::generate;

type Result<T, E = GeneratorError> = core::result::Result<T, E>;
type Error = GeneratorError;

#[derive(Debug)]
pub struct Generator<OT> {
    ot: OT,
    store: GeneratorStore,
    call_stack: Vec<(Call, Slice)>,
}

impl<OT> Generator<OT> {
    /// Creates a new generator.
    pub fn new(ot: OT, seed: [u8; 16], delta: Delta) -> Self {
        Self {
            ot,
            store: GeneratorStore::new(seed, delta),
            call_stack: Vec::new(),
        }
    }

    fn take_preprocess_calls(&mut self) -> Vec<(Arc<Circuit>, Vec<Key>, Slice)> {
        self.call_stack
            .filter_drain(|(call, _)| {
                call.inputs()
                    .iter()
                    .all(|slice| self.store.is_set_keys(*slice))
            })
            .map(|(call, output)| {
                let input_macs = call
                    .inputs()
                    .iter()
                    .flat_map(|input| self.store.try_get_keys(*input).expect("keys should be set"))
                    .copied()
                    .collect::<Vec<_>>();
                (call.into_parts().0, input_macs, output)
            })
            .collect()
    }

    fn take_execute_calls(&mut self) -> Vec<(Arc<Circuit>, Vec<Key>, Slice)> {
        self.call_stack
            .filter_drain(|(call, _)| {
                call.inputs()
                    .iter()
                    .all(|slice| self.store.is_committed(*slice))
            })
            .map(|(call, output)| {
                let input_macs = call
                    .inputs()
                    .iter()
                    .flat_map(|input| self.store.try_get_keys(*input).expect("keys should be set"))
                    .copied()
                    .collect::<Vec<_>>();
                (call.into_parts().0, input_macs, output)
            })
            .collect()
    }
}

impl<OT> Memory<Binary> for Generator<OT> {
    type Error = GeneratorError;

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

impl<OT> Vm<Binary> for Generator<OT> {
    type Error = GeneratorError;

    fn call_raw(&mut self, call: Call) -> Result<Slice> {
        let slice = self.store.alloc_output(call.circ().output_len());
        self.call_stack.push((call, slice));
        Ok(slice)
    }
}

#[async_trait]
impl<Ctx, OT> Execute<Ctx> for Generator<OT>
where
    Ctx: Context,
    OT: COTSender<Ctx, Block> + Send,
{
    type Error = GeneratorError;

    async fn flush(&mut self, ctx: &mut Ctx) -> Result<()> {
        while self.store.wants_flush() {
            let ot = &mut self.ot;
            let (recv, flush, ot_keys) = self.store.flush()?;
            if !ot_keys.is_empty() {
                let (flush, _) = ctx
                    .try_join(
                        scoped!(move |ctx| {
                            ctx.io_mut().send(flush).await?;
                            let flush = ctx.io_mut().expect_next().await?;
                            Ok(flush)
                        }),
                        scoped!(move |ctx| {
                            ot.send_correlated(ctx, Key::as_blocks(&ot_keys))
                                .await
                                .map_err(Error::from)
                        }),
                    )
                    .await??;

                recv.receive(flush)?;
            } else {
                ctx.io_mut().send(flush).await?;
                let flush = ctx.io_mut().expect_next().await?;
                recv.receive(flush)?;
            }
        }

        Ok(())
    }

    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<()> {
        let delta = *self.store.delta();
        while !self.call_stack.is_empty() {
            let outputs = ctx
                .blocking_map_unordered(
                    scoped!(move |ctx, call| {
                        let (circ, input_macs, output_ref) = call;
                        let output = generate(ctx, circ, delta, input_macs).await;
                        (output_ref, output)
                    }),
                    self.take_preprocess_calls(),
                    Some(|(circ, _, _): &(Arc<Circuit>, _, _)| circ.and_count()),
                )
                .await?;

            for (output_ref, output) in outputs {
                let output = output?;
                self.store.set_output(output_ref, &output.outputs)?;
            }
        }

        Ok(())
    }

    async fn execute(&mut self, ctx: &mut Ctx) -> Result<()> {
        let delta = *self.store.delta();
        while !self.call_stack.is_empty() {
            let ready_calls = self.take_execute_calls();

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
                .await?;

            for (output_ref, output) in outputs {
                let output = output?;
                self.store.set_output(output_ref, &output.outputs)?;
                self.store.mark_output(output_ref)?;
            }
        }

        Ok(())
    }
}
#[derive(Debug, thiserror::Error)]
#[error("generator error")]
pub struct GeneratorError {}

impl From<GeneratorStoreError> for GeneratorError {
    fn from(value: GeneratorStoreError) -> Self {
        dbg!(value);
        todo!()
    }
}

impl From<crate::generator::GeneratorError> for GeneratorError {
    fn from(value: crate::generator::GeneratorError) -> Self {
        dbg!(value);
        todo!()
    }
}

impl From<std::io::Error> for GeneratorError {
    fn from(value: std::io::Error) -> Self {
        dbg!(value);
        todo!()
    }
}

impl From<mpz_ot::OTError> for GeneratorError {
    fn from(value: mpz_ot::OTError) -> Self {
        dbg!(value);
        todo!()
    }
}

impl From<mpz_common::ContextError> for GeneratorError {
    fn from(value: mpz_common::ContextError) -> Self {
        dbg!(value);
        todo!()
    }
}
