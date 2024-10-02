use core::fmt;
use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_common::Context;
use mpz_garble_core::{Generator as GeneratorCore, GeneratorOutput};
use mpz_memory_core::correlated::{Delta, Key};
use serio::SinkExt;

/// Generate a garbled circuit, streaming the encrypted gates to the evaluator in batches.
///
/// # Blocking
///
/// This function performs blocking computation, so be careful when calling it from an async context.
///
/// # Arguments
///
/// * `ctx` - The context to use.
/// * `circ` - The circuit to garble.
/// * `delta` - The generators delta value.
/// * `inputs` - The inputs of the circuit.
/// * `hash` - Whether to hash the circuit.
#[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
pub async fn generate<Ctx: Context>(
    ctx: &mut Ctx,
    circ: Arc<Circuit>,
    delta: Delta,
    inputs: Vec<Key>,
) -> Result<GeneratorOutput, GeneratorError> {
    let mut gen = GeneratorCore::default();
    let mut gen_iter = gen.generate_batched(&circ, delta, inputs)?;
    let io = ctx.io_mut();

    while let Some(batch) = gen_iter.by_ref().next() {
        io.feed(batch).await?;
    }

    Ok(gen_iter.finish()?)
}

/// Garbled circuit generator error.
#[derive(Debug, thiserror::Error)]
pub struct GeneratorError {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + 'static>>,
}

#[derive(Debug)]
enum ErrorKind {
    Io,
    Core,
}

impl fmt::Display for GeneratorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("generator error: ")?;

        match &self.kind {
            ErrorKind::Io => f.write_str("io error")?,
            ErrorKind::Core => f.write_str("core error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<std::io::Error> for GeneratorError {
    fn from(err: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            source: Some(Box::new(err)),
        }
    }
}

impl From<mpz_garble_core::GeneratorError> for GeneratorError {
    fn from(err: mpz_garble_core::GeneratorError) -> Self {
        Self {
            kind: ErrorKind::Core,
            source: Some(Box::new(err)),
        }
    }
}
