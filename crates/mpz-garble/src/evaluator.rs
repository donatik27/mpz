use core::fmt;
use std::sync::Arc;

use mpz_circuits::Circuit;
use mpz_common::Context;
use mpz_garble_core::{
    EncryptedGateBatch, Evaluator as EvaluatorCore, EvaluatorOutput, GarbledCircuit,
};
use mpz_memory_core::correlated::Mac;
use serio::stream::IoStreamExt;

#[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
pub async fn receive_garbled_circuit<Ctx: Context>(
    ctx: &mut Ctx,
    circ: &Circuit,
    commitments: bool,
) -> Result<GarbledCircuit, EvaluatorError> {
    let gate_count = circ.and_count();
    let mut gates = Vec::with_capacity(gate_count);

    while gates.len() < gate_count {
        let batch: EncryptedGateBatch = ctx.io_mut().expect_next().await?;
        gates.extend_from_slice(&batch.into_array());
    }

    // Trim off any batch padding.
    gates.truncate(gate_count);

    let commitments = if commitments {
        let commitments: Vec<_> = ctx.io_mut().expect_next().await?;

        // Make sure the generator sent the expected number of commitments.
        if commitments.len() != circ.output_len() {
            return Err(EvaluatorError::generator(format!(
                "generator sent wrong number of output commitments: expected {}, got {}",
                circ.output_len(),
                commitments.len()
            )));
        }

        Some(commitments)
    } else {
        None
    };

    Ok(GarbledCircuit { gates, commitments })
}

/// Evaluate a garbled circuit, streaming the encrypted gates from the evaluator in batches.
///
/// # Blocking
///
/// This function performs blocking computation, so be careful when calling it from an async context.
///
/// # Arguments
///
/// * `ctx` - The context to use.
/// * `circ` - The circuit to evaluate.
/// * `inputs` - The inputs of the circuit.
#[tracing::instrument(fields(thread = %ctx.id()), skip_all)]
pub async fn evaluate<Ctx: Context>(
    ctx: &mut Ctx,
    circ: Arc<Circuit>,
    inputs: Vec<Mac>,
) -> Result<EvaluatorOutput, EvaluatorError> {
    let mut ev = EvaluatorCore::default();
    let mut ev_consumer = ev.evaluate_batched(&circ, inputs)?;
    let io = ctx.io_mut();

    while ev_consumer.wants_gates() {
        let batch: EncryptedGateBatch = io.expect_next().await?;
        ev_consumer.next(batch);
    }

    Ok(ev_consumer.finish()?)
}

/// Garbled circuit evaluator error.
#[derive(Debug, thiserror::Error)]
pub struct EvaluatorError {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl EvaluatorError {
    fn generator<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self {
            kind: ErrorKind::Generator,
            source: Some(err.into()),
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    Io,
    Core,
    Generator,
}

impl fmt::Display for EvaluatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("evaluator error: ")?;

        match &self.kind {
            ErrorKind::Io => f.write_str("io error")?,
            ErrorKind::Core => f.write_str("core error")?,
            ErrorKind::Generator => f.write_str("generator error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

impl From<std::io::Error> for EvaluatorError {
    fn from(err: std::io::Error) -> Self {
        Self {
            kind: ErrorKind::Io,
            source: Some(Box::new(err)),
        }
    }
}

impl From<mpz_garble_core::EvaluatorError> for EvaluatorError {
    fn from(err: mpz_garble_core::EvaluatorError) -> Self {
        Self {
            kind: ErrorKind::Core,
            source: Some(Box::new(err)),
        }
    }
}
