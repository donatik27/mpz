//! This crate provides an implementation of garbled circuit protocols to facilitate MPC.

// #![deny(missing_docs, unreachable_pub, unused_must_use)]
// #![deny(clippy::all)]
// #![forbid(unsafe_code)]

use core::fmt;

use async_trait::async_trait;

use mpz_circuits::Circuit;
use mpz_memory_core::{ClearRepr, Ptr, Slice, StaticSize, ToRaw, Vector};
use mpz_vm_core::{Call, DecodeFuture};

/// The result type for a VM.
pub type Result<T> = core::result::Result<T, VmError>;

#[derive(Debug, thiserror::Error)]
pub struct VmError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("vm error: ")?;

        match &self.kind {
            ErrorKind::Io => f.write_str("io error")?,
            ErrorKind::Memory => f.write_str("memory error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
enum ErrorKind {
    Io,
    Memory,
}

impl VmError {
    pub fn memory<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self {
            kind: ErrorKind::Memory,
            source: Some(err.into()),
        }
    }
}

/// This trait provides methods for interacting with values in memory.
pub trait Alloc {
    /// Allocates a new value.
    fn alloc_raw(&mut self, size: usize) -> Result<Slice>;
}

pub trait AllocExt: Alloc {
    fn alloc<T: StaticSize>(&mut self) -> Result<T> {
        todo!()
    }

    fn alloc_vec<T: StaticSize>(&mut self, len: usize) -> Result<Vector<T>> {
        todo!()
    }
}

impl<T> AllocExt for T where T: Alloc {}

pub trait AssignPublic {
    type Value;

    fn assign_public_raw(&mut self, raw: Slice, value: Self::Value) -> Result<()>;
}

pub trait AssignPrivate {
    type Value;

    fn assign_private_raw(&mut self, raw: Slice, value: Self::Value) -> Result<()>;
}

pub trait AssignBlind {
    fn assign_blind_raw(&mut self, raw: Slice) -> Result<()>;
}

pub trait Callable {
    /// Calls a circuit with the provided inputs, returning the output.
    fn call_raw(&mut self, call: Call) -> Result<Slice>;
}

pub trait Decode {
    type Value;

    /// Decodes a value from memory.
    ///
    /// Returns a future which will resolve to the value when it is ready.
    fn decode_raw(&mut self, raw: Slice) -> Result<DecodeFuture<Self::Value>>;
}

#[async_trait]
pub trait Synchronize<Ctx> {
    /// Synchronizes the state of the VM.
    async fn sync(&mut self, ctx: &mut Ctx) -> Result<()>;
}

#[async_trait]
pub trait Commit<Ctx> {
    /// Commits the memory of the VM.
    async fn commit(&mut self, ctx: &mut Ctx) -> Result<()>;
}

#[async_trait]
pub trait Preprocess<Ctx> {
    /// Preprocesses the callstack.
    async fn preprocess(&mut self, ctx: &mut Ctx) -> Result<()>;
}

#[async_trait]
pub trait Execute<Ctx> {
    /// Executes the callstack.
    async fn execute(&mut self, ctx: &mut Ctx) -> Result<()>;
}
