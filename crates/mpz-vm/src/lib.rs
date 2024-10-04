//! This crate provides an implementation of garbled circuit protocols to
//! facilitate MPC.

// #![deny(missing_docs, unreachable_pub, unused_must_use)]
// #![deny(clippy::all)]
// #![forbid(unsafe_code)]

use core::fmt;

use async_trait::async_trait;

use mpz_memory_core::{ClearValue, MemoryType, Repr, Slice, Vector};
use mpz_vm_core::{Call, DecodeFuture, DecodeFutureTyped};

/// The result type for a VM.
pub type Result<T> = core::result::Result<T, VmError>;

pub mod prelude {
    pub use crate::{
        AllocExt, AssignExt, Callable, CommitExt, DecodeExt, Execute, Preprocess, Synchronize,
        ViewExt,
    };
    pub use mpz_vm_core::Call;
}

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

pub trait Memory {
    type MemoryType: MemoryType;
}

/// This trait provides methods for interacting with values in memory.
pub trait Alloc: Memory {
    /// Allocates a new value.
    fn alloc_raw(&mut self, size: usize) -> Result<Slice>;
}

pub trait AllocExt: Alloc {
    fn alloc<T>(&mut self) -> Result<T>
    where
        T: Repr<Self::MemoryType>,
    {
        let slice = self.alloc_raw(T::SIZE)?;
        Ok(T::from_raw(slice))
    }
}

impl<T> AllocExt for T where T: Alloc {}

/// Configures the view of the memory.
pub trait View: Memory {
    /// Sets the slice of memory as public.
    fn configure_public_raw(&mut self, slice: Slice) -> Result<()>;

    /// Sets the slice of memory as private.
    fn configure_private_raw(&mut self, slice: Slice) -> Result<()>;

    /// Sets the slice of memory as blind.
    fn configure_blind_raw(&mut self, slice: Slice) -> Result<()>;
}

pub trait ViewExt: View {
    fn configure_public<T>(&mut self, value: T) -> Result<()>
    where
        T: Repr<Self::MemoryType>,
    {
        self.configure_public_raw(value.to_raw())
    }

    fn configure_private<T>(&mut self, value: T) -> Result<()>
    where
        T: Repr<Self::MemoryType>,
    {
        self.configure_private_raw(value.to_raw())
    }

    fn configure_blind<T>(&mut self, value: T) -> Result<()>
    where
        T: Repr<Self::MemoryType>,
    {
        self.configure_blind_raw(value.to_raw())
    }
}

impl<T> ViewExt for T where T: View {}

pub trait Assign: Memory {
    fn assign_raw(
        &mut self,
        raw: Slice,
        value: <Self::MemoryType as MemoryType>::Raw,
    ) -> Result<()>;
}

pub trait AssignExt: Assign {
    fn assign<T>(&mut self, value: T, clear: T::Clear) -> Result<()>
    where
        T: Repr<Self::MemoryType>,
    {
        self.assign_raw(value.to_raw(), clear.into_clear())
    }
}

impl<T> AssignExt for T where T: Assign {}

/// Commit memory.
pub trait Commit: Memory {
    /// Commits the slice of memory.
    fn commit_raw(&mut self, slice: Slice) -> Result<()>;
}

pub trait CommitExt: Commit {
    fn commit<T>(&mut self, value: T) -> Result<()>
    where
        T: Repr<Self::MemoryType>,
    {
        self.commit_raw(value.to_raw())
    }
}

impl<T> CommitExt for T where T: Commit {}

pub trait Callable {
    /// Calls a circuit with the provided inputs, returning the output.
    fn call(&mut self, call: Call) -> Result<Slice>;
}

pub trait Decode: Memory {
    /// Decodes a value from memory.
    ///
    /// Returns a future which will resolve to the value when it is ready.
    fn decode_raw(
        &mut self,
        raw: Slice,
    ) -> Result<DecodeFuture<<Self::MemoryType as MemoryType>::Raw>>;
}

pub trait DecodeExt: Decode {
    fn decode<T>(
        &mut self,
        raw: Slice,
    ) -> Result<DecodeFutureTyped<<Self::MemoryType as MemoryType>::Raw, T::Clear>>
    where
        T: Repr<Self::MemoryType>,
    {
        self.decode_raw(raw).map(|fut| {
            DecodeFutureTyped::new(fut, <T::Clear as ClearValue<Self::MemoryType>>::from_clear)
        })
    }
}

impl<T> DecodeExt for T where T: Decode {}

#[async_trait]
pub trait Synchronize<Ctx> {
    /// Synchronizes the state of the VM.
    async fn sync(&mut self, ctx: &mut Ctx) -> Result<()>;
}

#[async_trait]
pub trait MemorySync<Ctx> {
    /// Synchronizes the memory of all parties.
    async fn sync_memory(&mut self, ctx: &mut Ctx) -> Result<()>;
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
