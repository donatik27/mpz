use crate::{ClearRepr, Ptr, StaticSize, ToRaw};

/// Type of a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Type {
    U8,
    U16,
    U32,
    U64,
    U128,
}

/// Clear value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
}

/// An unsigned 8-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U8(Ptr);

impl StaticSize for U8 {
    const SIZE: usize = 1;
}

impl ToRaw for U8 {
    fn to_raw(&self) -> Ptr {
        self.0
    }
}

impl ClearRepr for U8 {
    type Repr = u8;
}

/// An unsigned 16-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U16(Ptr);

impl StaticSize for U16 {
    const SIZE: usize = 2;
}

impl ToRaw for U16 {
    fn to_raw(&self) -> Ptr {
        self.0
    }
}

impl ClearRepr for U16 {
    type Repr = u16;
}

/// An unsigned 32-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U32(Ptr);

impl StaticSize for U32 {
    const SIZE: usize = 4;
}

impl ToRaw for U32 {
    fn to_raw(&self) -> Ptr {
        self.0
    }
}

impl ClearRepr for U32 {
    type Repr = u32;
}

/// An unsigned 64-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U64(Ptr);

impl StaticSize for U64 {
    const SIZE: usize = 8;
}

impl ToRaw for U64 {
    fn to_raw(&self) -> Ptr {
        self.0
    }
}

impl ClearRepr for U64 {
    type Repr = u64;
}

/// An unsigned 128-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U128(Ptr);

impl StaticSize for U128 {
    const SIZE: usize = 16;
}

impl ToRaw for U128 {
    fn to_raw(&self) -> Ptr {
        self.0
    }
}

impl ClearRepr for U128 {
    type Repr = u128;
}
