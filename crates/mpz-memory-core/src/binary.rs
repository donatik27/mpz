use itybity::{FromBitIterator, IntoBitIterator, IntoBits};
use mpz_core::bitvec::BitVec;

use crate::{ClearValue, FromRaw, MemoryType, Ptr, Repr, Slice, ToRaw};

pub struct Binary;

impl MemoryType for Binary {
    type Raw = BitVec;
}

/// An unsigned 8-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U8(Ptr);

impl ClearValue<Binary> for u8 {
    fn into_clear(self) -> BitVec {
        BitVec::from_iter(self.into_iter_lsb0())
    }

    fn from_clear(value: BitVec) -> Self {
        debug_assert_eq!(value.len(), 8);
        u8::from_lsb0_iter(value.iter().by_vals())
    }
}

impl FromRaw for U8 {
    fn from_raw(slice: Slice) -> Self {
        Self(slice.ptr)
    }
}

impl ToRaw for U8 {
    fn to_raw(&self) -> Slice {
        Slice::new_unchecked(self.0, Self::SIZE)
    }
}

impl<const N: usize> ClearValue<Binary> for [u8; N] {
    fn into_clear(self) -> BitVec {
        BitVec::from_iter(self.into_iter_lsb0())
    }

    fn from_clear(value: BitVec) -> Self {
        debug_assert_eq!(value.len(), 8 * N);
        Self::from_lsb0_iter(value.iter().by_vals())
    }
}

impl Repr<Binary> for U8 {
    const SIZE: usize = 8;
    type Clear = u8;
}

/// An unsigned 16-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U16(Ptr);

impl ClearValue<Binary> for u16 {
    fn into_clear(self) -> BitVec {
        BitVec::from_iter(self.into_iter_lsb0())
    }

    fn from_clear(value: BitVec) -> Self {
        debug_assert_eq!(value.len(), 16);
        u16::from_lsb0_iter(value.iter().by_vals())
    }
}

impl FromRaw for U16 {
    fn from_raw(slice: Slice) -> Self {
        Self(slice.ptr)
    }
}

impl ToRaw for U16 {
    fn to_raw(&self) -> Slice {
        Slice::new_unchecked(self.0, Self::SIZE)
    }
}

impl<const N: usize> ClearValue<Binary> for [u16; N] {
    fn into_clear(self) -> BitVec {
        BitVec::from_iter(self.into_iter_lsb0())
    }

    fn from_clear(value: BitVec) -> Self {
        debug_assert_eq!(value.len(), 16 * N);
        Self::from_lsb0_iter(value.iter().by_vals())
    }
}

impl Repr<Binary> for U16 {
    const SIZE: usize = 16;
    type Clear = u16;
}

/// An unsigned 32-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U32(Ptr);

impl ClearValue<Binary> for u32 {
    fn into_clear(self) -> BitVec {
        BitVec::from_iter(self.into_iter_lsb0())
    }

    fn from_clear(value: BitVec) -> Self {
        debug_assert_eq!(value.len(), 32);
        u32::from_lsb0_iter(value.iter().by_vals())
    }
}

impl FromRaw for U32 {
    fn from_raw(slice: Slice) -> Self {
        Self(slice.ptr)
    }
}

impl ToRaw for U32 {
    fn to_raw(&self) -> Slice {
        Slice::new_unchecked(self.0, Self::SIZE)
    }
}

impl Repr<Binary> for U32 {
    const SIZE: usize = 32;
    type Clear = u32;
}

impl<const N: usize> ClearValue<Binary> for [u32; N] {
    fn into_clear(self) -> BitVec {
        BitVec::from_iter(self.into_iter_lsb0())
    }

    fn from_clear(value: BitVec) -> Self {
        debug_assert_eq!(value.len(), 32 * N);
        Self::from_lsb0_iter(value.iter().by_vals())
    }
}

/// An unsigned 64-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U64(Ptr);

impl ClearValue<Binary> for u64 {
    fn into_clear(self) -> BitVec {
        BitVec::from_iter(self.into_iter_lsb0())
    }

    fn from_clear(value: BitVec) -> Self {
        debug_assert_eq!(value.len(), 64);
        u64::from_lsb0_iter(value.iter().by_vals())
    }
}

impl<const N: usize> ClearValue<Binary> for [u64; N] {
    fn into_clear(self) -> BitVec {
        BitVec::from_iter(self.into_iter_lsb0())
    }

    fn from_clear(value: BitVec) -> Self {
        debug_assert_eq!(value.len(), 64 * N);
        Self::from_lsb0_iter(value.iter().by_vals())
    }
}

impl FromRaw for U64 {
    fn from_raw(slice: Slice) -> Self {
        Self(slice.ptr)
    }
}

impl ToRaw for U64 {
    fn to_raw(&self) -> Slice {
        Slice::new_unchecked(self.0, Self::SIZE)
    }
}

impl Repr<Binary> for U64 {
    const SIZE: usize = 64;
    type Clear = u64;
}

/// An unsigned 128-bit integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U128(Ptr);

impl ClearValue<Binary> for u128 {
    fn into_clear(self) -> BitVec {
        BitVec::from_iter(self.into_iter_lsb0())
    }

    fn from_clear(value: BitVec) -> Self {
        debug_assert_eq!(value.len(), 128);
        u128::from_lsb0_iter(value.iter().by_vals())
    }
}

impl FromRaw for U128 {
    fn from_raw(slice: Slice) -> Self {
        Self(slice.ptr)
    }
}

impl ToRaw for U128 {
    fn to_raw(&self) -> Slice {
        Slice::new_unchecked(self.0, Self::SIZE)
    }
}

impl<const N: usize> ClearValue<Binary> for [u128; N] {
    fn into_clear(self) -> BitVec {
        BitVec::from_iter(self.into_iter_lsb0())
    }

    fn from_clear(value: BitVec) -> Self {
        debug_assert_eq!(value.len(), 128 * N);
        Self::from_lsb0_iter(value.iter().by_vals())
    }
}

impl Repr<Binary> for U128 {
    const SIZE: usize = 128;
    type Clear = u128;
}
