pub mod binary;
pub mod correlated;
pub mod store;
pub mod view;

use core::fmt;
use std::{
    marker::PhantomData,
    ops::{Index, IndexMut},
};

use mpz_core::bitvec::{BitSlice, BitVec};
use serde::{Deserialize, Serialize};

pub(crate) type RangeSet = utils::range::RangeSet<usize>;
pub(crate) type Range = std::ops::Range<usize>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignKind {
    Public,
    Private,
    Blind,
}

/// Memory pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Ptr(usize);

impl Ptr {
    pub(crate) fn new(ptr: usize) -> Self {
        Self(ptr)
    }

    /// Returns the pointer as a `usize`.
    pub fn as_usize(&self) -> usize {
        self.0 as usize
    }
}

impl fmt::Display for Ptr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}", self.0)
    }
}

pub trait MemoryType {
    /// Raw memory type.
    type Raw;
}

pub trait ToRaw {
    /// Returns the underlying raw memory slice.
    fn to_raw(&self) -> Slice;
}

pub trait FromRaw {
    /// Creates a new value from a raw memory slice.
    fn from_raw(slice: Slice) -> Self;
}

pub trait Repr<T: MemoryType>: FromRaw + ToRaw {
    const SIZE: usize;
    type Clear: ClearValue<T>;
}

pub trait ClearValue<T: MemoryType> {
    /// Converts `self` into a raw clear value.
    fn into_clear(self) -> T::Raw;

    /// Converts a raw clear value into `Self`.
    fn from_clear(value: T::Raw) -> Self;
}

/// A slice of contiguous memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Slice {
    ptr: Ptr,
    size: usize,
}

impl Slice {
    /// Creates a new slice.
    ///
    /// Do not use this unless you know what you're doing. It will cause bugs
    /// and break security.
    #[inline]
    pub fn new_unchecked(ptr: Ptr, size: usize) -> Self {
        Self { ptr, size }
    }

    /// Creates a new slice from a range.
    ///
    /// Do not use this unless you know what you're doing. It will cause bugs
    /// and break security.
    #[inline]
    pub fn from_range_unchecked(range: Range) -> Self {
        Self {
            ptr: Ptr::new(range.start),
            size: range.len(),
        }
    }

    /// Returns a pointer to the start of slice.
    #[inline]
    pub fn ptr(&self) -> Ptr {
        self.ptr
    }

    /// Returns the length of the slice.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Returns the memory range of the slice.
    #[inline]
    pub fn to_range(&self) -> Range {
        self.ptr.as_usize()..self.ptr.as_usize() + self.size
    }

    /// Returns a `RangeSet` of the slices.
    pub fn to_rangeset(slices: impl IntoIterator<Item = Self>) -> RangeSet {
        RangeSet::from(
            slices
                .into_iter()
                .map(|slice| slice.to_range())
                .collect::<Vec<_>>(),
        )
    }
}

impl fmt::Display for Slice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Slice {{ ptr: {}, size: {} }}", self.ptr, self.size)
    }
}

impl From<Slice> for Range {
    fn from(slice: Slice) -> Self {
        slice.to_range()
    }
}

impl<T> Index<Slice> for [T] {
    type Output = [T];

    fn index(&self, index: Slice) -> &Self::Output {
        &self[index.to_range()]
    }
}

impl<T> Index<Slice> for Vec<T> {
    type Output = [T];

    fn index(&self, index: Slice) -> &Self::Output {
        &self[index.to_range()]
    }
}

impl<T> IndexMut<Slice> for [T] {
    fn index_mut(&mut self, index: Slice) -> &mut Self::Output {
        &mut self[index.to_range()]
    }
}

impl<T> IndexMut<Slice> for Vec<T> {
    fn index_mut(&mut self, index: Slice) -> &mut Self::Output {
        &mut self[index.to_range()]
    }
}

impl Index<Slice> for BitVec {
    type Output = BitSlice;

    fn index(&self, index: Slice) -> &Self::Output {
        &self[index.to_range()]
    }
}

impl IndexMut<Slice> for BitVec {
    fn index_mut(&mut self, index: Slice) -> &mut Self::Output {
        &mut self[index.to_range()]
    }
}

/// An array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Array<T, const N: usize> {
    slice: Slice,
    _pd: PhantomData<T>,
}

impl<T, const N: usize> FromRaw for Array<T, N> {
    fn from_raw(slice: Slice) -> Self {
        Self {
            slice,
            _pd: PhantomData,
        }
    }
}

impl<T, const N: usize> ToRaw for Array<T, N> {
    fn to_raw(&self) -> Slice {
        self.slice
    }
}

impl<T, R, const N: usize> Repr<R> for Array<T, N>
where
    T: Repr<R>,
    R: MemoryType,
    [T::Clear; N]: ClearValue<R>,
{
    const SIZE: usize = T::SIZE * N;
    type Clear = [T::Clear; N];
}

/// A vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vector<T> {
    ptr: Ptr,
    len: usize,
    _pd: PhantomData<T>,
}
