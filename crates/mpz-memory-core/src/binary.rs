use itybity::{FromBitIterator, IntoBitIterator, IntoBits};
use mpz_core::bitvec::BitVec;

use crate::{ClearValue, FromRaw, MemoryType, Ptr, Repr, Slice, StaticSize, ToRaw};

pub struct Binary;

impl MemoryType for Binary {
    type Raw = BitVec;
}

macro_rules! impl_uint {
    ($ty:ty, $ident:ident, $size:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $ident(Ptr);

        impl Repr<Binary> for $ident {
            type Clear = $ty;
        }

        impl StaticSize<Binary> for $ty {
            const SIZE: usize = $size;
        }

        impl<const N: usize> StaticSize<Binary> for [$ty; N] {
            const SIZE: usize = $size * N;
        }

        impl StaticSize<Binary> for $ident {
            const SIZE: usize = $size;
        }

        impl<const N: usize> StaticSize<Binary> for [$ident; N] {
            const SIZE: usize = $size * N;
        }

        impl FromRaw<Binary> for $ident {
            fn from_raw(slice: Slice) -> Self {
                Self(slice.ptr)
            }
        }

        impl ToRaw for $ident {
            fn to_raw(&self) -> Slice {
                Slice::new_unchecked(self.0, Self::SIZE)
            }
        }

        impl ClearValue<Binary> for $ty {
            fn into_clear(self) -> BitVec {
                BitVec::from_iter(self.into_iter_lsb0())
            }

            fn from_clear(value: BitVec) -> Self {
                debug_assert_eq!(value.len(), $size);
                <$ty>::from_lsb0_iter(value.iter().by_vals())
            }
        }

        impl<const N: usize> ClearValue<Binary> for [$ty; N] {
            fn into_clear(self) -> BitVec {
                BitVec::from_iter(self.into_iter_lsb0())
            }

            fn from_clear(value: BitVec) -> Self {
                debug_assert_eq!(value.len(), $size * N);
                Self::from_lsb0_iter(value.iter().by_vals())
            }
        }
    };
}

impl_uint!(u8, U8, 8);
impl_uint!(u16, U16, 16);
impl_uint!(u32, U32, 32);
impl_uint!(u64, U64, 64);
impl_uint!(u128, U128, 128);

impl<T, U> ClearValue<Binary> for (T, U)
where
    T: ClearValue<Binary> + StaticSize<Binary>,
    U: ClearValue<Binary> + StaticSize<Binary>,
{
    fn into_clear(self) -> BitVec {
        let (a, b) = (self.0.into_clear(), self.1.into_clear());
        let mut value = BitVec::with_capacity(a.len() + b.len());
        value.extend_from_bitslice(&a);
        value.extend_from_bitslice(&b);
        value
    }

    fn from_clear(value: BitVec) -> Self {
        let a = T::from_clear(value[..T::SIZE].to_bitvec());
        let b = U::from_clear(value[T::SIZE..].to_bitvec());
        (a, b)
    }
}
