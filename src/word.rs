pub trait Word:
    std::cmp::PartialEq
    + std::fmt::Debug
    + Copy
    + num::traits::WrappingAdd
    + num::traits::WrappingSub
    + num::traits::WrappingShl
    + num::traits::WrappingShr
    + std::ops::BitAnd<Output = Self>
    + std::ops::BitOr<Output = Self>
    + std::ops::BitXor<Output = Self>
    + std::ops::Shl<Output = Self>
    + std::ops::Shr<Output = Self>
{
    const ZERO: Self;
    const BYTES: usize;
    const P: Self;
    const Q: Self;

    fn from_usize(val: usize) -> Self;
    fn from_u8(val: u8) -> Self;
}

impl Word for u8 {
    const ZERO: Self = 0u8;
    const BYTES: usize = 1;
    const P: Self = 0xB7u8;
    const Q: Self = 0x9Fu8;

    fn from_usize(val: usize) -> Self {
        val as Self
    }

    fn from_u8(val: u8) -> Self {
        val as Self
    }
}

impl Word for u16 {
    const ZERO: Self = 0u16;
    const BYTES: usize = 2;
    const P: Self = 0xB7E1u16;
    const Q: Self = 0x9E37u16;

    fn from_usize(val: usize) -> Self {
        val as Self
    }

    fn from_u8(val: u8) -> Self {
        val as Self
    }
}

impl Word for u32 {
    const ZERO: Self = 0u32;
    const BYTES: usize = 4;
    const P: Self = 0xB7E15163u32;
    const Q: Self = 0x9E3779B9u32;

    fn from_usize(val: usize) -> Self {
        val as Self
    }

    fn from_u8(val: u8) -> Self {
        val as Self
    }
}

impl Word for u64 {
    const ZERO: Self = 0u64;
    const BYTES: usize = 8;
    const P: Self = 0xB7E151628AED2A6Bu64;
    const Q: Self = 0x9E3779B97F4A7C15u64;

    fn from_usize(val: usize) -> Self {
        val as Self
    }

    fn from_u8(val: u8) -> Self {
        val as Self
    }
}

impl Word for u128 {
    const ZERO: Self = 0u128;
    const BYTES: usize = 16;
    const P: Self = 0xB7E151628AED2A6ABF7158809CF4F3C7u128;
    const Q: Self = 0x9E3779B97F4A7C15F39CC0605CEDC835u128;

    fn from_usize(val: usize) -> Self {
        val as Self
    }

    fn from_u8(val: u8) -> Self {
        val as Self
    }
}
