use std::{
    fmt::Debug,
    ops::{Add, Mul, Neg},
};

pub trait MultiplicativeInverse {
    fn inverse(&self) -> Self;
}

pub trait HasNeutral {
    fn neutral() -> Self;
}

pub trait HasGenerator {
    fn generator() -> &'static Self;
}

pub trait CanReduceHash {
    fn reduce_hash(hash: &[u8; 32]) -> Self;
}

pub trait FromLeBytes {
    fn from_le_bytes(bytes: &[u8]) -> Option<Self>
    where
        Self: Sized;
}

pub trait ToLeBytes {
    fn to_le_bytes(&self) -> Vec<u8>;
}

pub trait HasSqrt: Sized {
    fn sqrt(&self) -> Option<Self>;
}

pub trait IsOdd {
    fn is_odd(&self) -> bool;
}

pub trait CheckedAdd: Sized {
    fn checked_add(&self, rhs: &Self) -> Option<Self>;
}

/// Trait defining the operations required for an elliptic curve
pub trait EllipticCurve:
    Clone
    + Copy
    + Debug
    + Add<Output = Self>
    + Mul<Self::Scalar, Output = Self>
    + HasGenerator
    + HasNeutral
{
    /// The scalar field type
    type Scalar: Clone
        + Copy
        + Debug
        + Default
        + Eq
        + Mul<Output = <Self as EllipticCurve>::Scalar>
        + for<'a> Mul<&'a <Self as EllipticCurve>::Scalar, Output = <Self as EllipticCurve>::Scalar>
        + MultiplicativeInverse
        + ToLeBytes
        + Neg<Output = Self::Scalar>;

    type Uint: CheckedAdd + FromLeBytes + ToLeBytes;

    /// Extracts the x-coordinate as a scalar value
    fn get_x_coord(&self) -> Self::Scalar;

    /// Reduces a hash value to a scalar
    fn reduce_hash(hash: &[u8; 32]) -> Self::Scalar;

    fn is_high(s: &Self::Scalar) -> bool;

    fn lin_comb(s1: &Self::Scalar, p1: &Self, s2: &Self::Scalar, p2: &Self) -> Self;

    fn decompress(bytes_le: &[u8], is_y_odd: bool) -> Option<Self>;

    const ORDER: Self::Uint;
}
