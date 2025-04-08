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

pub trait HasSqrt {
    fn sqrt(&self) -> Self;
}

pub trait IsOdd {
    fn is_odd(&self) -> bool;
}

/// Trait defining the operations required for an elliptic curve
pub trait EllipticCurve:
    Sized
    + Clone
    + Copy
    + Debug
    + Add<Output = Self>
    + Mul<Self::Scalar, Output = Self>
    + HasGenerator
    + HasNeutral
    + TryFrom<(Self::FieldElement, Self::FieldElement), Error: Debug>
{
    /// The scalar field type
    type Scalar: Clone
        + Debug
        + Default
        + Eq
        + Mul<Output = <Self as EllipticCurve>::Scalar>
        + MultiplicativeInverse
        + ToLeBytes
        + Neg<Output = Self::Scalar>;

    type FieldElement: Clone
        + Debug
        + Default
        + Eq
        + Neg<Output = Self::FieldElement>
        + Add<u64, Output = <Self as EllipticCurve>::FieldElement>
        + Add<Output = <Self as EllipticCurve>::FieldElement>
        + Mul<Output = <Self as EllipticCurve>::FieldElement>
        + MultiplicativeInverse
        + HasSqrt
        + FromLeBytes
        + IsOdd;

    /// Extracts the x-coordinate as a scalar value
    fn get_x_coord(&self) -> Self::Scalar;

    /// Reduces a hash value to a scalar
    fn reduce_hash(hash: &[u8; 32]) -> Self::Scalar;

    fn is_high(s: &Self::Scalar) -> bool;

    fn curve_order_as_fe() -> Self::FieldElement;

    fn lin_comb(s1: &Self::Scalar, p1: &Self, s2: &Self::Scalar, p2: &Self) -> Self;
}
