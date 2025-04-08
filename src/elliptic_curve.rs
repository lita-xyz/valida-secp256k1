use std::fmt::Debug;

/// Trait defining the operations required for an elliptic curve
pub trait EllipticCurve: Sized + Clone + Debug {
    /// The scalar field type
    type Scalar: Clone + Debug + Default + Eq;

    /// Returns the neutral element (point at infinity)
    fn neutral() -> Self;

    /// Returns the generator point
    fn generator() -> Self;

    /// Computes scalar multiplication (k * P)
    fn scalar_mul(&self, k: &Self::Scalar) -> Self;

    /// Computes scalar modular inverse (k^-1 mod n)
    fn scalar_inverse(k: &Self::Scalar) -> Self::Scalar;

    /// Adds two points on the curve
    fn add(&self, other: &Self) -> Self;

    /// Extracts the x-coordinate as a scalar value
    fn get_x_coord(&self) -> Self::Scalar;

    /// Computes the modular multiplication of scalars
    fn scalar_mul_mod(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar;

    /// Reduces a hash value to a scalar
    fn reduce_hash(hash: &[u8; 32]) -> Self::Scalar;

    fn is_high(s: &Self::Scalar) -> bool;
}
