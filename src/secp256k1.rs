use crate::elliptic_curve::{
    CheckedAdd, EllipticCurve, FromLeBytes, HasGenerator, HasNeutral, HasSqrt, IsOdd, ToLeBytes,
};
use k256::{
    elliptic_curve::{bigint::ArrayEncoding, Curve},
    Secp256k1, U256,
};
use std::{
    fmt::Debug,
    ops::{Add, Mul},
};
use valida_intrinsics as intrinsics;
pub mod base_field;
pub use base_field::*;
pub mod scalar_field;
pub use scalar_field::*;
mod constants;
use constants::*;

impl Mul<Secp256k1Scalar> for Secp256k1Point {
    type Output = Secp256k1Point;

    fn mul(self, rhs: Secp256k1Scalar) -> Self::Output {
        let mut copied = self;
        intrinsics::smul_secp256k1(&rhs.0, &mut copied.0);
        copied
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Secp256k1Point(intrinsics::Secp256k1Point);

impl Secp256k1Point {
    pub fn create(x_bytes: [u8; 32], y_bytes: [u8; 32]) -> Option<Self> {
        let x = Secp256k1FieldElement::from_repr(&x_bytes)?;
        let y = Secp256k1FieldElement::from_repr(&y_bytes)?;

        let lhs = y * &y;
        let rhs = x * &x * &x + 7 as u64;

        let satisfies_equation = lhs.0.normalize() == rhs.0.normalize();

        if satisfies_equation {
            Some(Secp256k1Point(intrinsics::Secp256k1Point {
                x: x_bytes,
                y: y_bytes,
            }))
        } else {
            None
        }
    }

    pub fn to_repr(&self) -> ([u8; 32], [u8; 32]) {
        (self.0.x, self.0.y)
    }
}

impl Add for Secp256k1Point {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        const ONE: [u8; 32] = {
            let mut x: [u8; 32] = [0; 32];
            x[0] = 1;
            x
        };

        let arg_1 = intrinsics::Secp256k1Comb {
            point: self.0,
            scalar: intrinsics::Secp256k1Scalar { value: ONE },
        };

        let mut arg_2 = intrinsics::Secp256k1Comb {
            point: rhs.0,
            scalar: intrinsics::Secp256k1Scalar { value: ONE },
        };

        intrinsics::comb_secp256k1(&arg_1, &mut arg_2);
        Secp256k1Point(arg_2.point)
    }
}

impl HasNeutral for Secp256k1Point {
    #[inline(always)]
    fn neutral() -> Self {
        Default::default()
    }
}

const GENERATOR: Secp256k1Point = Secp256k1Point(intrinsics::Secp256k1Point {
    x: R_GEN.0,
    y: R_GEN.1,
});

impl HasGenerator for Secp256k1Point {
    #[inline(always)]
    fn generator() -> &'static Self {
        &GENERATOR
    }
}

impl TryFrom<(Secp256k1FieldElement, Secp256k1FieldElement)> for Secp256k1Point {
    type Error = ();

    #[inline(always)]
    fn try_from(
        value: (Secp256k1FieldElement, Secp256k1FieldElement),
    ) -> Result<Self, Self::Error> {
        let x = value.0.to_repr();
        let y = value.1.to_repr();

        Ok(Secp256k1Point(intrinsics::Secp256k1Point { x, y }))
    }
}

impl CheckedAdd for U256 {
    #[inline(always)]
    fn checked_add(&self, rhs: &Self) -> Option<Self> {
        k256::elliptic_curve::bigint::CheckedAdd::checked_add(self, rhs).into_option()
    }
}

impl FromLeBytes for U256 {
    #[inline(always)]
    fn from_le_bytes(bytes: &[u8]) -> Option<Self>
    where
        Self: Sized,
    {
        Some(U256::from_le_slice(bytes))
    }
}

impl ToLeBytes for U256 {
    #[inline(always)]
    fn to_le_bytes(&self) -> Vec<u8> {
        self.to_le_byte_array().to_vec()
    }
}

impl EllipticCurve for Secp256k1Point {
    type Scalar = Secp256k1Scalar;
    type Uint = U256;

    #[inline(always)]
    fn get_x_coord(&self) -> Self::Scalar {
        scalar_reduce(&self.0.x)
    }

    #[inline(always)]
    fn reduce_hash(hash: &[u8; 32]) -> Self::Scalar {
        let mut r: intrinsics::Secp256k1Scalar = Default::default();

        // Read big-endian 32-bit words from the input
        let mut b32_copied = *hash;
        b32_copied.reverse();
        r.value = b32_copied;

        scalar_reduce(&r.value)
    }

    #[inline(always)]
    fn is_high(s: &Self::Scalar) -> bool {
        s.is_high()
    }

    #[inline(always)]
    fn lin_comb(s1: &Self::Scalar, p1: &Self, s2: &Self::Scalar, p2: &Self) -> Self {
        let arg_1 = intrinsics::Secp256k1Comb {
            point: p1.0,
            scalar: s1.0,
        };
        let mut arg_2 = intrinsics::Secp256k1Comb {
            point: p2.0,
            scalar: s2.0,
        };
        intrinsics::comb_secp256k1(&arg_1, &mut arg_2);

        Secp256k1Point(arg_2.point)
    }

    #[inline(always)]
    fn decompress(bytes_le: &[u8], is_y_odd: bool) -> Option<Self> {
        let fx = Secp256k1FieldElement::from_le_bytes(bytes_le)?;

        let y_squared = fx * &fx * &fx + 7 as u64;
        let y_r = y_squared.sqrt()?;

        let y = if y_r.is_odd() != is_y_odd { -y_r } else { y_r };

        Self::try_from((fx, y)).ok()
    }

    const ORDER: Self::Uint = Secp256k1::ORDER;
}

#[cfg(test)]
mod tests {
    use crate::elliptic_curve::FromLeBytes;
    use crate::elliptic_curve::MultiplicativeInverse;

    use super::Secp256k1Point as P;
    use super::Secp256k1Scalar as S;
    use super::*;

    #[test]
    fn add_neutral_to_generator() {
        assert_eq!(*P::generator() + P::neutral(), *P::generator());
    }

    #[test]
    fn add_gen_to_itself_and_compare_against_scalar_multiplication() {
        let mut two: [u8; 32] = [0; 32];
        two[0] = 2;

        assert_eq!(
            *P::generator() + *P::generator(),
            *P::generator() * S::from_le_bytes(&two).unwrap()
        );
    }

    #[test]
    fn invert_two() {
        let mut two: [u8; 32] = [0; 32];
        two[0] = 2;

        let mut one: [u8; 32] = [0; 32];
        one[0] = 1;

        let one = S::from_le_bytes(&one).unwrap();
        let two = S::from_le_bytes(&two).unwrap();
        let two_inv = two.inverse();

        assert_eq!(two * two_inv, one);
    }
}
