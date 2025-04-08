use std::ops::{Add, Mul, Neg};

use ff::PrimeField;
use k256::FieldElement;

use crate::elliptic_curve::{FromLeBytes, HasSqrt, IsOdd, MultiplicativeInverse};

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct Secp256k1FieldElement(pub(crate) FieldElement);

impl Secp256k1FieldElement {
    #[inline(always)]
    pub fn to_repr(&self) -> [u8; 32] {
        let mut repr: [u8; 32] = self.0.to_repr().into();
        repr.reverse();
        repr
    }

    #[inline(always)]
    pub fn from_repr(bytes: &[u8; 32]) -> Option<Self> {
        let mut repr = bytes.clone();
        repr.reverse();
        FieldElement::from_bytes(&repr.into())
            .into_option()
            .map(Secp256k1FieldElement)
    }
}

impl IsOdd for Secp256k1FieldElement {
    #[inline(always)]
    fn is_odd(&self) -> bool {
        self.0.normalize().is_odd().into()
    }
}

impl FromLeBytes for Secp256k1FieldElement {
    #[inline(always)]
    fn from_le_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }

        let bytes_be: [u8; 32] = bytes.try_into().unwrap();
        Secp256k1FieldElement::from_repr(&bytes_be)
    }
}

impl MultiplicativeInverse for Secp256k1FieldElement {
    #[inline(always)]
    fn inverse(&self) -> Self {
        Secp256k1FieldElement(self.0.invert().unwrap())
    }
}

impl Add for Secp256k1FieldElement {
    type Output = Secp256k1FieldElement;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        Secp256k1FieldElement(&self.0 + &rhs.0)
    }
}

impl Add<u64> for Secp256k1FieldElement {
    type Output = Secp256k1FieldElement;

    #[inline(always)]
    fn add(self, rhs: u64) -> Self::Output {
        Secp256k1FieldElement(&self.0 + &FieldElement::from(rhs))
    }
}

impl Mul for Secp256k1FieldElement {
    type Output = Secp256k1FieldElement;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        Secp256k1FieldElement(&self.0 * &rhs.0)
    }
}

impl Mul<&Secp256k1FieldElement> for Secp256k1FieldElement {
    type Output = Secp256k1FieldElement;

    #[inline(always)]
    fn mul(self, rhs: &Self) -> Self::Output {
        Secp256k1FieldElement(&self.0 * &rhs.0)
    }
}

impl HasSqrt for Secp256k1FieldElement {
    #[inline(always)]
    fn sqrt(&self) -> Option<Self> {
        self.0.sqrt().into_option().map(Secp256k1FieldElement)
    }
}

impl Neg for Secp256k1FieldElement {
    type Output = Secp256k1FieldElement;

    #[inline(always)]
    fn neg(self) -> Self::Output {
        Secp256k1FieldElement(-self.0.normalize())
    }
}
