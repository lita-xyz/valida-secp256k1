use crate::elliptic_curve::{FromLeBytes, MultiplicativeInverse, ToLeBytes};
use ff::PrimeField;
use k256::{
    elliptic_curve::{
        bigint::{ArrayEncoding, Encoding},
        ops::Reduce,
        Curve,
    },
    Scalar, Secp256k1, U256,
};
use std::ops::{Mul, Neg};
use valida_intrinsics as intrinsics;

const FRAC_MODULUS_2: U256 = Secp256k1::ORDER.shr_vartime(1);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Secp256k1Scalar(pub(crate) intrinsics::Secp256k1Scalar);

impl Secp256k1Scalar {
    #[inline(always)]
    pub fn is_high(&self) -> bool {
        let u256 = U256::from_le_slice(&self.0.value);
        u256 > FRAC_MODULUS_2
    }
}

impl Mul for Secp256k1Scalar {
    type Output = Self;

    #[inline(always)]
    fn mul(mut self, rhs: Self) -> Self::Output {
        intrinsics::muls_secp256k1(&rhs.0, &mut self.0);
        self
    }
}

impl Mul<&Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Self;

    #[inline(always)]
    fn mul(mut self, rhs: &Self) -> Self::Output {
        intrinsics::muls_secp256k1(&rhs.0, &mut self.0);
        self
    }
}

impl MultiplicativeInverse for Secp256k1Scalar {
    #[inline(always)]
    fn inverse(&self) -> Self {
        let mut copied = *self;
        intrinsics::sinv_secp256k1(&mut copied.0);
        copied
    }
}

#[inline(always)]
pub fn scalar_reduce(s: &[u8; 32]) -> Secp256k1Scalar {
    let value = U256::from_le_slice(s);
    let scalar = Scalar::reduce(value);
    let u256: U256 = scalar.into();
    Secp256k1Scalar(intrinsics::Secp256k1Scalar {
        value: u256.to_le_byte_array().into(),
    })
}

impl Secp256k1Scalar {
    #[inline(always)]
    pub fn create(value: [u8; 32]) -> Option<Self> {
        let u256 = U256::from_le_slice(&value);
        if u256 < Secp256k1::ORDER {
            Some(Secp256k1Scalar(intrinsics::Secp256k1Scalar { value }))
        } else {
            None
        }
    }
}

impl FromLeBytes for Secp256k1Scalar {
    #[inline(always)]
    fn from_le_bytes(value: &[u8]) -> Option<Self> {
        let u256 = U256::from_le_slice(&value);
        if u256 < Secp256k1::ORDER {
            Some(Secp256k1Scalar(intrinsics::Secp256k1Scalar {
                value: value.try_into().ok()?,
            }))
        } else {
            None
        }
    }
}

impl ToLeBytes for Secp256k1Scalar {
    #[inline(always)]
    fn to_le_bytes(&self) -> Vec<u8> {
        self.0.value.to_vec()
    }
}

impl Neg for Secp256k1Scalar {
    type Output = Secp256k1Scalar;

    #[inline(always)]
    fn neg(self) -> Self::Output {
        let u256 = U256::from_le_slice(&self.0.value);
        let bytes = u256.to_be_bytes();
        let scalar = Scalar::from_repr(bytes.into()).unwrap();
        let scalar = -scalar;
        let u256: U256 = scalar.into();
        Secp256k1Scalar(intrinsics::Secp256k1Scalar {
            value: u256.to_le_byte_array().into(),
        })
    }
}
