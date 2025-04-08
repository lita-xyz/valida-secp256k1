use lazy_static::lazy_static;
use num_bigint::BigUint;
use num_traits::ops::euclid::Euclid;
use std::fmt::Debug;

use crate::elliptic_curve::EllipticCurve;
use valida_intrinsics as intrinsics;

lazy_static! {
    static ref SCALAR_ORDER: BigUint = {
        BigUint::parse_bytes(
            b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        .unwrap()
    };
}

lazy_static! {
    static ref FRAC_SCALAR_ORDER_2: BigUint = SCALAR_ORDER.div_euclid(&BigUint::from(2 as u32));
}

lazy_static! {
    static ref BASE_FIELD: BigUint = {
        BigUint::parse_bytes(
            b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .unwrap()
    };
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Secp256k1Scalar(intrinsics::Secp256k1Scalar);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Secp256k1Point(intrinsics::Secp256k1Point);

fn scalar_reduce(s: &intrinsics::Secp256k1Scalar) -> intrinsics::Secp256k1Scalar {
    let value = BigUint::from_bytes_le(&s.value);

    let r = value.rem_euclid(&SCALAR_ORDER);
    let value: [u8; 32] = r.to_bytes_le().try_into().unwrap();

    intrinsics::Secp256k1Scalar { value }
}

impl Secp256k1Scalar {
    pub fn create(value: [u8; 32]) -> Option<Self> {
        let value_as_biguint = BigUint::from_bytes_le(&value);
        if value_as_biguint < *SCALAR_ORDER {
            Some(Secp256k1Scalar(intrinsics::Secp256k1Scalar { value }))
        } else {
            None
        }
    }
}

impl Secp256k1Point {
    pub fn create(x_bytes: [u8; 32], y_bytes: [u8; 32]) -> Option<Self> {
        let x = BigUint::from_bytes_le(&x_bytes);
        let y = BigUint::from_bytes_le(&y_bytes);

        let lhs = &y * &y;
        let rhs = &x * &x * &x + BigUint::from(7 as u8);

        let satisfies_equation = lhs.rem_euclid(&BASE_FIELD) == rhs.rem_euclid(&BASE_FIELD);

        if satisfies_equation {
            Some(Secp256k1Point(intrinsics::Secp256k1Point {
                x: x_bytes,
                y: y_bytes,
            }))
        } else {
            None
        }
    }
}

const R_GEN: ([u8; 32], [u8; 32]) = {
    match (
        const_hex::const_decode_to_array(
            b"0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        ),
        const_hex::const_decode_to_array(
            b"0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        ),
    ) {
        (Ok(a), Ok(b)) => ({ a }, { b }),
        _ => panic!("Failed to decode hex values"),
    }
};

impl EllipticCurve for Secp256k1Point {
    type Scalar = Secp256k1Scalar;

    fn neutral() -> Self {
        Default::default()
    }

    fn generator() -> Self {
        Secp256k1Point(intrinsics::Secp256k1Point {
            x: {
                let mut v = R_GEN.0.clone();
                v.reverse();
                v
            },
            y: {
                let mut v = R_GEN.1.clone();
                v.reverse();
                v
            },
        })
    }

    fn scalar_mul(&self, k: &Self::Scalar) -> Self {
        let mut copied = *self;
        intrinsics::smul_secp256k1(&k.0, &mut copied.0);
        copied
    }

    fn scalar_inverse(k: &Self::Scalar) -> Self::Scalar {
        let mut copied = *k;
        intrinsics::sinv_secp256k1(&mut copied.0);
        copied
    }

    fn add(&self, other: &Self) -> Self {
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
            point: other.0,
            scalar: intrinsics::Secp256k1Scalar { value: ONE },
        };

        intrinsics::comb_secp256k1(&arg_1, &mut arg_2);
        Secp256k1Point(arg_2.point)
    }

    fn get_x_coord(&self) -> Self::Scalar {
        Secp256k1Scalar(scalar_reduce(&intrinsics::Secp256k1Scalar {
            value: self.0.x,
        }))
    }

    fn scalar_mul_mod(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        let mut copied = *b;
        intrinsics::muls_secp256k1(&a.0, &mut copied.0);
        copied
    }

    fn reduce_hash(hash: &[u8; 32]) -> Self::Scalar {
        let mut r: intrinsics::Secp256k1Scalar = Default::default();

        // Read big-endian 32-bit words from the input
        let mut b32_copied = *hash;
        b32_copied.reverse();
        r.value = b32_copied;

        Secp256k1Scalar(scalar_reduce(&r))
    }

    fn is_high(s: &Self::Scalar) -> bool {
        BigUint::from_bytes_le(&s.0.value) > *FRAC_SCALAR_ORDER_2
    }
}

#[cfg(test)]
mod tests {
    use super::Secp256k1Point as P;
    use super::Secp256k1Scalar as S;
    use super::*;

    #[test]
    fn add_neutral_to_generator() {
        assert_eq!(P::generator().add(&P::neutral()), P::generator());
    }

    #[test]
    fn add_gen_to_itself_and_compare_against_scalar_multiplication() {
        let mut two: [u8; 32] = [0; 32];
        two[0] = 2;

        assert_eq!(
            P::generator().add(&P::generator()),
            P::generator().scalar_mul(&S::create(two).unwrap())
        );
    }

    #[test]
    fn invert_two() {
        let mut two: [u8; 32] = [0; 32];
        two[0] = 2;

        let mut one: [u8; 32] = [0; 32];
        one[0] = 1;

        let one = S::create(one).unwrap();
        let two = S::create(two).unwrap();
        let two_inv = P::scalar_inverse(&two);

        assert_eq!(P::scalar_mul_mod(&two, &two_inv), one);
    }
}
