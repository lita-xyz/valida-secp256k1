use std::marker::PhantomData;

use crate::elliptic_curve::EllipticCurve;

/// ECDSA implementation that works with any type implementing the EllipticCurve trait
pub struct ECDSA<C: EllipticCurve> {
    _phantom: PhantomData<C>,
}

/// ECDSA signature consisting of (r, s) components
#[derive(Clone, Debug)]
pub struct Signature<C: EllipticCurve> {
    pub r: C::Scalar,
    pub s: C::Scalar,
}

impl<C: EllipticCurve> ECDSA<C> {
    /// Verify a signature using the public key
    pub fn verify(hash: &[u8; 32], signature: &Signature<C>, public_key: &C) -> bool {
        let z = C::reduce_hash(hash);
        let r = &signature.r;
        let s = &signature.s;

        // Check if r and s are in valid range (non-zero)
        if *r == C::Scalar::default() || *s == C::Scalar::default() {
            return false;
        }

        if C::is_high(s) {
            return false;
        }

        // Compute s^-1
        let s_inv = C::scalar_inverse(s);

        // Compute u1 = z * s^-1
        let u1 = C::scalar_mul_mod(&z, &s_inv);

        // Compute u2 = r * s^-1
        let u2 = C::scalar_mul_mod(r, &s_inv);

        // Compute the point P = u1*G + u2*Q
        let u1_g = C::generator().scalar_mul(&u1);
        let u2_q = public_key.scalar_mul(&u2);
        let p = u1_g.add(&u2_q);

        // Extract x-coordinate of P as v
        let v = p.get_x_coord();

        // Verify that v = r
        v == *r
    }
}
