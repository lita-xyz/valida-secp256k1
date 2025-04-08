use std::marker::PhantomData;

use crate::elliptic_curve::{EllipticCurve, MultiplicativeInverse};
use crate::elliptic_curve::{FromLeBytes, HasSqrt, IsOdd, ToLeBytes};

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

pub struct RecoveryId(pub u8);

impl RecoveryId {
    fn is_y_odd(&self) -> bool {
        (self.0 & 1) != 0
    }

    fn is_x_reduced(&self) -> bool {
        (self.0 & 0b10) != 0
    }
}

impl<C: EllipticCurve + 'static> ECDSA<C> {
    /// Verify a signature using the public key
    pub fn verify(hash: &[u8; 32], signature: &Signature<C>, public_key: &C) -> bool {
        let z = C::reduce_hash(hash);
        let r = &signature.r;
        let s = &signature.s;

        // Check if r and s are in valid range (non-zero)
        if *r == C::Scalar::default() || *s == C::Scalar::default() {
            return false;
        }

        if C::is_high(&s) {
            return false;
        }

        // Compute s^-1
        let s_inv = s.inverse();

        // Compute u1 = z * s^-1
        let u1: C::Scalar = z.clone() * s_inv.clone();

        // Compute u2 = r * s^-1
        let u2 = r.clone() * s_inv.clone();

        // Compute the point P = u1*G + u2*Q
        let u1_g = *C::generator() * u1;
        let u2_q = public_key.clone() * u2.clone();
        let p = u1_g + u2_q;

        // Extract x-coordinate of P as v
        let v = p.get_x_coord();

        // Verify that v = r
        v == *r
    }

    pub fn recover(
        hash: &[u8; 32],
        signature: &Signature<C>,
        recovery_id: &RecoveryId,
    ) -> Result<C, ()> {
        let r = signature.r.clone();
        let s = signature.s.clone();

        let is_y_odd = recovery_id.is_y_odd();
        let is_x_reduced = recovery_id.is_x_reduced();

        let mut fx = C::FieldElement::from_le_bytes(&r.to_le_bytes()).unwrap();

        if is_x_reduced {
            // TODO: should check that it does not overflow in 256 integer
            // https://github.com/RustCrypto/signatures/blob/0e69f92b566383ed4b5ecd176536428d0f60d499/ecdsa/src/recovery.rs#L358
            fx = fx + C::curve_order_as_fe();
        }

        let y_squared = fx.clone() * fx.clone() * fx.clone() + 7 as u64;
        let y_r = y_squared.sqrt();

        let y = if y_r.is_odd() != is_y_odd { -y_r } else { y_r };

        let point_r = C::try_from((fx, y)).unwrap();

        let z = C::reduce_hash(&hash);

        let r_inv = r.inverse();

        let u_1 = -(z * r_inv.clone());
        let u_2 = s * r_inv;

        let q_a = C::lin_comb(&u_1, &C::generator(), &u_2, &point_r);

        Ok(q_a)
    }
}
