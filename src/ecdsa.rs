use std::marker::PhantomData;

use crate::elliptic_curve::{CheckedAdd, EllipticCurve, MultiplicativeInverse};
use crate::elliptic_curve::{FromLeBytes, ToLeBytes};

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

pub struct RecoveryId(u8);

impl RecoveryId {
    pub fn new(recid: u8) -> Option<RecoveryId> {
        if recid <= 4 {
            Some(RecoveryId(recid))
        } else {
            None
        }
    }
}

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
        let r = signature.r;
        let s = signature.s;

        // Check if r and s are in valid range (non-zero)
        if r == C::Scalar::default() || s == C::Scalar::default() {
            return false;
        }

        if C::is_high(&s) {
            return false;
        }

        // Compute s^-1
        let s_inv = s.inverse();

        // Compute u1 = z * s^-1
        let u1: C::Scalar = z * &s_inv;

        // Compute u2 = r * s^-1
        let u2 = r * &s_inv;

        // Compute the point P = u1*G + u2*Q
        let p = C::lin_comb(&u1, C::generator(), &u2, public_key);

        // Extract x-coordinate of P as v
        let v = p.get_x_coord();

        // Verify that v = r
        v == r
    }

    pub fn recover(
        hash: &[u8; 32],
        signature: &Signature<C>,
        recovery_id: &RecoveryId,
    ) -> Result<C, ()> {
        let r = signature.r;
        let s = signature.s;

        let is_y_odd = recovery_id.is_y_odd();
        let is_x_reduced = recovery_id.is_x_reduced();

        let bytes_le = if is_x_reduced {
            C::Uint::to_le_bytes(
                &C::Uint::from_le_bytes(&r.to_le_bytes())
                    .ok_or(())?
                    .checked_add(&C::ORDER)
                    .ok_or(())?,
            )
        } else {
            r.to_le_bytes()
        };

        let point_r = C::decompress(&bytes_le, is_y_odd).ok_or(())?;

        let z = C::reduce_hash(&hash);

        let r_inv = r.inverse();

        let u_1 = -(z * &r_inv);
        let u_2 = s * &r_inv;

        let q_a = C::lin_comb(&u_1, &C::generator(), &u_2, &point_r);

        Ok(q_a)
    }
}
