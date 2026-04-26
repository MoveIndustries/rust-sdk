// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

pub mod chunked_amount;
pub mod confidential_key_rotation;
pub mod confidential_normalization;
pub mod confidential_registration;
pub mod confidential_transfer;
pub mod confidential_withdraw;
pub mod encrypted_amount;
pub mod fiat_shamir;
pub mod range_proof;
pub mod scalar_ts;
pub mod twisted_ed25519;
pub mod twisted_el_gamal;
pub mod withdraw_protocol;

pub use chunked_amount::*;
pub use confidential_key_rotation::*;
pub use confidential_normalization::*;
pub use confidential_registration::*;
pub use confidential_transfer::*;
pub use confidential_withdraw::*;
pub use encrypted_amount::*;
pub use fiat_shamir::*;
pub use scalar_ts::{
    fix_alpha_limbs_weighted_lincomb, lin_comb_pow2_mod_l, mul_mod_l, scalar_pow2_mod_l, sub_mod_l,
    sub_mul_mod_l,
};
pub use twisted_ed25519::*;
pub use twisted_el_gamal::*;
pub use withdraw_protocol::*;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};

/// Compressed encoding of the secondary generator **H** (Ristretto255).
/// Matches TS `HASH_BASE_POINT` / `H_RISTRETTO` (`twistedEd25519.ts`) and the on-chain constant.
const H_RISTRETTO_COMPRESSED: [u8; 32] = [
    0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc, 0x65, 0xc3, 0x77, 0xa1, 0x04, 0x8d, 0x74, 0x5f,
    0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd, 0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34,
];

/// The secondary generator H (used for amount commitments).
pub fn h_ristretto() -> RistrettoPoint {
    CompressedRistretto(H_RISTRETTO_COMPRESSED)
        .decompress()
        .expect("H_RISTRETTO is a valid Ristretto point")
}

#[cfg(test)]
mod h_tests {
    use super::*;

    #[test]
    fn h_matches_ts_sdk_constant() {
        assert_eq!(h_ristretto().compress().to_bytes(), H_RISTRETTO_COMPRESSED);
    }
}
