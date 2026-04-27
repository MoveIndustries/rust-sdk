// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! Shared σ-protocol helpers used by every confidential-asset proof
//! (transfer, withdraw, key-rotation, normalization).

use crate::crypto::chunked_amount::CHUNK_BITS;
use crate::crypto::scalar_ts::scalar_pow2_mod_l;
use crate::crypto::twisted_el_gamal::TwistedElGamalCiphertext;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity;

/// Decompress a 32-byte Ristretto point. Returns `None` if the bytes are not
/// a valid encoding. Verifiers use the `Option`; provers, working with
/// freshly-encoded points, do `.expect("...")`.
#[inline]
pub fn decompress_point(p: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*p).decompress()
}

/// Σᵢ 2^(CHUNK_BITS·i) · ctᵢ.D — weighted sum of the D-component of an
/// encrypted-amount's chunked ciphertext.
#[inline]
pub fn sum_d_weighted(cts: &[TwistedElGamalCiphertext]) -> RistrettoPoint {
    cts.iter()
        .enumerate()
        .fold(RistrettoPoint::identity(), |acc, (i, ct)| {
            acc + ct.d * scalar_pow2_mod_l(CHUNK_BITS * i as u32)
        })
}

/// Σᵢ 2^(CHUNK_BITS·i) · ctᵢ.C — weighted sum of the C-component of an
/// encrypted-amount's chunked ciphertext.
#[inline]
pub fn sum_c_weighted(cts: &[TwistedElGamalCiphertext]) -> RistrettoPoint {
    cts.iter()
        .enumerate()
        .fold(RistrettoPoint::identity(), |acc, (i, ct)| {
            acc + ct.c * scalar_pow2_mod_l(CHUNK_BITS * i as u32)
        })
}
