// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

use curve25519_dalek::scalar::Scalar;
use rand::RngCore;

/// Number modulo order of curve ed25519 (the Ristretto group order).
pub fn ed25519_mod_n(a: &Scalar) -> Scalar {
    // Scalar arithmetic in curve25519-dalek is already modulo the group order
    *a
}

/// Clamp and reduce a 512-bit hash to a Ristretto scalar.
/// Input bytes (64 bytes LE) → mod l.
pub fn scalar_from_512_bits_le(bytes: &[u8; 64]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(bytes)
}

/// Generate a random scalar < l.
pub fn ed25519_gen_random() -> Scalar {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// Generate a list of random scalars.
pub fn ed25519_gen_list_of_random(len: usize) -> Vec<Scalar> {
    (0..len).map(|_| ed25519_gen_random()).collect()
}
