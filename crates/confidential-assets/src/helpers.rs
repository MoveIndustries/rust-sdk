// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

/// Generate Fiat-Shamir challenge using SHA2-512 with raw concatenation.
/// @deprecated Use fiat_shamir_challenge from crypto::fiat_shamir instead.
pub fn gen_fiat_shamir_challenge(arrays: &[&[u8]]) -> Scalar {
    let mut hasher = Sha512::new();
    for arr in arrays {
        hasher.update(arr);
    }
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.into())
}
