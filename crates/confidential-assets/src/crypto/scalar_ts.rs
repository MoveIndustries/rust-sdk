// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! BigInt modular arithmetic matching the TS SDK (`ed25519modN`, weighted linear combos).

use curve25519_dalek::scalar::Scalar;
use num_bigint::BigUint;
use num_traits::{One, Zero};

/// Ed25519 / Ristretto subgroup order `l` (LE 32 bytes, same as dalek `BASEPOINT_ORDER`).
const GROUP_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

fn group_order() -> BigUint {
    BigUint::from_bytes_le(&GROUP_ORDER_LE)
}

fn scalar_to_biguint(s: &Scalar) -> BigUint {
    BigUint::from_bytes_le(&s.to_bytes())
}

fn biguint_to_scalar(x: &BigUint) -> Scalar {
    let l = group_order();
    let m = x % &l;
    let le = m.to_bytes_le();
    let mut b = [0u8; 32];
    let n = le.len().min(32);
    b[..n].copy_from_slice(&le[..n]);
    Scalar::from_bytes_mod_order(b)
}

/// `ed25519modN` — reduce integer mod l, then as Scalar.
pub fn ed25519_mod_n_biguint(x: BigUint) -> Scalar {
    biguint_to_scalar(&(x % group_order()))
}

/// Weighted sum `sum_i terms[i] * 2^(chunk_bits * i)` mod l (matches TS linear combos in transfer proofs).
pub fn lin_comb_pow2_mod_l(terms: &[Scalar], chunk_bits: u32) -> Scalar {
    let l = group_order();
    let mut acc = BigUint::zero();
    for (idx, t) in terms.iter().enumerate() {
        let bi = scalar_to_biguint(t);
        let coef = BigUint::one() << ((chunk_bits as usize) * idx);
        acc = (acc + bi * coef) % &l;
    }
    biguint_to_scalar(&acc)
}

/// `a - b` mod l.
pub fn sub_mod_l(a: &Scalar, b: &Scalar) -> Scalar {
    let l = group_order();
    let ai = scalar_to_biguint(a);
    let bi = scalar_to_biguint(b);
    let diff = if ai >= bi { ai - bi } else { &l - (bi - ai) };
    biguint_to_scalar(&(diff % &l))
}

/// `a * b` mod l (integer-style multiply of canonical scalar encodings).
pub fn mul_mod_l(a: &Scalar, b: &Scalar) -> Scalar {
    let l = group_order();
    let p = (scalar_to_biguint(a) * scalar_to_biguint(b)) % &l;
    biguint_to_scalar(&p)
}

/// `k - p * v` mod l.
pub fn sub_mul_mod_l(k: &Scalar, p: &Scalar, v: &Scalar) -> Scalar {
    let pv = mul_mod_l(p, v);
    sub_mod_l(k, &pv)
}

/// `2^k mod l` as a `Scalar` (for weighting ciphertext components like TS `D.multiply(2n ** …)`).
pub fn scalar_pow2_mod_l(k: u32) -> Scalar {
    let l = group_order();
    let bi = (BigUint::one() << k) % &l;
    biguint_to_scalar(&bi)
}

/// Responses `k_i - p * w_i` per limb do not compose under [`lin_comb_pow2_mod_l`]; adjust the last
/// limb so `lin_comb_pow2(α) = lin_comb_pow2(k) - p * lin_comb_pow2(w)` (mod l), matching the
/// verifier’s weighted recombination.
pub fn fix_alpha_limbs_weighted_lincomb(
    k: &[Scalar],
    p: &Scalar,
    w: &[Scalar],
    chunk_bits: u32,
) -> Vec<Scalar> {
    let n = k.len();
    assert_eq!(w.len(), n);
    if n == 0 {
        return vec![];
    }
    if n == 1 {
        return vec![sub_mul_mod_l(&k[0], p, &w[0])];
    }
    let l_k = lin_comb_pow2_mod_l(k, chunk_bits);
    let l_w = lin_comb_pow2_mod_l(w, chunk_bits);
    let l_tar = sub_mod_l(&l_k, &mul_mod_l(p, &l_w));
    let mut out: Vec<Scalar> = (0..n - 1).map(|i| sub_mul_mod_l(&k[i], p, &w[i])).collect();
    let acc = lin_comb_pow2_mod_l(&out, chunk_bits);
    let diff = sub_mod_l(&l_tar, &acc);
    let w_last = scalar_pow2_mod_l(chunk_bits * (n - 1) as u32);
    out.push(mul_mod_l(&diff, &w_last.invert()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::ed25519_gen_random;

    #[test]
    fn fix_alpha_limbs_matches_aggregate_sub_mul() {
        let n = 4u32;
        let chunk_bits = 16u32;
        let k: Vec<Scalar> = (0..n).map(|_| ed25519_gen_random()).collect();
        let w: Vec<Scalar> = (0..n).map(|_| ed25519_gen_random()).collect();
        let p = ed25519_gen_random();
        let fixed = fix_alpha_limbs_weighted_lincomb(&k, &p, &w, chunk_bits);
        let lhs = lin_comb_pow2_mod_l(&fixed, chunk_bits);
        let l_k = lin_comb_pow2_mod_l(&k, chunk_bits);
        let l_w = lin_comb_pow2_mod_l(&w, chunk_bits);
        let rhs = sub_mod_l(&l_k, &mul_mod_l(&p, &l_w));
        assert_eq!(lhs, rhs);
    }
}
