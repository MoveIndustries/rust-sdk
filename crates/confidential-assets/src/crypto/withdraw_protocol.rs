// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0
//!
//! Confidential **withdraw** sigma proof — aligned with `ts-sdk/confidential-assets` /
//! `confidentialWithdraw.ts` (serialized proof is **36 × 32** bytes; older `21 × 32` constants are stale).

use crate::consts::{PROOF_CHUNK_SIZE, PROTOCOL_ID_WITHDRAWAL};
use crate::crypto::chunked_amount::{
    AVAILABLE_BALANCE_CHUNK_COUNT, CHUNK_BITS, ChunkedAmount, TRANSFER_AMOUNT_CHUNK_COUNT,
};
use crate::crypto::encrypted_amount::EncryptedAmount;
use crate::crypto::h_ristretto;
use crate::crypto::scalar_ts::{ed25519_mod_n_biguint, lin_comb_pow2_mod_l, mul_mod_l};
use crate::crypto::sigma_helpers::{sum_c_weighted, sum_d_weighted};
use crate::crypto::twisted_ed25519::TwistedEd25519PublicKey;
use crate::utils::ed25519_gen_list_of_random;
use crate::utils::ed25519_gen_random;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use num_bigint::BigUint;
use sha2::{Digest, Sha512};

/// Serialized withdraw sigma proof size (matches current TS `serializeSigmaProof` output).
pub const WITHDRAW_SIGMA_PROOF_BYTES: usize = PROOF_CHUNK_SIZE * 36;

/// Decompress a freshly-encoded Ristretto point. Panics on invalid bytes.
fn decompress(p: &[u8; 32]) -> RistrettoPoint {
    crate::crypto::sigma_helpers::decompress_point(p).expect("valid ristretto encoding")
}

fn g_bytes() -> [u8; 32] {
    RISTRETTO_BASEPOINT_POINT.compress().to_bytes()
}

fn h_bytes() -> [u8; 32] {
    h_ristretto().compress().to_bytes()
}

fn scalar_from_u128(amount: u128) -> Scalar {
    let mut b = [0u8; 32];
    b[..16].copy_from_slice(&amount.to_le_bytes());
    Scalar::from_bytes_mod_order(b)
}

/// Encode one u64 chunk as 32-byte LE scalar (TS `numberToBytesLE(chunk, 32)`).
fn chunk_u64_to_scalar_bytes(chunk: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&chunk.to_le_bytes());
    out
}

/// Fiat–Shamir challenge for withdraw (matches TS `dstHash` + `ed25519modN(bytesToNumberLE(hash))`).
// σ-protocol challenge — each parameter is a distinct transcript input.
#[allow(clippy::too_many_arguments)]
pub fn withdraw_fiat_shamir_challenge(
    chain_id: u8,
    sender_address: &[u8],
    contract_address: &[u8],
    pk_bytes: &[u8; 32],
    withdraw_amount: &ChunkedAmount,
    old_balance_ciphertext_bytes: &[u8],
    x1: &[u8; 32],
    x2: &[u8; 32],
    x3_list: &[[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
    x4_list: &[[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
) -> Scalar {
    let mut extra: Vec<u8> = Vec::new();
    extra.extend_from_slice(contract_address);
    extra.extend_from_slice(&g_bytes());
    extra.extend_from_slice(&h_bytes());
    extra.extend_from_slice(pk_bytes);
    for c in withdraw_amount
        .chunks()
        .iter()
        .take(TRANSFER_AMOUNT_CHUNK_COUNT)
    {
        extra.extend_from_slice(&chunk_u64_to_scalar_bytes(*c));
    }
    extra.extend_from_slice(old_balance_ciphertext_bytes);
    extra.extend_from_slice(x1);
    extra.extend_from_slice(x2);
    for x in x3_list {
        extra.extend_from_slice(x);
    }
    for x in x4_list {
        extra.extend_from_slice(x);
    }
    let dst = format!("MovementConfidentialAsset/{PROTOCOL_ID_WITHDRAWAL}");
    let mut hasher = Sha512::new();
    hasher.update(dst.as_bytes());
    hasher.update([chain_id]);
    hasher.update(sender_address);
    hasher.update(&extra);
    let h = hasher.finalize();
    let mut h64 = [0u8; 64];
    h64.copy_from_slice(&h);
    ed25519_mod_n_biguint(BigUint::from_bytes_le(&h64))
}

/// Parameters for withdraw sigma verification (TS `ConfidentialWithdraw.verifySigmaProof`).
pub struct WithdrawVerifyParams<'a> {
    pub sigma: &'a WithdrawSigmaProofWire,
    pub sender_encrypted_balance: &'a EncryptedAmount,
    pub sender_encrypted_balance_after: &'a EncryptedAmount,
    pub amount_to_withdraw: u128,
    pub chain_id: u8,
    pub sender_address: &'a [u8],
    pub contract_address: &'a [u8],
}

/// Withdraw sigma proof as raw 32-byte chunks (wire / TS object form).
#[derive(Clone, Debug)]
pub struct WithdrawSigmaProofWire {
    pub alpha1: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
    pub alpha2: [u8; 32],
    pub alpha3: [u8; 32],
    pub alpha4: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
    pub x1: [u8; 32],
    pub x2: [u8; 32],
    pub x3: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
    pub x4: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
}

impl WithdrawSigmaProofWire {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WITHDRAW_SIGMA_PROOF_BYTES);
        for a in &self.alpha1 {
            out.extend_from_slice(a);
        }
        out.extend_from_slice(&self.alpha2);
        out.extend_from_slice(&self.alpha3);
        for a in &self.alpha4 {
            out.extend_from_slice(a);
        }
        out.extend_from_slice(&self.x1);
        out.extend_from_slice(&self.x2);
        for x in &self.x3 {
            out.extend_from_slice(x);
        }
        for x in &self.x4 {
            out.extend_from_slice(x);
        }
        debug_assert_eq!(out.len(), WITHDRAW_SIGMA_PROOF_BYTES);
        out
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != WITHDRAW_SIGMA_PROOF_BYTES {
            return Err(format!(
                "withdraw sigma: expected {} bytes, got {}",
                WITHDRAW_SIGMA_PROOF_BYTES,
                bytes.len()
            ));
        }
        let mut o = 0usize;
        let mut take32 = || -> Result<[u8; 32], String> {
            let s = o;
            o += 32;
            bytes[s..s + 32].try_into().map_err(|_| "slice".to_string())
        };
        let mut alpha1 = [[0u8; 32]; 8];
        for a in &mut alpha1 {
            *a = take32()?;
        }
        let alpha2 = take32()?;
        let alpha3 = take32()?;
        let mut alpha4 = [[0u8; 32]; 8];
        for a in &mut alpha4 {
            *a = take32()?;
        }
        let x1 = take32()?;
        let x2 = take32()?;
        let mut x3 = [[0u8; 32]; 8];
        for x in &mut x3 {
            *x = take32()?;
        }
        let mut x4 = [[0u8; 32]; 8];
        for x in &mut x4 {
            *x = take32()?;
        }
        Ok(Self {
            alpha1,
            alpha2,
            alpha3,
            alpha4,
            x1,
            x2,
            x3,
            x4,
        })
    }
}

/// Verify withdraw sigma proof (TS `ConfidentialWithdraw.verifySigmaProof`).
pub fn verify_withdraw_sigma_proof(opts: &WithdrawVerifyParams<'_>) -> bool {
    let pk = opts.sender_encrypted_balance.public_key();
    let pk_bytes = pk.to_bytes();
    let pk_pt = pk.as_point();

    let withdraw_chunks = ChunkedAmount::from_transfer_amount(opts.amount_to_withdraw);
    let old_ct = opts.sender_encrypted_balance.get_ciphertext();
    let new_ct = opts.sender_encrypted_balance_after.get_ciphertext();
    if old_ct.len() != AVAILABLE_BALANCE_CHUNK_COUNT
        || new_ct.len() != AVAILABLE_BALANCE_CHUNK_COUNT
    {
        return false;
    }

    let old_balance_bytes = opts.sender_encrypted_balance.get_ciphertext_bytes();

    let p = withdraw_fiat_shamir_challenge(
        opts.chain_id,
        opts.sender_address,
        opts.contract_address,
        &pk_bytes,
        &withdraw_chunks,
        &old_balance_bytes,
        &opts.sigma.x1,
        &opts.sigma.x2,
        &opts.sigma.x3,
        &opts.sigma.x4,
    );

    let a1: Vec<Scalar> = opts
        .sigma
        .alpha1
        .iter()
        .map(|b| Scalar::from_bytes_mod_order(*b))
        .collect();
    let a2 = Scalar::from_bytes_mod_order(opts.sigma.alpha2);
    let a3 = Scalar::from_bytes_mod_order(opts.sigma.alpha3);
    let a4: Vec<Scalar> = opts
        .sigma
        .alpha4
        .iter()
        .map(|b| Scalar::from_bytes_mod_order(*b))
        .collect();

    let d_old = sum_d_weighted(old_ct);
    let c_old = sum_c_weighted(old_ct);

    let lin_a1 = lin_comb_pow2_mod_l(&a1, CHUNK_BITS);

    let x1_re = RISTRETTO_BASEPOINT_POINT * lin_a1 + d_old * a2 + c_old * p
        - RISTRETTO_BASEPOINT_POINT * mul_mod_l(&p, &scalar_from_u128(opts.amount_to_withdraw));

    let h = h_ristretto();
    let x2_re = h * a3 + pk_pt * p;

    let mut ok = x1_re == decompress(&opts.sigma.x1);
    ok &= x2_re == decompress(&opts.sigma.x2);

    for i in 0..AVAILABLE_BALANCE_CHUNK_COUNT {
        let x3i = RISTRETTO_BASEPOINT_POINT * a1[i] + h * a4[i] + new_ct[i].c * p;
        ok &= x3i == decompress(&opts.sigma.x3[i]);
        let x4i = pk_pt * a4[i] + new_ct[i].d * p;
        ok &= x4i == decompress(&opts.sigma.x4[i]);
    }

    ok
}

/// Generate withdraw sigma proof (TS `ConfidentialWithdraw.genSigmaProof`).
///
/// `new_balance_randomness` must match the per-chunk randomness used to build
/// `sender_encrypted_balance_after` (same as TS `this.randomness`).
// σ-protocol prover — each parameter is a distinct cryptographic input.
#[allow(clippy::too_many_arguments)]
pub fn gen_withdraw_sigma_proof(
    decryption_scalar: &Scalar,
    pk: &TwistedEd25519PublicKey,
    sender_encrypted_balance: &EncryptedAmount,
    sender_encrypted_balance_after: &EncryptedAmount,
    new_balance_randomness: &[Scalar; AVAILABLE_BALANCE_CHUNK_COUNT],
    amount_to_withdraw: u128,
    chain_id: u8,
    sender_address: &[u8],
    contract_address: &[u8],
) -> WithdrawSigmaProofWire {
    let pk_bytes = pk.to_bytes();
    let pk_pt = pk.as_point();
    let h = h_ristretto();
    let g = RISTRETTO_BASEPOINT_POINT;

    let x1_list: Vec<Scalar> = ed25519_gen_list_of_random(AVAILABLE_BALANCE_CHUNK_COUNT);
    let x2 = ed25519_gen_random();
    let x3 = ed25519_gen_random();
    let x4_nonce: Vec<Scalar> = ed25519_gen_list_of_random(AVAILABLE_BALANCE_CHUNK_COUNT);

    let lin_x1 = lin_comb_pow2_mod_l(&x1_list, CHUNK_BITS);

    let d_sum = sum_d_weighted(sender_encrypted_balance.get_ciphertext());
    let x1_pt = g * lin_x1 + d_sum * x2;
    let x2_pt = h * x3;
    let x3_list_pts: Vec<RistrettoPoint> = x1_list
        .iter()
        .zip(x4_nonce.iter())
        .map(|(x1i, x4i)| g * x1i + h * x4i)
        .collect();
    let x4_list_pts: Vec<RistrettoPoint> = x4_nonce.iter().map(|x4i| pk_pt * x4i).collect();

    let x1_b = x1_pt.compress().to_bytes();
    let x2_b = x2_pt.compress().to_bytes();
    let x3_b: [[u8; 32]; 8] = std::array::from_fn(|i| x3_list_pts[i].compress().to_bytes());
    let x4_b: [[u8; 32]; 8] = std::array::from_fn(|i| x4_list_pts[i].compress().to_bytes());

    let withdraw_chunks = ChunkedAmount::from_transfer_amount(amount_to_withdraw);
    let old_ct_bytes = sender_encrypted_balance.get_ciphertext_bytes();

    let challenge = withdraw_fiat_shamir_challenge(
        chain_id,
        sender_address,
        contract_address,
        &pk_bytes,
        &withdraw_chunks,
        &old_ct_bytes,
        &x1_b,
        &x2_b,
        &x3_b,
        &x4_b,
    );

    let s_le = *decryption_scalar;
    let s_inv = s_le.invert();
    let ps = mul_mod_l(&challenge, &s_le);
    let ps_inv = mul_mod_l(&challenge, &s_inv);

    let after_chunks = sender_encrypted_balance_after.chunked_amount().chunks();
    let mut alpha1 = [[0u8; 32]; 8];
    for i in 0..8 {
        let p_chunk = mul_mod_l(&challenge, &Scalar::from(after_chunks[i]));
        let a = x1_list[i] - p_chunk;
        alpha1[i] = a.to_bytes();
    }

    let alpha2 = (x2 - ps).to_bytes();
    let alpha3 = (x3 - ps_inv).to_bytes();

    let mut alpha4 = [[0u8; 32]; 8];
    for i in 0..8 {
        let r_chunk = mul_mod_l(&challenge, &new_balance_randomness[i]);
        let a = x4_nonce[i] - r_chunk;
        alpha4[i] = a.to_bytes();
    }

    WithdrawSigmaProofWire {
        alpha1,
        alpha2,
        alpha3,
        alpha4,
        x1: x1_b,
        x2: x2_b,
        x3: x3_b,
        x4: x4_b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::twisted_ed25519::TwistedEd25519PrivateKey;

    #[test]
    fn withdraw_sigma_gen_verify_roundtrip() {
        let dk = TwistedEd25519PrivateKey::generate();
        let pk = dk.public_key();
        let bal: u128 = 1_000_000;
        let wd: u128 = 100;
        let r_curr: Vec<Scalar> = (0..8).map(|_| ed25519_gen_random()).collect();
        let r_new: Vec<Scalar> = (0..8).map(|_| ed25519_gen_random()).collect();
        let current = EncryptedAmount::new_with_randomness(
            ChunkedAmount::from_amount(bal),
            pk.clone(),
            r_curr,
        )
        .unwrap();
        let after = EncryptedAmount::new_with_randomness(
            ChunkedAmount::from_amount(bal - wd),
            pk.clone(),
            r_new.clone(),
        )
        .unwrap();
        let r_arr: [Scalar; 8] = r_new.try_into().expect("len 8");

        let proof = gen_withdraw_sigma_proof(
            dk.as_scalar(),
            &pk,
            &current,
            &after,
            &r_arr,
            wd,
            1,
            &[0u8; 32],
            &[0u8; 32],
        );

        let ok = verify_withdraw_sigma_proof(&WithdrawVerifyParams {
            sigma: &proof,
            sender_encrypted_balance: &current,
            sender_encrypted_balance_after: &after,
            amount_to_withdraw: wd,
            chain_id: 1,
            sender_address: &[0u8; 32],
            contract_address: &[0u8; 32],
        });
        assert!(ok, "withdraw sigma should verify");

        let bytes = proof.serialize();
        let dec = WithdrawSigmaProofWire::deserialize(&bytes).unwrap();
        assert_eq!(dec.serialize(), bytes);
    }
}
