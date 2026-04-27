// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

use crate::consts::{PROOF_CHUNK_SIZE, PROTOCOL_ID_NORMALIZATION, SIGMA_PROOF_NORMALIZATION_SIZE};
use crate::crypto::chunked_amount::{AVAILABLE_BALANCE_CHUNK_COUNT, CHUNK_BITS, ChunkedAmount};
use crate::crypto::encrypted_amount::EncryptedAmount;
use crate::crypto::fiat_shamir::fiat_shamir_challenge_ts;
use crate::crypto::h_ristretto;
use crate::crypto::scalar_ts::{lin_comb_pow2_mod_l, mul_mod_l};
use crate::crypto::sigma_helpers::{decompress_point, sum_c_weighted, sum_d_weighted};
use crate::crypto::twisted_ed25519::{TwistedEd25519PrivateKey, TwistedEd25519PublicKey};
use crate::utils::{ed25519_gen_list_of_random, ed25519_gen_random};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

/// Normalization sigma proof (matches TS `ConfidentialNormalizationSigmaProof`).
#[derive(Clone, Debug)]
pub struct NormalizationSigmaProof {
    pub alpha1_list: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
    pub alpha2: [u8; 32],
    pub alpha3: [u8; 32],
    pub alpha4_list: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
    pub x1: [u8; 32],
    pub x2: [u8; 32],
    pub x3_list: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
    pub x4_list: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
}

/// Confidential normalization context.
pub struct ConfidentialNormalization {
    decryption_key: TwistedEd25519PrivateKey,
    unnormalized_encrypted_available_balance: EncryptedAmount,
    normalized_encrypted_available_balance: EncryptedAmount,
    chain_id: u8,
    sender_address: Vec<u8>,
    contract_address: Vec<u8>,
    // Held for TS API parity; the normalization σ-protocol does not bind to the token address.
    #[allow(dead_code)]
    token_address: Vec<u8>,
}

impl ConfidentialNormalization {
    pub fn create(
        decryption_key: TwistedEd25519PrivateKey,
        unnormalized_available_balance: EncryptedAmount,
        chain_id: u8,
        sender_address: &[u8],
        contract_address: &[u8],
        token_address: &[u8],
    ) -> Self {
        let amount = unnormalized_available_balance.get_amount();
        let pk = decryption_key.public_key();
        let normalized_chunked = ChunkedAmount::from_amount(amount);
        let normalized_ea = EncryptedAmount::new(normalized_chunked, pk);
        Self {
            decryption_key,
            unnormalized_encrypted_available_balance: unnormalized_available_balance,
            normalized_encrypted_available_balance: normalized_ea,
            chain_id,
            sender_address: sender_address.to_vec(),
            contract_address: contract_address.to_vec(),
            token_address: token_address.to_vec(),
        }
    }

    pub fn unnormalized_encrypted_available_balance(&self) -> &EncryptedAmount {
        &self.unnormalized_encrypted_available_balance
    }

    pub fn normalized_encrypted_available_balance(&self) -> &EncryptedAmount {
        &self.normalized_encrypted_available_balance
    }

    fn fiat_shamir(
        &self,
        x1: &[u8; 32],
        x2: &[u8; 32],
        x3_list: &[[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
        x4_list: &[[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
    ) -> Scalar {
        let g_b = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
        let h_b = h_ristretto().compress().to_bytes();
        let pk_b = self.decryption_key.public_key().to_bytes();
        let unnorm_ct = self
            .unnormalized_encrypted_available_balance
            .get_ciphertext_bytes();
        let norm_ct = self
            .normalized_encrypted_available_balance
            .get_ciphertext_bytes();
        let mut parts: Vec<&[u8]> = vec![
            &self.contract_address,
            &g_b,
            &h_b,
            &pk_b,
            &unnorm_ct,
            &norm_ct,
            x1,
            x2,
        ];
        for x in x3_list {
            parts.push(x);
        }
        for x in x4_list {
            parts.push(x);
        }
        fiat_shamir_challenge_ts(
            PROTOCOL_ID_NORMALIZATION,
            self.chain_id,
            &self.sender_address,
            &parts,
        )
    }

    pub fn gen_sigma_proof(&self) -> NormalizationSigmaProof {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = h_ristretto();
        let pk_pt = self.decryption_key.public_key();
        let pk_pt = pk_pt.as_point();

        let unnorm_ct = self
            .unnormalized_encrypted_available_balance
            .get_ciphertext();

        let x1_list = ed25519_gen_list_of_random(AVAILABLE_BALANCE_CHUNK_COUNT);
        let x2 = ed25519_gen_random();
        let x3 = ed25519_gen_random();
        let x4_list = ed25519_gen_list_of_random(AVAILABLE_BALANCE_CHUNK_COUNT);

        let lin_x1 = lin_comb_pow2_mod_l(&x1_list, CHUNK_BITS);
        let d_sum = sum_d_weighted(unnorm_ct);
        let x1_pt = g * lin_x1 + d_sum * x2;
        let x2_pt = h * x3;
        let x3_list_pts: Vec<RistrettoPoint> = x1_list
            .iter()
            .zip(x4_list.iter())
            .map(|(x1i, x4i)| g * x1i + h * x4i)
            .collect();
        let x4_list_pts: Vec<RistrettoPoint> = x4_list.iter().map(|x4i| pk_pt * x4i).collect();

        let x1_b = x1_pt.compress().to_bytes();
        let x2_b = x2_pt.compress().to_bytes();
        let x3_b: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT] =
            std::array::from_fn(|i| x3_list_pts[i].compress().to_bytes());
        let x4_b: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT] =
            std::array::from_fn(|i| x4_list_pts[i].compress().to_bytes());

        let p = self.fiat_shamir(&x1_b, &x2_b, &x3_b, &x4_b);

        let s = *self.decryption_key.as_scalar();
        let s_inv = s.invert();

        let norm_chunks = self
            .normalized_encrypted_available_balance
            .chunked_amount()
            .chunks();
        let mut alpha1_list = [[0u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT];
        for i in 0..AVAILABLE_BALANCE_CHUNK_COUNT {
            let p_chunk = mul_mod_l(&p, &Scalar::from(norm_chunks[i]));
            alpha1_list[i] = (x1_list[i] - p_chunk).to_bytes();
        }
        let alpha2 = (x2 - mul_mod_l(&p, &s)).to_bytes();
        let alpha3 = (x3 - mul_mod_l(&p, &s_inv)).to_bytes();

        let norm_r = self.normalized_encrypted_available_balance.randomness();
        let mut alpha4_list = [[0u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT];
        for i in 0..AVAILABLE_BALANCE_CHUNK_COUNT {
            let pri = mul_mod_l(&p, &norm_r[i]);
            alpha4_list[i] = (x4_list[i] - pri).to_bytes();
        }

        NormalizationSigmaProof {
            alpha1_list,
            alpha2,
            alpha3,
            alpha4_list,
            x1: x1_b,
            x2: x2_b,
            x3_list: x3_b,
            x4_list: x4_b,
        }
    }

    pub fn verify_sigma_proof(
        public_key: &TwistedEd25519PublicKey,
        sigma_proof: &NormalizationSigmaProof,
        unnormalized_encrypted_balance: &EncryptedAmount,
        normalized_encrypted_balance: &EncryptedAmount,
        chain_id: u8,
        sender_address: &[u8],
        contract_address: &[u8],
        _token_address: &[u8],
    ) -> bool {
        let unnorm_ct = unnormalized_encrypted_balance.get_ciphertext();
        let norm_ct = normalized_encrypted_balance.get_ciphertext();
        if unnorm_ct.len() != AVAILABLE_BALANCE_CHUNK_COUNT
            || norm_ct.len() != AVAILABLE_BALANCE_CHUNK_COUNT
        {
            return false;
        }
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = h_ristretto();
        let pk_pt = public_key.as_point();

        let g_b = g.compress().to_bytes();
        let h_b = h.compress().to_bytes();
        let pk_b = public_key.to_bytes();
        let unnorm_ct_b = unnormalized_encrypted_balance.get_ciphertext_bytes();
        let norm_ct_b = normalized_encrypted_balance.get_ciphertext_bytes();

        let mut parts: Vec<&[u8]> = vec![
            contract_address,
            &g_b,
            &h_b,
            &pk_b,
            &unnorm_ct_b,
            &norm_ct_b,
            &sigma_proof.x1,
            &sigma_proof.x2,
        ];
        for x in &sigma_proof.x3_list {
            parts.push(x);
        }
        for x in &sigma_proof.x4_list {
            parts.push(x);
        }
        let p =
            fiat_shamir_challenge_ts(PROTOCOL_ID_NORMALIZATION, chain_id, sender_address, &parts);

        let a1: Vec<Scalar> = sigma_proof
            .alpha1_list
            .iter()
            .map(|b| Scalar::from_bytes_mod_order(*b))
            .collect();
        let a2 = Scalar::from_bytes_mod_order(sigma_proof.alpha2);
        let a3 = Scalar::from_bytes_mod_order(sigma_proof.alpha3);
        let a4: Vec<Scalar> = sigma_proof
            .alpha4_list
            .iter()
            .map(|b| Scalar::from_bytes_mod_order(*b))
            .collect();

        let d_old = sum_d_weighted(unnorm_ct);
        let c_old = sum_c_weighted(unnorm_ct);
        let lin_a1 = lin_comb_pow2_mod_l(&a1, CHUNK_BITS);

        let x1_re = g * lin_a1 + d_old * a2 + c_old * p;
        let x2_re = h * a3 + pk_pt * p;

        let Some(x1_p) = decompress_point(&sigma_proof.x1) else {
            return false;
        };
        let Some(x2_p) = decompress_point(&sigma_proof.x2) else {
            return false;
        };
        let mut ok = x1_re == x1_p && x2_re == x2_p;
        for i in 0..AVAILABLE_BALANCE_CHUNK_COUNT {
            let x3i = g * a1[i] + h * a4[i] + norm_ct[i].c * p;
            let Some(x3p) = decompress_point(&sigma_proof.x3_list[i]) else {
                return false;
            };
            ok &= x3i == x3p;
            let x4i = pk_pt * a4[i] + norm_ct[i].d * p;
            let Some(x4p) = decompress_point(&sigma_proof.x4_list[i]) else {
                return false;
            };
            ok &= x4i == x4p;
        }
        ok
    }

    pub async fn gen_range_proof(&self) -> Result<Vec<u8>, String> {
        crate::crypto::range_proof::generate_range_proof(
            self.normalized_encrypted_available_balance.get_ciphertext(),
            self.normalized_encrypted_available_balance
                .chunked_amount()
                .chunks(),
            self.normalized_encrypted_available_balance.randomness(),
        )
    }

    pub async fn verify_range_proof(
        range_proof: &[u8],
        normalized_encrypted_balance: &EncryptedAmount,
    ) -> Result<bool, String> {
        crate::crypto::range_proof::verify_range_proof(
            range_proof,
            normalized_encrypted_balance.get_ciphertext(),
        )
    }

    pub fn serialize_sigma_proof(proof: &NormalizationSigmaProof) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGMA_PROOF_NORMALIZATION_SIZE);
        for a in &proof.alpha1_list {
            out.extend_from_slice(a);
        }
        out.extend_from_slice(&proof.alpha2);
        out.extend_from_slice(&proof.alpha3);
        for a in &proof.alpha4_list {
            out.extend_from_slice(a);
        }
        out.extend_from_slice(&proof.x1);
        out.extend_from_slice(&proof.x2);
        for x in &proof.x3_list {
            out.extend_from_slice(x);
        }
        for x in &proof.x4_list {
            out.extend_from_slice(x);
        }
        debug_assert_eq!(out.len(), SIGMA_PROOF_NORMALIZATION_SIZE);
        out
    }

    pub fn deserialize_sigma_proof(bytes: &[u8]) -> Result<NormalizationSigmaProof, String> {
        if bytes.len() != SIGMA_PROOF_NORMALIZATION_SIZE {
            return Err(format!(
                "normalization sigma: expected {} bytes, got {}",
                SIGMA_PROOF_NORMALIZATION_SIZE,
                bytes.len()
            ));
        }
        let mut o = 0usize;
        let mut take32 = || -> [u8; 32] {
            let s = o;
            o += PROOF_CHUNK_SIZE;
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&bytes[s..s + 32]);
            buf
        };
        let mut alpha1_list = [[0u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT];
        for a in &mut alpha1_list {
            *a = take32();
        }
        let alpha2 = take32();
        let alpha3 = take32();
        let mut alpha4_list = [[0u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT];
        for a in &mut alpha4_list {
            *a = take32();
        }
        let x1 = take32();
        let x2 = take32();
        let mut x3_list = [[0u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT];
        for x in &mut x3_list {
            *x = take32();
        }
        let mut x4_list = [[0u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT];
        for x in &mut x4_list {
            *x = take32();
        }
        Ok(NormalizationSigmaProof {
            alpha1_list,
            alpha2,
            alpha3,
            alpha4_list,
            x1,
            x2,
            x3_list,
            x4_list,
        })
    }

    pub async fn authorize_normalization(
        &self,
    ) -> Result<(NormalizationSigmaProof, Vec<u8>, EncryptedAmount), String> {
        let sigma = self.gen_sigma_proof();
        let range = self.gen_range_proof().await?;
        Ok((
            sigma,
            range,
            self.normalized_encrypted_available_balance.clone(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_sigma_gen_verify_roundtrip() {
        let dk = TwistedEd25519PrivateKey::generate();
        let pk = dk.public_key();
        let unnormalized_chunks: Vec<u64> = (0..AVAILABLE_BALANCE_CHUNK_COUNT - 1)
            .map(|_| ((1u128 << CHUNK_BITS as u128) + 100u128) as u64)
            .chain(std::iter::once(0u64))
            .collect();
        let unnormalized = EncryptedAmount::new(
            ChunkedAmount::from_raw_chunks(unnormalized_chunks),
            pk.clone(),
        );

        let n = ConfidentialNormalization::create(
            dk,
            unnormalized.clone(),
            7,
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
        );

        let proof = n.gen_sigma_proof();
        let ok = ConfidentialNormalization::verify_sigma_proof(
            &pk,
            &proof,
            &unnormalized,
            n.normalized_encrypted_available_balance(),
            7,
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
        );
        assert!(ok, "normalization sigma should verify");

        let bytes = ConfidentialNormalization::serialize_sigma_proof(&proof);
        assert_eq!(bytes.len(), SIGMA_PROOF_NORMALIZATION_SIZE);
        let dec = ConfidentialNormalization::deserialize_sigma_proof(&bytes).unwrap();
        assert_eq!(
            ConfidentialNormalization::serialize_sigma_proof(&dec),
            bytes
        );
    }
}
