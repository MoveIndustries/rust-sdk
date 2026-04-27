// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

use crate::consts::{PROOF_CHUNK_SIZE, PROTOCOL_ID_ROTATION, SIGMA_PROOF_KEY_ROTATION_SIZE};
use crate::crypto::chunked_amount::{AVAILABLE_BALANCE_CHUNK_COUNT, CHUNK_BITS};
use crate::crypto::encrypted_amount::EncryptedAmount;
use crate::crypto::fiat_shamir::fiat_shamir_challenge_ts;
use crate::crypto::h_ristretto;
use crate::crypto::scalar_ts::{lin_comb_pow2_mod_l, mul_mod_l, scalar_pow2_mod_l};
use crate::crypto::twisted_ed25519::{TwistedEd25519PrivateKey, TwistedEd25519PublicKey};
use crate::crypto::twisted_el_gamal::TwistedElGamalCiphertext;
use crate::utils::{ed25519_gen_list_of_random, ed25519_gen_random};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

/// Key-rotation sigma proof (matches TS `ConfidentialKeyRotationSigmaProof`).
#[derive(Clone, Debug)]
pub struct KeyRotationSigmaProof {
    pub alpha1_list: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
    pub alpha2: [u8; 32],
    pub alpha3: [u8; 32],
    pub alpha4: [u8; 32],
    pub alpha5_list: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
    pub x1: [u8; 32],
    pub x2: [u8; 32],
    pub x3: [u8; 32],
    pub x4_list: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
    pub x5_list: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
}

fn decompress(p: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto(*p).decompress()
}

fn sum_d_weighted(cts: &[TwistedElGamalCiphertext]) -> RistrettoPoint {
    cts.iter()
        .enumerate()
        .fold(RistrettoPoint::identity(), |acc, (i, ct)| {
            let coef = scalar_pow2_mod_l(CHUNK_BITS * i as u32);
            acc + ct.d * coef
        })
}

fn sum_c_weighted(cts: &[TwistedElGamalCiphertext]) -> RistrettoPoint {
    cts.iter()
        .enumerate()
        .fold(RistrettoPoint::identity(), |acc, (i, ct)| {
            let coef = scalar_pow2_mod_l(CHUNK_BITS * i as u32);
            acc + ct.c * coef
        })
}

/// Confidential key rotation context.
pub struct ConfidentialKeyRotation {
    sender_decryption_key: TwistedEd25519PrivateKey,
    new_sender_decryption_key: TwistedEd25519PrivateKey,
    current_encrypted_available_balance: EncryptedAmount,
    new_encrypted_available_balance: EncryptedAmount,
    chain_id: u8,
    sender_address: Vec<u8>,
    contract_address: Vec<u8>,
    // Held for TS API parity; the key-rotation σ-protocol does not bind to the token address.
    #[allow(dead_code)]
    token_address: Vec<u8>,
}

impl ConfidentialKeyRotation {
    pub fn create(
        sender_decryption_key: TwistedEd25519PrivateKey,
        new_sender_decryption_key: TwistedEd25519PrivateKey,
        current_encrypted_available_balance: EncryptedAmount,
        chain_id: u8,
        sender_address: &[u8],
        contract_address: &[u8],
        token_address: &[u8],
    ) -> Self {
        let amount = current_encrypted_available_balance.get_amount();
        let new_pk = new_sender_decryption_key.public_key();
        let new_ea = EncryptedAmount::from_amount_and_public_key(amount, &new_pk);
        Self {
            sender_decryption_key,
            new_sender_decryption_key,
            current_encrypted_available_balance,
            new_encrypted_available_balance: new_ea,
            chain_id,
            sender_address: sender_address.to_vec(),
            contract_address: contract_address.to_vec(),
            token_address: token_address.to_vec(),
        }
    }

    pub fn new_encrypted_available_balance(&self) -> &EncryptedAmount {
        &self.new_encrypted_available_balance
    }

    pub fn current_encrypted_available_balance(&self) -> &EncryptedAmount {
        &self.current_encrypted_available_balance
    }

    fn fiat_shamir(
        &self,
        x1: &[u8; 32],
        x2: &[u8; 32],
        x3: &[u8; 32],
        x4_list: &[[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
        x5_list: &[[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT],
    ) -> Scalar {
        let g_b = RISTRETTO_BASEPOINT_POINT.compress().to_bytes();
        let h_b = h_ristretto().compress().to_bytes();
        let curr_pk = self
            .current_encrypted_available_balance
            .public_key()
            .to_bytes();
        let new_pk = self.new_encrypted_available_balance.public_key().to_bytes();
        let curr_ct = self
            .current_encrypted_available_balance
            .get_ciphertext_bytes();
        let new_ct = self.new_encrypted_available_balance.get_ciphertext_bytes();
        let mut parts: Vec<&[u8]> = vec![
            &self.contract_address,
            &g_b,
            &h_b,
            &curr_pk,
            &new_pk,
            &curr_ct,
            &new_ct,
            x1,
            x2,
            x3,
        ];
        for x in x4_list {
            parts.push(x);
        }
        for x in x5_list {
            parts.push(x);
        }
        fiat_shamir_challenge_ts(
            PROTOCOL_ID_ROTATION,
            self.chain_id,
            &self.sender_address,
            &parts,
        )
    }

    pub fn gen_sigma_proof(&self) -> KeyRotationSigmaProof {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = h_ristretto();

        let curr_ct = self.current_encrypted_available_balance.get_ciphertext();
        let new_pk_pt = self.new_encrypted_available_balance.public_key().as_point();

        let x1_list = ed25519_gen_list_of_random(AVAILABLE_BALANCE_CHUNK_COUNT);
        let x2 = ed25519_gen_random();
        let x3 = ed25519_gen_random();
        let x4 = ed25519_gen_random();
        let x5_list = ed25519_gen_list_of_random(AVAILABLE_BALANCE_CHUNK_COUNT);

        let lin_x1 = lin_comb_pow2_mod_l(&x1_list, CHUNK_BITS);
        let d_sum = sum_d_weighted(curr_ct);
        let x1_pt = g * lin_x1 + d_sum * x2;
        let x2_pt = h * x3;
        let x3_pt = h * x4;
        let x4_list_pts: Vec<RistrettoPoint> = x1_list
            .iter()
            .zip(x5_list.iter())
            .map(|(x1i, x5i)| g * x1i + h * x5i)
            .collect();
        let x5_list_pts: Vec<RistrettoPoint> = x5_list.iter().map(|x5i| new_pk_pt * x5i).collect();

        let x1_b = x1_pt.compress().to_bytes();
        let x2_b = x2_pt.compress().to_bytes();
        let x3_b = x3_pt.compress().to_bytes();
        let x4_b: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT] =
            std::array::from_fn(|i| x4_list_pts[i].compress().to_bytes());
        let x5_b: [[u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT] =
            std::array::from_fn(|i| x5_list_pts[i].compress().to_bytes());

        let p = self.fiat_shamir(&x1_b, &x2_b, &x3_b, &x4_b, &x5_b);

        let old_s = *self.sender_decryption_key.as_scalar();
        let new_s = *self.new_sender_decryption_key.as_scalar();
        let old_s_inv = old_s.invert();
        let new_s_inv = new_s.invert();

        let curr_chunks = self
            .current_encrypted_available_balance
            .chunked_amount()
            .chunks();
        let mut alpha1_list = [[0u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT];
        for i in 0..AVAILABLE_BALANCE_CHUNK_COUNT {
            let p_chunk = mul_mod_l(&p, &Scalar::from(curr_chunks[i]));
            alpha1_list[i] = (x1_list[i] - p_chunk).to_bytes();
        }
        let alpha2 = (x2 - mul_mod_l(&p, &old_s)).to_bytes();
        let alpha3 = (x3 - mul_mod_l(&p, &old_s_inv)).to_bytes();
        let alpha4 = (x4 - mul_mod_l(&p, &new_s_inv)).to_bytes();

        let new_r = self.new_encrypted_available_balance.randomness();
        let mut alpha5_list = [[0u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT];
        for i in 0..AVAILABLE_BALANCE_CHUNK_COUNT {
            let pri = mul_mod_l(&p, &new_r[i]);
            alpha5_list[i] = (x5_list[i] - pri).to_bytes();
        }

        KeyRotationSigmaProof {
            alpha1_list,
            alpha2,
            alpha3,
            alpha4,
            alpha5_list,
            x1: x1_b,
            x2: x2_b,
            x3: x3_b,
            x4_list: x4_b,
            x5_list: x5_b,
        }
    }

    pub fn verify_sigma_proof(
        sigma_proof: &KeyRotationSigmaProof,
        curr_public_key: &TwistedEd25519PublicKey,
        new_public_key: &TwistedEd25519PublicKey,
        curr_encrypted_balance: &[TwistedElGamalCiphertext],
        new_encrypted_balance: &[TwistedElGamalCiphertext],
        chain_id: u8,
        sender_address: &[u8],
        contract_address: &[u8],
    ) -> bool {
        if curr_encrypted_balance.len() != AVAILABLE_BALANCE_CHUNK_COUNT
            || new_encrypted_balance.len() != AVAILABLE_BALANCE_CHUNK_COUNT
        {
            return false;
        }
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = h_ristretto();
        let pk_old = curr_public_key.as_point();
        let pk_new = new_public_key.as_point();

        let g_b = g.compress().to_bytes();
        let h_b = h.compress().to_bytes();
        let curr_pk_b = curr_public_key.to_bytes();
        let new_pk_b = new_public_key.to_bytes();
        let curr_ct_b: Vec<u8> = curr_encrypted_balance
            .iter()
            .flat_map(|c| c.to_bytes())
            .collect();
        let new_ct_b: Vec<u8> = new_encrypted_balance
            .iter()
            .flat_map(|c| c.to_bytes())
            .collect();
        let mut parts: Vec<&[u8]> = vec![
            contract_address,
            &g_b,
            &h_b,
            &curr_pk_b,
            &new_pk_b,
            &curr_ct_b,
            &new_ct_b,
            &sigma_proof.x1,
            &sigma_proof.x2,
            &sigma_proof.x3,
        ];
        for x in &sigma_proof.x4_list {
            parts.push(x);
        }
        for x in &sigma_proof.x5_list {
            parts.push(x);
        }
        let p = fiat_shamir_challenge_ts(PROTOCOL_ID_ROTATION, chain_id, sender_address, &parts);

        let a1: Vec<Scalar> = sigma_proof
            .alpha1_list
            .iter()
            .map(|b| Scalar::from_bytes_mod_order(*b))
            .collect();
        let a2 = Scalar::from_bytes_mod_order(sigma_proof.alpha2);
        let a3 = Scalar::from_bytes_mod_order(sigma_proof.alpha3);
        let a4 = Scalar::from_bytes_mod_order(sigma_proof.alpha4);
        let a5: Vec<Scalar> = sigma_proof
            .alpha5_list
            .iter()
            .map(|b| Scalar::from_bytes_mod_order(*b))
            .collect();

        let d_old = sum_d_weighted(curr_encrypted_balance);
        let c_old = sum_c_weighted(curr_encrypted_balance);

        let lin_a1 = lin_comb_pow2_mod_l(&a1, CHUNK_BITS);
        let x1_re = g * lin_a1 + d_old * a2 + c_old * p;
        let x2_re = h * a3 + pk_old * p;
        let x3_re = h * a4 + pk_new * p;

        let Some(x1_p) = decompress(&sigma_proof.x1) else {
            return false;
        };
        let Some(x2_p) = decompress(&sigma_proof.x2) else {
            return false;
        };
        let Some(x3_p) = decompress(&sigma_proof.x3) else {
            return false;
        };

        let mut ok = x1_re == x1_p && x2_re == x2_p && x3_re == x3_p;
        for i in 0..AVAILABLE_BALANCE_CHUNK_COUNT {
            let x4i = g * a1[i] + h * a5[i] + new_encrypted_balance[i].c * p;
            let Some(x4p) = decompress(&sigma_proof.x4_list[i]) else {
                return false;
            };
            ok &= x4i == x4p;
            let x5i = pk_new * a5[i] + new_encrypted_balance[i].d * p;
            let Some(x5p) = decompress(&sigma_proof.x5_list[i]) else {
                return false;
            };
            ok &= x5i == x5p;
        }
        ok
    }

    pub async fn gen_range_proof(&self) -> Result<Vec<u8>, String> {
        crate::crypto::range_proof::generate_range_proof(
            self.new_encrypted_available_balance.get_ciphertext(),
            self.new_encrypted_available_balance
                .chunked_amount()
                .chunks(),
            self.new_encrypted_available_balance.randomness(),
        )
    }

    pub async fn verify_range_proof(
        range_proof: &[u8],
        new_encrypted_balance: &[TwistedElGamalCiphertext],
    ) -> Result<bool, String> {
        crate::crypto::range_proof::verify_range_proof(range_proof, new_encrypted_balance)
    }

    pub fn serialize_sigma_proof(proof: &KeyRotationSigmaProof) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGMA_PROOF_KEY_ROTATION_SIZE);
        for a in &proof.alpha1_list {
            out.extend_from_slice(a);
        }
        out.extend_from_slice(&proof.alpha2);
        out.extend_from_slice(&proof.alpha3);
        out.extend_from_slice(&proof.alpha4);
        for a in &proof.alpha5_list {
            out.extend_from_slice(a);
        }
        out.extend_from_slice(&proof.x1);
        out.extend_from_slice(&proof.x2);
        out.extend_from_slice(&proof.x3);
        for x in &proof.x4_list {
            out.extend_from_slice(x);
        }
        for x in &proof.x5_list {
            out.extend_from_slice(x);
        }
        debug_assert_eq!(out.len(), SIGMA_PROOF_KEY_ROTATION_SIZE);
        out
    }

    pub fn deserialize_sigma_proof(bytes: &[u8]) -> Result<KeyRotationSigmaProof, String> {
        if bytes.len() != SIGMA_PROOF_KEY_ROTATION_SIZE {
            return Err(format!(
                "key-rotation sigma: expected {} bytes, got {}",
                SIGMA_PROOF_KEY_ROTATION_SIZE,
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
        let alpha4 = take32();
        let mut alpha5_list = [[0u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT];
        for a in &mut alpha5_list {
            *a = take32();
        }
        let x1 = take32();
        let x2 = take32();
        let x3 = take32();
        let mut x4_list = [[0u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT];
        for x in &mut x4_list {
            *x = take32();
        }
        let mut x5_list = [[0u8; 32]; AVAILABLE_BALANCE_CHUNK_COUNT];
        for x in &mut x5_list {
            *x = take32();
        }
        Ok(KeyRotationSigmaProof {
            alpha1_list,
            alpha2,
            alpha3,
            alpha4,
            alpha5_list,
            x1,
            x2,
            x3,
            x4_list,
            x5_list,
        })
    }

    pub async fn authorize_key_rotation(
        &self,
    ) -> Result<(KeyRotationSigmaProof, Vec<u8>, EncryptedAmount), String> {
        let sigma = self.gen_sigma_proof();
        let range = self.gen_range_proof().await?;
        Ok((sigma, range, self.new_encrypted_available_balance.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::chunked_amount::ChunkedAmount;

    #[test]
    fn key_rotation_sigma_gen_verify_roundtrip() {
        let old_dk = TwistedEd25519PrivateKey::generate();
        let new_dk = TwistedEd25519PrivateKey::generate();
        let old_pk = old_dk.public_key();
        let bal: u128 = 1_234_567;
        let r_curr: Vec<Scalar> = (0..AVAILABLE_BALANCE_CHUNK_COUNT)
            .map(|_| ed25519_gen_random())
            .collect();
        let current = EncryptedAmount::new_with_randomness(
            ChunkedAmount::from_amount(bal),
            old_pk.clone(),
            r_curr,
        )
        .unwrap();

        let kr = ConfidentialKeyRotation::create(
            old_dk,
            new_dk.clone(),
            current.clone(),
            7,
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
        );

        let proof = kr.gen_sigma_proof();
        let new_pk = new_dk.public_key();
        let ok = ConfidentialKeyRotation::verify_sigma_proof(
            &proof,
            &old_pk,
            &new_pk,
            current.get_ciphertext(),
            kr.new_encrypted_available_balance().get_ciphertext(),
            7,
            &[1u8; 32],
            &[2u8; 32],
        );
        assert!(ok, "key-rotation sigma should verify");

        let bytes = ConfidentialKeyRotation::serialize_sigma_proof(&proof);
        assert_eq!(bytes.len(), SIGMA_PROOF_KEY_ROTATION_SIZE);
        let dec = ConfidentialKeyRotation::deserialize_sigma_proof(&bytes).unwrap();
        assert_eq!(ConfidentialKeyRotation::serialize_sigma_proof(&dec), bytes);
    }
}
