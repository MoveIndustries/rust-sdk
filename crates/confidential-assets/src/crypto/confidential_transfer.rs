// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! Confidential transfer sigma proofs — aligned with `ts-sdk/confidential-assets` / Move layout.

use crate::bcs::bcs_serialize_move_vector_u8;
use crate::consts::{
    MAX_SENDER_AUDITOR_HINT_BYTES, PROTOCOL_ID_TRANSFER, SIGMA_PROOF_TRANSFER_SIZE,
};
use crate::crypto::chunked_amount::{
    AVAILABLE_BALANCE_CHUNK_COUNT, CHUNK_BITS, ChunkedAmount, MAX_CONFIDENTIAL_TRANSFER_PLAINTEXT,
    TRANSFER_AMOUNT_CHUNK_COUNT,
};
use crate::crypto::encrypted_amount::EncryptedAmount;
use crate::crypto::fiat_shamir::fiat_shamir_challenge_ts;
use crate::crypto::h_ristretto;
use crate::crypto::scalar_ts::{
    fix_alpha_limbs_weighted_lincomb, lin_comb_pow2_mod_l, scalar_pow2_mod_l, sub_mod_l,
    sub_mul_mod_l,
};
use crate::crypto::sigma_helpers::{sum_c_weighted, sum_d_weighted};
use crate::crypto::twisted_ed25519::{TwistedEd25519PrivateKey, TwistedEd25519PublicKey};
use crate::crypto::twisted_el_gamal::TwistedElGamalCiphertext;
use crate::utils::ed25519_gen_list_of_random;
use crate::utils::ed25519_gen_random;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

fn g_bytes() -> [u8; 32] {
    RISTRETTO_BASEPOINT_POINT.compress().to_bytes()
}

fn h_bytes() -> [u8; 32] {
    h_ristretto().compress().to_bytes()
}

/// Compare a (computed) point against a (proof-supplied) compressed encoding.
///
/// ristretto255 has a unique canonical 32-byte encoding, so two points are equal
/// iff their compressed bytes are equal. This avoids decompressing untrusted proof
/// bytes in the verifier — malformed or non-canonical inputs simply compare
/// unequal, so verification returns `false` cleanly instead of panicking.
fn point_eq_compressed(lhs: &RistrettoPoint, rhs: &[u8; 32]) -> bool {
    lhs.compress().to_bytes() == *rhs
}

/// Transfer sigma proof (TS `ConfidentialTransferSigmaProof`): scalars as 32-byte LE, points as compressed.
#[derive(Clone, Debug)]
pub struct TransferSigmaProof {
    pub alpha1_list: Vec<[u8; 32]>,
    pub alpha2: [u8; 32],
    pub alpha3_list: Vec<[u8; 32]>,
    pub alpha4_list: Vec<[u8; 32]>,
    pub alpha5: [u8; 32],
    pub alpha6_list: Vec<[u8; 32]>,
    pub x1: [u8; 32],
    pub x2_list: Vec<[u8; 32]>,
    pub x3_list: Vec<[u8; 32]>,
    pub x4_list: Vec<[u8; 32]>,
    pub x5: [u8; 32],
    pub x6_list: Vec<[u8; 32]>,
    pub x7_list: Vec<[u8; 32]>,
    pub x8_list: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct TransferRangeProof {
    pub range_proof_amount: Vec<u8>,
    pub range_proof_new_balance: Vec<u8>,
}

pub struct ConfidentialTransfer {
    sender_decryption_key: TwistedEd25519PrivateKey,
    sender_encrypted_available_balance: EncryptedAmount,
    sender_encrypted_available_balance_after_transfer: EncryptedAmount,
    transfer_amount_encrypted_by_sender: EncryptedAmount,
    transfer_amount_encrypted_by_recipient: EncryptedAmount,
    transfer_amount_encrypted_by_auditors: Option<Vec<EncryptedAmount>>,
    recipient_encryption_key: TwistedEd25519PublicKey,
    auditor_encryption_keys: Vec<TwistedEd25519PublicKey>,
    /// 8 scalars (TS); encryption uses first `TRANSFER_AMOUNT_CHUNK_COUNT` for transfer EAs.
    transfer_amount_randomness: Vec<Scalar>,
    new_balance_randomness: Vec<Scalar>,
    amount: u128,
    chain_id: u8,
    sender_address: Vec<u8>,
    contract_address: Vec<u8>,
    token_address: Vec<u8>,
    sender_auditor_hint: Vec<u8>,
}

impl ConfidentialTransfer {
    // Each argument is a distinct cryptographic input to the σ-protocol; collapsing
    // into a struct just shuffles complexity without making the call site clearer.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        sender_decryption_key: TwistedEd25519PrivateKey,
        sender_balance_amount: u128,
        sender_balance_randomness: Vec<Scalar>,
        amount: u128,
        recipient_encryption_key: TwistedEd25519PublicKey,
        auditor_encryption_keys: Vec<TwistedEd25519PublicKey>,
        chain_id: u8,
        sender_address: &[u8],
        contract_address: &[u8],
        token_address: &[u8],
        sender_auditor_hint: &[u8],
    ) -> Result<Self, String> {
        if sender_balance_randomness.len() != AVAILABLE_BALANCE_CHUNK_COUNT {
            return Err(format!(
                "sender_balance_randomness must have length {AVAILABLE_BALANCE_CHUNK_COUNT}"
            ));
        }
        let sender_pk = sender_decryption_key.public_key();
        let current_chunked = ChunkedAmount::from_amount(sender_balance_amount);
        let current_ea = EncryptedAmount::new_with_randomness(
            current_chunked,
            sender_pk,
            sender_balance_randomness,
        )?;
        Self::create_with_balance(
            sender_decryption_key,
            sender_balance_amount,
            current_ea.get_ciphertext().to_vec(),
            amount,
            recipient_encryption_key,
            auditor_encryption_keys,
            chain_id,
            sender_address,
            contract_address,
            token_address,
            sender_auditor_hint,
        )
    }

    /// Build a transfer context from the **on-chain** sender ciphertext.
    ///
    /// Move's `verify_transfer_sigma_proof` binds the σ-proof to the actual stored
    /// `current_balance` ciphertext (real D points, real C points) — both via the
    /// Fiat-Shamir transcript and the MSM check. Re-encrypting the known plaintext
    /// with fresh randomness here would yield a different ciphertext than what's
    /// stored on chain, the FS challenges would diverge, and the proof would be
    /// rejected with `ESIGMA_PROTOCOL_VERIFY_FAILED`. Tests built on a fresh deposit
    /// → rollover happen to mask this because Move's deposit path uses
    /// `new_pending_balance_u64_no_randonmess` (D = 0, C = v·G), which coincidentally
    /// matches a rebuild from `amount + zero randomness`; a second consecutive
    /// transfer (no intervening rollover) exercises real randomness and exposes the
    /// divergence.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_balance(
        sender_decryption_key: TwistedEd25519PrivateKey,
        sender_balance_amount: u128,
        sender_balance_ciphertext: Vec<TwistedElGamalCiphertext>,
        amount: u128,
        recipient_encryption_key: TwistedEd25519PublicKey,
        auditor_encryption_keys: Vec<TwistedEd25519PublicKey>,
        chain_id: u8,
        sender_address: &[u8],
        contract_address: &[u8],
        token_address: &[u8],
        sender_auditor_hint: &[u8],
    ) -> Result<Self, String> {
        if sender_auditor_hint.len() > MAX_SENDER_AUDITOR_HINT_BYTES {
            return Err(format!(
                "senderAuditorHint exceeds MAX_SENDER_AUDITOR_HINT_BYTES ({MAX_SENDER_AUDITOR_HINT_BYTES})"
            ));
        }
        if sender_balance_ciphertext.len() != AVAILABLE_BALANCE_CHUNK_COUNT {
            return Err(format!(
                "sender_balance_ciphertext must have length {AVAILABLE_BALANCE_CHUNK_COUNT}"
            ));
        }
        if amount > sender_balance_amount {
            return Err("Insufficient balance for transfer".to_string());
        }
        if amount > MAX_CONFIDENTIAL_TRANSFER_PLAINTEXT {
            return Err("Transfer amount exceeds MAX_CONFIDENTIAL_TRANSFER_PLAINTEXT".to_string());
        }
        let new_balance = sender_balance_amount - amount;
        let sender_pk = sender_decryption_key.public_key();

        let current_ea = EncryptedAmount::from_ciphertext_vec_for_verification(
            sender_balance_ciphertext,
            sender_pk.clone(),
        )?;

        let new_rnd = ed25519_gen_list_of_random(AVAILABLE_BALANCE_CHUNK_COUNT);
        let new_chunked = ChunkedAmount::from_amount(new_balance);
        let new_ea =
            EncryptedAmount::new_with_randomness(new_chunked, sender_pk.clone(), new_rnd.clone())?;

        let transfer_rnd = ed25519_gen_list_of_random(AVAILABLE_BALANCE_CHUNK_COUNT);
        let transfer_chunked = ChunkedAmount::from_transfer_amount(amount);
        let transfer_ea_sender = EncryptedAmount::new_with_randomness(
            transfer_chunked.clone(),
            sender_pk.clone(),
            transfer_rnd.clone(),
        )?;
        let transfer_ea_recipient = EncryptedAmount::new_with_randomness(
            transfer_chunked.clone(),
            recipient_encryption_key.clone(),
            transfer_rnd.clone(),
        )?;

        let auditor_eas: Option<Vec<EncryptedAmount>> = if auditor_encryption_keys.is_empty() {
            None
        } else {
            Some(
                auditor_encryption_keys
                    .iter()
                    .map(|aud_pk| {
                        EncryptedAmount::new_with_randomness(
                            transfer_chunked.clone(),
                            aud_pk.clone(),
                            transfer_rnd.clone(),
                        )
                        .expect("transfer rnd length ok")
                    })
                    .collect(),
            )
        };

        Ok(Self {
            sender_decryption_key,
            sender_encrypted_available_balance: current_ea,
            sender_encrypted_available_balance_after_transfer: new_ea,
            transfer_amount_encrypted_by_sender: transfer_ea_sender,
            transfer_amount_encrypted_by_recipient: transfer_ea_recipient,
            transfer_amount_encrypted_by_auditors: auditor_eas,
            recipient_encryption_key,
            auditor_encryption_keys,
            transfer_amount_randomness: transfer_rnd,
            new_balance_randomness: new_rnd,
            amount,
            chain_id,
            sender_address: sender_address.to_vec(),
            contract_address: contract_address.to_vec(),
            token_address: token_address.to_vec(),
            sender_auditor_hint: sender_auditor_hint.to_vec(),
        })
    }

    pub fn sender_encrypted_available_balance(&self) -> &EncryptedAmount {
        &self.sender_encrypted_available_balance
    }

    pub fn amount(&self) -> u128 {
        self.amount
    }

    pub fn token_address(&self) -> &[u8] {
        &self.token_address
    }

    pub fn transfer_amount_encrypted_by_sender(&self) -> &EncryptedAmount {
        &self.transfer_amount_encrypted_by_sender
    }
    pub fn transfer_amount_encrypted_by_recipient(&self) -> &EncryptedAmount {
        &self.transfer_amount_encrypted_by_recipient
    }
    pub fn transfer_amount_encrypted_by_auditors(&self) -> &Option<Vec<EncryptedAmount>> {
        &self.transfer_amount_encrypted_by_auditors
    }
    pub fn sender_encrypted_available_balance_after_transfer(&self) -> &EncryptedAmount {
        &self.sender_encrypted_available_balance_after_transfer
    }
    pub fn auditor_encryption_keys(&self) -> &[TwistedEd25519PublicKey] {
        &self.auditor_encryption_keys
    }

    pub fn gen_sigma_proof(&self) -> TransferSigmaProof {
        let i = AVAILABLE_BALANCE_CHUNK_COUNT;
        let j = TRANSFER_AMOUNT_CHUNK_COUNT;
        assert_eq!(self.transfer_amount_randomness.len(), i);

        let sender_pk_pt = self.sender_decryption_key.public_key();
        let sender_ristretto = sender_pk_pt.as_point();
        let recipient_ristretto = self.recipient_encryption_key.as_point();
        let h = h_ristretto();

        let x1_list: Vec<Scalar> = ed25519_gen_list_of_random(i);
        let x2 = ed25519_gen_random();
        let x3_list: Vec<Scalar> = ed25519_gen_list_of_random(i);
        let x4_list: Vec<Scalar> = ed25519_gen_list_of_random(i);
        let x5 = ed25519_gen_random();
        let x6_list: Vec<Scalar> = ed25519_gen_list_of_random(i);

        let h_coeff = sub_mod_l(
            &lin_comb_pow2_mod_l(&x6_list, CHUNK_BITS),
            &lin_comb_pow2_mod_l(&x3_list[..j], CHUNK_BITS),
        );

        let x1_sum = lin_comb_pow2_mod_l(&x1_list, CHUNK_BITS);
        let old_bal = self.sender_encrypted_available_balance.get_ciphertext();
        let new_bal = self
            .sender_encrypted_available_balance_after_transfer
            .get_ciphertext();

        let x1_pt = RISTRETTO_BASEPOINT_POINT * x1_sum + h * h_coeff + sum_d_weighted(old_bal) * x2
            - sum_d_weighted(new_bal) * x2;

        let x2_list: Vec<[u8; 32]> = x6_list
            .iter()
            .map(|el| (sender_ristretto * el).compress().to_bytes())
            .collect();
        let x3_list_pts: Vec<[u8; 32]> = x3_list[..j]
            .iter()
            .map(|x3| (recipient_ristretto * x3).compress().to_bytes())
            .collect();
        let x4_list_pts: Vec<[u8; 32]> = x4_list[..j]
            .iter()
            .enumerate()
            .map(|(idx, x4)| {
                (RISTRETTO_BASEPOINT_POINT * x4 + h * x3_list[idx])
                    .compress()
                    .to_bytes()
            })
            .collect();
        let x5_pt = (h * x5).compress().to_bytes();
        let x6_list_pts: Vec<[u8; 32]> = x1_list
            .iter()
            .enumerate()
            .map(|(idx, el)| {
                (RISTRETTO_BASEPOINT_POINT * el + h * x6_list[idx])
                    .compress()
                    .to_bytes()
            })
            .collect();

        let mut x7_flat: Vec<[u8; 32]> = Vec::new();
        for aud_pk in &self.auditor_encryption_keys {
            let aud_pt = aud_pk.as_point();
            for x3 in &x3_list[..j] {
                x7_flat.push((aud_pt * x3).compress().to_bytes());
            }
        }

        let x8_list: Vec<[u8; 32]> = x3_list[..j]
            .iter()
            .map(|el| (sender_ristretto * el).compress().to_bytes())
            .collect();

        let x1_bytes = x1_pt.compress().to_bytes();

        let mut extra = Vec::new();
        extra.extend_from_slice(&self.contract_address);
        extra.extend_from_slice(&self.token_address);
        extra.extend_from_slice(&g_bytes());
        extra.extend_from_slice(&h_bytes());
        extra.extend_from_slice(&sender_pk_pt.to_bytes());
        extra.extend_from_slice(&self.recipient_encryption_key.to_bytes());
        for aud in &self.auditor_encryption_keys {
            extra.extend_from_slice(&aud.to_bytes());
        }
        extra.extend_from_slice(
            &self
                .sender_encrypted_available_balance
                .get_ciphertext_bytes(),
        );
        extra.extend_from_slice(
            &self
                .transfer_amount_encrypted_by_recipient
                .get_ciphertext_bytes(),
        );
        if let Some(ref auds) = self.transfer_amount_encrypted_by_auditors {
            for ea in auds {
                extra.extend_from_slice(&ea.get_ciphertext_d_point_bytes());
            }
        }
        extra.extend_from_slice(
            &self
                .transfer_amount_encrypted_by_sender
                .get_ciphertext_d_point_bytes(),
        );
        extra.extend_from_slice(
            &self
                .sender_encrypted_available_balance_after_transfer
                .get_ciphertext_bytes(),
        );
        extra.extend_from_slice(&x1_bytes);
        for x in &x2_list {
            extra.extend_from_slice(x);
        }
        for x in &x3_list_pts {
            extra.extend_from_slice(x);
        }
        for x in &x4_list_pts {
            extra.extend_from_slice(x);
        }
        extra.extend_from_slice(&x5_pt);
        for x in &x6_list_pts {
            extra.extend_from_slice(x);
        }
        for x in &x7_flat {
            extra.extend_from_slice(x);
        }
        for x in &x8_list {
            extra.extend_from_slice(x);
        }
        extra.extend_from_slice(&bcs_serialize_move_vector_u8(&self.sender_auditor_hint));

        let p = fiat_shamir_challenge_ts(
            PROTOCOL_ID_TRANSFER,
            self.chain_id,
            &self.sender_address,
            &[&extra],
        );

        let s_le = self.sender_decryption_key.as_scalar();
        let invert_s = s_le.invert();

        let bal_after_chunks = self
            .sender_encrypted_available_balance_after_transfer
            .chunked_amount()
            .chunks();
        let bal_scalars: Vec<Scalar> = bal_after_chunks.iter().map(|&c| Scalar::from(c)).collect();
        let alpha1_scalars =
            fix_alpha_limbs_weighted_lincomb(&x1_list, &p, &bal_scalars, CHUNK_BITS);
        let alpha1_list: Vec<[u8; 32]> = alpha1_scalars.iter().map(|s| s.to_bytes()).collect();

        let alpha2 = sub_mul_mod_l(&x2, &p, s_le).to_bytes();

        let alpha3_scalars = fix_alpha_limbs_weighted_lincomb(
            &x3_list[..j],
            &p,
            &self.transfer_amount_randomness[..j],
            CHUNK_BITS,
        );
        let alpha3_list: Vec<[u8; 32]> = alpha3_scalars.iter().map(|s| s.to_bytes()).collect();

        let amt_chunks = self
            .transfer_amount_encrypted_by_sender
            .chunked_amount()
            .chunks();
        let amt_scalars: Vec<Scalar> = amt_chunks.iter().map(|&c| Scalar::from(c)).collect();
        let alpha4_scalars =
            fix_alpha_limbs_weighted_lincomb(&x4_list[..j], &p, &amt_scalars, CHUNK_BITS);
        let alpha4_list: Vec<[u8; 32]> = alpha4_scalars.iter().map(|s| s.to_bytes()).collect();

        let alpha5 = sub_mul_mod_l(&x5, &p, &invert_s).to_bytes();

        let new_r = self.new_balance_randomness.clone();
        let alpha6_scalars = fix_alpha_limbs_weighted_lincomb(&x6_list, &p, &new_r, CHUNK_BITS);
        let alpha6_list: Vec<[u8; 32]> = alpha6_scalars.iter().map(|s| s.to_bytes()).collect();

        TransferSigmaProof {
            alpha1_list,
            alpha2,
            alpha3_list,
            alpha4_list,
            alpha5,
            alpha6_list,
            x1: x1_bytes,
            x2_list,
            x3_list: x3_list_pts,
            x4_list: x4_list_pts,
            x5: x5_pt,
            x6_list: x6_list_pts,
            x7_list: x7_flat,
            x8_list,
        }
    }

    /// Verify a transfer sigma proof (TS `verifySigmaProof`).
    ///
    /// Prover responses adjust the last limb per chunk group so weighted sums mod `l` match the
    /// verifier’s `lin_comb_pow2_mod_l` on limb scalars. Validate against the TS SDK on shared
    /// fixtures before production use.
    pub fn verify_sigma_proof(opts: &TransferVerifyParams) -> bool {
        let j = TRANSFER_AMOUNT_CHUNK_COUNT;
        let i = AVAILABLE_BALANCE_CHUNK_COUNT;
        let proof = &opts.sigma_proof;
        if proof.alpha1_list.len() != i
            || proof.alpha3_list.len() != j
            || proof.alpha4_list.len() != j
            || proof.alpha6_list.len() != i
            || proof.x2_list.len() != i
            || proof.x3_list.len() != j
            || proof.x4_list.len() != j
            || proof.x6_list.len() != i
            || proof.x8_list.len() != j
        {
            return false;
        }

        let sender_pk = opts.sender_private_key.public_key();
        let sender_b = sender_pk.to_bytes();
        let recipient_b = opts.recipient_public_key.to_bytes();
        let sender_ristretto = sender_pk.as_point();
        let recipient_ristretto = opts.recipient_public_key.as_point();
        let h = h_ristretto();

        let auditor_pks: Vec<[u8; 32]> = opts
            .auditors
            .as_ref()
            .map(|a| a.public_keys.iter().map(|k| k.to_bytes()).collect())
            .unwrap_or_default();

        let mut extra = Vec::new();
        extra.extend_from_slice(&opts.contract_address);
        extra.extend_from_slice(&opts.token_address);
        extra.extend_from_slice(&g_bytes());
        extra.extend_from_slice(&h_bytes());
        extra.extend_from_slice(&sender_b);
        extra.extend_from_slice(&recipient_b);
        for pk in &auditor_pks {
            extra.extend_from_slice(pk);
        }
        let old_ct = &opts.encrypted_actual_balance;
        for ct in old_ct {
            extra.extend_from_slice(&ct.to_bytes());
        }
        extra.extend_from_slice(
            &opts
                .encrypted_transfer_amount_by_recipient
                .get_ciphertext_bytes(),
        );
        if let Some(ref aud) = opts.auditors {
            for row in &aud.auditors_cb_list {
                for ct in row {
                    extra.extend_from_slice(&ct.d_bytes());
                }
            }
        }
        extra.extend_from_slice(
            &opts
                .encrypted_transfer_amount_by_sender
                .get_ciphertext_d_point_bytes(),
        );
        extra.extend_from_slice(
            &opts
                .encrypted_actual_balance_after_transfer
                .get_ciphertext_bytes(),
        );
        extra.extend_from_slice(&proof.x1);
        for x in &proof.x2_list {
            extra.extend_from_slice(x);
        }
        for x in &proof.x3_list {
            extra.extend_from_slice(x);
        }
        for x in &proof.x4_list {
            extra.extend_from_slice(x);
        }
        extra.extend_from_slice(&proof.x5);
        for x in &proof.x6_list {
            extra.extend_from_slice(x);
        }
        for x in &proof.x7_list {
            extra.extend_from_slice(x);
        }
        for x in &proof.x8_list {
            extra.extend_from_slice(x);
        }
        extra.extend_from_slice(&bcs_serialize_move_vector_u8(&opts.sender_auditor_hint));

        let challenge = fiat_shamir_challenge_ts(
            PROTOCOL_ID_TRANSFER,
            opts.chain_id,
            &opts.sender_address,
            &[&extra],
        );

        let a1: Vec<Scalar> = proof
            .alpha1_list
            .iter()
            .map(|b| Scalar::from_bytes_mod_order(*b))
            .collect();
        let a2 = Scalar::from_bytes_mod_order(proof.alpha2);
        let a3: Vec<Scalar> = proof
            .alpha3_list
            .iter()
            .map(|b| Scalar::from_bytes_mod_order(*b))
            .collect();
        let a4: Vec<Scalar> = proof
            .alpha4_list
            .iter()
            .map(|b| Scalar::from_bytes_mod_order(*b))
            .collect();
        let a5 = Scalar::from_bytes_mod_order(proof.alpha5);
        let a6: Vec<Scalar> = proof
            .alpha6_list
            .iter()
            .map(|b| Scalar::from_bytes_mod_order(*b))
            .collect();

        let p = challenge;

        let old_d_sum = sum_d_weighted(old_ct);
        let old_c_sum = sum_c_weighted(old_ct);
        let new_ct = opts
            .encrypted_actual_balance_after_transfer
            .get_ciphertext();
        let new_d_sum = sum_d_weighted(new_ct);

        let rec_ct = opts.encrypted_transfer_amount_by_recipient.get_ciphertext();
        let amount_c_sum =
            rec_ct[..j]
                .iter()
                .enumerate()
                .fold(RistrettoPoint::identity(), |acc, (idx, ct)| {
                    let coef = scalar_pow2_mod_l(CHUNK_BITS * idx as u32);
                    acc + ct.c * coef
                });

        let verify_h = sub_mod_l(
            &lin_comb_pow2_mod_l(&a6, CHUNK_BITS),
            &lin_comb_pow2_mod_l(&a3[..j], CHUNK_BITS),
        );

        let x1_re = RISTRETTO_BASEPOINT_POINT * lin_comb_pow2_mod_l(&a1, CHUNK_BITS)
            + h * verify_h
            + old_d_sum * a2
            - new_d_sum * a2
            + old_c_sum * p
            - amount_c_sum * p;

        let x2_list: Vec<RistrettoPoint> = a6
            .iter()
            .enumerate()
            .map(|(idx, el)| sender_ristretto * el + new_ct[idx].d * p)
            .collect();
        let x3_list: Vec<RistrettoPoint> = a3[..j]
            .iter()
            .enumerate()
            .map(|(idx, a3s)| recipient_ristretto * a3s + rec_ct[idx].d * p)
            .collect();
        let x4_list: Vec<RistrettoPoint> = a4[..j]
            .iter()
            .enumerate()
            .map(|(idx, a4s)| RISTRETTO_BASEPOINT_POINT * a4s + h * a3[idx] + rec_ct[idx].c * p)
            .collect();
        let x5_re = h * a5 + sender_ristretto * p;
        let x6_list: Vec<RistrettoPoint> = a1
            .iter()
            .enumerate()
            .map(|(idx, a1s)| RISTRETTO_BASEPOINT_POINT * a1s + h * a6[idx] + new_ct[idx].c * p)
            .collect();

        let mut ok = point_eq_compressed(&x1_re, &proof.x1);
        for (x, b) in x2_list.iter().zip(&proof.x2_list) {
            ok &= point_eq_compressed(x, b);
        }
        for (x, b) in x3_list.iter().zip(&proof.x3_list) {
            ok &= point_eq_compressed(x, b);
        }
        for (x, b) in x4_list.iter().zip(&proof.x4_list) {
            ok &= point_eq_compressed(x, b);
        }
        ok &= point_eq_compressed(&x5_re, &proof.x5);
        for (x, b) in x6_list.iter().zip(&proof.x6_list) {
            ok &= point_eq_compressed(x, b);
        }
        for (x, b) in x8_list_verify(opts, &a3[..j], &p, sender_ristretto)
            .iter()
            .zip(&proof.x8_list)
        {
            ok &= point_eq_compressed(x, b);
        }

        if let Some(ref aud) = opts.auditors {
            let mut xi = 0usize;
            for (au_idx, au_pk) in aud.public_keys.iter().enumerate() {
                let au_pt = au_pk.as_point();
                for (idx_j, a3s) in a3.iter().take(j).enumerate() {
                    let d_pt = aud.auditors_cb_list[au_idx][idx_j].d;
                    let x7 = au_pt * a3s + d_pt * p;
                    if xi >= proof.x7_list.len() {
                        return false;
                    }
                    ok &= point_eq_compressed(&x7, &proof.x7_list[xi]);
                    xi += 1;
                }
            }
            if xi != proof.x7_list.len() {
                return false;
            }
        } else if !proof.x7_list.is_empty() {
            return false;
        }

        ok
    }

    pub fn serialize_sigma_proof(proof: &TransferSigmaProof) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGMA_PROOF_TRANSFER_SIZE + proof.x7_list.len() * 32);
        for a in &proof.alpha1_list {
            out.extend_from_slice(a);
        }
        out.extend_from_slice(&proof.alpha2);
        for a in &proof.alpha3_list {
            out.extend_from_slice(a);
        }
        for a in &proof.alpha4_list {
            out.extend_from_slice(a);
        }
        out.extend_from_slice(&proof.alpha5);
        for a in &proof.alpha6_list {
            out.extend_from_slice(a);
        }
        out.extend_from_slice(&proof.x1);
        for x in &proof.x2_list {
            out.extend_from_slice(x);
        }
        for x in &proof.x3_list {
            out.extend_from_slice(x);
        }
        for x in &proof.x4_list {
            out.extend_from_slice(x);
        }
        out.extend_from_slice(&proof.x5);
        for x in &proof.x6_list {
            out.extend_from_slice(x);
        }
        for x in &proof.x7_list {
            out.extend_from_slice(x);
        }
        for x in &proof.x8_list {
            out.extend_from_slice(x);
        }
        out
    }

    pub fn deserialize_sigma_proof(bytes: &[u8]) -> Result<TransferSigmaProof, String> {
        const CHUNK: usize = 32;
        if !bytes.len().is_multiple_of(CHUNK) {
            return Err("sigma proof length must be multiple of 32".into());
        }
        if bytes.len() < SIGMA_PROOF_TRANSFER_SIZE {
            return Err(format!(
                "sigma proof too short: {} < {}",
                bytes.len(),
                SIGMA_PROOF_TRANSFER_SIZE
            ));
        }
        let extra = (bytes.len() - SIGMA_PROOF_TRANSFER_SIZE) / CHUNK;
        if !extra.is_multiple_of(4) {
            return Err("extra X7 chunks must be multiple of 4".into());
        }

        let mut o = 0usize;
        let take32 = |b: &[u8], o: &mut usize| -> [u8; 32] {
            let s = *o;
            *o += 32;
            b[s..s + 32]
                .try_into()
                .expect("32-byte slice converts to [u8; 32]")
        };
        let take_n = |b: &[u8], o: &mut usize, n: usize| -> Vec<[u8; 32]> {
            (0..n).map(|_| take32(b, o)).collect()
        };

        let alpha1_list = take_n(bytes, &mut o, 8);
        let alpha2 = take32(bytes, &mut o);
        let alpha3_list = take_n(bytes, &mut o, 4);
        let alpha4_list = take_n(bytes, &mut o, 4);
        let alpha5 = take32(bytes, &mut o);
        let alpha6_list = take_n(bytes, &mut o, 8);
        let x1 = take32(bytes, &mut o);
        let x2_list = take_n(bytes, &mut o, 8);
        let x3_list = take_n(bytes, &mut o, 4);
        let x4_list = take_n(bytes, &mut o, 4);
        let x5 = take32(bytes, &mut o);
        let x6_list = take_n(bytes, &mut o, 8);
        let x7_list = take_n(bytes, &mut o, extra);
        let x8_list = take_n(bytes, &mut o, 4);
        if o != bytes.len() {
            return Err("trailing bytes in sigma proof".into());
        }
        Ok(TransferSigmaProof {
            alpha1_list,
            alpha2,
            alpha3_list,
            alpha4_list,
            alpha5,
            alpha6_list,
            x1,
            x2_list,
            x3_list,
            x4_list,
            x5,
            x6_list,
            x7_list,
            x8_list,
        })
    }

    /// Generate batch range proofs for the transfer amount (recipient view) and
    /// the sender's new balance — matches TS `genRangeProof`.
    pub async fn gen_range_proof(&self) -> Result<TransferRangeProof, String> {
        let amt_chunks: Vec<u64> = self
            .transfer_amount_encrypted_by_recipient
            .chunked_amount()
            .chunks()
            .to_vec();
        let amt_rs: Vec<Scalar> =
            self.transfer_amount_randomness[..TRANSFER_AMOUNT_CHUNK_COUNT].to_vec();
        let bal_chunks: Vec<u64> = self
            .sender_encrypted_available_balance_after_transfer
            .chunked_amount()
            .chunks()
            .to_vec();
        let bal_rs: Vec<Scalar> = self.new_balance_randomness.clone();
        let range_proof_amount = crate::crypto::range_proof::prove_chunked_amount_range(
            &amt_chunks,
            &amt_rs,
            CHUNK_BITS as usize,
        )?;
        let range_proof_new_balance = crate::crypto::range_proof::prove_chunked_amount_range(
            &bal_chunks,
            &bal_rs,
            CHUNK_BITS as usize,
        )?;
        Ok(TransferRangeProof {
            range_proof_amount,
            range_proof_new_balance,
        })
    }

    pub async fn verify_range_proof(
        encrypted_amount_by_recipient: &EncryptedAmount,
        encrypted_balance_after: &EncryptedAmount,
        range_proof_amount: &[u8],
        range_proof_new_balance: &[u8],
    ) -> Result<bool, String> {
        let amt_ok = crate::crypto::range_proof::verify_chunked_amount_range(
            range_proof_amount,
            &encrypted_amount_by_recipient.get_ciphertext()[..TRANSFER_AMOUNT_CHUNK_COUNT],
            CHUNK_BITS as usize,
        )?;
        let bal_ok = crate::crypto::range_proof::verify_chunked_amount_range(
            range_proof_new_balance,
            encrypted_balance_after.get_ciphertext(),
            CHUNK_BITS as usize,
        )?;
        Ok(amt_ok && bal_ok)
    }

    pub async fn authorize_transfer(
        &self,
    ) -> Result<
        (
            TransferSigmaProof,
            TransferRangeProof,
            EncryptedAmount,
            EncryptedAmount,
            Vec<EncryptedAmount>,
        ),
        String,
    > {
        let sigma = self.gen_sigma_proof();
        let range = self.gen_range_proof().await?;
        Ok((
            sigma,
            range,
            self.sender_encrypted_available_balance_after_transfer
                .clone(),
            self.transfer_amount_encrypted_by_recipient.clone(),
            self.transfer_amount_encrypted_by_auditors
                .clone()
                .unwrap_or_default(),
        ))
    }
}

fn x8_list_verify(
    opts: &TransferVerifyParams,
    a3: &[Scalar],
    p: &Scalar,
    sender_ristretto: &RistrettoPoint,
) -> Vec<RistrettoPoint> {
    let j = TRANSFER_AMOUNT_CHUNK_COUNT;
    let s_ct = opts.encrypted_transfer_amount_by_sender.get_ciphertext();
    (0..j)
        .map(|i| sender_ristretto * a3[i] + s_ct[i].d * p)
        .collect()
}

/// Parameters for sigma proof verification (TS `verifySigmaProof` opts).
pub struct TransferVerifyParams {
    pub sender_private_key: TwistedEd25519PrivateKey,
    pub recipient_public_key: TwistedEd25519PublicKey,
    pub encrypted_actual_balance: Vec<TwistedElGamalCiphertext>,
    pub encrypted_actual_balance_after_transfer: EncryptedAmount,
    pub encrypted_transfer_amount_by_recipient: EncryptedAmount,
    pub encrypted_transfer_amount_by_sender: EncryptedAmount,
    pub sigma_proof: TransferSigmaProof,
    pub auditors: Option<AuditorParams>,
    pub chain_id: u8,
    pub sender_address: Vec<u8>,
    pub contract_address: Vec<u8>,
    pub token_address: Vec<u8>,
    pub sender_auditor_hint: Vec<u8>,
}

pub struct AuditorParams {
    pub public_keys: Vec<TwistedEd25519PublicKey>,
    pub auditors_cb_list: Vec<Vec<TwistedElGamalCiphertext>>,
}
