// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0
use crate::consts::PROTOCOL_ID_REGISTRATION;
use crate::crypto::fiat_shamir::fiat_shamir_challenge_full;
use crate::crypto::h_ristretto;
use crate::crypto::twisted_ed25519::{TwistedEd25519PrivateKey, TwistedEd25519PublicKey};
use crate::utils::ed25519_gen_random;
use curve25519_dalek::scalar::Scalar;
/// A registration proof: Schnorr-style ZKPoK of a decryption key.
#[derive(Clone, Debug)]
pub struct RegistrationProof {
    /// Commitment: R = k * H (32 bytes), matching TS `H_RISTRETTO.multiply(k)`.
    pub commitment: [u8; 32],
    /// Response: s = k - c * dk⁻¹ (mod l), matching TS `genRegistrationProof`.
    pub response: [u8; 32],
}
/// Generate a registration proof (ZKPoK of decryption key).
///
/// Proves knowledge of `dk` such that `ek = dk⁻¹ · H` (Movement TS / on-chain model).
pub fn gen_registration_proof(
    decryption_key: &TwistedEd25519PrivateKey,
    chain_id: u8,
    sender_address: &[u8],
    contract_address: &[u8],
    token_address: &[u8],
) -> RegistrationProof {
    let h = h_ristretto();
    // 1. Random nonce k
    let k = ed25519_gen_random();
    // 2. Commitment: R = k * H
    let r_point = k * h;
    let commitment = r_point.compress().to_bytes();
    // 3. Fiat-Shamir challenge
    let c = fiat_shamir_challenge_full(
        PROTOCOL_ID_REGISTRATION,
        chain_id,
        sender_address,
        contract_address,
        token_address,
        &[&decryption_key.public_key().to_bytes(), &commitment],
    );
    // 4. Response: s = k - c * dk⁻¹ (secret exponent on H is dk⁻¹ when ek = dk⁻¹·H)
    let dk = decryption_key.as_scalar();
    let dk_inv = dk.invert();
    let s = k - c * dk_inv;
    let response = s.to_bytes();
    RegistrationProof {
        commitment,
        response,
    }
}
/// Verify a registration proof.
pub fn verify_registration_proof(
    encryption_key_bytes: &[u8],
    proof: &RegistrationProof,
    chain_id: u8,
    sender_address: &[u8],
    contract_address: &[u8],
    token_address: &[u8],
) -> bool {
    // Parse public key
    let ek_bytes: [u8; 32] = match encryption_key_bytes.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk = match TwistedEd25519PublicKey::from_bytes(&ek_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    // Parse commitment point R
    use curve25519_dalek::ristretto::CompressedRistretto;
    let r_point = match CompressedRistretto(proof.commitment).decompress() {
        Some(p) => p,
        None => return false,
    };
    // Parse response scalar s
    let s_ct = Scalar::from_canonical_bytes(proof.response);
    if !bool::from(s_ct.is_some()) {
        return false;
    }
    // CtOption doesn't expose value() or unwrap(). We know it's valid from is_some check.
    // Use a match on Option converted via Into
    let s: Scalar = match <Option<Scalar>>::from(s_ct) {
        Some(s) => s,
        None => return false,
    };
    // Recompute challenge (must match `gen_registration_proof`: PK then commitment R)
    let pk_bytes = pk.to_bytes();
    let c = fiat_shamir_challenge_full(
        PROTOCOL_ID_REGISTRATION,
        chain_id,
        sender_address,
        contract_address,
        token_address,
        &[&pk_bytes, &proof.commitment],
    );
    // Verify: s * H + c * PK == R (TS `verifyRegistrationProof`)
    let h = h_ristretto();
    let lhs = s * h + c * pk.as_point();
    lhs == r_point
}
