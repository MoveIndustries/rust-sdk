// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! Bulletproofs range-proof wrapper that delegates to `movement_rp_wasm` (the same
//! upstream the TS SDK builds as WASM). Both libraries agree on the wire format
//! (32-byte LE scalar, compressed Ristretto point), so the boundary is byte-based.

use crate::crypto::h_ristretto;
use crate::crypto::twisted_el_gamal::TwistedElGamalCiphertext;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

/// Generate a batch range proof for `vals` with per-value randomness `randomness`.
/// Returns `(proof_bytes, commitment_bytes)` matching TS `genBatchRangeZKP`.
pub fn prove_range_batch(
    vals: &[u64],
    randomness: &[Scalar],
    val_base: &RistrettoPoint,
    rand_base: &RistrettoPoint,
    num_bits: usize,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
    if vals.len() != randomness.len() {
        return Err(format!(
            "vals len {} != randomness len {}",
            vals.len(),
            randomness.len()
        ));
    }
    let rs: Vec<Vec<u8>> = randomness.iter().map(|r| r.to_bytes().to_vec()).collect();
    let val_base_b = val_base.compress().to_bytes().to_vec();
    let rand_base_b = rand_base.compress().to_bytes().to_vec();
    let out = movement_rp_wasm::rp::_batch_range_proof(
        vals.to_vec(),
        rs,
        val_base_b,
        rand_base_b,
        num_bits,
    )
    .map_err(|e| format!("batch range proof: {}", e))?;
    Ok((out.proof(), out.comms()))
}

/// Verify a batch range proof.
pub fn verify_range_batch(
    proof: &[u8],
    commitments: &[Vec<u8>],
    val_base: &RistrettoPoint,
    rand_base: &RistrettoPoint,
    num_bits: usize,
) -> Result<bool, String> {
    use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
    use curve25519_dalek_ng::ristretto::CompressedRistretto as NgCompressed;
    use merlin::Transcript;

    if commitments.is_empty() {
        return Err("empty commitments".into());
    }
    let proof = RangeProof::from_bytes(proof).map_err(|e| format!("rp deser: {:?}", e))?;
    let val_base_b: [u8; 32] = val_base.compress().to_bytes();
    let rand_base_b: [u8; 32] = rand_base.compress().to_bytes();
    let pg = PedersenGens {
        B: NgCompressed(val_base_b)
            .decompress()
            .ok_or("val_base decompress")?,
        B_blinding: NgCompressed(rand_base_b)
            .decompress()
            .ok_or("rand_base decompress")?,
    };
    let gens = BulletproofGens::new(64, 16);
    let comms: Vec<NgCompressed> = commitments
        .iter()
        .map(|c| NgCompressed::from_slice(c.as_slice()))
        .collect();
    let dst: &[u8] = b"MovementConfidentialAsset/BulletproofRangeProof";
    let ok = proof
        .verify_multiple(&gens, &pg, &mut Transcript::new(dst), &comms, num_bits)
        .is_ok();
    Ok(ok)
}

/// Convenience for sigma-protocol callers: prove the chunked plaintext values
/// of an `EncryptedAmount` are each in `[0, 2^num_bits)` using G/H as bases.
pub fn prove_chunked_amount_range(
    chunks: &[u64],
    randomness: &[Scalar],
    num_bits: usize,
) -> Result<Vec<u8>, String> {
    let (proof, _comms) = prove_range_batch(
        chunks,
        randomness,
        &RISTRETTO_BASEPOINT_POINT,
        &h_ristretto(),
        num_bits,
    )?;
    Ok(proof)
}

/// Verify a batch range proof produced for the C-components of `ciphertexts`
/// (matches TS `verifyBatchRangeZKP` with `comm = C.toRawBytes()` per chunk).
pub fn verify_chunked_amount_range(
    proof: &[u8],
    ciphertexts: &[TwistedElGamalCiphertext],
    num_bits: usize,
) -> Result<bool, String> {
    let comms: Vec<Vec<u8>> = ciphertexts.iter().map(|ct| ct.c_bytes().to_vec()).collect();
    verify_range_batch(
        proof,
        &comms,
        &RISTRETTO_BASEPOINT_POINT,
        &h_ristretto(),
        num_bits,
    )
}

// Backwards-compat shims for existing call-sites.
pub fn generate_range_proof(
    _ciphertexts: &[TwistedElGamalCiphertext],
    values: &[u64],
    randomness: &[Scalar],
) -> Result<Vec<u8>, String> {
    use crate::crypto::chunked_amount::CHUNK_BITS;
    prove_chunked_amount_range(values, randomness, CHUNK_BITS as usize)
}

pub fn verify_range_proof(
    proof: &[u8],
    ciphertexts: &[TwistedElGamalCiphertext],
) -> Result<bool, String> {
    use crate::crypto::chunked_amount::CHUNK_BITS;
    verify_chunked_amount_range(proof, ciphertexts, CHUNK_BITS as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::chunked_amount::CHUNK_BITS;
    use crate::utils::ed25519_gen_random;

    #[test]
    fn batch_roundtrip_g_h() {
        let vals: Vec<u64> = vec![100, 1, 0, 65535, 7, 0, 0, 0];
        let rs: Vec<Scalar> = (0..vals.len()).map(|_| ed25519_gen_random()).collect();
        let (proof, comms) = prove_range_batch(
            &vals,
            &rs,
            &RISTRETTO_BASEPOINT_POINT,
            &h_ristretto(),
            CHUNK_BITS as usize,
        )
        .unwrap();
        assert_eq!(comms.len(), vals.len());
        let ok = verify_range_batch(
            &proof,
            &comms,
            &RISTRETTO_BASEPOINT_POINT,
            &h_ristretto(),
            CHUNK_BITS as usize,
        )
        .unwrap();
        assert!(ok);
    }

    /// Guards against the on-chain `ERANGE_PROOF_VERIFICATION_FAILED` regression: a proof
    /// produced by the prover (`movement_rp_wasm`) MUST verify under the contract's DST
    /// `MovementConfidentialAsset/BulletproofRangeProof` (confidential_proof.move:34) and MUST
    /// NOT verify under the legacy `AptosConfidentialAsset/...` label. The Fiat–Shamir
    /// challenges are bound to the transcript's initial DST, so the prover and the contract
    /// must use byte-identical labels. If this fails under `Movement`, the prover DST has
    /// drifted from the contract again (see wasm-bindings range-proofs/src/lib.rs).
    #[test]
    fn range_proof_dst_matches_contract() {
        use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
        use curve25519_dalek_ng::ristretto::CompressedRistretto as NgCompressed;
        use merlin::Transcript;

        let vals: Vec<u64> = vec![100, 1, 0, 65535, 7, 0, 0, 0];
        let rs: Vec<Scalar> = (0..vals.len()).map(|_| ed25519_gen_random()).collect();
        let (proof_bytes, comms) = prove_range_batch(
            &vals,
            &rs,
            &RISTRETTO_BASEPOINT_POINT,
            &h_ristretto(),
            CHUNK_BITS as usize,
        )
        .unwrap();

        let verify_under = |dst: &'static [u8]| -> bool {
            let proof = RangeProof::from_bytes(&proof_bytes).unwrap();
            let pg = PedersenGens {
                B: NgCompressed(RISTRETTO_BASEPOINT_POINT.compress().to_bytes())
                    .decompress()
                    .unwrap(),
                B_blinding: NgCompressed(h_ristretto().compress().to_bytes())
                    .decompress()
                    .unwrap(),
            };
            let gens = BulletproofGens::new(64, 16);
            let c: Vec<NgCompressed> = comms
                .iter()
                .map(|c| NgCompressed::from_slice(c.as_slice()))
                .collect();
            proof
                .verify_multiple(&gens, &pg, &mut Transcript::new(dst), &c, CHUNK_BITS as usize)
                .is_ok()
        };

        let aptos = verify_under(b"AptosConfidentialAsset/BulletproofRangeProof");
        let movement = verify_under(b"MovementConfidentialAsset/BulletproofRangeProof");

        println!("verify under Aptos*    DST = {aptos}");
        println!("verify under Movement* DST = {movement}");

        assert!(
            movement,
            "prover DST must match the contract's MovementConfidentialAsset/... (confidential_proof.move:34)"
        );
        assert!(
            !aptos,
            "prover must NOT still use the legacy AptosConfidentialAsset/... DST"
        );
    }
}
