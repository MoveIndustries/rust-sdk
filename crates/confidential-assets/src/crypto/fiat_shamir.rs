// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};
/// DST prefix for Fiat-Shamir hashing.
const DST_PREFIX: &[u8] = b"MovementConfidentialAsset/";
/// Domain-separated hash using SHA2-512.
/// Returns 64 bytes: SHA512(DST_PREFIX || tag || data)
pub fn dst_hash(tag: &str, data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(DST_PREFIX);
    hasher.update(tag.as_bytes());
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}
/// Generate a Fiat-Shamir challenge as a Scalar.
/// Hash = SHA512(DST_PREFIX || protocol_id || chain_id_le || sender || contract || token || extra_data)
/// Result = bytes_to_scalar_le(hash) mod l
pub fn fiat_shamir_challenge(
    protocol_id: &str,
    chain_id: u8,
    sender_address: &[u8],
    token_address: &[u8],
    extra_data: &[&[u8]],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(DST_PREFIX);
    hasher.update(protocol_id.as_bytes());
    // chain_id as single byte
    hasher.update([chain_id]);
    hasher.update(sender_address);
    hasher.update(token_address);
    for data in extra_data {
        hasher.update(*data);
    }
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.into())
}
/// Generate Fiat-Shamir challenge with contract address included.
pub fn fiat_shamir_challenge_with_contract(
    protocol_id: &str,
    chain_id: u8,
    sender_address: &[u8],
    contract_address: &[u8],
    token_address: &[u8],
    extra_data: &[&[u8]],
) -> Scalar {
    let mut combined = vec![sender_address, contract_address, token_address];
    for d in extra_data {
        combined.push(*d);
    }
    fiat_shamir_challenge(
        protocol_id,
        chain_id,
        &combined.concat(),
        token_address,
        &[],
    )
}
/// SHA512(utf8(dst) || concatenated `parts`), matching TS `dstHash(dst, ...data)` (no extra prefix).
pub fn dst_hash_ts(dst: &str, parts: &[&[u8]]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(dst.as_bytes());
    for p in parts {
        hasher.update(*p);
    }
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

/// Matches TS `fiatShamirChallenge(protocolId, chainId, senderAddress, ...publicInputs)`:
/// SHA512(utf8("MovementConfidentialAsset/" + protocolId) || chain_id || sender || public_inputs…).
pub fn fiat_shamir_challenge_ts(
    protocol_id: &str,
    chain_id: u8,
    sender_address: &[u8],
    public_inputs: &[&[u8]],
) -> Scalar {
    let mut hasher = Sha512::new();
    let dst = format!("MovementConfidentialAsset/{protocol_id}");
    hasher.update(dst.as_bytes());
    hasher.update([chain_id]);
    hasher.update(sender_address);
    for p in public_inputs {
        hasher.update(*p);
    }
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.into())
}

/// Full Fiat-Shamir challenge for confidential proofs.
/// Matches the TS SDK's fiatShamirChallenge exactly:
/// SHA512(DST_PREFIX || protocol_id || chain_id_le || sender || contract || token || ...extra)
pub fn fiat_shamir_challenge_full(
    protocol_id: &str,
    chain_id: u8,
    sender_address: &[u8],
    contract_address: &[u8],
    token_address: &[u8],
    extra_data: &[&[u8]],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(DST_PREFIX);
    hasher.update(protocol_id.as_bytes());
    hasher.update([chain_id]);
    hasher.update(sender_address);
    hasher.update(contract_address);
    hasher.update(token_address);
    for data in extra_data {
        hasher.update(*data);
    }
    let hash = hasher.finalize();
    Scalar::from_bytes_mod_order_wide(&hash.into())
}
