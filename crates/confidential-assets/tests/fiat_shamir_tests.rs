// Tests for Fiat-Shamir hashing
// Ported from confidential-assets/tests/units/fiatShamir.test.ts

use confidential_assets::crypto::fiat_shamir::{dst_hash, fiat_shamir_challenge};

#[test]
fn dst_hash_produces_64_byte_output() {
    let result = dst_hash("test-tag", &[1, 2, 3]);
    assert_eq!(result.len(), 64);
}

#[test]
fn dst_hash_is_deterministic() {
    let data = vec![1u8, 2, 3, 4];
    let a = dst_hash("tag", &data);
    let b = dst_hash("tag", &data);
    assert_eq!(a, b);
}

#[test]
fn different_dsts_produce_different_hashes() {
    let data = vec![1u8, 2, 3];
    let a = dst_hash("tag-a", &data);
    let b = dst_hash("tag-b", &data);
    assert_ne!(a, b);
}

#[test]
fn different_data_produces_different_hashes() {
    let a = dst_hash("tag", &[1]);
    let b = dst_hash("tag", &[2]);
    assert_ne!(a, b);
}

#[test]
fn fiat_shamir_challenge_returns_a_scalar() {
    use curve25519_dalek::scalar::Scalar;
    let sender = vec![0u8; 32];
    let token = vec![0u8; 32];
    let challenge = fiat_shamir_challenge("Test", 1, &sender, &token, &[]);
    // Scalar should not be zero
    assert_ne!(challenge, Scalar::ZERO);
}

#[test]
fn fiat_shamir_challenge_is_deterministic() {
    let sender = vec![0xaau8; 32];
    let token = vec![0xbbu8; 32];
    let data = vec![1u8, 2, 3];
    let a = fiat_shamir_challenge("Withdrawal", 1, &sender, &token, &[&data]);
    let b = fiat_shamir_challenge("Withdrawal", 1, &sender, &token, &[&data]);
    assert_eq!(a, b);
}

#[test]
fn different_chain_ids_produce_different_challenges() {
    let sender = vec![0u8; 32];
    let token = vec![0u8; 32];
    let data = vec![1u8, 2, 3];
    let a = fiat_shamir_challenge("Withdrawal", 1, &sender, &token, &[&data]);
    let b = fiat_shamir_challenge("Withdrawal", 2, &sender, &token, &[&data]);
    assert_ne!(a, b);
}

#[test]
fn different_protocol_ids_produce_different_challenges() {
    let sender = vec![0u8; 32];
    let token = vec![0u8; 32];
    let a = fiat_shamir_challenge("Withdrawal", 1, &sender, &token, &[]);
    let b = fiat_shamir_challenge("Transfer", 1, &sender, &token, &[]);
    assert_ne!(a, b);
}

#[test]
fn different_sender_addresses_produce_different_challenges() {
    let token = vec![0u8; 32];
    let sender1 = vec![0x01u8; 32];
    let sender2 = vec![0x02u8; 32];
    let a = fiat_shamir_challenge("Withdrawal", 1, &sender1, &token, &[]);
    let b = fiat_shamir_challenge("Withdrawal", 1, &sender2, &token, &[]);
    assert_ne!(a, b);
}
