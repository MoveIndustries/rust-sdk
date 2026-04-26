// TS SDK `dstHash` / `fiatShamirChallenge` (variadic) parity
use confidential_assets::crypto::fiat_shamir::{dst_hash_ts, fiat_shamir_challenge_ts};
use curve25519_dalek::scalar::Scalar;

#[test]
fn dst_hash_ts_matches_tag_plus_data() {
    let a = dst_hash_ts("test-tag", &[&[1u8, 2, 3]]);
    let b = dst_hash_ts("test-tag", &[&[1u8, 2, 3]]);
    assert_eq!(a, b);
    assert_eq!(a.len(), 64);
}

#[test]
fn fiat_shamir_challenge_ts_deterministic() {
    let sender = [0xaau8; 32];
    let extra = [1u8, 2, 3];
    let a = fiat_shamir_challenge_ts("Withdrawal", 1, &sender, &[&extra]);
    let b = fiat_shamir_challenge_ts("Withdrawal", 1, &sender, &[&extra]);
    assert_eq!(a, b);
    assert_ne!(a, Scalar::ZERO);
}

#[test]
fn fiat_shamir_challenge_ts_differs_by_protocol() {
    let sender = [0u8; 32];
    let a = fiat_shamir_challenge_ts("Withdrawal", 1, &sender, &[]);
    let b = fiat_shamir_challenge_ts("Transfer", 1, &sender, &[]);
    assert_ne!(a, b);
}
