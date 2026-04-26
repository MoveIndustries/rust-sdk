// Tests for registration proof (ZKPoK of decryption key)
// Ported from confidential-assets/tests/units/registration.test.ts
use confidential_assets::crypto::confidential_registration::{
    gen_registration_proof, verify_registration_proof,
};
use confidential_assets::crypto::twisted_ed25519::TwistedEd25519PrivateKey;
use confidential_assets::utils::ed25519_gen_random;

fn make_key() -> TwistedEd25519PrivateKey {
    let scalar = ed25519_gen_random();
    TwistedEd25519PrivateKey::from_scalar(scalar)
}

fn sender_address() -> Vec<u8> {
    vec![0xa1u8; 32]
}
fn contract_address() -> Vec<u8> {
    vec![0x55u8; 32]
}
fn token_address() -> Vec<u8> {
    vec![0xfau8; 32]
}

#[test]
fn generates_a_valid_registration_proof() {
    let dk = make_key();
    let proof = gen_registration_proof(
        &dk,
        1,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    assert_eq!(proof.commitment.len(), 32);
    assert_eq!(proof.response.len(), 32);
}

#[test]
fn valid_proof_verifies_successfully() {
    let dk = make_key();
    let ek = dk.public_key().to_bytes();
    let proof = gen_registration_proof(
        &dk,
        1,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    let valid = verify_registration_proof(
        &ek,
        &proof,
        1,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    assert!(valid);
}

#[test]
fn proof_fails_with_wrong_chain_id() {
    let dk = make_key();
    let ek = dk.public_key().to_bytes();
    let proof = gen_registration_proof(
        &dk,
        1,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    let valid = verify_registration_proof(
        &ek,
        &proof,
        99,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    assert!(!valid);
}

#[test]
fn proof_fails_with_wrong_sender_address() {
    let dk = make_key();
    let ek = dk.public_key().to_bytes();
    let proof = gen_registration_proof(
        &dk,
        1,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    let wrong_sender = vec![0xbbu8; 32];
    let valid = verify_registration_proof(
        &ek,
        &proof,
        1,
        &wrong_sender,
        &contract_address(),
        &token_address(),
    );
    assert!(!valid);
}

#[test]
fn proof_fails_with_wrong_token_address() {
    let dk = make_key();
    let ek = dk.public_key().to_bytes();
    let proof = gen_registration_proof(
        &dk,
        1,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    let wrong_token = vec![0xccu8; 32];
    let valid = verify_registration_proof(
        &ek,
        &proof,
        1,
        &sender_address(),
        &contract_address(),
        &wrong_token,
    );
    assert!(!valid);
}

#[test]
fn proof_fails_with_wrong_encryption_key() {
    let dk = make_key();
    let proof = gen_registration_proof(
        &dk,
        1,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    let other_dk = make_key();
    let other_ek = other_dk.public_key().to_bytes();
    let valid = verify_registration_proof(
        &other_ek,
        &proof,
        1,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    assert!(!valid);
}

#[test]
fn different_keys_produce_different_proofs() {
    let dk1 = make_key();
    let dk2 = make_key();
    let proof1 = gen_registration_proof(
        &dk1,
        1,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    let proof2 = gen_registration_proof(
        &dk2,
        1,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    assert_ne!(proof1.commitment, proof2.commitment);
}

#[test]
fn same_key_produces_different_proofs_each_time() {
    let dk = make_key();
    let proof1 = gen_registration_proof(
        &dk,
        1,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    let proof2 = gen_registration_proof(
        &dk,
        1,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    // Commitments should differ due to random nonce
    assert_ne!(proof1.commitment, proof2.commitment);
    // But both should verify
    let ek = dk.public_key().to_bytes();
    assert!(verify_registration_proof(
        &ek,
        &proof1,
        1,
        &sender_address(),
        &contract_address(),
        &token_address()
    ));
    assert!(verify_registration_proof(
        &ek,
        &proof2,
        1,
        &sender_address(),
        &contract_address(),
        &token_address()
    ));
}

#[test]
fn proof_fails_with_wrong_contract_address() {
    let dk = make_key();
    let ek = dk.public_key().to_bytes();
    let proof = gen_registration_proof(
        &dk,
        1,
        &sender_address(),
        &contract_address(),
        &token_address(),
    );
    let wrong_contract = vec![0x66u8; 32];
    assert!(!verify_registration_proof(
        &ek,
        &proof,
        1,
        &sender_address(),
        &wrong_contract,
        &token_address()
    ));
}
