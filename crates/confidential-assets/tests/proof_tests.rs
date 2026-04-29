// Tests for confidential proof generation and verification
// Ported from confidential-assets/tests/units/confidentialProofs.test.ts
// Only non-skipped tests are included.
use confidential_assets::SIGMA_PROOF_TRANSFER_SIZE;
use confidential_assets::crypto::chunked_amount::{
    AVAILABLE_BALANCE_CHUNK_COUNT, CHUNK_BITS, ChunkedAmount,
};
use confidential_assets::crypto::confidential_key_rotation::ConfidentialKeyRotation;
use confidential_assets::crypto::confidential_normalization::ConfidentialNormalization;
use confidential_assets::crypto::confidential_transfer::{
    ConfidentialTransfer, TransferVerifyParams,
};
use confidential_assets::crypto::confidential_withdraw::ConfidentialWithdraw;
use confidential_assets::crypto::encrypted_amount::EncryptedAmount;
use confidential_assets::crypto::twisted_ed25519::TwistedEd25519PrivateKey;

const ALICE_BALANCE: u128 = 18446744073709551716u128;
const TEST_CHAIN_ID: u8 = 1;

fn test_sender_addr() -> Vec<u8> {
    vec![0u8; 32]
}
fn test_token_addr() -> Vec<u8> {
    vec![0u8; 32]
}
fn test_contract_addr() -> Vec<u8> {
    let mut a = vec![0u8; 32];
    a[31] = 0x07;
    a
}

#[test]
fn generate_withdraw_sigma_proof() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    let alice_chunked = ChunkedAmount::from_amount(ALICE_BALANCE);
    let alice_ea = EncryptedAmount::new(alice_chunked, alice_pk);
    let withdraw_amount: u128 = 1u128 << 16;

    let cw = ConfidentialWithdraw::create_with_balance(
        alice_dk,
        ALICE_BALANCE,
        alice_ea.get_ciphertext().to_vec(),
        withdraw_amount,
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
    )
    .expect("create_with_balance should succeed");

    let sigma = cw.gen_sigma_proof();
    assert_eq!(
        sigma.serialize().len(),
        confidential_assets::SIGMA_PROOF_WITHDRAW_SIZE
    );
}

#[test]
fn generate_transfer_sigma_proof() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let bob_dk = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    let bob_pk = bob_dk.public_key();
    let alice_chunked = ChunkedAmount::from_amount(ALICE_BALANCE);
    let alice_ea = EncryptedAmount::new(alice_chunked, alice_pk);
    let transfer_amount: u128 = 10;

    let ct = ConfidentialTransfer::create(
        alice_dk,
        ALICE_BALANCE,
        alice_ea.randomness().to_vec(),
        transfer_amount,
        bob_pk,
        vec![], // no auditors
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
        &[],
    )
    .expect("create should succeed");

    let sigma = ct.gen_sigma_proof();
    assert!(!sigma.alpha1_list.is_empty());
}

#[test]
fn transfer_sigma_gen_verify_roundtrip() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let bob_dk = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    let alice_chunked = ChunkedAmount::from_amount(ALICE_BALANCE);
    let alice_ea = EncryptedAmount::new(alice_chunked, alice_pk);
    let transfer_amount: u128 = 10;

    let ct = ConfidentialTransfer::create(
        alice_dk.clone(),
        ALICE_BALANCE,
        alice_ea.randomness().to_vec(),
        transfer_amount,
        bob_dk.public_key(),
        vec![],
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
        &[],
    )
    .expect("create");

    let sigma = ct.gen_sigma_proof();
    let opts = TransferVerifyParams {
        sender_private_key: alice_dk,
        recipient_public_key: bob_dk.public_key(),
        encrypted_actual_balance: ct
            .sender_encrypted_available_balance()
            .get_ciphertext()
            .to_vec(),
        encrypted_actual_balance_after_transfer: ct
            .sender_encrypted_available_balance_after_transfer()
            .clone(),
        encrypted_transfer_amount_by_recipient: ct.transfer_amount_encrypted_by_recipient().clone(),
        encrypted_transfer_amount_by_sender: ct.transfer_amount_encrypted_by_sender().clone(),
        sigma_proof: sigma,
        auditors: None,
        chain_id: TEST_CHAIN_ID,
        sender_address: test_sender_addr(),
        contract_address: test_contract_addr(),
        token_address: test_token_addr(),
        sender_auditor_hint: vec![],
    };
    assert!(
        ConfidentialTransfer::verify_sigma_proof(&opts),
        "transfer sigma roundtrip should verify"
    );
}

/// Malformed proof points must cause verification to return `false`, not panic.
/// `[0xff; 32]` is not a canonical ristretto255 encoding; comparing in compressed
/// form (rather than decompressing untrusted bytes) keeps the verifier panic-free.
#[test]
fn transfer_sigma_verify_rejects_malformed_proof_points_without_panic() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let bob_dk = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    let alice_chunked = ChunkedAmount::from_amount(ALICE_BALANCE);
    let alice_ea = EncryptedAmount::new(alice_chunked, alice_pk);

    let ct = ConfidentialTransfer::create(
        alice_dk.clone(),
        ALICE_BALANCE,
        alice_ea.randomness().to_vec(),
        10,
        bob_dk.public_key(),
        vec![],
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
        &[],
    )
    .expect("create");

    let mut sigma = ct.gen_sigma_proof();
    sigma.x1 = [0xffu8; 32]; // not a valid canonical ristretto255 encoding

    let opts = TransferVerifyParams {
        sender_private_key: alice_dk,
        recipient_public_key: bob_dk.public_key(),
        encrypted_actual_balance: ct
            .sender_encrypted_available_balance()
            .get_ciphertext()
            .to_vec(),
        encrypted_actual_balance_after_transfer: ct
            .sender_encrypted_available_balance_after_transfer()
            .clone(),
        encrypted_transfer_amount_by_recipient: ct.transfer_amount_encrypted_by_recipient().clone(),
        encrypted_transfer_amount_by_sender: ct.transfer_amount_encrypted_by_sender().clone(),
        sigma_proof: sigma,
        auditors: None,
        chain_id: TEST_CHAIN_ID,
        sender_address: test_sender_addr(),
        contract_address: test_contract_addr(),
        token_address: test_token_addr(),
        sender_auditor_hint: vec![],
    };
    assert!(
        !ConfidentialTransfer::verify_sigma_proof(&opts),
        "malformed x1 must fail verification, not panic"
    );
}

/// Same panic-resistance check for the withdraw σ-verifier.
#[test]
fn withdraw_sigma_verify_rejects_malformed_proof_points_without_panic() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    let alice_chunked = ChunkedAmount::from_amount(ALICE_BALANCE);
    let alice_ea = EncryptedAmount::new(alice_chunked, alice_pk);
    let withdraw_amount: u128 = 1u128 << 16;

    let cw = ConfidentialWithdraw::create_with_balance(
        alice_dk,
        ALICE_BALANCE,
        alice_ea.get_ciphertext().to_vec(),
        withdraw_amount,
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
    )
    .expect("create_with_balance");

    let mut sigma = cw.gen_sigma_proof();
    sigma.x2 = [0xffu8; 32]; // not a valid canonical ristretto255 encoding

    assert!(
        !ConfidentialWithdraw::verify_sigma_proof(
            cw.sender_encrypted_available_balance(),
            cw.sender_encrypted_available_balance_after_withdrawal(),
            withdraw_amount,
            &sigma,
            TEST_CHAIN_ID,
            &test_sender_addr(),
            &test_contract_addr(),
            &test_token_addr(),
        ),
        "malformed x2 must fail verification, not panic"
    );
}

#[test]
fn transfer_sigma_proof_serialize_deserialize_roundtrip_no_auditors() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let bob_dk = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    let alice_chunked = ChunkedAmount::from_amount(ALICE_BALANCE);
    let alice_ea = EncryptedAmount::new(alice_chunked, alice_pk);

    let ct = ConfidentialTransfer::create(
        alice_dk,
        ALICE_BALANCE,
        alice_ea.randomness().to_vec(),
        10,
        bob_dk.public_key(),
        vec![],
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
        &[],
    )
    .expect("create should succeed");

    let sigma = ct.gen_sigma_proof();
    let bytes = ConfidentialTransfer::serialize_sigma_proof(&sigma);
    assert_eq!(bytes.len(), SIGMA_PROOF_TRANSFER_SIZE);
    let decoded =
        ConfidentialTransfer::deserialize_sigma_proof(&bytes).expect("deserialize should succeed");
    assert_eq!(decoded.alpha1_list.len(), 8);
    assert!(decoded.x7_list.is_empty());
    assert_eq!(decoded.x8_list.len(), 4);
}

#[test]
fn transfer_sigma_proof_serialize_deserialize_roundtrip_with_auditors() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let bob_dk = TwistedEd25519PrivateKey::generate();
    let auditor = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    let alice_chunked = ChunkedAmount::from_amount(ALICE_BALANCE);
    let alice_ea = EncryptedAmount::new(alice_chunked, alice_pk);

    let ct = ConfidentialTransfer::create(
        alice_dk,
        ALICE_BALANCE,
        alice_ea.randomness().to_vec(),
        10,
        bob_dk.public_key(),
        vec![auditor.public_key()],
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
        &[],
    )
    .expect("create should succeed");

    let sigma = ct.gen_sigma_proof();
    let bytes = ConfidentialTransfer::serialize_sigma_proof(&sigma);
    let decoded =
        ConfidentialTransfer::deserialize_sigma_proof(&bytes).expect("deserialize should succeed");
    assert_eq!(decoded.alpha1_list.len(), 8);
    assert_eq!(decoded.x2_list.len(), 8);
    assert_eq!(decoded.x7_list.len(), 4);
    assert_eq!(decoded.x8_list.len(), 4);
}

#[test]
fn generate_key_rotation_sigma_proof() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let new_alice_dk = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    let alice_chunked = ChunkedAmount::from_amount(ALICE_BALANCE);
    let alice_ea = EncryptedAmount::new(alice_chunked, alice_pk);

    let kr = ConfidentialKeyRotation::create(
        alice_dk,
        new_alice_dk,
        alice_ea,
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
    );

    let sigma = kr.gen_sigma_proof();
    assert!(!sigma.alpha1_list.is_empty());
}

#[test]
fn generate_normalization_sigma_proof() {
    let alice_dk = TwistedEd25519PrivateKey::generate();
    let alice_pk = alice_dk.public_key();
    // Create unnormalized balance with overflow in chunks
    let unnormalized_chunks: Vec<u64> = (0..AVAILABLE_BALANCE_CHUNK_COUNT - 1)
        .map(|_| ((1u128 << CHUNK_BITS as u128) + 100u128) as u64)
        .chain(std::iter::once(0u64))
        .collect();
    let unnormalized_chunked = ChunkedAmount::from_raw_chunks(unnormalized_chunks);
    let unnormalized_ea = EncryptedAmount::new(unnormalized_chunked, alice_pk);

    let norm = ConfidentialNormalization::create(
        alice_dk,
        unnormalized_ea,
        TEST_CHAIN_ID,
        &test_sender_addr(),
        &test_contract_addr(),
        &test_token_addr(),
    );

    let sigma = norm.gen_sigma_proof();
    assert!(!sigma.alpha1_list.is_empty());
}
