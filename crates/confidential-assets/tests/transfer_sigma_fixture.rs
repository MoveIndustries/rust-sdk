//! Optional **Movement TS → Rust** parity for transfer sigma proofs.
//!
//! Regenerate `tests/fixtures/transfer_sigma.fixture.json` with `fixtures/ts/generate.ts` (see
//! `fixtures/ts/README.md`), pointing at the sibling `../ts-sdk/confidential-assets` checkout.
//!
//! **Note:** Twisted Ed25519 encryption keys follow Movement: `pk = s⁻¹·H` with fixed `H`
//! (`HASH_BASE_POINT`). Packages that use a different key model are not wire-compatible.

use confidential_assets::consts::SIGMA_PROOF_TRANSFER_SIZE;
use confidential_assets::crypto::confidential_transfer::{
    AuditorParams, ConfidentialTransfer, TransferVerifyParams,
};
use confidential_assets::crypto::encrypted_amount::EncryptedAmount;
use confidential_assets::crypto::twisted_ed25519::{
    TwistedEd25519PrivateKey, TwistedEd25519PublicKey,
};
use confidential_assets::crypto::twisted_el_gamal::TwistedElGamalCiphertext;
use serde::Deserialize;

const FIXTURE: &str = include_str!("fixtures/transfer_sigma.fixture.json");

#[derive(Debug, Deserialize)]
struct TransferSigmaFixture {
    skip: bool,
    inputs: FixtureInputs,
    verify: FixtureVerify,
}

#[derive(Debug, Deserialize)]
struct FixtureInputs {
    chain_id: u8,
    sender_address_hex: String,
    contract_address_hex: String,
    token_address_hex: String,
    sender_auditor_hint_hex: String,
    sender_private_key_hex: String,
    recipient_public_key_hex: String,
}

#[derive(Debug, Deserialize)]
struct FixtureVerify {
    serialized_sigma_proof_hex: String,
    encrypted_actual_balance_hex: String,
    encrypted_balance_after_transfer_hex: String,
    encrypted_transfer_by_recipient_hex: String,
    encrypted_transfer_by_sender_hex: String,
    #[serde(default)]
    auditor_rows: Vec<AuditorRowFixture>,
}

#[derive(Debug, Deserialize)]
struct AuditorRowFixture {
    public_key_hex: String,
    #[serde(default)]
    transfer_ciphertexts_hex: Vec<String>,
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(vec![]);
    }
    hex::decode(t).map_err(|e| e.to_string())
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let v = hex_decode(s)?;
    v.try_into()
        .map_err(|_| "expected 32 bytes (64 hex chars)".to_string())
}

fn parse_ct_vec(label: &str, hex_str: &str) -> Result<Vec<TwistedElGamalCiphertext>, String> {
    let raw = hex_decode(hex_str)?;
    if raw.len() % 64 != 0 {
        return Err(format!(
            "{label}: ciphertext blob length {} not a multiple of 64",
            raw.len()
        ));
    }
    raw.chunks(64)
        .enumerate()
        .map(|(i, c)| {
            TwistedElGamalCiphertext::from_bytes(c).map_err(|e| format!("{label} chunk {i}: {e}"))
        })
        .collect()
}

#[test]
fn transfer_sigma_fixture_json_parses() {
    let _: TransferSigmaFixture = serde_json::from_str(FIXTURE).expect("fixture JSON");
}

#[test]
fn transfer_sigma_fixture_verifies_when_not_skipped() {
    let f: TransferSigmaFixture = serde_json::from_str(FIXTURE).expect("fixture JSON");
    if f.skip {
        return;
    }

    let proof_hex = f.verify.serialized_sigma_proof_hex.trim();
    assert!(
        !proof_hex.is_empty(),
        "skip is false but serialized_sigma_proof_hex is empty. Paste the TS `serializeSigmaProof` output as hex ({} bytes = {} hex chars), or set skip back to true.",
        SIGMA_PROOF_TRANSFER_SIZE,
        SIGMA_PROOF_TRANSFER_SIZE * 2
    );
    let proof_bytes = hex_decode(proof_hex).expect("serialized_sigma_proof_hex must be valid hex");
    assert!(
        proof_bytes.len() >= SIGMA_PROOF_TRANSFER_SIZE,
        "serialized_sigma_proof_hex decodes to {} bytes; need at least {} (base transfer proof).",
        proof_bytes.len(),
        SIGMA_PROOF_TRANSFER_SIZE
    );
    let sigma_proof =
        ConfidentialTransfer::deserialize_sigma_proof(&proof_bytes).expect("deserialize sigma");

    let sender_dk = TwistedEd25519PrivateKey::from_bytes(
        &hex32(&f.inputs.sender_private_key_hex).expect("sender sk"),
    );
    let recipient_pk = TwistedEd25519PublicKey::from_bytes(
        &hex32(&f.inputs.recipient_public_key_hex).expect("recipient pk"),
    )
    .expect("recipient pk");

    let encrypted_actual_balance = parse_ct_vec(
        "encrypted_actual_balance",
        &f.verify.encrypted_actual_balance_hex,
    )
    .expect("old balance ciphertexts");

    let encrypted_actual_balance_after_transfer =
        EncryptedAmount::from_ciphertext_vec_for_verification(
            parse_ct_vec(
                "encrypted_balance_after_transfer",
                &f.verify.encrypted_balance_after_transfer_hex,
            )
            .expect("after balance"),
            sender_dk.public_key(),
        )
        .expect("after EncryptedAmount");

    let encrypted_transfer_amount_by_recipient =
        EncryptedAmount::from_ciphertext_vec_for_verification(
            parse_ct_vec(
                "encrypted_transfer_by_recipient",
                &f.verify.encrypted_transfer_by_recipient_hex,
            )
            .expect("recipient transfer"),
            recipient_pk.clone(),
        )
        .expect("recipient EA");

    let encrypted_transfer_amount_by_sender =
        EncryptedAmount::from_ciphertext_vec_for_verification(
            parse_ct_vec(
                "encrypted_transfer_by_sender",
                &f.verify.encrypted_transfer_by_sender_hex,
            )
            .expect("sender transfer"),
            sender_dk.public_key(),
        )
        .expect("sender transfer EA");

    let auditors = if f.verify.auditor_rows.is_empty() {
        None
    } else {
        let mut public_keys = Vec::new();
        let mut auditors_cb_list = Vec::new();
        for row in &f.verify.auditor_rows {
            public_keys.push(
                TwistedEd25519PublicKey::from_bytes(
                    &hex32(&row.public_key_hex).expect("auditor pk"),
                )
                .expect("auditor pk"),
            );
            let mut row_cts = Vec::new();
            for (i, hx) in row.transfer_ciphertexts_hex.iter().enumerate() {
                let raw = hex_decode(hx).expect("auditor chunk hex");
                assert_eq!(raw.len(), 64, "auditor chunk {i} must be 64 bytes hex");
                row_cts.push(TwistedElGamalCiphertext::from_bytes(&raw).expect("auditor ct"));
            }
            auditors_cb_list.push(row_cts);
        }
        Some(AuditorParams {
            public_keys,
            auditors_cb_list,
        })
    };

    let opts = TransferVerifyParams {
        sender_private_key: sender_dk,
        recipient_public_key: recipient_pk,
        encrypted_actual_balance,
        encrypted_actual_balance_after_transfer,
        encrypted_transfer_amount_by_recipient,
        encrypted_transfer_amount_by_sender,
        sigma_proof,
        auditors,
        chain_id: f.inputs.chain_id,
        sender_address: hex_decode(&f.inputs.sender_address_hex).expect("sender address"),
        contract_address: hex_decode(&f.inputs.contract_address_hex).expect("contract"),
        token_address: hex_decode(&f.inputs.token_address_hex).expect("token"),
        sender_auditor_hint: hex_decode(&f.inputs.sender_auditor_hint_hex).expect("hint"),
    };

    assert!(
        ConfidentialTransfer::verify_sigma_proof(&opts),
        "TS-generated fixture should verify; if this fails, compare Fiat-Shamir transcript and key model with the Movement TS SDK"
    );
}
