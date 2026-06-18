// Example: Set (and clear) chain-level and per-asset auditors on confidential assets
//
// Demonstrates two independent auditor flows:
//
//  A. Chain auditor — applies to every confidential transfer on the network:
//       1. Set the chain auditor EK (signed by the chain auditor admin)
//       2. Read it back from chain to verify
//       3. Clear it (signed by the chain auditor admin)
//
//  B. Asset auditor — applies only to transfers of a specific FA token:
//       1. Set the asset auditor EK (signed by the FA root owner / issuer)
//       2. Read it back from chain to verify
//       3. Clear it (signed by the issuer)
//
// Prerequisites:
//   - A. The chain auditor admin must already be assigned via the governance Move script
//        (see deploy/scripts/setup_chain_auditor.move). Provide that admin's private key
//        in CHAIN_AUDITOR_ADMIN_PRIVATE_KEY.
//   - B. A fungible asset token whose root owner you control.
//
// Environment variables:
//   CHAIN_AUDITOR_ADMIN_PRIVATE_KEY  — hex Ed25519 private key of the chain auditor admin (required for A)
//   TOKEN_ADDRESS                    — hex address of the FA metadata object (required for B)
//   ISSUER_PRIVATE_KEY               — hex Ed25519 private key of the FA root owner (required for B)
//   MOVEMENT_NETWORK                 — TESTNET | MAINNET | LOCAL (optional, default LOCAL)
//   MOVEMENT_RPC_URL                 — custom RPC endpoint, used when MOVEMENT_NETWORK is not set
//   CONFIDENTIAL_MODULE_ADDRESS      — defaults to 0x1
//
// Run:
//   CHAIN_AUDITOR_ADMIN_PRIVATE_KEY=<hex> TOKEN_ADDRESS=0x<addr> ISSUER_PRIVATE_KEY=<hex> \
//     cargo run -p confidential-assets --example set_auditor_example --features confidential-assets/e2e

use confidential_assets::api::ConfidentialAsset;
use confidential_assets::crypto::twisted_ed25519::TwistedEd25519PrivateKey;
use movement_sdk::{
    Movement, MovementConfig, MovementError, MovementResult,
    account::Ed25519Account,
    types::AccountAddress,
};
use std::env;

#[tokio::main]
async fn main() -> MovementResult<()> {
    println!("=== Set Auditor Example ===\n");

    // ── 1. Build the Movement client ─────────────────────────────────────────
    let config = match env::var("MOVEMENT_NETWORK") {
        Ok(network) => match network.to_uppercase().as_str() {
            "TESTNET" => MovementConfig::testnet(),
            "MAINNET" => MovementConfig::mainnet(),
            _ => MovementConfig::local(),
        },
        Err(_) => match env::var("MOVEMENT_RPC_URL") {
            Ok(url) => MovementConfig::custom(&url)?,
            Err(_) => MovementConfig::local(),
        },
    };
    let movement = Movement::new(config)?;
    println!("Connected to Movement network.\n");

    let module_address =
        env::var("CONFIDENTIAL_MODULE_ADDRESS").unwrap_or_else(|_| "0x1".to_string());
    let ca = ConfidentialAsset::new(&movement, Some(&module_address))?;

    // ── 2. Generate a shared auditor key pair ─────────────────────────────────
    // The same dk/ek pair is reused for both the chain and asset auditor sections.
    let auditor_dk = TwistedEd25519PrivateKey::generate();
    let auditor_ek = auditor_dk.public_key();
    println!("Generated auditor decryption key (dk): {}", hex::encode(auditor_dk.to_bytes()));
    println!("Generated auditor encryption key (ek): {}", hex::encode(auditor_ek.to_bytes()));
    println!();

    // ════════════════════════════════════════════════════════════════════════
    // A. Chain auditor
    // ════════════════════════════════════════════════════════════════════════

    let chain_admin_key_hex = env::var("CHAIN_AUDITOR_ADMIN_PRIVATE_KEY").map_err(|_| {
        MovementError::Internal(
            "CHAIN_AUDITOR_ADMIN_PRIVATE_KEY is required (hex Ed25519 key of the chain auditor admin)".to_string(),
        )
    })?;
    let chain_admin = Ed25519Account::from_private_key_hex(&chain_admin_key_hex)
        .map_err(|e| MovementError::Internal(format!("invalid CHAIN_AUDITOR_ADMIN_PRIVATE_KEY: {e}")))?;

    println!("── A. Chain auditor ─────────────────────────────────────────────");
    println!("Chain auditor admin: {}", chain_admin.address());

    let current_chain = ca.get_chain_auditor_encryption_key().await?;
    println!(
        "Current chain auditor EK: {}",
        current_chain
            .as_ref()
            .map(|ek| hex::encode(ek.to_bytes()))
            .unwrap_or_else(|| "(none)".to_string())
    );

    // Set
    println!("Setting chain auditor EK …");
    let payload = ca.set_chain_auditor(Some(&auditor_ek))?;
    movement.sign_submit_and_wait(&chain_admin, payload, None).await?;

    let stored_chain = ca
        .get_chain_auditor_encryption_key()
        .await?
        .ok_or_else(|| MovementError::Internal("Chain auditor EK not found after set".to_string()))?;
    assert_eq!(
        stored_chain.to_bytes(),
        auditor_ek.to_bytes(),
        "Stored chain auditor EK does not match"
    );
    println!("  Verified — stored EK: {}", hex::encode(stored_chain.to_bytes()));

    // Clear
    println!("Clearing chain auditor EK …");
    let payload = ca.set_chain_auditor(None)?;
    movement.sign_submit_and_wait(&chain_admin, payload, None).await?;

    assert!(
        ca.get_chain_auditor_encryption_key().await?.is_none(),
        "Chain auditor EK should be None after clearing"
    );
    println!("  Verified — chain auditor EK is cleared.");
    println!();

    // ════════════════════════════════════════════════════════════════════════
    // B. Asset auditor
    // ════════════════════════════════════════════════════════════════════════

    let token_raw = env::var("TOKEN_ADDRESS").map_err(|_| {
        MovementError::Internal(
            "TOKEN_ADDRESS is required (hex address of the FA metadata object)".to_string(),
        )
    })?;
    let token = AccountAddress::from_hex(&token_raw)
        .map_err(|e| MovementError::Internal(format!("invalid TOKEN_ADDRESS: {e}")))?;

    let issuer_key_hex = env::var("ISSUER_PRIVATE_KEY").map_err(|_| {
        MovementError::Internal(
            "ISSUER_PRIVATE_KEY is required (hex Ed25519 key of the FA root owner)".to_string(),
        )
    })?;
    let issuer = Ed25519Account::from_private_key_hex(&issuer_key_hex)
        .map_err(|e| MovementError::Internal(format!("invalid ISSUER_PRIVATE_KEY: {e}")))?;

    println!("── B. Asset auditor ─────────────────────────────────────────────");
    println!("Issuer  : {}", issuer.address());
    println!("Token   : {token}");

    let current_asset = ca.get_asset_auditor_encryption_key(&token).await?;
    println!(
        "Current asset auditor EK: {}",
        current_asset
            .as_ref()
            .map(|ek| hex::encode(ek.to_bytes()))
            .unwrap_or_else(|| "(none)".to_string())
    );

    // Set
    println!("Setting asset auditor EK …");
    let payload = ca.set_asset_auditor(&token, Some(&auditor_ek))?;
    movement.sign_submit_and_wait(&issuer, payload, None).await?;

    let stored_asset = ca
        .get_asset_auditor_encryption_key(&token)
        .await?
        .ok_or_else(|| MovementError::Internal("Asset auditor EK not found after set".to_string()))?;
    assert_eq!(
        stored_asset.to_bytes(),
        auditor_ek.to_bytes(),
        "Stored asset auditor EK does not match"
    );
    println!("  Verified — stored EK: {}", hex::encode(stored_asset.to_bytes()));

    // Clear
    println!("Clearing asset auditor EK …");
    let payload = ca.set_asset_auditor(&token, None)?;
    movement.sign_submit_and_wait(&issuer, payload, None).await?;

    assert!(
        ca.get_asset_auditor_encryption_key(&token).await?.is_none(),
        "Asset auditor EK should be None after clearing"
    );
    println!("  Verified — asset auditor EK is cleared.");
    println!();

    println!("All assertions passed. Example complete!");
    Ok(())
}
