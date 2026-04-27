// Mirrors the snippets in `crates/confidential-assets/README.md` so that the public
// API drifts and the README go out of sync are caught at compile time. None of these
// functions are ever invoked — they exist solely so `cargo build --tests` (and CI)
// type-check the README's examples against the real crate API.
//
// When you change the README, update the corresponding `_readme_*` body to match the
// new snippet verbatim (keeping the unreachable `return` so it never executes).

#![allow(dead_code, unused_variables, unreachable_code)]

use confidential_assets::api::ConfidentialAsset;
use confidential_assets::crypto::twisted_ed25519::{
    DECRYPTION_KEY_DERIVATION_MESSAGE, TwistedEd25519PrivateKey, TwistedEd25519PublicKey,
};
use movement_sdk::account::Ed25519Account;
use movement_sdk::types::AccountAddress;
use movement_sdk::{Movement, MovementConfig, MovementResult};

async fn _readme_setup_and_walkthrough() -> MovementResult<()> {
    return Ok(()); // never executed — body below exists only to type-check the README.

    // --- Setup boilerplate (used in every example below) ----------------------------
    let movement = Movement::new(MovementConfig::testnet())?;
    let alice = Ed25519Account::generate();

    let signature = alice.sign_message(DECRYPTION_KEY_DERIVATION_MESSAGE);
    let sig_bytes = signature.to_bytes();
    let alice_dk = TwistedEd25519PrivateKey::from_bytes(&sig_bytes[..32])?;

    let token: AccountAddress =
        "0x000000000000000000000000000000000000000000000000000000000000000a"
            .parse()
            .map_err(|e: movement_sdk::MovementError| e)?;
    let module_address = std::env::var("CONFIDENTIAL_MODULE_ADDRESS")
        .map_err(|e| movement_sdk::MovementError::Internal(e.to_string()))?;
    let ca = ConfidentialAsset::new(&movement, Some(module_address.as_str()), false)?;

    // --- 1. Register a confidential balance -----------------------------------------
    let payload = ca
        .register_balance(&alice.address(), &token, &alice_dk)
        .await?;
    movement.sign_submit_and_wait(&alice, payload, None).await?;

    // --- 2. Deposit from public balance into pending --------------------------------
    let payload = ca.deposit(&alice.address(), &token, 5, None)?;
    movement.sign_submit_and_wait(&alice, payload, None).await?;

    let recipient: AccountAddress = "0x1".parse().map_err(|e: movement_sdk::MovementError| e)?;
    let payload = ca.deposit(&alice.address(), &token, 5, Some(&recipient))?;
    movement.sign_submit_and_wait(&alice, payload, None).await?;

    // --- 3. Rollover pending → available --------------------------------------------
    for p in ca
        .rollover_pending_balance(&alice.address(), &token, Some(&alice_dk), false)
        .await?
    {
        movement.sign_submit_and_wait(&alice, p, None).await?;
    }

    // --- 4. Read your own confidential balance --------------------------------------
    let bal = ca.get_balance(&alice.address(), &token, &alice_dk).await?;
    let _ = bal.available_balance();
    let _ = bal.pending_balance();

    // --- 5. Withdraw to a public balance --------------------------------------------
    let payload = ca
        .withdraw(&alice.address(), &token, 1, &alice_dk, None)
        .await?;
    movement.sign_submit_and_wait(&alice, payload, None).await?;

    // --- 6. Confidential transfer ---------------------------------------------------
    let bob: AccountAddress = "0x2".parse().map_err(|e: movement_sdk::MovementError| e)?;
    let payload = ca
        .transfer(&alice.address(), &bob, &token, 2, &alice_dk, &[], &[])
        .await?;
    movement.sign_submit_and_wait(&alice, payload, None).await?;

    // --- 7. Transfer with auditor encryption ----------------------------------------
    let auditor_pk: TwistedEd25519PublicKey = TwistedEd25519PrivateKey::generate().public_key();
    let payload = ca
        .transfer(
            &alice.address(),
            &bob,
            &token,
            2,
            &alice_dk,
            &[auditor_pk],
            &[],
        )
        .await?;
    movement.sign_submit_and_wait(&alice, payload, None).await?;

    // --- 8. Rotate your decryption key ----------------------------------------------
    let new_dk = TwistedEd25519PrivateKey::generate();
    for p in ca
        .rotate_encryption_key(&alice.address(), &alice_dk, &new_dk, &token)
        .await?
    {
        movement.sign_submit_and_wait(&alice, p, None).await?;
    }
    let _ = ca.get_balance(&alice.address(), &token, &new_dk).await?;

    // --- 9. Normalize manually ------------------------------------------------------
    let payload = ca
        .normalize_balance(&alice.address(), &alice_dk, &token)
        .await?;
    movement.sign_submit_and_wait(&alice, payload, None).await?;

    // --- 10. Probe state without funds ----------------------------------------------
    let _registered = ca.has_user_registered(&alice.address(), &token).await?;
    let _normalized = ca.is_balance_normalized(&alice.address(), &token).await?;
    let _frozen = ca
        .is_pending_balance_frozen(&alice.address(), &token)
        .await?;
    let _auditor = ca.get_asset_auditor_encryption_key(&token).await?;

    Ok(())
}
