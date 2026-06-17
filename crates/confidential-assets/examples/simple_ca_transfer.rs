// Example: Simple confidential asset transfer
//
// This example demonstrates how to:
// Init:
//  create and fund 2 accounts
// CA transfer:
// 1. Initialize the confidential asset for the 2 accounts
// 2. Deposit some token on account 1
// 3. Do a CA transfer from account 1 to account 2
// 4. Verify the account balances
//
// Run with:
//   1. MOVEMENT_NETWORK=TESTNET|MAINNET|LOCAL — picks a preset
//   2. MOVEMENT_RPC_URL=http://... — custom endpoint (used when MOVEMENT_NETWORK is not set)
//   3. Falls back to http://127.0.0.1:8080/v1 (default local)
//   4. CONFIDENTIAL_MODULE_ADDRESS=0x<addr>  (optional, defaults to 0x1)
//   To run wih all defaul:
//   cargo run --example simple_ca_transfer --features e2e
//   cargo run -p confidential-assets --example simple_ca_transfer --features confidential-assets/e2e

use confidential_assets::api::ConfidentialAsset;
use confidential_assets::crypto::twisted_ed25519::{
    DECRYPTION_KEY_DERIVATION_MESSAGE, TwistedEd25519PrivateKey,
};
use movement_sdk::{
    Movement, MovementConfig, MovementError, MovementResult,
    account::Ed25519Account,
    transaction::{EntryFunction, TransactionPayload},
    types::{AccountAddress, Identifier, MoveModuleId, TypeTag},
};
use std::env;

// 2 MOVE — enough for the default gas budget (max_gas × gas_price = 200_000_000 octas)
// plus headroom for subsequent transactions.
const FUND_AMOUNT: u64 = 1_000_000_000;
const DEPOSIT_AMOUNT: u64 = 10;
const TRANSFER_AMOUNT: u64 = 4;

// The FA token used in the example. Defaults to the well-known testnet/localnet address
// (0x…0a, the MOVE coin FA metadata), but can be overridden via TOKEN_ADDRESS.
const DEFAULT_TOKEN_ADDRESS: &str =
    "0x000000000000000000000000000000000000000000000000000000000000000a";

#[tokio::main]
async fn main() -> MovementResult<()> {
    println!("=== Simple Confidential Asset Transfer Example ===\n");

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

    // ── 2. Resolve addresses ──────────────────────────────────────────────────
    let module_address =
        env::var("CONFIDENTIAL_MODULE_ADDRESS").unwrap_or_else(|_| "0x1".to_string());

    let token_raw = env::var("TOKEN_ADDRESS").unwrap_or_else(|_| DEFAULT_TOKEN_ADDRESS.to_string());
    let token =
        AccountAddress::from_hex(&token_raw).expect("TOKEN_ADDRESS must be a valid hex address");

    let ca = ConfidentialAsset::new(&movement, Some(&module_address))?;

    // ── 3. Create and fund two accounts ──────────────────────────────────────
    let alice = Ed25519Account::generate();
    let bob = Ed25519Account::generate();

    println!("Alice address: {}", alice.address());
    println!("Bob   address: {}", bob.address());
    println!();

    // Derive the CA decryption key from the account signing key (same approach as
    // `get_test_confidential_account` in the e2e helpers).
    let alice_dk = {
        let sig = alice.sign_message(DECRYPTION_KEY_DERIVATION_MESSAGE);
        let bytes = sig.to_bytes();
        TwistedEd25519PrivateKey::from_bytes(&bytes[..32]).expect("signature has at least 32 bytes")
    };
    let bob_dk = {
        let sig = bob.sign_message(DECRYPTION_KEY_DERIVATION_MESSAGE);
        let bytes = sig.to_bytes();
        TwistedEd25519PrivateKey::from_bytes(&bytes[..32]).expect("signature has at least 32 bytes")
    };

    println!("Funding Alice …");
    movement.fund_account(alice.address(), FUND_AMOUNT).await?;
    println!("Funding Bob …");
    movement.fund_account(bob.address(), FUND_AMOUNT).await?;

    // Migrate native coin → FA store (required before any FA operation).
    println!("Migrating Alice's coins to fungible store …");
    let migrate = migrate_payload()?;
    movement.sign_submit_and_wait(&alice, migrate, None).await?;

    println!("Migrating Bob's coins to fungible store …");
    let migrate = migrate_payload()?;
    movement.sign_submit_and_wait(&bob, migrate, None).await?;
    println!();

    // ── 4. Register confidential balances for both accounts ──────────────────
    println!("Registering Alice's confidential balance …");
    let payload = ca
        .register_balance(&alice.address(), &token, &alice_dk)
        .await?;
    movement.sign_submit_and_wait(&alice, payload, None).await?;

    println!("Registering Bob's confidential balance …");
    let payload = ca.register_balance(&bob.address(), &token, &bob_dk).await?;
    movement.sign_submit_and_wait(&bob, payload, None).await?;
    println!();

    // ── 5. Deposit public FA tokens into Alice's confidential balance ─────────
    println!("Depositing {DEPOSIT_AMOUNT} tokens into Alice's confidential balance …");
    let payload = ca.deposit(&alice.address(), &token, DEPOSIT_AMOUNT, None)?;
    movement.sign_submit_and_wait(&alice, payload, None).await?;

    let bal = ca.get_balance(&alice.address(), &token, &alice_dk).await?;
    println!(
        "  Alice after deposit  — available: {}, pending: {}",
        bal.available_balance(),
        bal.pending_balance()
    );

    // ── 6. Rollover Alice's pending balance → available ───────────────────────
    println!("Rolling over Alice's pending balance …");
    let payloads = ca
        .rollover_pending_balance(&alice.address(), &token, None, false)
        .await?;
    for p in payloads {
        movement.sign_submit_and_wait(&alice, p, None).await?;
    }

    let bal = ca.get_balance(&alice.address(), &token, &alice_dk).await?;
    println!(
        "  Alice after rollover — available: {}, pending: {}",
        bal.available_balance(),
        bal.pending_balance()
    );
    println!();

    // ── 7. Confidential transfer: Alice → Bob ────────────────────────────────
    println!("Transferring {TRANSFER_AMOUNT} tokens from Alice to Bob (confidential) …");
    let payload = ca
        .transfer(
            &alice.address(),
            &bob.address(),
            &token,
            TRANSFER_AMOUNT,
            &alice_dk,
            &[], // no additional auditors
            &[], // no auditor hint
        )
        .await?;
    movement.sign_submit_and_wait(&alice, payload, None).await?;
    println!();

    // ── 8. Verify balances after transfer ────────────────────────────────────
    let alice_bal = ca.get_balance(&alice.address(), &token, &alice_dk).await?;
    let bob_bal = ca.get_balance(&bob.address(), &token, &bob_dk).await?;

    println!("=== Balances after transfer ===");
    println!(
        "  Alice — available: {}, pending: {}",
        alice_bal.available_balance(),
        alice_bal.pending_balance()
    );
    println!(
        "  Bob   — available: {}, pending: {}",
        bob_bal.available_balance(),
        bob_bal.pending_balance()
    );
    println!();

    assert_eq!(
        alice_bal.available_balance(),
        (DEPOSIT_AMOUNT - TRANSFER_AMOUNT) as u128,
        "Alice's available balance should be DEPOSIT - TRANSFER"
    );
    assert_eq!(
        bob_bal.pending_balance(),
        TRANSFER_AMOUNT as u128,
        "Bob's pending balance should equal the transfer amount"
    );

    // ── 9. Normalize Alice's available balance ────────────────────────────────
    println!("Normalizing Alice's balance …");
    let payload = ca
        .normalize_balance(&alice.address(), &alice_dk, &token)
        .await?;
    movement.sign_submit_and_wait(&alice, payload, None).await?;

    let alice_bal = ca.get_balance(&alice.address(), &token, &alice_dk).await?;
    println!(
        "  Alice after normalize — available: {}, pending: {}",
        alice_bal.available_balance(),
        alice_bal.pending_balance()
    );
    assert_eq!(
        alice_bal.available_balance(),
        (DEPOSIT_AMOUNT - TRANSFER_AMOUNT) as u128,
        "Alice's available balance should be unchanged after normalize"
    );
    println!();

    // ── 10. Rollover Bob's pending balance → available ────────────────────────
    println!("Rolling over Bob's pending balance …");
    let payloads = ca
        .rollover_pending_balance(&bob.address(), &token, Some(&bob_dk), false)
        .await?;
    for p in payloads {
        movement.sign_submit_and_wait(&bob, p, None).await?;
    }

    let bob_bal = ca.get_balance(&bob.address(), &token, &bob_dk).await?;
    println!(
        "  Bob after rollover — available: {}, pending: {}",
        bob_bal.available_balance(),
        bob_bal.pending_balance()
    );
    assert_eq!(
        bob_bal.available_balance(),
        TRANSFER_AMOUNT as u128,
        "Bob's available balance should equal the transfer amount after rollover"
    );
    assert_eq!(
        bob_bal.pending_balance(),
        0,
        "Bob's pending balance should be zero after rollover"
    );
    println!();

    // ── 11. Normalize Bob's available balance ─────────────────────────────────
    println!("Normalizing Bob's balance …");
    let payload = ca
        .normalize_balance(&bob.address(), &bob_dk, &token)
        .await?;
    movement.sign_submit_and_wait(&bob, payload, None).await?;

    let bob_bal = ca.get_balance(&bob.address(), &token, &bob_dk).await?;
    println!(
        "  Bob after normalize — available: {}, pending: {}",
        bob_bal.available_balance(),
        bob_bal.pending_balance()
    );
    assert_eq!(
        bob_bal.available_balance(),
        TRANSFER_AMOUNT as u128,
        "Bob's available balance should be unchanged after normalize"
    );

    println!("\nAll assertions passed. Example complete!");
    Ok(())
}

/// Build the `0x1::coin::migrate_to_fungible_store<AptosCoin>` payload.
fn migrate_payload() -> MovementResult<TransactionPayload> {
    let module = MoveModuleId::new(
        AccountAddress::from_hex("0x1").map_err(|e| MovementError::Internal(e.to_string()))?,
        Identifier::new("coin").map_err(|e| MovementError::Internal(e.to_string()))?,
    );
    Ok(EntryFunction::new(
        module,
        "migrate_to_fungible_store",
        vec![TypeTag::aptos_coin()],
        vec![],
    )
    .into())
}
