use confidential_assets::api::ConfidentialAsset;
use confidential_assets::crypto::twisted_ed25519::{
    DECRYPTION_KEY_DERIVATION_MESSAGE, TwistedEd25519PrivateKey,
};
use movement_sdk::account::Ed25519Account;
use movement_sdk::transaction::builder::{TransactionBuilder, sign_fee_payer_transaction};
use movement_sdk::transaction::types::FeePayerRawTransaction;
use movement_sdk::transaction::{EntryFunction, TransactionPayload};
use movement_sdk::types::{AccountAddress, Identifier, MoveModuleId, TypeTag};
use movement_sdk::{Movement, MovementConfig, MovementError, MovementResult};
use std::env;

pub const TOKEN_ADDRESS: &str =
    "0x000000000000000000000000000000000000000000000000000000000000000a";

// 2 MOVE fully covers the SDK's default gas budget (max_gas_amount 2_000_000 × gas_unit_price 100
// = 200_000_000 octas) plus headroom for actual gas spend on subsequent transactions.
pub const FUND_AMOUNT: u64 = 1_000_000_000;

pub fn module_address() -> String {
    let raw = env::var("CONFIDENTIAL_MODULE_ADDRESS").expect(
        "CONFIDENTIAL_MODULE_ADDRESS env var is required for e2e tests \
         (run scripts/start-localnet-confidential-assets.sh and export the printed module address)",
    );
    let hex = raw.trim_start_matches("0x");
    assert_eq!(
        hex.len(),
        64,
        "CONFIDENTIAL_MODULE_ADDRESS must be a 32-byte hex string (64 chars after 0x), got {} chars: {raw:?}",
        hex.len()
    );
    raw
}

pub fn token_address() -> AccountAddress {
    let raw = env::var("TOKEN_ADDRESS").unwrap_or_else(|_| TOKEN_ADDRESS.to_string());
    AccountAddress::from_hex(&raw).expect("TOKEN_ADDRESS must be a valid hex address")
}

pub fn make_movement() -> MovementResult<Movement> {
    let config = match env::var("MOVEMENT_NETWORK")
        .unwrap_or_else(|_| "LOCAL".into())
        .to_uppercase()
        .as_str()
    {
        "MAINNET" => MovementConfig::mainnet(),
        "TESTNET" => MovementConfig::testnet(),
        _ => MovementConfig::local(),
    };
    Movement::new(config)
}

pub fn make_confidential_asset(client: &Movement) -> ConfidentialAsset<'_> {
    ConfidentialAsset::new(client, Some(&module_address()))
        .expect("module_address() must be a valid hex address")
}

pub fn get_test_account() -> Ed25519Account {
    if let Ok(pk) = env::var("TESTNET_PK") {
        Ed25519Account::from_private_key_hex(pk.trim_start_matches("0x"))
            .expect("TESTNET_PK must be a valid Ed25519 hex private key")
    } else {
        Ed25519Account::generate()
    }
}

pub fn get_test_confidential_account(account: Option<&Ed25519Account>) -> TwistedEd25519PrivateKey {
    if let Ok(dk_hex) = env::var("TESTNET_DK") {
        let bytes = hex::decode(dk_hex.trim_start_matches("0x")).expect("TESTNET_DK must be hex");
        return TwistedEd25519PrivateKey::from_bytes(&bytes).expect("TESTNET_DK must be 32 bytes");
    }

    let Some(account) = account else {
        return TwistedEd25519PrivateKey::generate();
    };

    let signature = account.sign_message(DECRYPTION_KEY_DERIVATION_MESSAGE);
    let sig_bytes = signature.to_bytes();
    // Twisted Ed25519 derivation takes the first 32 bytes of the 64-byte signature mod the subgroup order.
    TwistedEd25519PrivateKey::from_bytes(&sig_bytes[..32]).expect("signature has at least 32 bytes")
}

pub fn migrate_payload() -> MovementResult<TransactionPayload> {
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

/// Fund + migrate native coin to the FA store, mirroring `migrateCoinsToFungibleStore` in TS helpers.
pub async fn fund_and_migrate(client: &Movement, account: &Ed25519Account) -> MovementResult<()> {
    client.fund_account(account.address(), FUND_AMOUNT).await?;
    let payload = migrate_payload()?;
    client.sign_submit_and_wait(account, payload, None).await?;
    Ok(())
}

/// Fetch the FA balance for `owner` of metadata `token_address` via the on-chain view function.
pub async fn get_fa_balance(
    client: &Movement,
    owner: AccountAddress,
    token: AccountAddress,
) -> MovementResult<u64> {
    let args = vec![
        aptos_bcs::to_bytes(&owner).map_err(|e| MovementError::Bcs(e.to_string()))?,
        aptos_bcs::to_bytes(&token).map_err(|e| MovementError::Bcs(e.to_string()))?,
    ];
    client
        .view_bcs::<u64>(
            "0x1::primary_fungible_store::balance",
            vec!["0x1::fungible_asset::Metadata".to_string()],
            args,
        )
        .await
}

/// Sign + submit + wait helper that matches `sendAndWaitTx` in TS helpers.
pub async fn send_and_wait(
    client: &Movement,
    signer: &Ed25519Account,
    payload: TransactionPayload,
) -> MovementResult<serde_json::Value> {
    let resp = client.sign_submit_and_wait(signer, payload, None).await?;
    Ok(resp.into_inner())
}

/// Create + fund + migrate a fee payer account. Mirrors TS `feePayerAccount` setup.
pub async fn make_fee_payer(client: &Movement) -> MovementResult<Ed25519Account> {
    let fee_payer = Ed25519Account::generate();
    fund_and_migrate(client, &fee_payer).await?;
    Ok(fee_payer)
}

/// Sponsored sign + submit + wait: sender signs, fee_payer pays gas.
/// Mirrors TS `withFeePayer: true` flow used in the TS confidential-asset tests.
pub async fn send_and_wait_sponsored(
    client: &Movement,
    sender: &Ed25519Account,
    fee_payer: &Ed25519Account,
    payload: TransactionPayload,
) -> MovementResult<serde_json::Value> {
    let sender_seq = client.get_sequence_number(sender.address()).await?;
    let chain_id = client.ensure_chain_id().await?;

    let raw_txn = TransactionBuilder::new()
        .sender(sender.address())
        .sequence_number(sender_seq)
        .payload(payload)
        .chain_id(chain_id)
        .build()?;

    let fee_payer_txn = FeePayerRawTransaction {
        raw_txn,
        secondary_signer_addresses: vec![],
        fee_payer_address: fee_payer.address(),
    };

    let signed = sign_fee_payer_transaction(&fee_payer_txn, sender, &[], fee_payer)?;
    let resp = client.submit_and_wait(&signed, None).await?;
    Ok(resp.into_inner())
}
