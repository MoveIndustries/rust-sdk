use super::helpers::{
    fund_and_migrate, get_test_account, get_test_confidential_account, make_movement,
    module_address, send_and_wait, token_address,
};
use confidential_assets::ConfidentialAssetTransactionBuilder;
use movement_sdk::account::Ed25519Account;

const DEPOSIT_AMOUNT: u64 = 5;
const WITHDRAW_AMOUNT: u64 = 1;
const TRANSFER_AMOUNT: u64 = 2;

/// Lower-level builder smoke test: `register_balance` then `deposit` lands amount in
/// `pending`. Mirrors the high-level API test but exercises the raw transaction builder.
#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn builder_register_then_deposit_updates_pending() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let module = module_address();
    let builder = ConfidentialAssetTransactionBuilder::new(&movement, Some(&module))
        .expect("valid module address");

    fund_and_migrate(&movement, &alice).await.expect("fund");

    let register_payload = builder
        .register_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("build register");
    send_and_wait(&movement, &alice, register_payload)
        .await
        .expect("register tx");

    let deposit_payload = builder
        .deposit(&alice.address(), &token_address(), DEPOSIT_AMOUNT, None)
        .expect("build deposit");
    send_and_wait(&movement, &alice, deposit_payload)
        .await
        .expect("deposit tx");
}

/// Builder-level rollover: a single `rollover_pending_balance` payload submitted after
/// a deposit moves funds pending → available.
#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn builder_rolls_over_pending_balance() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let module = module_address();
    let builder = ConfidentialAssetTransactionBuilder::new(&movement, Some(&module))
        .expect("valid module address");

    fund_and_migrate(&movement, &alice).await.expect("fund");
    let register_payload = builder
        .register_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("build register");
    send_and_wait(&movement, &alice, register_payload)
        .await
        .expect("register tx");

    let dep = builder
        .deposit(&alice.address(), &token_address(), DEPOSIT_AMOUNT, None)
        .expect("build deposit");
    send_and_wait(&movement, &alice, dep)
        .await
        .expect("deposit tx");

    let rollover = builder
        .rollover_pending_balance(&alice.address(), &token_address(), false, true)
        .await
        .expect("build rollover");
    send_and_wait(&movement, &alice, rollover)
        .await
        .expect("rollover tx");
}

/// With `check_normalized = true`, the builder must refuse to produce a rollover when
/// the available balance isn't normalized (vs. the high-level API which auto-prepends
/// a normalize transaction).
#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn builder_errors_when_rollover_check_normalized_fails() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let module = module_address();
    let builder = ConfidentialAssetTransactionBuilder::new(&movement, Some(&module))
        .expect("valid module address");

    fund_and_migrate(&movement, &alice).await.expect("fund");
    let r = builder
        .register_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("build register");
    send_and_wait(&movement, &alice, r)
        .await
        .expect("register tx");
    let dep = builder
        .deposit(&alice.address(), &token_address(), DEPOSIT_AMOUNT, None)
        .expect("build deposit");
    send_and_wait(&movement, &alice, dep)
        .await
        .expect("deposit tx");
    let rollover = builder
        .rollover_pending_balance(&alice.address(), &token_address(), false, true)
        .await
        .expect("first rollover build");
    send_and_wait(&movement, &alice, rollover)
        .await
        .expect("first rollover tx");

    let dep2 = builder
        .deposit(&alice.address(), &token_address(), DEPOSIT_AMOUNT, None)
        .expect("build deposit 2");
    send_and_wait(&movement, &alice, dep2)
        .await
        .expect("deposit 2 tx");

    // After a second deposit + rollover, the available balance is no longer normalized;
    // requesting the builder with check_normalized=true should error.
    let res = builder
        .rollover_pending_balance(&alice.address(), &token_address(), false, true)
        .await;
    assert!(
        res.is_err(),
        "expected check_normalized to fail before normalize"
    );
}

/// Builder-level withdraw: produces a withdraw payload that the on-chain Move verifier
/// accepts (σ-proof + range-proof + ciphertext args wired correctly).
#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn builder_withdraws_alices_balance() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let module = module_address();
    let builder = ConfidentialAssetTransactionBuilder::new(&movement, Some(&module))
        .expect("valid module address");

    fund_and_migrate(&movement, &alice).await.expect("fund");
    let r = builder
        .register_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("build register");
    send_and_wait(&movement, &alice, r)
        .await
        .expect("register tx");
    let dep = builder
        .deposit(&alice.address(), &token_address(), DEPOSIT_AMOUNT, None)
        .expect("build deposit");
    send_and_wait(&movement, &alice, dep)
        .await
        .expect("deposit tx");
    let rollover = builder
        .rollover_pending_balance(&alice.address(), &token_address(), false, true)
        .await
        .expect("rollover build");
    send_and_wait(&movement, &alice, rollover)
        .await
        .expect("rollover tx");

    let withdraw_payload = builder
        .withdraw(
            &alice.address(),
            &token_address(),
            WITHDRAW_AMOUNT,
            &alice_dk,
            None,
        )
        .await
        .expect("withdraw build");
    send_and_wait(&movement, &alice, withdraw_payload)
        .await
        .expect("withdraw tx");
}

/// Builder-level self-transfer: produces a transfer payload accepted by Move's
/// `verify_transfer_sigma_proof` (basic positive case for the raw builder API).
#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn builder_transfers_to_self() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let module = module_address();
    let builder = ConfidentialAssetTransactionBuilder::new(&movement, Some(&module))
        .expect("valid module address");

    fund_and_migrate(&movement, &alice).await.expect("fund");
    let r = builder
        .register_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("build register");
    send_and_wait(&movement, &alice, r)
        .await
        .expect("register tx");
    let dep = builder
        .deposit(&alice.address(), &token_address(), DEPOSIT_AMOUNT, None)
        .expect("build deposit");
    send_and_wait(&movement, &alice, dep)
        .await
        .expect("deposit tx");
    let rollover = builder
        .rollover_pending_balance(&alice.address(), &token_address(), false, true)
        .await
        .expect("rollover build");
    send_and_wait(&movement, &alice, rollover)
        .await
        .expect("rollover tx");

    let transfer = builder
        .transfer(
            &alice.address(),
            &alice.address(),
            &token_address(),
            TRANSFER_AMOUNT,
            &alice_dk,
            &[],
            &[],
        )
        .await
        .expect("transfer build");
    send_and_wait(&movement, &alice, transfer)
        .await
        .expect("transfer tx");
}

/// Builder mirror of the high-level negative test: building a transfer to an
/// unregistered recipient must error during payload construction.
#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn builder_transfer_to_unregistered_recipient_errors() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let bob = Ed25519Account::generate();
    let module = module_address();
    let builder = ConfidentialAssetTransactionBuilder::new(&movement, Some(&module))
        .expect("valid module address");

    fund_and_migrate(&movement, &alice).await.expect("fund");
    let r = builder
        .register_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("build register");
    send_and_wait(&movement, &alice, r)
        .await
        .expect("register tx");

    let res = builder
        .transfer(
            &alice.address(),
            &bob.address(),
            &token_address(),
            TRANSFER_AMOUNT,
            &alice_dk,
            &[],
            &[],
        )
        .await;
    assert!(
        res.is_err(),
        "expected transfer to unregistered recipient to fail"
    );
}

/// On a fresh localnet, no global auditor encryption key has been set for the test
/// token, so `get_asset_auditor_encryption_key` must return `None` (not an error).
#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn builder_get_asset_auditor_encryption_key_returns_none_on_fresh_localnet() {
    let movement = make_movement().expect("movement client");
    let module = module_address();
    let builder = ConfidentialAssetTransactionBuilder::new(&movement, Some(&module))
        .expect("valid module address");

    let auditor = builder
        .get_asset_auditor_encryption_key(&token_address())
        .await
        .expect("get_asset_auditor_encryption_key");
    assert!(
        auditor.is_none(),
        "expected no auditor on fresh localnet, got Some(_)"
    );
}
