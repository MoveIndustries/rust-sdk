use super::helpers::{
    fund_and_migrate, get_test_account, get_test_confidential_account, make_movement,
    module_address, send_and_wait, token_address,
};
use confidential_assets::ConfidentialAssetTransactionBuilder;
use movement_sdk::account::Ed25519Account;

const DEPOSIT_AMOUNT: u64 = 5;
const WITHDRAW_AMOUNT: u64 = 1;
const TRANSFER_AMOUNT: u64 = 2;

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn builder_register_then_deposit_updates_pending() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let module = module_address();
    let builder = ConfidentialAssetTransactionBuilder::new(&movement, Some(&module));

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

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn builder_rolls_over_pending_balance() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let module = module_address();
    let builder = ConfidentialAssetTransactionBuilder::new(&movement, Some(&module));

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

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn builder_errors_when_rollover_check_normalized_fails() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let module = module_address();
    let builder = ConfidentialAssetTransactionBuilder::new(&movement, Some(&module));

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

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn builder_withdraws_alices_balance() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let module = module_address();
    let builder = ConfidentialAssetTransactionBuilder::new(&movement, Some(&module));

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

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn builder_transfers_to_self() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let module = module_address();
    let builder = ConfidentialAssetTransactionBuilder::new(&movement, Some(&module));

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

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn builder_transfer_to_unregistered_recipient_errors() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let bob = Ed25519Account::generate();
    let module = module_address();
    let builder = ConfidentialAssetTransactionBuilder::new(&movement, Some(&module));

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
