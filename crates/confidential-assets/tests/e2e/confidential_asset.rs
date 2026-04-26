use super::helpers::{
    FUND_AMOUNT, fund_and_migrate, get_fa_balance, get_test_account, get_test_confidential_account,
    make_confidential_asset, make_fee_payer, make_movement, send_and_wait, send_and_wait_sponsored,
    token_address,
};
use confidential_assets::crypto::twisted_ed25519::TwistedEd25519PrivateKey;
use movement_sdk::account::Ed25519Account;

const DEPOSIT_AMOUNT: u64 = 5;
const WITHDRAW_AMOUNT: u64 = 1;
const TRANSFER_AMOUNT: u64 = 2;

const NEEDS_LOCALNET: &str = "requires localnet — see tests/README.md";
const WIP_TRANSFER_PROOF: &str =
    "depends on transfer-σ Rust gen↔verify (WIP — see crates/confidential-assets/README.md)";
const WIP_WITHDRAW_PROOF: &str =
    "depends on withdraw-σ Rust gen↔verify (WIP — see crates/confidential-assets/README.md)";
const WIP_KEY_ROTATION: &str =
    "depends on key-rotation σ proof generation (WIP — see crates/confidential-assets/README.md)";
const WIP_NORMALIZATION: &str =
    "depends on normalization σ proof generation (WIP — see crates/confidential-assets/README.md)";

async fn register_alice(
    movement: &movement_sdk::Movement,
    alice: &Ed25519Account,
    alice_dk: &TwistedEd25519PrivateKey,
) {
    let ca = make_confidential_asset(movement);
    let token = token_address();
    let payload = ca
        .register_balance(&alice.address(), &token, alice_dk)
        .await
        .expect("build register_balance");
    send_and_wait(movement, alice, payload)
        .await
        .expect("register_balance tx");
}

async fn deposit(movement: &movement_sdk::Movement, alice: &Ed25519Account, amount: u64) {
    let ca = make_confidential_asset(movement);
    let token = token_address();
    let payload = ca
        .deposit(&alice.address(), &token, amount, None)
        .expect("build deposit");
    send_and_wait(movement, alice, payload)
        .await
        .expect("deposit tx");
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_deposits_alices_balance_and_checks_pending() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;

    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let ca = make_confidential_asset(&movement);
    let bal = ca
        .get_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("get_balance");
    assert_eq!(bal.available_balance(), 0);
    assert_eq!(bal.pending_balance(), DEPOSIT_AMOUNT as u128);
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_rolls_over_alices_pending_to_available() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;
    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let ca = make_confidential_asset(&movement);
    let payloads = ca
        .rollover_pending_balance(&alice.address(), &token_address(), None, false)
        .await
        .expect("build rollover");
    for p in payloads {
        send_and_wait(&movement, &alice, p)
            .await
            .expect("rollover tx");
    }

    let bal = ca
        .get_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("get_balance");
    assert_eq!(bal.available_balance(), DEPOSIT_AMOUNT as u128);
    assert_eq!(bal.pending_balance(), 0);
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_errors_on_rollover_when_not_normalized() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;
    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let ca = make_confidential_asset(&movement);
    // first rollover sets the available chunked but un-normalized state
    let first = ca
        .rollover_pending_balance(&alice.address(), &token_address(), None, false)
        .await
        .expect("first rollover build");
    for p in first {
        send_and_wait(&movement, &alice, p)
            .await
            .expect("first rollover tx");
    }
    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let err = ca
        .rollover_pending_balance(&alice.address(), &token_address(), None, false)
        .await
        .expect_err("expected rollover-without-dk to error when un-normalized");
    let msg = format!("{err}");
    assert!(
        msg.contains("normalized") || msg.contains("not normalized"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_withdraws_alices_confidential_balance() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;
    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let ca = make_confidential_asset(&movement);
    let rollovers = ca
        .rollover_pending_balance(&alice.address(), &token_address(), None, false)
        .await
        .expect("rollover build");
    for p in rollovers {
        send_and_wait(&movement, &alice, p).await.expect("rollover");
    }

    // Use a fee payer so alice's public balance only changes by the withdrawn amount —
    // matches the TS test's `withFeePayer: true` setup. Without sponsoring, gas paid in
    // the same FA token (MOVE) skews the assertion.
    let fee_payer = make_fee_payer(&movement).await.expect("fee payer");
    let pre = get_fa_balance(&movement, alice.address(), token_address())
        .await
        .expect("pre fa balance");

    let payload = ca
        .withdraw(
            &alice.address(),
            &token_address(),
            WITHDRAW_AMOUNT,
            &alice_dk,
            None,
        )
        .await
        .expect("withdraw build");
    send_and_wait_sponsored(&movement, &alice, &fee_payer, payload)
        .await
        .expect("withdraw tx");

    let post = get_fa_balance(&movement, alice.address(), token_address())
        .await
        .expect("post fa balance");
    assert_eq!(post, pre + WITHDRAW_AMOUNT);

    let bal = ca
        .get_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("get_balance");
    assert_eq!(
        bal.available_balance(),
        (DEPOSIT_AMOUNT - WITHDRAW_AMOUNT) as u128
    );
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_throws_when_withdrawing_more_than_available() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;
    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let ca = make_confidential_asset(&movement);
    let rollovers = ca
        .rollover_pending_balance(&alice.address(), &token_address(), None, false)
        .await
        .expect("rollover build");
    for p in rollovers {
        send_and_wait(&movement, &alice, p).await.expect("rollover");
    }

    let bal = ca
        .get_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("get_balance");
    let too_much = bal.available_balance() as u64 + 1;

    let res = ca
        .withdraw(
            &alice.address(),
            &token_address(),
            too_much,
            &alice_dk,
            None,
        )
        .await;
    assert!(
        res.is_err(),
        "expected withdraw build to fail with insufficient balance"
    );
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_throws_when_transferring_to_unregistered_recipient() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let bob = Ed25519Account::generate();

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;

    let ca = make_confidential_asset(&movement);
    let res = ca
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

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_throws_when_transferring_more_than_available() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;
    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let ca = make_confidential_asset(&movement);
    let bal = ca
        .get_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("get_balance");
    let too_much = bal.available_balance() as u64 + 1;

    let res = ca
        .transfer(
            &alice.address(),
            &alice.address(),
            &token_address(),
            too_much,
            &alice_dk,
            &[],
            &[],
        )
        .await;
    assert!(
        res.is_err(),
        "expected transfer of more than available to fail"
    );
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_transfers_alice_to_alice_pending_no_auditor() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;
    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let ca = make_confidential_asset(&movement);
    let rollovers = ca
        .rollover_pending_balance(&alice.address(), &token_address(), None, false)
        .await
        .expect("rollover build");
    for p in rollovers {
        send_and_wait(&movement, &alice, p).await.expect("rollover");
    }

    let pre = ca
        .get_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("get_balance");

    let payload = ca
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
    send_and_wait(&movement, &alice, payload)
        .await
        .expect("transfer tx");

    let post = ca
        .get_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("get_balance");
    assert_eq!(
        post.available_balance(),
        pre.available_balance() - TRANSFER_AMOUNT as u128
    );
    assert_eq!(
        post.pending_balance(),
        pre.pending_balance() + TRANSFER_AMOUNT as u128
    );
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_transfers_alice_to_alice_with_auditor() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let auditor = TwistedEd25519PrivateKey::generate();

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;
    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let ca = make_confidential_asset(&movement);
    let rollovers = ca
        .rollover_pending_balance(&alice.address(), &token_address(), None, false)
        .await
        .expect("rollover build");
    for p in rollovers {
        send_and_wait(&movement, &alice, p).await.expect("rollover");
    }

    let payload = ca
        .transfer(
            &alice.address(),
            &alice.address(),
            &token_address(),
            TRANSFER_AMOUNT,
            &alice_dk,
            &[auditor.public_key()],
            &[],
        )
        .await
        .expect("transfer build");
    send_and_wait(&movement, &alice, payload)
        .await
        .expect("transfer tx");
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_checks_alices_balance_not_frozen() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;

    let ca = make_confidential_asset(&movement);
    let frozen = ca
        .is_pending_balance_frozen(&alice.address(), &token_address())
        .await
        .expect("is_pending_balance_frozen");
    assert!(!frozen);
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_throws_checking_frozen_for_unregistered_account() {
    let movement = make_movement().expect("movement client");
    let bob = Ed25519Account::generate();

    let ca = make_confidential_asset(&movement);
    let res = ca
        .is_pending_balance_frozen(&bob.address(), &token_address())
        .await;
    assert!(
        res.is_err(),
        "expected error querying frozen for unregistered account"
    );
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_throws_is_normalized_for_unregistered_account() {
    let movement = make_movement().expect("movement client");
    let bob = Ed25519Account::generate();

    let ca = make_confidential_asset(&movement);
    let res = ca
        .is_balance_normalized(&bob.address(), &token_address())
        .await;
    assert!(
        res.is_err(),
        "expected error querying is_normalized for unregistered account"
    );
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_normalizes_alices_balance() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;
    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let ca = make_confidential_asset(&movement);
    let rollovers = ca
        .rollover_pending_balance(&alice.address(), &token_address(), None, false)
        .await
        .expect("rollover build");
    for p in rollovers {
        send_and_wait(&movement, &alice, p).await.expect("rollover");
    }

    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;
    let payload = ca
        .normalize_balance(&alice.address(), &alice_dk, &token_address())
        .await
        .expect("normalize build");
    send_and_wait(&movement, &alice, payload)
        .await
        .expect("normalize tx");

    let normalized = ca
        .is_balance_normalized(&alice.address(), &token_address())
        .await
        .expect("is_balance_normalized");
    assert!(normalized);
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_withdraws_to_another_account() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let bob = Ed25519Account::generate();

    fund_and_migrate(&movement, &alice)
        .await
        .expect("fund alice");
    movement
        .fund_account(bob.address(), FUND_AMOUNT)
        .await
        .expect("fund bob");
    register_alice(&movement, &alice, &alice_dk).await;
    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let ca = make_confidential_asset(&movement);
    let rollovers = ca
        .rollover_pending_balance(&alice.address(), &token_address(), None, false)
        .await
        .expect("rollover build");
    for p in rollovers {
        send_and_wait(&movement, &alice, p).await.expect("rollover");
    }

    let pre = get_fa_balance(&movement, bob.address(), token_address())
        .await
        .unwrap_or(0);

    let payload = ca
        .withdraw(
            &alice.address(),
            &token_address(),
            WITHDRAW_AMOUNT,
            &alice_dk,
            Some(&bob.address()),
        )
        .await
        .expect("withdraw build");
    send_and_wait(&movement, &alice, payload)
        .await
        .expect("withdraw tx");

    let post = get_fa_balance(&movement, bob.address(), token_address())
        .await
        .expect("post fa balance");
    assert_eq!(post, pre + WITHDRAW_AMOUNT);
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_rotates_alices_encryption_key() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let new_dk = TwistedEd25519PrivateKey::generate();

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;
    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let ca = make_confidential_asset(&movement);
    // Rotate requires pending == 0; roll it over first.
    let rollover = ca
        .rollover_pending_balance(&alice.address(), &token_address(), Some(&alice_dk), false)
        .await
        .expect("rollover build");
    for p in rollover {
        send_and_wait(&movement, &alice, p)
            .await
            .expect("rollover tx");
    }

    let pre = ca
        .get_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("get_balance");

    let payloads = ca
        .rotate_encryption_key(&alice.address(), &alice_dk, &new_dk, &token_address())
        .await
        .expect("rotate build");
    for p in payloads {
        send_and_wait(&movement, &alice, p)
            .await
            .expect("rotate tx");
    }

    let post = ca
        .get_balance(&alice.address(), &token_address(), &new_dk)
        .await
        .expect("get_balance new");
    assert_eq!(
        post.available_balance() + post.pending_balance(),
        pre.available_balance() + pre.pending_balance()
    );
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_withdraws_with_total_balance_after_deposit() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;
    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let ca = make_confidential_asset(&movement);
    let pre = ca
        .get_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("get_balance");
    // available is 0 here; pending is DEPOSIT_AMOUNT — pull from total.
    let amount = pre.available_balance() as u64 + 1;

    let fee_payer = make_fee_payer(&movement).await.expect("fee payer");
    let withdraw_payload = ca
        .withdraw_with_total_balance(&alice, &token_address(), amount, &alice_dk, None)
        .await
        .expect("withdraw_with_total_balance build");
    send_and_wait_sponsored(&movement, &alice, &fee_payer, withdraw_payload)
        .await
        .expect("withdraw tx");

    let post = ca
        .get_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("get_balance");
    assert_eq!(post.pending_balance(), 0);
}

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn it_transfers_with_total_balance_after_deposit() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));

    fund_and_migrate(&movement, &alice).await.expect("fund");
    register_alice(&movement, &alice, &alice_dk).await;
    deposit(&movement, &alice, DEPOSIT_AMOUNT).await;

    let ca = make_confidential_asset(&movement);
    let pre = ca
        .get_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("get_balance");
    let transfer_amount = pre.available_balance() as u64 + 1;

    let transfer_payload = ca
        .transfer_with_total_balance(
            &alice,
            &alice.address(),
            &token_address(),
            transfer_amount,
            &alice_dk,
            &[],
            &[],
        )
        .await
        .expect("transfer_with_total_balance build");
    send_and_wait(&movement, &alice, transfer_payload)
        .await
        .expect("transfer-with-total tx");

    let post = ca
        .get_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("get_balance");
    let pre_total = pre.available_balance() + pre.pending_balance();
    assert_eq!(post.available_balance() + post.pending_balance(), pre_total);
}

// suppress unused-const warnings — these document why a test was deferred
const _: &[&str] = &[
    NEEDS_LOCALNET,
    WIP_TRANSFER_PROOF,
    WIP_WITHDRAW_PROOF,
    WIP_KEY_ROTATION,
    WIP_NORMALIZATION,
];
