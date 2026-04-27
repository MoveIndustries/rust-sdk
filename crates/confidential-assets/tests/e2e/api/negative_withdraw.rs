use crate::e2e::helpers::{
    fund_and_migrate, get_test_account, get_test_confidential_account, make_confidential_asset,
    make_movement, send_and_wait, token_address,
};

/// Negative path: depositing without rolling over leaves `available = 0`; a withdraw
/// must fail either at proof construction or on chain (insufficient balance).
#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn withdraw_from_un_rolled_over_balance_should_fail() {
    let movement = make_movement().expect("movement client");
    let alice = get_test_account();
    let alice_dk = get_test_confidential_account(Some(&alice));
    let ca = make_confidential_asset(&movement);

    fund_and_migrate(&movement, &alice).await.expect("fund");
    let register = ca
        .register_balance(&alice.address(), &token_address(), &alice_dk)
        .await
        .expect("build register");
    send_and_wait(&movement, &alice, register)
        .await
        .expect("register tx");

    let dep = ca
        .deposit(&alice.address(), &token_address(), 50_000_000, None)
        .expect("build deposit");
    send_and_wait(&movement, &alice, dep)
        .await
        .expect("deposit tx");

    // Without a rollover, the available balance is still zero — withdraw should fail
    // either at proof construction or on chain.
    let res = ca
        .withdraw(
            &alice.address(),
            &token_address(),
            10_000_000,
            &alice_dk,
            None,
        )
        .await;
    if let Ok(payload) = res {
        let tx = movement.sign_submit_and_wait(&alice, payload, None).await;
        assert!(tx.is_err(), "expected on-chain withdraw to fail");
    }
}
