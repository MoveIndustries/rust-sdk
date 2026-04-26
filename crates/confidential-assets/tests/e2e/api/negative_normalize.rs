use crate::e2e::helpers::{
    fund_and_migrate, get_test_confidential_account, make_confidential_asset, make_movement,
    send_and_wait, token_address,
};
use movement_sdk::account::Ed25519Account;

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn normalize_after_rollover_succeeds() {
    let movement = make_movement().expect("movement client");
    let alice = Ed25519Account::generate();
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

    let payloads = ca
        .rollover_pending_balance(&alice.address(), &token_address(), Some(&alice_dk), false)
        .await
        .expect("rollover build");
    for p in payloads {
        send_and_wait(&movement, &alice, p)
            .await
            .expect("rollover tx");
    }

    let normalize = ca
        .normalize_balance(&alice.address(), &alice_dk, &token_address())
        .await
        .expect("normalize build");
    send_and_wait(&movement, &alice, normalize)
        .await
        .expect("normalize tx");
}
