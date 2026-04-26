use crate::e2e::helpers::{
    fund_and_migrate, get_test_confidential_account, make_confidential_asset, make_movement,
    send_and_wait, token_address,
};
use movement_sdk::account::Ed25519Account;
use movement_sdk::types::AccountAddress;

#[tokio::test]
#[ignore = "requires localnet — see tests/README.md"]
async fn transfer_to_unregistered_recipient_should_fail() {
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

    // Hard-coded recipient (not registered) — same address used in TS unit
    let recipient = AccountAddress::from_hex(
        "0x82094619a5e8621f2bf9e6479a62ed694dca9b8fd69b0383fce359a3070aa0d4",
    )
    .expect("valid address");

    let res = ca
        .transfer(
            &alice.address(),
            &recipient,
            &token_address(),
            10_000_000,
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
