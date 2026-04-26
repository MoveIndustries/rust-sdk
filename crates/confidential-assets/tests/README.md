# confidential-assets — tests

This crate has two layers of tests:

- **Unit/crypto tests** (default) — pure-Rust tests covering proof generation, encryption, fixtures, etc. Run tests:

```
cargo test -p confidential-assets
```

- **End-to-end tests** (`e2e` feature, all `#[ignore]`-d) — drive a real Movement localnet and exercise
the on-chain confidential-asset module: register, deposit, rollover, withdraw, transfer, normalize,
rotate keys.

## Running e2e tests

1. Start a localnet with the `confidential_asset` feature flag (87) enabled and the module
  published. The required helper script lives at
   `[scripts/start-localnet-confidential-assets.sh](https://github.com/movementlabsxyz/aptos-core/blob/confidential-asset-prod/scripts/start-localnet-confidential-assets.sh)`
   in the `**confidential-asset-prod` branch** of
   `[movementlabsxyz/aptos-core](https://github.com/movementlabsxyz/aptos-core)`. Clone that
   branch locally — the script depends on sibling Move sources and helper files in the same
   repo, so a remote `curl | bash` won't work.
   The script enables feature flag 87, publishes the `confidential_asset` module, and outputs  
   the `aptos_experimental` / publish-signer address. That printed address is what you'll
   export as `CONFIDENTIAL_MODULE_ADDRESS` below.
   Leave the localnet running in that terminal. Open a new terminal back in this repo for the
   next steps.
2. Export env vars and run the suite. Required:
  ```bash
   export CONFIDENTIAL_MODULE_ADDRESS=0x...   # outputted by the script above
  ```
   Optional:
3. Run the tests. Target the `e2e_lib` test binary specifically (so the lib unit tests aren't
  re-run with `--ignored`), and serialize with `--test-threads=1` so the localnet faucet
   isn't hammered by 20+ concurrent `fund_account` calls (it'll drain its own gas balance and
   start returning `INSUFFICIENT_BALANCE_FOR_TRANSACTION_FEE` if you don't):

## Layout

- `tests/e2e/helpers.rs` — env-driven config, account setup, fund-and-migrate helper, send-and-wait helper.
- `tests/e2e/confidential_asset.rs` — high-level `ConfidentialAsset` API tests (port of TS
`confidentialAsset.test.ts`).
- `tests/e2e/txn_builder.rs` — lower-level `ConfidentialAssetTransactionBuilder` tests (port of TS
`confidentialAssetTxnBuilder.test.ts`).
- `tests/e2e/api/` — single-operation negative tests ported from `tests/units/api/negative*.ts`.

## Known gaps

Withdraw-σ and transfer-σ now round-trip through their own Rust verifiers (`withdraw_sigma_gen_verify_roundtrip`,
`transfer_sigma_gen_verify_roundtrip`) and the verifier accepts TS-generated fixtures. Range proofs are
delegated to the upstream `movement_rp_wasm` (same prover the TS SDK builds as WASM); the verify path uses
`bulletproofs::RangeProof::verify_multiple` against the same DST. Pollard kangaroo decryption is delegated to
the upstream `pollard-kangaroo` (`Kangaroo32` preset) — matches the TS WASM module's secret-size assumption.

All four σ-provers (withdraw, transfer, key-rotation, normalization) now round-trip with their own Rust verifiers.