# movement-sdk

A user-friendly, idiomatic Rust SDK for the [Movement Network](https://docs.movementnetwork.xyz)
blockchain. This is the main crate of the
[Movement Rust SDK workspace](../../README.md); for confidential-asset operations see
[`confidential-assets`](../confidential-assets/), and for compile-time contract bindings see
[`movement-sdk-macros`](../movement-sdk-macros/).

## Features

- **Full blockchain interaction** — connect, query, and submit transactions on Movement.
- **Multiple signature schemes** — Ed25519, Secp256k1, Secp256r1 (P-256), MultiKey, BLS12-381,
  and OIDC keyless accounts.
- **Transaction building** — fluent builder for entry functions, scripts, sponsored (fee-payer)
  transactions, multi-agent, and batched submission.
- **Type-safe contract bindings** — proc macros (via [`movement-sdk-macros`](../movement-sdk-macros/))
  to generate typed wrappers from Move ABIs.
- **Modular** — feature flags to compile only what you need.

## Add to your crate

The crate is path-published only inside this workspace (not on crates.io). Add as a git
dependency:

```toml
[dependencies]
movement-sdk = { git = "https://github.com/MoveIndustries/rust-sdk", package = "movement-sdk" }
```

Or, if your crate is in this workspace, use the workspace dep:

```toml
[dependencies]
movement-sdk = { workspace = true }
```

## Quick start

```rust
use movement_sdk::{Movement, MovementConfig};
use movement_sdk::account::{Account, Ed25519Account};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Connect to testnet
    let movement = Movement::new(MovementConfig::testnet())?;

    // Create a new account
    let account = Ed25519Account::generate();
    println!("Address: {}", account.address());

    // Read its balance
    let balance = movement.get_balance(account.address()).await?;
    println!("Balance: {} octas", balance);

    Ok(())
}
```

## Feature flags

| Feature | Default | Description |
|---|---|---|
| `ed25519` | ✓ | Ed25519 signature scheme |
| `secp256k1` | ✓ | Secp256k1 ECDSA signatures |
| `secp256r1` | ✓ | Secp256r1 (P-256) ECDSA signatures |
| `mnemonic` | ✓ | BIP-39 mnemonic phrase derivation |
| `indexer` | ✓ | GraphQL indexer client |
| `faucet` | ✓ | Faucet integration for testnets / localnet |
| `bls` | | BLS12-381 signatures |
| `keyless` | | OIDC-based keyless authentication |
| `macros` | | Procedural macros for type-safe contract bindings |
| `e2e` | | E2E test feature gate (used by tests only) |
| `full` | | Convenience: enable everything |

### Minimal build

Compile with only the signature scheme you need:

```toml
[dependencies]
movement-sdk = { git = "https://github.com/MoveIndustries/rust-sdk", package = "movement-sdk", default-features = false, features = ["ed25519"] }
```

### Full build

```toml
[dependencies]
movement-sdk = { git = "https://github.com/MoveIndustries/rust-sdk", package = "movement-sdk", features = ["full"] }
```

## Examples

Runnable examples live in [`examples/`](examples/). Each example sets `required-features` in
the workspace `Cargo.toml` so it picks the right feature set. Run any example with:

```bash
cargo run -p movement-sdk --example <name> --features "ed25519,faucet"
```

| Category | Examples |
|---|---|
| Basics | [`transfer`](examples/transfer.rs), [`view_function`](examples/view_function.rs), [`balance_checker`](examples/balance_checker.rs), [`transaction_data`](examples/transaction_data.rs), [`simulation`](examples/simulation.rs) |
| Transactions | [`entry_function`](examples/entry_function.rs), [`script_transaction`](examples/script_transaction.rs), [`sponsored_transaction`](examples/sponsored_transaction.rs), [`multi_agent`](examples/multi_agent.rs), [`transaction_waiting`](examples/transaction_waiting.rs), [`advanced_transactions`](examples/advanced_transactions.rs) |
| Accounts | [`account_management`](examples/account_management.rs), [`multi_key_account`](examples/multi_key_account.rs), [`multi_sig_account`](examples/multi_sig_account.rs), [`multisig_v2`](examples/multisig_v2.rs) |
| Smart contracts | [`deploy_module`](examples/deploy_module.rs), [`call_contract`](examples/call_contract.rs), [`read_contract_state`](examples/read_contract_state.rs), [`nft_operations`](examples/nft_operations.rs), [`codegen`](examples/codegen.rs), [`contract_bindings`](examples/contract_bindings.rs) |
| Indexer / events | [`indexer_queries`](examples/indexer_queries.rs), [`event_queries`](examples/event_queries.rs) |

## Development

### Build

```bash
cargo build -p movement-sdk                    # Default features
cargo build -p movement-sdk --all-features     # All features
cargo build -p movement-sdk --release          # Release build
```

### Lint and format

```bash
cargo clippy -p movement-sdk --all-features -- -D warnings
cargo fmt -p movement-sdk -- --check
```

### Unit tests (no network)

```bash
cargo test -p movement-sdk
cargo test -p movement-sdk --all-features
```

### E2E tests (requires Movement localnet)

The workspace ships a runner script that starts a localnet, runs the e2e suite, and tears
down afterwards:

```bash
./scripts/run-e2e.sh
```

…or manually:

```bash
movement node run-localnet --force-restart --with-faucet --do-not-delegate
cargo test -p movement-sdk --features "e2e,full" -- --ignored
```

### Code coverage

```bash
cargo tarpaulin -p movement-sdk --features "full" --skip-clean
```

## Resources

- [Movement Developer Documentation](https://docs.movementnetwork.xyz)
- [API reference (rustdoc on GitHub Pages)](https://moveindustries.github.io/rust-sdk/movement_sdk/index.html)

## License

Apache-2.0
