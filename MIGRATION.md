# Migration Guide: movement-sdk (aptos-core) to movement-sdk (new)

This guide helps you migrate from the old `movement-sdk` crate (located in the `aptos-labs/aptos-core` repository) to the new `movement-sdk` crate published on crates.io.

## Breaking Changes

> **Important**: These changes require immediate attention when migrating.

### 1. Dependency Configuration (Simplified)

**Old SDK** - Required git dependency with patches and rustflags:

```toml
# Cargo.toml
[dependencies]
movement-sdk = { git = "https://github.com/aptos-labs/aptos-core", branch = "devnet" }

[patch.crates-io]
merlin = { git = "https://github.com/aptos-labs/merlin" }
x25519-dalek = { git = "https://github.com/aptos-labs/x25519-dalek", branch = "zeroize_v1" }
```

```toml
# .cargo/config.toml (required)
[build]
rustflags = ["--cfg", "tokio_unstable"]
```

**New SDK** - Clean crates.io dependency:

```toml
# Cargo.toml
[dependencies]
movement-sdk = "0.1"
```

No `.cargo/config.toml` or patches required.

### 2. Account Type Renamed

| Old SDK | New SDK |
|---------|---------|
| `LocalAccount` | `Ed25519Account` |

The new SDK uses explicit account type names reflecting the signature scheme:

```rust
// Old
use movement_sdk::types::LocalAccount;
let account = LocalAccount::generate(&mut rand::rngs::OsRng);

// New
use movement_sdk::account::Ed25519Account;
let account = Ed25519Account::generate();
```

### 3. No Explicit RNG Required

**Old SDK** - Required explicit random number generator:

```rust
let mut rng = rand::rngs::OsRng;
let account = LocalAccount::generate(&mut rng);
```

**New SDK** - RNG handled internally:

```rust
let account = Ed25519Account::generate();
```

### 4. Immutable Account References

**Old SDK** - Required mutable reference for signing:

```rust
coin_client.transfer(&mut alice, bob.address(), 1_000, None).await?;
```

**New SDK** - Immutable references (signing doesn't mutate account):

```rust
movement.transfer_apt(&sender, recipient.address(), 1_000).await?;
```

### 5. Unified Client Architecture

**Old SDK** - Multiple separate clients:

```rust
use movement_sdk::{
    coin_client::CoinClient,
    rest_client::{Client, FaucetClient},
    types::LocalAccount,
};

let rest_client = Client::new(node_url);
let faucet_client = FaucetClient::new(faucet_url, node_url);
let coin_client = CoinClient::new(&rest_client);
```

**New SDK** - Single unified client:

```rust
use movement_sdk::{Movement, MovementConfig, account::Ed25519Account};

let movement = Movement::new(MovementConfig::testnet())?;
// All functionality available through `movement`
```

---

## Quick Start Migration

### Minimal Migration Example

**Old SDK:**

```rust
use movement_sdk::{
    coin_client::CoinClient,
    rest_client::{Client, FaucetClient},
    types::LocalAccount,
};
use url::Url;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let node_url = Url::parse("https://fullnode.devnet.movementnetwork.com")?;
    let faucet_url = Url::parse("https://faucet.testnet.movementnetwork.xyz")?;

    let rest_client = Client::new(node_url.clone());
    let faucet_client = FaucetClient::new(faucet_url, node_url);
    let coin_client = CoinClient::new(&rest_client);

    let mut alice = LocalAccount::generate(&mut rand::rngs::OsRng);
    let bob = LocalAccount::generate(&mut rand::rngs::OsRng);

    faucet_client.fund(alice.address(), 100_000_000).await?;
    faucet_client.create_account(bob.address()).await?;

    let txn_hash = coin_client
        .transfer(&mut alice, bob.address(), 1_000, None)
        .await?;
    rest_client.wait_for_transaction(&txn_hash).await?;

    let balance = coin_client.get_account_balance(&bob.address()).await?;
    println!("Bob's balance: {}", balance);

    Ok(())
}
```

**New SDK:**

```rust
use movement_sdk::{Movement, MovementConfig, account::Ed25519Account};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let movement = Movement::new(MovementConfig::devnet())?;

    let sender = Ed25519Account::generate();
    let recipient = Ed25519Account::generate();

    movement.fund_account(sender.address(), 100_000_000).await?;

    movement.transfer_apt(&sender, recipient.address(), 1_000).await?;

    let balance = movement.get_balance(recipient.address()).await?;
    println!("Recipient balance: {}", balance);

    Ok(())
}
```

---

## Detailed API Mapping

### Core Types

| Old SDK | New SDK | Notes |
|---------|---------|-------|
| `LocalAccount` | `Ed25519Account` | Default Ed25519 account |
| `LocalAccount::generate(&mut rng)` | `Ed25519Account::generate()` | No RNG needed |
| `LocalAccount::from_private_key()` | `Ed25519Account::from_private_key_hex()` | Accepts hex string |
| `account.address()` | `account.address()` | Same |
| `account.public_key()` | `account.public_key()` | Same |

### Client Initialization

| Old SDK | New SDK | Notes |
|---------|---------|-------|
| `Client::new(url)` | `Movement::new(MovementConfig::custom(url)?)` | Unified client |
| `Client::new(devnet_url)` | `Movement::devnet()?` | Preset for devnet |
| `Client::new(testnet_url)` | `Movement::testnet()?` | Preset for testnet |
| `Client::new(mainnet_url)` | `Movement::mainnet()?` | Preset for mainnet |
| N/A | `Movement::local()?` | New: local network preset |

### Faucet Operations

| Old SDK | New SDK | Notes |
|---------|---------|-------|
| `FaucetClient::new(faucet_url, node_url)` | Built into `Movement` | No separate client |
| `faucet_client.fund(address, amount)` | `movement.fund_account(address, amount)` | Waits for confirmation |
| `faucet_client.create_account(address)` | `movement.fund_account(address, 0)` | Fund with 0 to create |
| N/A | `movement.create_funded_account(amount)` | New: generate + fund |

### Coin/Transfer Operations

| Old SDK | New SDK | Notes |
|---------|---------|-------|
| `CoinClient::new(&rest_client)` | Built into `Movement` | No separate client |
| `coin_client.transfer(&mut account, ...)` | `movement.transfer_apt(&account, ...)` | Immutable reference |
| `coin_client.get_account_balance(&addr)` | `movement.get_balance(addr)` | Simpler API |
| N/A | `movement.transfer_coin(&account, addr, type, amt)` | New: generic coin transfer |

### Transaction Submission

| Old SDK | New SDK | Notes |
|---------|---------|-------|
| `rest_client.submit(txn)` | `movement.submit_transaction(&signed_txn)` | Same concept |
| `rest_client.wait_for_transaction(&hash)` | `movement.submit_and_wait(&signed_txn, timeout)` | Combined submit+wait |
| `rest_client.simulate(txn)` | `movement.simulate(&account, payload)` | Enhanced result parsing |
| N/A | `movement.simulate_and_submit(&account, payload)` | New: dry-run then submit |

### Transaction Building

| Old SDK | New SDK | Notes |
|---------|---------|-------|
| `transaction_factory.payload(...)` | `TransactionBuilder::new().payload(...)` | Fluent builder |
| Manual sequence number lookup | `movement.build_transaction(&account, payload)` | Auto-fetches seq num |
| Manual gas price lookup | `movement.build_transaction(&account, payload)` | Auto-fetches gas price |

### Account Resources

| Old SDK | New SDK | Notes |
|---------|---------|-------|
| `rest_client.get_account(addr)` | `movement.fullnode().get_account(addr)` | Via fullnode client |
| `rest_client.get_account_resources(addr)` | `movement.fullnode().get_account_resources(addr)` | Via fullnode client |
| `rest_client.get_account_resource(addr, type)` | `movement.fullnode().get_account_resource(addr, type)` | Via fullnode client |

---

## Migration by Feature

### Account Management

```rust
// Old: LocalAccount with explicit RNG
use movement_sdk::types::LocalAccount;
let account = LocalAccount::generate(&mut rand::rngs::OsRng);

// New: Ed25519Account (default), Secp256k1Account, or Secp256r1Account
use movement_sdk::account::Ed25519Account;
let account = Ed25519Account::generate();

// From private key (old)
let account = LocalAccount::from_private_key(private_key, 0);

// From private key (new)
let account = Ed25519Account::from_private_key_hex("0x...")?;
// Or from bytes:
let account = Ed25519Account::from_private_key_bytes(&bytes)?;
```

### REST Client / API Calls

```rust
// Old: Manual URL construction
use url::Url;
let url = Url::parse("https://fullnode.testnet.movementnetwork.com")?;
let client = Client::new(url);

// New: Network presets
let movement = Movement::new(MovementConfig::testnet())?;
// Or shortcuts:
let movement = Movement::testnet()?;
let movement = Movement::mainnet()?;
let movement = Movement::devnet()?;
let movement = Movement::local()?;

// Custom URL (new)
let movement = Movement::new(MovementConfig::custom("https://my-node.example.com/v1")?)?;

// Access raw fullnode client when needed
let fullnode = movement.fullnode();
let resources = fullnode.get_account_resources(address).await?;
```

### Transaction Building

```rust
// Old: transaction_factory approach
let payload = movement_sdk::transaction_builder::aptos_stdlib::aptos_coin_transfer(
    recipient,
    amount,
);
let raw_txn = transaction_factory
    .payload(payload)
    .sender(sender.address())
    .sequence_number(seq_num)
    .build();

// New: TransactionBuilder with helpers
use movement_sdk::transaction::{EntryFunction, TransactionBuilder};

// Simple transfer (automatic building)
movement.transfer_apt(&sender, recipient, amount).await?;

// Manual building with TransactionBuilder
let payload = EntryFunction::apt_transfer(recipient, amount)?;
let raw_txn = TransactionBuilder::new()
    .sender(sender.address())
    .sequence_number(seq_num)
    .payload(payload.into())
    .chain_id(movement.chain_id())
    .max_gas_amount(100_000)
    .gas_unit_price(100)
    .expiration_from_now(600)
    .build()?;

// Or let the SDK handle sequence number and gas
let raw_txn = movement.build_transaction(&sender, payload.into()).await?;
```

### BCS Serialization

Both SDKs use the same underlying BCS serialization:

```rust
// Both SDKs
use aptos_bcs;

let bytes = aptos_bcs::to_bytes(&value)?;
let value: MyType = aptos_bcs::from_bytes(&bytes)?;
```

Move types are available in the new SDK:

```rust
use movement_sdk::types::move_types::{MoveStructTag, MoveType};
use movement_sdk::types::TypeTag;
```

---

## New Features

The new SDK includes features not available in the old SDK:

### Multiple Signature Schemes

```rust
use movement_sdk::account::{Ed25519Account, Secp256k1Account, Secp256r1Account};

// Ed25519 (default, most common)
let ed25519_account = Ed25519Account::generate();

// Secp256k1 (Ethereum-compatible)
let secp256k1_account = Secp256k1Account::generate();

// Secp256r1 / P-256 (WebAuthn/passkey compatible)
let secp256r1_account = Secp256r1Account::generate();
```

### MultiKeyAccount (Mixed Signature Schemes)

Create accounts that require M-of-N signatures from keys of different types:

```rust
use movement_sdk::account::{AnyPrivateKey, MultiKeyAccount};
use movement_sdk::crypto::{Ed25519PrivateKey, Secp256k1PrivateKey};

// Create keys of different types
let ed25519_key = Ed25519PrivateKey::generate();
let secp256k1_key = Secp256k1PrivateKey::generate();

// Create a 2-of-2 multi-key account
let multi_key = MultiKeyAccount::new(
    vec![
        AnyPrivateKey::ed25519(ed25519_key),
        AnyPrivateKey::secp256k1(secp256k1_key),
    ],
    2, // threshold
)?;

// Use like any other account
movement.transfer_apt(&multi_key, recipient, amount).await?;
```

### Keyless Authentication (OIDC)

Enable authentication via Google, Apple, or other OIDC providers:

```rust
// Requires `keyless` feature
use movement_sdk::account::KeylessAccount;

let keyless = KeylessAccount::new(
    jwt_token,
    ephemeral_key_pair,
    pepper,
    uid_key,
)?;
```

### Sponsored (Fee Payer) Transactions

Let a third party pay for transaction gas fees:

```rust
use movement_sdk::transaction::{
    EntryFunction, TransactionBuilder,
    builder::sign_fee_payer_transaction,
    types::FeePayerRawTransaction,
};

// Build the transaction
let payload = EntryFunction::apt_transfer(recipient, amount)?;
let raw_txn = TransactionBuilder::new()
    .sender(sender.address())
    .sequence_number(seq_num)
    .payload(payload.into())
    .chain_id(movement.chain_id())
    .expiration_from_now(600)
    .build()?;

// Create fee payer transaction
let fee_payer_txn = FeePayerRawTransaction::new_simple(raw_txn, fee_payer.address());

// Sign with both sender and fee payer
let signed = sign_fee_payer_transaction(
    &fee_payer_txn,
    &sender,      // Original sender
    &[],          // Secondary signers (if any)
    &fee_payer,   // Fee payer
)?;

movement.submit_and_wait(&signed, None).await?;
```

### Transaction Simulation

Test transactions before submission:

```rust
// Simulate a transaction
let result = movement.simulate(&sender, payload.into()).await?;

if result.success() {
    println!("Gas needed: {}", result.gas_used());
    println!("Events: {:?}", result.events());
} else {
    println!("Would fail: {}", result.error_message().unwrap_or_default());
}

// Get gas estimate with safety margin
let estimated_gas = movement.estimate_gas(&sender, payload.into()).await?;

// Simulate then submit if successful
let result = movement.simulate_and_submit(&sender, payload.into()).await?;
```

### Batch Transactions

Submit multiple transactions efficiently:

```rust
// Batch multiple transfers
let results = movement.batch_transfer_apt(&sender, vec![
    (addr1, 1_000_000),
    (addr2, 2_000_000),
    (addr3, 3_000_000),
]).await?;

// Or batch arbitrary payloads
let payloads = vec![payload1, payload2, payload3];
let results = movement.submit_batch_and_wait(&sender, payloads, None).await?;
```

### Built-in Indexer Client

Query indexed blockchain data via GraphQL:

```rust
// Requires `indexer` feature (default)
if let Some(indexer) = movement.indexer() {
    // Use GraphQL queries
    let result = indexer.query(my_query).await?;
}
```

### Connection Pooling

Optimize for different workloads:

```rust
use movement_sdk::config::PoolConfig;

// High-throughput applications
let config = MovementConfig::testnet()
    .with_pool(PoolConfig::high_throughput());

// Low-latency applications  
let config = MovementConfig::testnet()
    .with_pool(PoolConfig::low_latency());

// Constrained environments
let config = MovementConfig::testnet()
    .with_pool(PoolConfig::minimal());

// Custom configuration
let config = MovementConfig::testnet()
    .with_pool(PoolConfig::builder()
        .max_idle_per_host(16)
        .max_idle_total(64)
        .idle_timeout(Duration::from_secs(60))
        .build());
```

### Retry Configuration

Handle transient failures automatically:

```rust
use movement_sdk::retry::RetryConfig;

// Aggressive retries for development
let config = MovementConfig::testnet()
    .with_retry(RetryConfig::aggressive());

// Conservative retries for production
let config = MovementConfig::mainnet()
    .with_retry(RetryConfig::conservative());

// Disable retries
let config = MovementConfig::testnet()
    .without_retry();
```

---

## Feature Flags

The new SDK uses feature flags for modular compilation. Only include what you need:

```toml
[dependencies]
# Default features (recommended for most users)
movement-sdk = "0.1"

# Minimal configuration (smaller binary)
movement-sdk = { version = "0.1", default-features = false, features = ["ed25519"] }

# Full features
movement-sdk = { version = "0.1", features = ["full"] }
```

### Available Features

| Feature | Default | Description |
|---------|---------|-------------|
| `ed25519` | Yes | Ed25519 signature scheme |
| `secp256k1` | Yes | Secp256k1 ECDSA (Ethereum-compatible) |
| `secp256r1` | Yes | Secp256r1/P-256 ECDSA (WebAuthn/passkey) |
| `mnemonic` | Yes | BIP-39 mnemonic phrase support |
| `indexer` | Yes | GraphQL indexer client |
| `faucet` | Yes | Testnet faucet integration |
| `bls` | No | BLS12-381 signatures |
| `keyless` | No | OIDC-based keyless authentication |
| `macros` | No | Proc macros for type-safe contract bindings |

### Reducing Binary Size

For minimal binary size, disable default features:

```toml
[dependencies]
movement-sdk = { version = "0.1", default-features = false, features = ["ed25519", "faucet"] }
```

---

## Troubleshooting

### Common Compilation Errors

**"Cannot find type `LocalAccount`"**

```rust
// Old
use movement_sdk::types::LocalAccount;

// New
use movement_sdk::account::Ed25519Account;
```

**"Method `transfer` not found"**

```rust
// Old
coin_client.transfer(&mut alice, bob.address(), 1_000, None).await?;

// New
movement.transfer_apt(&sender, recipient.address(), 1_000).await?;
```

**"Expected mutable reference"**

Account references are now immutable. Remove `mut`:

```rust
// Old
let mut account = ...;
client.method(&mut account, ...);

// New
let account = ...;
movement.method(&account, ...);
```

**"Feature `xyz` not enabled"**

Enable the required feature in `Cargo.toml`:

```toml
[dependencies]
movement-sdk = { version = "0.1", features = ["ed25519", "secp256k1", "faucet"] }
```

**"Cannot find `CoinClient`/`FaucetClient`"**

These are now integrated into the main `Movement` client:

```rust
// Old
let faucet_client = FaucetClient::new(...);
let coin_client = CoinClient::new(...);

// New - all methods on Movement
let movement = Movement::testnet()?;
movement.fund_account(...).await?;    // Was faucet_client.fund()
movement.transfer_apt(...).await?;    // Was coin_client.transfer()
movement.get_balance(...).await?;     // Was coin_client.get_account_balance()
```

### Runtime Errors

**"Faucet not available"**

Faucet is only available on testnet/devnet/local:

```rust
// This works
let movement = Movement::testnet()?;
movement.fund_account(address, amount).await?;

// This won't have a faucet
let movement = Movement::mainnet()?;
// movement.fund_account(...) // Error: faucet not available
```

**"Account not found"**

New accounts must be created/funded before use:

```rust
let account = Ed25519Account::generate();
// Fund the account first
movement.fund_account(account.address(), 100_000_000).await?;
// Now you can use it
movement.transfer_apt(&account, recipient, amount).await?;
```

---

## Getting Help

- [SDK Documentation](https://docs.rs/movement-sdk)
- [Examples](./crates/movement-sdk/examples/)
- [GitHub Issues](https://github.com/moveindustries/rust-sdk/issues)
