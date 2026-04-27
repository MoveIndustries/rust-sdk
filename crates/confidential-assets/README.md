# confidential-assets

Rust SDK for [Movement Network](https://movementnetwork.xyz) confidential assets — Twisted ElGamal
encryption, ZK proofs, and confidential transfers on MoveVM. Functional parity with the
[`@moveindustries/confidential-assets`](https://www.npmjs.com/package/@moveindustries/confidential-assets)
TypeScript SDK; same on-chain wire format, validated end-to-end against a localnet.

This crate is part of the [Movement Rust SDK workspace](../../README.md). It depends on
`movement-sdk` for HTTP / transaction building and on the upstream Rust source that the TS SDK
ships as WASM (`movement_rp_wasm`, `movement_pollard_kangaroo_wasm`) — same code path, no port.

## Status

- 47 unit + integration tests (crypto, BCS, σ-proof gen↔verify roundtrips, TS fixture): **passing**.
- 28 e2e tests against a Movement localnet (register / deposit / rollover / withdraw / transfer
  with and without auditor / two-transfers-without-rollover regression / normalize / rotate /
  total-balance variants, plus negative paths): **passing**.

See [`tests/README.md`](tests/README.md) for how to run the e2e suite (requires
[`scripts/start-localnet-confidential-assets.sh`](https://github.com/movementlabsxyz/aptos-core/blob/confidential-asset-prod/scripts/start-localnet-confidential-assets.sh)
from the `confidential-asset-prod` branch of our `aptos-core` repo).

## Concepts

A confidential balance for an `(account, token)` pair has two parts:

- **pending** — additive: anyone can `deposit_to` here without your permission. The deposited
  ciphertext is encrypted under your encryption key; only you (and any auditors specified at
  transfer time) can decrypt the amount.
- **available** — what you can spend. To move funds from pending → available you sign a
  `rollover_pending_balance` transaction.

The depositor's account address is still on-chain (it's the transaction's signer), so this scheme
hides **amounts**, not identities. For full sender/recipient anonymity you'd need a shielded-pool
design (separate construction).

You hold a **decryption key** (a `TwistedEd25519PrivateKey`) which is independent of your Aptos
account key. Its corresponding encryption key is what other parties use to deposit / transfer
to you. Decryption keys can be derived deterministically from your account by signing a fixed
domain string (see the module-level `DECRYPTION_KEY_DERIVATION_MESSAGE` const in
`confidential_assets::crypto::twisted_ed25519`).

The `ConfidentialAsset` high-level API builds Move entry-function payloads for each operation;
you sign and submit them with the standard `Movement` client.

## Examples

### Setup boilerplate (used in every example below)

```rust
use confidential_assets::api::ConfidentialAsset;
use confidential_assets::crypto::twisted_ed25519::{
    DECRYPTION_KEY_DERIVATION_MESSAGE, TwistedEd25519PrivateKey,
};
use movement_sdk::account::Ed25519Account;
use movement_sdk::types::AccountAddress;
use movement_sdk::{Movement, MovementConfig};

let movement = Movement::new(MovementConfig::testnet())?;
let alice = Ed25519Account::generate();

// Derive a deterministic decryption key from Alice's signing key: sign the
// fixed domain string and take the first 32 bytes of the signature as a scalar.
let signature = alice.sign_message(DECRYPTION_KEY_DERIVATION_MESSAGE);
let sig_bytes = signature.to_bytes();
let alice_dk = TwistedEd25519PrivateKey::from_bytes(&sig_bytes[..32])?;

let token: AccountAddress =
    "0x000000000000000000000000000000000000000000000000000000000000000a".parse()?;
let module_address = std::env::var("CONFIDENTIAL_MODULE_ADDRESS")?;
let ca = ConfidentialAsset::new(&movement, Some(module_address.as_str()))?;
```

### 1. Register a confidential balance

Required once per `(account, token)` before any other operation.

```rust
let payload = ca
    .register_balance(&alice.address(), &token, &alice_dk)
    .await?;
movement.sign_submit_and_wait(&alice, payload, None).await?;
```

### 2. Deposit from public balance into pending

Moves `amount` octas of the public FA token into Alice's *pending* confidential balance.
Anyone can do this — knowledge of Alice's encryption key (public) is enough.

```rust
let payload = ca.deposit(&alice.address(), &token, 5, None)?;
movement.sign_submit_and_wait(&alice, payload, None).await?;

// Or deposit on someone else's behalf:
let recipient: AccountAddress = "0x...".parse()?;
let payload = ca.deposit(&alice.address(), &token, 5, Some(&recipient))?;
movement.sign_submit_and_wait(&alice, payload, None).await?;
```

### 3. Rollover pending → available

Returns 1 or 2 transactions: if `available` isn't normalized yet, the API auto-prepends a
normalize transaction. Pass the decryption key so it can build that proof if needed.

```rust
for p in ca
    .rollover_pending_balance(&alice.address(), &token, Some(&alice_dk), /* freeze= */ false)
    .await?
{
    movement.sign_submit_and_wait(&alice, p, None).await?;
}
```

### 4. Read your own confidential balance

Decrypts pending and available locally using `alice_dk`.

```rust
let bal = ca.get_balance(&alice.address(), &token, &alice_dk).await?;
println!("available: {} octas", bal.available_balance());
println!("pending:   {} octas", bal.pending_balance());
```

### 5. Withdraw to a public balance

Moves `amount` octas from your *available* confidential balance back to a public FA balance
(yours by default, or any other address). Generates a withdraw σ-proof + range proof.

```rust
let payload = ca
    .withdraw(&alice.address(), &token, 1, &alice_dk, /* recipient = self */ None)
    .await?;
movement.sign_submit_and_wait(&alice, payload, None).await?;
```

> **Note on gas:** withdraw to a public FA balance of the same token used for gas (e.g.
> `0x1::aptos_coin::AptosCoin` / MOVE) will net out the gas cost from the withdrawn amount.
> If you want a clean accounting, submit the withdraw as a sponsored transaction with a
> separate fee payer — see the e2e helper `send_and_wait_sponsored` in
> `tests/e2e/helpers.rs`.

### 6. Confidential transfer

Moves `amount` from Alice's available balance into Bob's pending balance with the **amount
encrypted** under Bob's encryption key — only Alice and Bob (and any auditors, if specified)
can decrypt it. Sender, recipient, and the fact a transfer occurred are still public on-chain;
this scheme hides amounts, not identities. Both Alice and Bob must already be registered.

```rust
let bob: AccountAddress = "0x...".parse()?;
let payload = ca
    .transfer(
        &alice.address(),
        &bob,
        &token,
        2,
        &alice_dk,
        /* additional_auditor_encryption_keys = */ &[],
        /* sender_auditor_hint = */ &[],
    )
    .await?;
movement.sign_submit_and_wait(&alice, payload, None).await?;
```

### 7. Transfer with auditor encryption

Encrypt the transfer amount under additional auditor public keys (e.g., a regulator). The
auditor can later decrypt the amount; the on-chain world still cannot.

```rust
use confidential_assets::crypto::twisted_ed25519::TwistedEd25519PublicKey;

let auditor_pk: TwistedEd25519PublicKey = /* obtained out of band */;

let payload = ca
    .transfer(
        &alice.address(),
        &bob,
        &token,
        2,
        &alice_dk,
        &[auditor_pk],
        &[],
    )
    .await?;
movement.sign_submit_and_wait(&alice, payload, None).await?;
```

### 8. Rotate your decryption key

Useful when the old key is suspected compromised. The API auto-rolls-over any pending balance
first, then builds the rotate transaction.

```rust
let new_dk = TwistedEd25519PrivateKey::generate();
for p in ca
    .rotate_encryption_key(&alice.address(), &alice_dk, &new_dk, &token)
    .await?
{
    movement.sign_submit_and_wait(&alice, p, None).await?;
}

// From here on, use `new_dk` for `get_balance` / `withdraw` / `transfer`.
let bal = ca.get_balance(&alice.address(), &token, &new_dk).await?;
```

### 9. Normalize manually

Each chunked balance can drift from "normalized" form after rollovers. `rollover_pending_balance`
auto-normalizes when needed, but you can also do it explicitly:

```rust
let payload = ca
    .normalize_balance(&alice.address(), &alice_dk, &token)
    .await?;
movement.sign_submit_and_wait(&alice, payload, None).await?;
```

### 10. Probe state without funds

```rust
let registered = ca
    .has_user_registered(&alice.address(), &token)
    .await?;
let normalized = ca
    .is_balance_normalized(&alice.address(), &token)
    .await?;
let frozen = ca
    .is_pending_balance_frozen(&alice.address(), &token)
    .await?;
let auditor = ca.get_asset_auditor_encryption_key(&token).await?;
```

## Architecture

```
src/
├── api/                         high-level ConfidentialAsset client
├── internal/
│   ├── transaction_builder.rs   builds entry-function payloads (register / deposit / ...)
│   └── view_functions.rs        on-chain reads (balance, encryption_key, is_normalized, ...)
├── crypto/
│   ├── twisted_ed25519.rs       Twisted Ed25519 keys (Ristretto, h_ristretto base point)
│   ├── twisted_el_gamal.rs      Twisted ElGamal encrypt/decrypt
│   ├── encrypted_amount.rs      chunked amounts; kangaroo-based decrypt
│   ├── chunked_amount.rs        16-bit limb chunking (8 chunks balance, 4 chunks transfer)
│   ├── range_proof.rs           bulletproofs batch range proofs (delegates to upstream)
│   ├── fiat_shamir.rs           variadic challenge transcript (TS-aligned)
│   ├── confidential_registration.rs    register σ-protocol
│   ├── confidential_transfer.rs        transfer σ-protocol (+ auditor encryption)
│   ├── confidential_withdraw.rs        withdraw σ-protocol
│   ├── withdraw_protocol.rs            withdraw σ wire format + verifier
│   ├── confidential_key_rotation.rs    key-rotation σ-protocol
│   └── confidential_normalization.rs   normalization σ-protocol
├── bcs.rs                       Move-vector<u8> BCS helpers
├── consts.rs                    SIGMA_PROOF_*_SIZE, MODULE_NAME, default addrs
├── helpers.rs                   misc
├── memoize.rs                   cache keys for balance / encryption-key views
└── utils.rs                     scalar / hash utilities
```

## Dependencies

Cryptography:

- [`curve25519-dalek`](https://crates.io/crates/curve25519-dalek) — Ristretto group, scalar
  arithmetic.
- [`bulletproofs`](https://crates.io/crates/bulletproofs) — range-proof verification.
- [`merlin`](https://crates.io/crates/merlin) — Fiat-Shamir transcripts (the underlying bulletproof
  prover/verifier transcript framework).
- [`curve25519-dalek-ng`](https://crates.io/crates/curve25519-dalek-ng) — required by
  `bulletproofs 4.x`. Confined to the range-proof module; the rest of the crate uses the
  official `curve25519-dalek`. Conversion at the boundary is byte-based (32-byte point /
  scalar serialization).
- `sha2` / `sha3` / `rand` — hashes and CSRNG.

Movement-specific (shared with the TS SDK):

- [`movement_rp_wasm`](https://github.com/moveindustries/confidential-asset-wasm-bindings) —
  bulletproofs prover. Same Rust source the TS SDK builds as WASM; consumed here as an `rlib`.
- [`movement_pollard_kangaroo_wasm`](https://github.com/moveindustries/confidential-asset-wasm-bindings) —
  Pollard kangaroo DLP solver. Same source as the TS SDK's WASM, `Kangaroo32` preset.

Movement-SDK plumbing:

- `movement-sdk` — HTTP client, `EntryFunction` / `TransactionPayload`, account types.
- `aptos-bcs` — BCS serialization (Move-compatible).

## TypeScript SDK parity (`../ts-sdk/confidential-assets`)

| Area | TS SDK | This crate |
|---|---|---|
| Twisted Ed25519 encryption PK | `pk = s⁻¹·H` with fixed `H` (`HASH_BASE_POINT`) | ✅ same (`twisted_ed25519`) |
| Chunk layout | `CHUNK_BITS = 16`, balance 8 chunks, transfer 4 chunks | ✅ same (`chunked_amount`) |
| `bcsSerializeMoveVectorU8` | `utils/moveBcs` | ✅ `bcs::serialize_vector_u8` |
| Variadic Fiat-Shamir | `fiatShamirChallenge` | ✅ `fiat_shamir_challenge_ts` |
| Twisted ElGamal | `C = v·G + r·H`, `D = r·pk` | ✅ same (`twisted_el_gamal`) |
| Pollard kangaroo (DLP) | WASM `WASMKangaroo` | ✅ native `pollard-kangaroo` (Kangaroo32) |
| Range proofs | WASM `batch_range_proof` | ✅ native `movement_rp_wasm::rp::_batch_range_proof` (same upstream); verify via `bulletproofs::RangeProof::verify_multiple` |
| Registration σ | full gen + verify | ✅ gen↔verify roundtrip; on-chain verifier accepts |
| Transfer σ (56×32) | full gen + verify | ✅ gen↔verify roundtrip; verifies TS fixture; on-chain verifier accepts |
| Withdraw σ (36×32) | full gen + verify | ✅ gen↔verify roundtrip; on-chain verifier accepts |
| Key rotation σ (38×32) | full gen + verify | ✅ gen↔verify roundtrip; on-chain verifier accepts |
| Normalization σ (36×32) | full gen + verify | ✅ gen↔verify roundtrip; on-chain verifier accepts |
| Balance view cache + memoization | `utils/memoize` | ✅ `memoize` module |
| `rolloverPendingBalance` (auto-normalize) | returns 1-2 txs | ✅ same shape (`Vec<TransactionPayload>`) |
| `rotateEncryptionKey` (auto-rollover) | returns 1-3 txs | ✅ same shape |

## Testing

The crate has two layers of tests.

### Unit / integration (no network)

47 tests covering crypto primitives (Twisted ElGamal, Fiat-Shamir, σ-proof gen↔verify
roundtrips, range-proof wrapper, kangaroo decryption), BCS round-trips, and TS-fixture
verification. Run with the default `cargo test`:

```bash
cargo test -p confidential-assets
```

These tests do not touch the network and don't need any environment setup.

### End-to-end against a Movement localnet

28 tests that exercise the full lifecycle on a real chain: register → deposit → rollover →
withdraw → transfer (with/without auditor) → two-transfers-without-rollover regression →
normalize → key rotation → total-balance variants, plus negative paths (frozen balance,
unregistered recipient, over-withdraw, etc.).

**1. Start the localnet.** The required helper script lives at
[`scripts/start-localnet-confidential-assets.sh`](https://github.com/movementlabsxyz/aptos-core/blob/confidential-asset-prod/scripts/start-localnet-confidential-assets.sh)
in the **`confidential-asset-prod` branch** of
[`movementlabsxyz/aptos-core`](https://github.com/movementlabsxyz/aptos-core). Clone that
branch locally — the script depends on sibling Move sources and helper files in the same
repo, so a remote `curl | bash` won't work:

```bash
# In a separate directory, NOT inside the rust-sdk repo
git clone --branch confidential-asset-prod --depth 1 \
    https://github.com/movementlabsxyz/aptos-core.git
cd aptos-core
./scripts/start-localnet-confidential-assets.sh
```

The script enables feature flag 87, publishes the `confidential_asset` Move module, and
prints the publish-signer address. Leave the localnet running in that terminal. Note the
printed address — you'll export it as `CONFIDENTIAL_MODULE_ADDRESS` next.

**2. Set the module address.** In the rust-sdk repo's terminal:

```bash
export CONFIDENTIAL_MODULE_ADDRESS=0x<64-char hex from the script>
```

A length check will refuse to run if the address isn't exactly 32 bytes (64 hex chars after
`0x`).

**3. Run the suite:**

```bash
bash scripts/run-ca-e2e.sh
```

…which is shorthand for:

```bash
cargo test -p confidential-assets --features e2e --test e2e_lib \
    -- --ignored --test-threads=1
```

`--test-threads=1` is required to avoid hammering the localnet faucet with parallel funding
requests; the script enforces this.

### Optional env vars

| Variable | Default | Purpose |
|---|---|---|
| `CONFIDENTIAL_MODULE_ADDRESS` | *(required)* | Address of the published `confidential_asset` Move module. |
| `MOVEMENT_NETWORK` | `LOCAL` | `LOCAL` / `TESTNET` / `MAINNET`. Selects which `MovementConfig::*` preset is used. |
| `TOKEN_ADDRESS` | `0x...0a` (MOVE FA) | FA metadata address used as the test token. |
| `TESTNET_PK` | *(generates fresh)* | Reuse a funded Ed25519 account across runs (hex private key). |
| `TESTNET_DK` | *(derives from sender)* | Reuse a Twisted Ed25519 decryption key across runs. |

### What "passes" means

A passing e2e test means the Rust SDK constructed BCS-encoded entry-function args + σ-proofs +
range-proofs that the **on-chain Move verifier accepts** and that the resulting state matches
the test's expectations. It's the strongest end-to-end guarantee available short of mainnet.

See [`tests/README.md`](tests/README.md) for more detail and the list of `#[ignore]`d
diagnostic tests.

## License

Apache-2.0 © Move Industries
