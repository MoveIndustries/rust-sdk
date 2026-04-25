//! # Movement Rust SDK v2
//!
//! A user-friendly, idiomatic Rust SDK for the Movement blockchain.
//!
//! This SDK provides a complete interface for interacting with the Movement blockchain,
//! including account management, transaction building and signing, and API clients
//! for both the fullnode REST API and the indexer GraphQL API.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use movement_sdk::{Movement, MovementConfig};
//! use movement_sdk::account::{Account, Ed25519Account};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Connect to testnet
//!     let movement = Movement::new(MovementConfig::testnet())?;
//!
//!     // Create a new account
//!     let account = Ed25519Account::generate();
//!     println!("Address: {}", account.address());
//!
//!     // Get balance (after funding)
//!     let balance = movement.get_balance(account.address()).await?;
//!     println!("Balance: {} octas", balance);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Feature Flags
//!
//! The SDK uses feature flags to allow you to include only the functionality you need:
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `ed25519` | Yes | Ed25519 signature scheme |
//! | `secp256k1` | Yes | Secp256k1 ECDSA signatures |
//! | `secp256r1` | Yes | Secp256r1 (P-256) ECDSA signatures |
//! | `mnemonic` | Yes | BIP-39 mnemonic phrase support for key derivation |
//! | `indexer` | Yes | GraphQL indexer client |
//! | `faucet` | Yes | Faucet integration for testnets |
//! | `bls` | No | BLS12-381 signatures |
//! | `keyless` | No | OIDC-based keyless authentication |
//! | `macros` | No | Proc macros for type-safe contract bindings |
//!
//! ## Modules
//!
//! - [`account`] - Account management and key generation
//! - [`crypto`] - Cryptographic primitives and signature schemes
//! - [`transaction`] - Transaction building and signing
//! - [`api`] - REST and GraphQL API clients
//! - [`types`] - Core Movement types
//! - [`codegen`] - Code generation from Move ABIs

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    clippy::pedantic
)]
// Pedantic lint exceptions - these are intentionally allowed
#![allow(
    clippy::must_use_candidate,       // Too noisy for SDK functions
    clippy::match_same_arms,          // Sometimes intentionally explicit for clarity TODO: Remove, this showed a couple of issues
)]

pub mod account;
pub mod api;
pub mod codegen;
pub mod config;
pub mod crypto;
pub mod error;
pub mod retry;
pub mod transaction;
pub mod types;

mod movement;

// Re-export main entry points
pub use movement::Movement;
pub use config::MovementConfig;
pub use error::{MovementError, MovementResult};

// Re-export commonly used types
pub use types::{AccountAddress, ChainId, HashValue};

// Re-export proc macros when the feature is enabled
#[cfg(feature = "macros")]
pub use movement_sdk_macros::{MoveStruct, movement_contract, movement_contract_file};

// Re-export aptos_bcs for use by the MoveStruct derive macro
// This allows downstream users to use the derive macro without adding aptos-bcs as a dependency
#[doc(hidden)]
pub use aptos_bcs;

// Re-export const_hex for use by generated code (codegen and proc macros)
// This allows downstream users to use generated code without adding const-hex as a dependency
#[doc(hidden)]
pub use const_hex;

#[cfg(test)]
mod tests;
