// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! # Confidential Assets SDK
//!
//! Rust SDK for Movement Network confidential asset operations:
//! - Twisted Ed25519 key management
//! - Twisted ElGamal encryption/decryption
//! - Confidential registration, transfer, withdrawal, key rotation, normalization
//! - Fiat-Shamir sigma proofs
//! - Range proofs (placeholder for bulletproofs integration)
//!
//! ## Structure
//!
//! - `crypto` — Core cryptographic primitives (keys, encryption, proofs)
//! - `api` — High-level API for building confidential asset transactions
//! - `internal` — Transaction builder and on-chain view functions
//! - `bcs` — BCS serialization helpers
//! - `consts` — Protocol constants
//! - `helpers` — Utility functions
//! - `utils` — Scalar generation utilities

pub mod api;
pub mod bcs;
pub mod consts;
pub mod crypto;
pub mod helpers;
pub mod internal;
pub mod memoize;
pub mod utils;

// Re-export main API types
pub use api::ConfidentialAsset;
pub use bcs::bcs_serialize_move_vector_u8;
pub use bcs::serialize_vector_u8;
pub use consts::*;
pub use crypto::*;
pub use internal::transaction_builder::ConfidentialAssetTransactionBuilder;
pub use internal::view_functions::ConfidentialBalance;
pub use memoize::{
    clear_balance_cache, clear_cache, clear_encryption_key_cache, get_available_balance_cache_key,
    get_cache, get_encryption_key_cache_key, get_pending_balance_cache_key, memoize,
    memoize_async_run, set_cache,
};
