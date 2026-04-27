// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! Re-exports the canonical [`movement_sdk::crypto::twisted_ed25519`] module.
//!
//! The Twisted Ed25519 key types live in `movement-sdk` so other Movement
//! protocols can use them; this crate keeps the historical
//! `confidential_assets::crypto::twisted_ed25519::*` import paths working.

pub use movement_sdk::crypto::twisted_ed25519::{
    DECRYPTION_KEY_DERIVATION_MESSAGE, H_RISTRETTO_COMPRESSED, TWISTED_ED25519_PRIVATE_KEY_LENGTH,
    TWISTED_ED25519_PUBLIC_KEY_LENGTH, TwistedEd25519PrivateKey, TwistedEd25519PublicKey,
    h_ristretto,
};
