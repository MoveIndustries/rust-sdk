// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

pub const PROOF_CHUNK_SIZE: usize = 32;

/// Maximum `sender_auditor_hint` length (bytes) accepted by `confidential_transfer` on-chain.
pub const MAX_SENDER_AUDITOR_HINT_BYTES: usize = 256;

/// Matches current Movement TS `serializeSigmaProof` (36 limbs × 32 bytes). Older `21 × 32` constants are obsolete.
pub const SIGMA_PROOF_WITHDRAW_SIZE: usize = PROOF_CHUNK_SIZE * 36;
/// Base transfer sigma proof (no auditors): 56 × 32-byte chunks (TS / Move layout).
pub const SIGMA_PROOF_TRANSFER_SIZE: usize = PROOF_CHUNK_SIZE * 56;
/// Matches current Movement TS `serializeSigmaProof` (37 limbs × 32 bytes); legacy `23 × 32` is obsolete.
pub const SIGMA_PROOF_KEY_ROTATION_SIZE: usize = PROOF_CHUNK_SIZE * 38;
/// Matches current Movement TS `serializeSigmaProof` (36 limbs × 32 bytes); legacy `21 × 32` is obsolete.
pub const SIGMA_PROOF_NORMALIZATION_SIZE: usize = PROOF_CHUNK_SIZE * 36;
pub const SIGMA_PROOF_REGISTRATION_SIZE: usize = PROOF_CHUNK_SIZE * 2;

/// Confidential asset module deployed at the framework address.
pub const DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS: &str = "0x1";
pub const MODULE_NAME: &str = "confidential_asset";

/// Fiat-Shamir protocol identifiers.
pub const PROTOCOL_ID_WITHDRAWAL: &str = "Withdrawal";
pub const PROTOCOL_ID_TRANSFER: &str = "Transfer";
pub const PROTOCOL_ID_ROTATION: &str = "Rotation";
pub const PROTOCOL_ID_NORMALIZATION: &str = "Normalization";
pub const PROTOCOL_ID_REGISTRATION: &str = "Registration";
