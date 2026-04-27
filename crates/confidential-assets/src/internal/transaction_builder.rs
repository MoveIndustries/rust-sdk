// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! Transaction builder for confidential asset operations.
//!
//! Mirrors the TS SDK's `confidentialAssetTxnBuilder.ts`. Constructs entry
//! function payloads for each confidential asset Move entry point.
//!

use super::view_functions::{
    get_balance, get_chain_id_byte_for_proofs, get_encryption_key,
    get_global_auditor_encryption_key, is_balance_normalized, is_pending_balance_frozen,
};
use crate::bcs::serialize_vector_u8;
use crate::consts::{
    DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS, MAX_SENDER_AUDITOR_HINT_BYTES, MODULE_NAME,
};
use crate::crypto::confidential_registration::gen_registration_proof;
use crate::crypto::{
    TwistedEd25519PrivateKey, TwistedEd25519PublicKey,
    confidential_key_rotation::ConfidentialKeyRotation,
    confidential_normalization::ConfidentialNormalization,
    confidential_transfer::ConfidentialTransfer, confidential_withdraw::ConfidentialWithdraw,
};
use movement_sdk::{
    Movement, MovementError,
    transaction::{EntryFunction, TransactionPayload},
    types::{AccountAddress, Identifier, MoveModuleId},
};

/// Helper: BCS-encode an AccountAddress (fixed 32-byte serialization, infallible).
fn bcs_addr(addr: &AccountAddress) -> Vec<u8> {
    aptos_bcs::to_bytes(addr).expect("AccountAddress BCS serialization is infallible")
}

/// Helper: parse module address string to AccountAddress.
///
/// Panics on malformed input rather than silently zero-padding — a wrong module address
/// produces a LINKER_ERROR on-chain that's expensive to debug.
fn parse_module_address(addr: &str) -> AccountAddress {
    AccountAddress::from_hex(addr)
        .unwrap_or_else(|e| panic!("invalid confidential-asset module address {addr:?}: {e}"))
}

/// Build the on-chain `<contract_address>::confidential_asset` module id.
fn module_id(contract_address: AccountAddress) -> MoveModuleId {
    MoveModuleId::new(
        contract_address,
        Identifier::new(MODULE_NAME).expect("MODULE_NAME is a valid Move identifier"),
    )
}

/// Builder for confidential asset transactions.
///
/// Returns `TransactionPayload` (movement-sdk entry function) ready for
/// `movement.sign_and_submit()` / `movement.simulate()`.
pub struct ConfidentialAssetTransactionBuilder<'a> {
    pub client: &'a Movement,
    pub confidential_asset_module_address: String,
}

impl<'a> ConfidentialAssetTransactionBuilder<'a> {
    pub fn new(client: &'a Movement, confidential_asset_module_address: Option<&str>) -> Self {
        let addr = confidential_asset_module_address
            .unwrap_or(DEFAULT_CONFIDENTIAL_COIN_MODULE_ADDRESS)
            .to_string();
        Self {
            client,
            confidential_asset_module_address: addr,
        }
    }

    /// Build a `register` entry function payload.
    pub async fn register_balance(
        &self,
        sender: &AccountAddress,
        token_address: &AccountAddress,
        decryption_key: &TwistedEd25519PrivateKey,
    ) -> Result<TransactionPayload, MovementError> {
        let chain_id = get_chain_id_byte_for_proofs(self.client).await?;
        let contract_address = parse_module_address(&self.confidential_asset_module_address);
        let sender_bytes = sender.to_bytes();
        let token_bytes = token_address.to_bytes();

        let proof = gen_registration_proof(
            decryption_key,
            chain_id,
            &sender_bytes,
            contract_address.as_bytes(),
            &token_bytes,
        );

        let public_key_bytes = decryption_key.public_key().to_bytes();

        Ok(EntryFunction::new(
            module_id(contract_address),
            "register",
            vec![],
            vec![
                bcs_addr(token_address),
                serialize_vector_u8(&public_key_bytes),
                serialize_vector_u8(&proof.commitment),
                serialize_vector_u8(&proof.response),
            ],
        )
        .into())
    }

    /// Build a `deposit_to` entry function payload.
    pub fn deposit(
        &self,
        sender: &AccountAddress,
        token_address: &AccountAddress,
        amount: u64,
        recipient: Option<&AccountAddress>,
    ) -> Result<TransactionPayload, MovementError> {
        // Match TS: `recipient ?? sender` — depositing to one's own confidential
        // balance is the common case.
        let recipient_addr = recipient.copied().unwrap_or(*sender);
        let module_addr = parse_module_address(&self.confidential_asset_module_address);

        Ok(EntryFunction::new(
            module_id(module_addr),
            "deposit_to",
            vec![],
            vec![
                bcs_addr(token_address),
                bcs_addr(&recipient_addr),
                aptos_bcs::to_bytes(&amount).expect("u64 BCS serialization is infallible"),
            ],
        )
        .into())
    }

    /// Build a `withdraw_to` entry function payload.
    pub async fn withdraw(
        &self,
        sender: &AccountAddress,
        token_address: &AccountAddress,
        amount: u64,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        recipient: Option<&AccountAddress>,
    ) -> Result<TransactionPayload, MovementError> {
        let sender_bytes = sender.to_bytes();
        let token_bytes = token_address.to_bytes();

        // Get sender's available balance from chain
        let balance = get_balance(
            self.client,
            sender,
            token_address,
            sender_decryption_key,
            Some(&self.confidential_asset_module_address),
        )
        .await?;

        let chain_id = get_chain_id_byte_for_proofs(self.client).await?;
        let contract_address = parse_module_address(&self.confidential_asset_module_address);

        let confidential_withdraw = ConfidentialWithdraw::create_with_balance(
            sender_decryption_key.clone(),
            balance.available.get_amount(),
            balance.available.get_ciphertext().to_vec(),
            amount as u128,
            chain_id,
            &sender_bytes,
            contract_address.as_bytes(),
            &token_bytes,
        )
        .map_err(|e| MovementError::Internal(format!("withdraw create failed: {}", e)))?;

        let (proofs, range_proof_bytes, encrypted_amount_after_withdraw) = confidential_withdraw
            .authorize_withdrawal()
            .await
            .map_err(|e| MovementError::Internal(format!("withdraw auth failed: {}", e)))?;

        let recipient_addr = recipient.copied().unwrap_or(*sender);
        let module_addr = parse_module_address(&self.confidential_asset_module_address);

        Ok(EntryFunction::new(
            module_id(module_addr),
            "withdraw_to",
            vec![],
            vec![
                bcs_addr(token_address),
                bcs_addr(&recipient_addr),
                aptos_bcs::to_bytes(&amount).expect("u64 BCS serialization is infallible"),
                serialize_vector_u8(&encrypted_amount_after_withdraw.get_ciphertext_bytes()),
                serialize_vector_u8(&range_proof_bytes),
                serialize_vector_u8(&ConfidentialWithdraw::serialize_sigma_proof(&proofs)),
            ],
        )
        .into())
    }

    /// Build a `rollover_pending_balance` (or `rollover_pending_balance_and_freeze`) entry function payload.
    pub async fn rollover_pending_balance(
        &self,
        sender: &AccountAddress,
        token_address: &AccountAddress,
        with_freeze_balance: bool,
        check_normalized: bool,
    ) -> Result<TransactionPayload, MovementError> {
        if check_normalized {
            let is_norm = is_balance_normalized(
                self.client,
                sender,
                token_address,
                Some(&self.confidential_asset_module_address),
            )
            .await?;
            if !is_norm {
                return Err(MovementError::Internal(
                    "Balance must be normalized before rollover".to_string(),
                ));
            }
        }

        let function_name = if with_freeze_balance {
            "rollover_pending_balance_and_freeze"
        } else {
            "rollover_pending_balance"
        };

        let module_addr = parse_module_address(&self.confidential_asset_module_address);

        Ok(EntryFunction::new(
            module_id(module_addr),
            function_name,
            vec![],
            vec![bcs_addr(token_address)],
        )
        .into())
    }

    /// Build a `confidential_transfer` entry function payload.
    pub async fn transfer(
        &self,
        sender: &AccountAddress,
        recipient: &AccountAddress,
        token_address: &AccountAddress,
        amount: u64,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        additional_auditor_encryption_keys: &[TwistedEd25519PublicKey],
        sender_auditor_hint: &[u8],
    ) -> Result<TransactionPayload, MovementError> {
        if sender_auditor_hint.len() > MAX_SENDER_AUDITOR_HINT_BYTES {
            return Err(MovementError::Internal(format!(
                "senderAuditorHint exceeds MAX_SENDER_AUDITOR_HINT_BYTES ({})",
                MAX_SENDER_AUDITOR_HINT_BYTES
            )));
        }

        let sender_bytes = sender.to_bytes();
        let token_bytes = token_address.to_bytes();

        let chain_id = get_chain_id_byte_for_proofs(self.client).await?;

        // Get auditor public key for the token
        let global_auditor_pub_key = get_global_auditor_encryption_key(
            self.client,
            token_address,
            Some(&self.confidential_asset_module_address),
        )
        .await?;

        // Determine recipient encryption key
        let recipient_encryption_key = if sender == recipient {
            sender_decryption_key.public_key()
        } else {
            get_encryption_key(
                self.client,
                recipient,
                token_address,
                Some(&self.confidential_asset_module_address),
            )
            .await?
        };

        // Check if recipient balance is frozen
        let is_frozen = is_pending_balance_frozen(
            self.client,
            recipient,
            token_address,
            Some(&self.confidential_asset_module_address),
        )
        .await?;
        if is_frozen {
            return Err(MovementError::Internal(
                "Recipient balance is frozen".to_string(),
            ));
        }

        // Get sender's available balance
        let balance = get_balance(
            self.client,
            sender,
            token_address,
            sender_decryption_key,
            Some(&self.confidential_asset_module_address),
        )
        .await?;

        let contract_address = parse_module_address(&self.confidential_asset_module_address);

        // Assemble auditor keys
        let mut auditor_keys: Vec<TwistedEd25519PublicKey> = vec![];
        if let Some(auditor) = global_auditor_pub_key {
            auditor_keys.push(auditor);
        }
        auditor_keys.extend_from_slice(additional_auditor_encryption_keys);

        let confidential_transfer = ConfidentialTransfer::create(
            sender_decryption_key.clone(),
            balance.available.get_amount(),
            balance.available.randomness().to_vec(),
            amount as u128,
            recipient_encryption_key.clone(),
            auditor_keys.clone(),
            chain_id,
            &sender_bytes,
            contract_address.as_bytes(),
            &token_bytes,
            sender_auditor_hint,
        )
        .map_err(|e| MovementError::Internal(format!("transfer create failed: {}", e)))?;

        let (
            sigma_proof,
            range_proof,
            encrypted_amount_after_transfer,
            encrypted_amount_by_recipient,
            auditors_cb_list,
        ) = confidential_transfer
            .authorize_transfer()
            .await
            .map_err(|e| MovementError::Internal(format!("transfer auth failed: {}", e)))?;

        // Concatenate auditor keys and balances
        let auditor_encryption_keys_bytes: Vec<u8> = auditor_keys
            .iter()
            .flat_map(|k| k.to_bytes().to_vec())
            .collect();
        let auditor_balances_bytes: Vec<u8> = auditors_cb_list
            .iter()
            .flat_map(|cb| cb.get_ciphertext_bytes())
            .collect();

        let transfer_amount_encrypted = confidential_transfer
            .transfer_amount_encrypted_by_sender()
            .get_ciphertext_bytes();

        let module_addr = parse_module_address(&self.confidential_asset_module_address);

        Ok(EntryFunction::new(
            module_id(module_addr),
            "confidential_transfer",
            vec![],
            vec![
                bcs_addr(token_address),
                bcs_addr(recipient),
                serialize_vector_u8(&encrypted_amount_after_transfer.get_ciphertext_bytes()),
                serialize_vector_u8(&transfer_amount_encrypted),
                serialize_vector_u8(&encrypted_amount_by_recipient.get_ciphertext_bytes()),
                serialize_vector_u8(&auditor_encryption_keys_bytes),
                serialize_vector_u8(&auditor_balances_bytes),
                serialize_vector_u8(&range_proof.range_proof_new_balance),
                serialize_vector_u8(&range_proof.range_proof_amount),
                serialize_vector_u8(&ConfidentialTransfer::serialize_sigma_proof(&sigma_proof)),
                serialize_vector_u8(sender_auditor_hint),
            ],
        )
        .into())
    }

    /// Build a `rotate_encryption_key` (or `rotate_encryption_key_and_unfreeze`) entry function payload.
    pub async fn rotate_encryption_key(
        &self,
        sender: &AccountAddress,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        new_sender_decryption_key: &TwistedEd25519PrivateKey,
        token_address: &AccountAddress,
        check_pending_balance_empty: bool,
    ) -> Result<TransactionPayload, MovementError> {
        let chain_id = get_chain_id_byte_for_proofs(self.client).await?;

        let is_frozen = is_pending_balance_frozen(
            self.client,
            sender,
            token_address,
            Some(&self.confidential_asset_module_address),
        )
        .await?;

        let balance = get_balance(
            self.client,
            sender,
            token_address,
            sender_decryption_key,
            Some(&self.confidential_asset_module_address),
        )
        .await?;

        if check_pending_balance_empty && balance.pending_balance() > 0 {
            return Err(MovementError::Internal(
                "Pending balance must be 0 before rotating encryption key".to_string(),
            ));
        }

        let sender_bytes = sender.to_bytes();
        let token_bytes = token_address.to_bytes();
        let contract_address = parse_module_address(&self.confidential_asset_module_address);

        let key_rotation = ConfidentialKeyRotation::create(
            sender_decryption_key.clone(),
            new_sender_decryption_key.clone(),
            balance.available.clone(),
            chain_id,
            &sender_bytes,
            contract_address.as_bytes(),
            &token_bytes,
        );

        let (sigma_proof, range_proof_bytes, new_encrypted_available_balance) = key_rotation
            .authorize_key_rotation()
            .await
            .map_err(|e| MovementError::Internal(format!("key rotation auth failed: {}", e)))?;

        let new_public_key_bytes = new_sender_decryption_key.public_key().to_bytes();
        let method = if is_frozen {
            "rotate_encryption_key_and_unfreeze"
        } else {
            "rotate_encryption_key"
        };

        let module_addr = parse_module_address(&self.confidential_asset_module_address);

        Ok(EntryFunction::new(
            module_id(module_addr),
            method,
            vec![],
            vec![
                bcs_addr(token_address),
                serialize_vector_u8(&new_public_key_bytes),
                serialize_vector_u8(&new_encrypted_available_balance.get_ciphertext_bytes()),
                serialize_vector_u8(&range_proof_bytes),
                serialize_vector_u8(&ConfidentialKeyRotation::serialize_sigma_proof(
                    &sigma_proof,
                )),
            ],
        )
        .into())
    }

    /// Get the asset auditor encryption key for a token, if set.
    pub async fn get_asset_auditor_encryption_key(
        &self,
        token_address: &AccountAddress,
    ) -> Result<Option<TwistedEd25519PublicKey>, MovementError> {
        get_global_auditor_encryption_key(
            self.client,
            token_address,
            Some(&self.confidential_asset_module_address),
        )
        .await
    }

    /// Build a `normalize_balance` entry function payload.
    pub async fn normalize_balance(
        &self,
        sender: &AccountAddress,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        token_address: &AccountAddress,
    ) -> Result<TransactionPayload, MovementError> {
        let chain_id = get_chain_id_byte_for_proofs(self.client).await?;

        let balance = get_balance(
            self.client,
            sender,
            token_address,
            sender_decryption_key,
            Some(&self.confidential_asset_module_address),
        )
        .await?;

        let sender_bytes = sender.to_bytes();
        let token_bytes = token_address.to_bytes();
        let contract_address = parse_module_address(&self.confidential_asset_module_address);

        let normalization = ConfidentialNormalization::create(
            sender_decryption_key.clone(),
            balance.available.clone(),
            chain_id,
            &sender_bytes,
            contract_address.as_bytes(),
            &token_bytes,
        );

        let sigma_proof = normalization.gen_sigma_proof();
        let range_proof_bytes = normalization
            .gen_range_proof()
            .await
            .map_err(|e| MovementError::Internal(format!("normalize range proof failed: {}", e)))?;
        let new_balance = normalization
            .normalized_encrypted_available_balance()
            .clone();

        let module_addr = parse_module_address(&self.confidential_asset_module_address);
        Ok(EntryFunction::new(
            module_id(module_addr),
            "normalize",
            vec![],
            vec![
                bcs_addr(token_address),
                serialize_vector_u8(&new_balance.get_ciphertext_bytes()),
                serialize_vector_u8(&range_proof_bytes),
                serialize_vector_u8(&ConfidentialNormalization::serialize_sigma_proof(
                    &sigma_proof,
                )),
            ],
        )
        .into())
    }
}
