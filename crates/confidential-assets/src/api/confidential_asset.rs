// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! High-level confidential asset API.
//!
//! Mirrors the TS SDK's `confidentialAsset.ts`. Wraps the transaction builder
//! and view functions into a convenient interface that returns `TransactionPayload`
//! ready for `movement.sign_and_submit()`.
//!

use crate::crypto::{TwistedEd25519PrivateKey, TwistedEd25519PublicKey};
use crate::internal::transaction_builder::ConfidentialAssetTransactionBuilder;
use crate::internal::view_functions::{
    ConfidentialBalance, get_balance, get_encryption_key, get_global_auditor_encryption_key,
    is_balance_normalized, is_pending_balance_frozen,
};
use movement_sdk::account::Account;
use movement_sdk::{
    Movement, MovementError, transaction::payload::TransactionPayload, types::AccountAddress,
};

/// High-level API for confidential asset operations.
///
/// This struct wraps the transaction builder and provides methods corresponding
/// to each confidential asset operation (register, deposit, withdraw, transfer, etc.).
///
/// Transaction submission is done via `movement.sign_and_submit()` using the returned payloads.
pub struct ConfidentialAsset<'a> {
    pub transaction: ConfidentialAssetTransactionBuilder<'a>,
    pub with_fee_payer: bool,
}

impl<'a> ConfidentialAsset<'a> {
    pub fn new(
        client: &'a Movement,
        confidential_asset_module_address: Option<&str>,
        with_fee_payer: bool,
    ) -> Self {
        Self {
            transaction: ConfidentialAssetTransactionBuilder::new(
                client,
                confidential_asset_module_address,
            ),
            with_fee_payer,
        }
    }

    /// Get the confidential balance for an account.
    pub async fn get_balance(
        &self,
        account_address: &AccountAddress,
        token_address: &AccountAddress,
        decryption_key: &TwistedEd25519PrivateKey,
    ) -> Result<ConfidentialBalance, MovementError> {
        get_balance(
            self.transaction.client,
            account_address,
            token_address,
            decryption_key,
            Some(&self.transaction.confidential_asset_module_address),
        )
        .await
    }

    /// Build a register balance transaction.
    pub async fn register_balance(
        &self,
        sender: &AccountAddress,
        token_address: &AccountAddress,
        decryption_key: &TwistedEd25519PrivateKey,
    ) -> Result<TransactionPayload, MovementError> {
        self.transaction
            .register_balance(sender, token_address, decryption_key)
            .await
    }

    /// Build a deposit transaction.
    pub fn deposit(
        &self,
        sender: &AccountAddress,
        token_address: &AccountAddress,
        amount: u64,
        recipient: Option<&AccountAddress>,
    ) -> Result<TransactionPayload, MovementError> {
        self.transaction
            .deposit(sender, token_address, amount, recipient)
    }

    /// Build a withdraw transaction.
    pub async fn withdraw(
        &self,
        sender: &AccountAddress,
        token_address: &AccountAddress,
        amount: u64,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        recipient: Option<&AccountAddress>,
    ) -> Result<TransactionPayload, MovementError> {
        self.transaction
            .withdraw(
                sender,
                token_address,
                amount,
                sender_decryption_key,
                recipient,
            )
            .await
    }

    /// Build a transfer transaction.
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
        self.transaction
            .transfer(
                sender,
                recipient,
                token_address,
                amount,
                sender_decryption_key,
                additional_auditor_encryption_keys,
                sender_auditor_hint,
            )
            .await
    }

    /// Build payloads to withdraw using the sender's total (available + pending) balance.
    ///
    /// Mirrors the TS `withdrawWithTotalBalance`: if `available < amount`, auto-rollover
    /// (which itself normalizes if needed) before building the withdraw.
    /// Withdraw using the sender's total (available + pending) balance.
    ///
    /// Mirrors the TS `withdrawWithTotalBalance`: if `available < amount`, the rollover
    /// transactions are submitted **internally** (via `signer`), then the final withdraw
    /// payload is built against the rolled-over on-chain state and returned for the caller
    /// to sign and submit. The intermediate rollover requires waiting for inclusion
    /// because the withdraw σ-proof is bound to the on-chain ciphertext.
    pub async fn withdraw_with_total_balance<A: Account>(
        &self,
        signer: &A,
        token_address: &AccountAddress,
        amount: u64,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        recipient: Option<&AccountAddress>,
    ) -> Result<TransactionPayload, MovementError> {
        self.rollover_if_insufficient(signer, token_address, amount, sender_decryption_key)
            .await?;

        self.transaction
            .withdraw(
                &signer.address(),
                token_address,
                amount,
                sender_decryption_key,
                recipient,
            )
            .await
    }

    /// Transfer using the sender's total (available + pending) balance.
    ///
    /// Mirrors the TS `transferWithTotalBalance`: if `available < amount`, the rollover
    /// transactions are submitted internally (via `signer`), then the final transfer
    /// payload is built against the rolled-over on-chain state and returned.
    pub async fn transfer_with_total_balance<A: Account>(
        &self,
        signer: &A,
        recipient: &AccountAddress,
        token_address: &AccountAddress,
        amount: u64,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        additional_auditor_encryption_keys: &[TwistedEd25519PublicKey],
        sender_auditor_hint: &[u8],
    ) -> Result<TransactionPayload, MovementError> {
        self.rollover_if_insufficient(signer, token_address, amount, sender_decryption_key)
            .await?;

        self.transaction
            .transfer(
                &signer.address(),
                recipient,
                token_address,
                amount,
                sender_decryption_key,
                additional_auditor_encryption_keys,
                sender_auditor_hint,
            )
            .await
    }

    /// Check `available + pending`; if available is short, submit rollover transactions
    /// (so the chain reflects the rolled-over state) before the caller builds withdraw/transfer.
    async fn rollover_if_insufficient<A: Account>(
        &self,
        signer: &A,
        token_address: &AccountAddress,
        amount: u64,
        sender_decryption_key: &TwistedEd25519PrivateKey,
    ) -> Result<(), MovementError> {
        let sender = signer.address();
        let balance = self
            .get_balance(&sender, token_address, sender_decryption_key)
            .await?;
        let amount_u128 = amount as u128;
        if balance.available_balance() >= amount_u128 {
            return Ok(());
        }
        if balance.available_balance() + balance.pending_balance() < amount_u128 {
            return Err(MovementError::Internal(format!(
                "Insufficient balance. Pending balance - {}, Available balance - {}",
                balance.pending_balance(),
                balance.available_balance()
            )));
        }
        let rollover = self
            .rollover_pending_balance(&sender, token_address, Some(sender_decryption_key), false)
            .await?;
        for payload in rollover {
            self.transaction
                .client
                .sign_submit_and_wait(signer, payload, None)
                .await?;
        }
        Ok(())
    }

    /// Build a rollover pending balance transaction (may also normalize first).
    pub async fn rollover_pending_balance(
        &self,
        sender: &AccountAddress,
        token_address: &AccountAddress,
        sender_decryption_key: Option<&TwistedEd25519PrivateKey>,
        with_freeze_balance: bool,
    ) -> Result<Vec<TransactionPayload>, MovementError> {
        let mut payloads = Vec::new();

        // Check if normalization is needed
        let is_norm = is_balance_normalized(
            self.transaction.client,
            sender,
            token_address,
            Some(&self.transaction.confidential_asset_module_address),
        )
        .await?;

        if !is_norm {
            let dk = sender_decryption_key.ok_or_else(|| {
                MovementError::Internal("Rollover failed. Balance is not normalized and no sender decryption key was provided.".to_string())
            })?;

            let normalize_payload = self
                .transaction
                .normalize_balance(sender, dk, token_address)
                .await?;
            payloads.push(normalize_payload);
        }

        let rollover_payload = self
            .transaction
            .rollover_pending_balance(
                sender,
                token_address,
                with_freeze_balance,
                false, // already checked above
            )
            .await?;
        payloads.push(rollover_payload);

        Ok(payloads)
    }

    /// Build a rotate encryption key transaction (with optional rollover first).
    pub async fn rotate_encryption_key(
        &self,
        sender: &AccountAddress,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        new_sender_decryption_key: &TwistedEd25519PrivateKey,
        token_address: &AccountAddress,
    ) -> Result<Vec<TransactionPayload>, MovementError> {
        let mut payloads = Vec::new();

        // Check if pending balance needs rollover
        let balance = self
            .get_balance(sender, token_address, sender_decryption_key)
            .await?;
        if balance.pending_balance() > 0 {
            let rollover_payloads = self
                .rollover_pending_balance(
                    sender,
                    token_address,
                    Some(sender_decryption_key),
                    true, // freeze after rollover
                )
                .await?;
            payloads.extend(rollover_payloads);
        }

        let rotate_payload = self
            .transaction
            .rotate_encryption_key(
                sender,
                sender_decryption_key,
                new_sender_decryption_key,
                token_address,
                true,
            )
            .await?;
        payloads.push(rotate_payload);

        Ok(payloads)
    }

    /// Build a normalize balance transaction.
    pub async fn normalize_balance(
        &self,
        sender: &AccountAddress,
        sender_decryption_key: &TwistedEd25519PrivateKey,
        token_address: &AccountAddress,
    ) -> Result<TransactionPayload, MovementError> {
        self.transaction
            .normalize_balance(sender, sender_decryption_key, token_address)
            .await
    }

    /// Check if a user has registered a confidential balance.
    pub async fn has_user_registered(
        &self,
        account_address: &AccountAddress,
        token_address: &AccountAddress,
    ) -> Result<bool, MovementError> {
        crate::internal::view_functions::has_user_registered(
            self.transaction.client,
            account_address,
            token_address,
            Some(&self.transaction.confidential_asset_module_address),
        )
        .await
    }

    /// Check if a user's balance is normalized.
    pub async fn is_balance_normalized(
        &self,
        account_address: &AccountAddress,
        token_address: &AccountAddress,
    ) -> Result<bool, MovementError> {
        is_balance_normalized(
            self.transaction.client,
            account_address,
            token_address,
            Some(&self.transaction.confidential_asset_module_address),
        )
        .await
    }

    /// Check if a user's pending balance is frozen.
    pub async fn is_pending_balance_frozen(
        &self,
        account_address: &AccountAddress,
        token_address: &AccountAddress,
    ) -> Result<bool, MovementError> {
        is_pending_balance_frozen(
            self.transaction.client,
            account_address,
            token_address,
            Some(&self.transaction.confidential_asset_module_address),
        )
        .await
    }

    /// Get the encryption key for an account.
    pub async fn get_encryption_key(
        &self,
        account_address: &AccountAddress,
        token_address: &AccountAddress,
    ) -> Result<TwistedEd25519PublicKey, MovementError> {
        get_encryption_key(
            self.transaction.client,
            account_address,
            token_address,
            Some(&self.transaction.confidential_asset_module_address),
        )
        .await
    }

    /// Get the asset auditor encryption key for a token.
    pub async fn get_asset_auditor_encryption_key(
        &self,
        token_address: &AccountAddress,
    ) -> Result<Option<TwistedEd25519PublicKey>, MovementError> {
        get_global_auditor_encryption_key(
            self.transaction.client,
            token_address,
            Some(&self.transaction.confidential_asset_module_address),
        )
        .await
    }
}
