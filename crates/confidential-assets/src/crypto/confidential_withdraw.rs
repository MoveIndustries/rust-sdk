// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::chunked_amount::ChunkedAmount;
use crate::crypto::encrypted_amount::EncryptedAmount;
use crate::crypto::twisted_ed25519::TwistedEd25519PrivateKey;
use crate::crypto::twisted_el_gamal::TwistedElGamalCiphertext;
use crate::crypto::withdraw_protocol::{
    WithdrawSigmaProofWire, WithdrawVerifyParams, gen_withdraw_sigma_proof,
    verify_withdraw_sigma_proof,
};

/// Withdrawal sigma proof (wire format; matches Movement TS).
pub type WithdrawSigmaProof = WithdrawSigmaProofWire;

/// Confidential withdrawal: generates sigma proof + range proof.
pub struct ConfidentialWithdraw {
    decryption_key: TwistedEd25519PrivateKey,
    sender_encrypted_available_balance: EncryptedAmount,
    sender_encrypted_available_balance_after_withdrawal: EncryptedAmount,
    amount: u128,
    chain_id: u8,
    sender_address: Vec<u8>,
    contract_address: Vec<u8>,
    token_address: Vec<u8>,
}

impl ConfidentialWithdraw {
    /// Create a withdrawal context from an encrypted on-chain balance.
    ///
    /// Recovers the sender's cleartext balance from `sender_available_balance_cipher_text`
    /// via the Pollard kangaroo DLP solver, then delegates to [`Self::create_with_balance`].
    /// Mirrors the TS `ConfidentialWithdraw.create` entry point.
    pub async fn create(
        decryption_key: TwistedEd25519PrivateKey,
        sender_available_balance_cipher_text: &[TwistedElGamalCiphertext],
        amount: u128,
        chain_id: u8,
        sender_address: &[u8],
        contract_address: &[u8],
        token_address: &[u8],
    ) -> Result<Self, String> {
        let ea = EncryptedAmount::from_ciphertext_and_decryption_key(
            sender_available_balance_cipher_text,
            &decryption_key,
        )?;
        Self::create_with_balance(
            decryption_key,
            ea.get_amount(),
            sender_available_balance_cipher_text.to_vec(),
            amount,
            chain_id,
            sender_address,
            contract_address,
            token_address,
        )
    }

    /// Create with known balance amount and ciphertext-aligned state.
    // σ-protocol context — each parameter is a distinct cryptographic input.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_balance(
        decryption_key: TwistedEd25519PrivateKey,
        sender_balance_amount: u128,
        sender_balance_ciphertext: Vec<TwistedElGamalCiphertext>,
        amount: u128,
        chain_id: u8,
        sender_address: &[u8],
        contract_address: &[u8],
        token_address: &[u8],
    ) -> Result<Self, String> {
        if amount > sender_balance_amount {
            return Err("Insufficient balance for withdrawal".to_string());
        }
        let pk = decryption_key.public_key();
        let new_balance = sender_balance_amount - amount;
        // Use the on-chain ciphertext as-is for the current balance; re-encrypting with
        // fresh randomness would produce a different ciphertext than what's stored on-chain
        // and the σ-proof transcript would not match the on-chain verifier.
        let current_ea = EncryptedAmount::from_ciphertext_and_decryption_key(
            &sender_balance_ciphertext,
            &decryption_key,
        )?;
        let new_chunked = ChunkedAmount::from_amount(new_balance);
        let new_ea = EncryptedAmount::new(new_chunked, pk.clone());
        Ok(Self {
            decryption_key,
            sender_encrypted_available_balance: current_ea,
            sender_encrypted_available_balance_after_withdrawal: new_ea,
            amount,
            chain_id,
            sender_address: sender_address.to_vec(),
            contract_address: contract_address.to_vec(),
            token_address: token_address.to_vec(),
        })
    }

    /// Generate the sigma proof for the withdrawal (Movement TS–aligned).
    pub fn gen_sigma_proof(&self) -> WithdrawSigmaProof {
        let pk = self.decryption_key.public_key();
        let rnd = self
            .sender_encrypted_available_balance_after_withdrawal
            .randomness();
        let r: [curve25519_dalek::scalar::Scalar; 8] = std::array::from_fn(|i| rnd[i]);
        gen_withdraw_sigma_proof(
            self.decryption_key.as_scalar(),
            &pk,
            &self.sender_encrypted_available_balance,
            &self.sender_encrypted_available_balance_after_withdrawal,
            &r,
            self.amount,
            self.chain_id,
            &self.sender_address,
            &self.contract_address,
            &self.token_address,
        )
    }

    /// Verify a withdrawal sigma proof.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_sigma_proof(
        sender_encrypted_balance: &EncryptedAmount,
        sender_encrypted_balance_after: &EncryptedAmount,
        amount: u128,
        proof: &WithdrawSigmaProof,
        chain_id: u8,
        sender_address: &[u8],
        contract_address: &[u8],
        token_address: &[u8],
    ) -> bool {
        verify_withdraw_sigma_proof(&WithdrawVerifyParams {
            sigma: proof,
            sender_encrypted_balance,
            sender_encrypted_balance_after,
            amount_to_withdraw: amount,
            chain_id,
            sender_address,
            contract_address,
            token_address,
        })
    }

    /// Generate range proof for the new balance.
    pub async fn gen_range_proof(&self) -> Result<Vec<u8>, String> {
        crate::crypto::range_proof::generate_range_proof(
            self.sender_encrypted_available_balance_after_withdrawal
                .get_ciphertext(),
            self.sender_encrypted_available_balance_after_withdrawal
                .chunked_amount()
                .chunks(),
            self.sender_encrypted_available_balance_after_withdrawal
                .randomness(),
        )
    }

    /// Verify range proof.
    pub async fn verify_range_proof(
        range_proof: &[u8],
        sender_encrypted_balance_after: &EncryptedAmount,
    ) -> Result<bool, String> {
        crate::crypto::range_proof::verify_range_proof(
            range_proof,
            sender_encrypted_balance_after.get_ciphertext(),
        )
    }

    /// Serialize sigma proof to bytes.
    pub fn serialize_sigma_proof(proof: &WithdrawSigmaProof) -> Vec<u8> {
        proof.serialize()
    }

    pub fn deserialize_sigma_proof(bytes: &[u8]) -> Result<WithdrawSigmaProof, String> {
        WithdrawSigmaProofWire::deserialize(bytes)
    }

    pub fn sender_encrypted_available_balance(&self) -> &EncryptedAmount {
        &self.sender_encrypted_available_balance
    }

    pub fn sender_encrypted_available_balance_after_withdrawal(&self) -> &EncryptedAmount {
        &self.sender_encrypted_available_balance_after_withdrawal
    }

    pub async fn authorize_withdrawal(
        &self,
    ) -> Result<(WithdrawSigmaProof, Vec<u8>, EncryptedAmount), String> {
        let sigma = self.gen_sigma_proof();
        let range = self.gen_range_proof().await?;
        Ok((
            sigma,
            range,
            self.sender_encrypted_available_balance_after_withdrawal
                .clone(),
        ))
    }
}
