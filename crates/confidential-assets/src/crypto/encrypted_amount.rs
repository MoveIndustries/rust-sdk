// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0
use crate::crypto::chunked_amount::ChunkedAmount;
use crate::crypto::twisted_ed25519::{TwistedEd25519PrivateKey, TwistedEd25519PublicKey};
use crate::crypto::twisted_el_gamal::{TwistedElGamal, TwistedElGamalCiphertext};
use crate::utils::ed25519_gen_random;
use curve25519_dalek::scalar::Scalar;
/// Encrypted amount: holds chunked ciphertexts and can decrypt to get the amount.
#[derive(Clone, Debug)]
pub struct EncryptedAmount {
    chunked_amount: ChunkedAmount,
    ciphertext: Vec<TwistedElGamalCiphertext>,
    public_key: TwistedEd25519PublicKey,
    /// Randomness used per chunk (needed for proof generation).
    randomness: Vec<Scalar>,
}
impl EncryptedAmount {
    /// Create a new encrypted amount from a chunked amount and public key.
    pub fn new(chunked_amount: ChunkedAmount, public_key: TwistedEd25519PublicKey) -> Self {
        let randomness: Vec<Scalar> = (0..chunked_amount.len())
            .map(|_| ed25519_gen_random())
            .collect();
        Self::new_with_randomness(chunked_amount, public_key, randomness)
            .expect("generated randomness length matches chunks")
    }

    /// Encrypt with caller-provided randomness (length must be ≥ chunk count; only first `chunked.len()` used).
    pub fn new_with_randomness(
        chunked_amount: ChunkedAmount,
        public_key: TwistedEd25519PublicKey,
        randomness: Vec<Scalar>,
    ) -> Result<Self, String> {
        if randomness.len() < chunked_amount.len() {
            return Err(format!(
                "randomness length {} < chunk count {}",
                randomness.len(),
                chunked_amount.len()
            ));
        }
        let scalars = chunked_amount.to_scalars();
        let ciphertext: Vec<TwistedElGamalCiphertext> = scalars
            .iter()
            .zip(randomness.iter().take(chunked_amount.len()))
            .map(|(v, r)| TwistedElGamal::encrypt_chunk(*v, &public_key, *r))
            .collect();
        Ok(Self {
            chunked_amount,
            ciphertext,
            public_key,
            randomness,
        })
    }
    /// Create from amount and public key (for balance, 4 chunks).
    pub fn from_amount_and_public_key(amount: u128, public_key: &TwistedEd25519PublicKey) -> Self {
        let chunked = ChunkedAmount::from_amount(amount);
        Self::new(chunked, public_key.clone())
    }
    /// Create from ciphertext and private key by recovering each chunk via the
    /// upstream Pollard kangaroo. Per-chunk randomness is unknown after decryption,
    /// so the returned `EncryptedAmount` carries `Scalar::ZERO` randomness — only
    /// the chunk plaintexts are valid for downstream sigma-prover use.
    pub fn from_ciphertext_and_decryption_key(
        ciphertext: &[TwistedElGamalCiphertext],
        private_key: &TwistedEd25519PrivateKey,
    ) -> Result<Self, String> {
        let mut chunks: Vec<u64> = Vec::with_capacity(ciphertext.len());
        for ct in ciphertext {
            chunks.push(TwistedElGamal::decrypt_chunk_with_pk(ct, private_key)?);
        }
        let chunked_amount = crate::crypto::chunked_amount::ChunkedAmount::from_raw_chunks(chunks);
        let randomness = vec![Scalar::ZERO; ciphertext.len()];
        let public_key = private_key.public_key();
        Ok(Self {
            chunked_amount,
            ciphertext: ciphertext.to_vec(),
            public_key,
            randomness,
        })
    }
    /// Get the decrypted amount (only works if chunked_amount is already known).
    pub fn get_amount(&self) -> u128 {
        self.chunked_amount.to_amount()
    }
    /// Get the ciphertext.
    pub fn get_ciphertext(&self) -> &[TwistedElGamalCiphertext] {
        &self.ciphertext
    }
    /// Get the ciphertext bytes (all chunks concatenated).
    pub fn get_ciphertext_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for ct in &self.ciphertext {
            out.extend_from_slice(&ct.to_bytes());
        }
        out
    }
    /// Concatenate D points only (32 bytes per chunk), matching TS `getCipherTextDPointBytes`.
    pub fn get_ciphertext_d_point_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for ct in &self.ciphertext {
            out.extend_from_slice(&ct.d_bytes());
        }
        out
    }
    /// Plaintext chunk values as scalars (matches TS `getAmountChunks` used in sigma proofs).
    pub fn amount_chunks_as_scalars(&self) -> Vec<Scalar> {
        self.chunked_amount
            .chunks()
            .iter()
            .map(|&c| Scalar::from(c))
            .collect()
    }
    /// Get the chunked amount.
    pub fn chunked_amount(&self) -> &ChunkedAmount {
        &self.chunked_amount
    }
    /// Get the randomness used for encryption.
    pub fn randomness(&self) -> &[Scalar] {
        &self.randomness
    }
    /// Get the public key.
    pub fn public_key(&self) -> &TwistedEd25519PublicKey {
        &self.public_key
    }

    /// Rebuild an encrypted amount from existing ciphertext limbs (e.g. TS-generated fixtures).
    ///
    /// Chunk plaintext values are set to zero; sigma **verification** only uses curve points from
    /// `ciphertext`, not these placeholders.
    pub fn from_ciphertext_vec_for_verification(
        ciphertext: Vec<TwistedElGamalCiphertext>,
        public_key: TwistedEd25519PublicKey,
    ) -> Result<Self, String> {
        let n = ciphertext.len();
        if n == 0 {
            return Err("empty ciphertext".into());
        }
        let chunked_amount = ChunkedAmount::from_raw_chunks(vec![0u64; n]);
        let randomness = vec![Scalar::ZERO; n];
        Ok(Self {
            chunked_amount,
            ciphertext,
            public_key,
            randomness,
        })
    }
}
