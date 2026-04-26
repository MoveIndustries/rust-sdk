// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0
use crate::crypto::h_ristretto;
use crate::crypto::twisted_ed25519::{TwistedEd25519PrivateKey, TwistedEd25519PublicKey};
use crate::utils::ed25519_gen_random;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
/// Twisted ElGamal ciphertext (Movement TS convention): `C = v*G + r*H`, `D = r*PK`.
#[derive(Clone, Debug)]
pub struct TwistedElGamalCiphertext {
    /// C = v*G + r*H  (the "left" component)
    pub c: RistrettoPoint,
    /// D = r*PK  (the "right" component)
    pub d: RistrettoPoint,
}
impl TwistedElGamalCiphertext {
    pub fn new(c: RistrettoPoint, d: RistrettoPoint) -> Self {
        Self { c, d }
    }
    /// Get the C component bytes (32 bytes).
    pub fn c_bytes(&self) -> [u8; 32] {
        self.c.compress().to_bytes()
    }
    /// Get the D component bytes (32 bytes).
    pub fn d_bytes(&self) -> [u8; 32] {
        self.d.compress().to_bytes()
    }
    /// Serialize ciphertext as C || D (64 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.c_bytes());
        out.extend_from_slice(&self.d_bytes());
        out
    }
    /// Deserialize ciphertext from C || D (64 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 64 {
            return Err(format!("Expected 64 bytes, got {}", bytes.len()));
        }
        let c_bytes: [u8; 32] = bytes[0..32].try_into().map_err(|_| "slice error")?;
        let d_bytes: [u8; 32] = bytes[32..64].try_into().map_err(|_| "slice error")?;
        use curve25519_dalek::ristretto::CompressedRistretto;
        let c = CompressedRistretto(c_bytes)
            .decompress()
            .ok_or("Invalid C point")?;
        let d = CompressedRistretto(d_bytes)
            .decompress()
            .ok_or("Invalid D point")?;
        Ok(Self { c, d })
    }
}
/// Twisted ElGamal encryption/decryption operations.
pub struct TwistedElGamal;
impl TwistedElGamal {
    /// Encrypt a scalar value v under a public key.
    /// Returns ciphertext (C, D) where C = r*G + v*H, D = r*PK.
    pub fn encrypt_with_pk(
        value: Scalar,
        public_key: &TwistedEd25519PublicKey,
    ) -> TwistedElGamalCiphertext {
        let r = ed25519_gen_random();
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = h_ristretto();
        let c = value * g + r * h;
        let d = r * public_key.as_point();
        TwistedElGamalCiphertext::new(c, d)
    }
    /// Encrypt a single ciphertext for one chunk.
    pub fn encrypt_chunk(
        value: Scalar,
        public_key: &TwistedEd25519PublicKey,
        r: Scalar,
    ) -> TwistedElGamalCiphertext {
        let g = RISTRETTO_BASEPOINT_POINT;
        let h = h_ristretto();
        let c = value * g + r * h;
        let d = r * public_key.as_point();
        TwistedElGamalCiphertext::new(c, d)
    }
    /// Compute `m*G` for the ciphertext: matches TS `calculateCiphertextMG` (`C - s*D`).
    /// The result is a Ristretto point whose discrete log w.r.t. G is the chunk plaintext.
    pub fn calculate_ciphertext_mg(
        ciphertext: &TwistedElGamalCiphertext,
        private_key: &TwistedEd25519PrivateKey,
    ) -> RistrettoPoint {
        let s = private_key.as_scalar();
        ciphertext.c - s * ciphertext.d
    }

    /// Recover the plaintext value of a chunk via the upstream Pollard kangaroo.
    /// Uses `Kangaroo32` which matches the TS SDK's chunk DLP table.
    pub fn decrypt_chunk_with_pk(
        ciphertext: &TwistedElGamalCiphertext,
        private_key: &TwistedEd25519PrivateKey,
    ) -> Result<u64, String> {
        use pollard_kangaroo::kangaroo::{Kangaroo, presets::Presets};
        let mg = Self::calculate_ciphertext_mg(ciphertext, private_key);
        let mg_bytes = mg.compress().to_bytes();
        let ng_pt = curve25519_dalek_ng::ristretto::CompressedRistretto(mg_bytes)
            .decompress()
            .ok_or_else(|| "kangaroo: invalid mG point".to_string())?;
        let kangaroo = Kangaroo::from_preset(Presets::Kangaroo32)
            .map_err(|e| format!("kangaroo init: {:?}", e))?;
        kangaroo
            .solve_dlp(&ng_pt, None)
            .map_err(|e| format!("kangaroo solve: {:?}", e))?
            .ok_or_else(|| "kangaroo: no solution found".to_string())
    }

    /// Legacy point-returning decryption (returns `v*G`); kept for callers that
    /// handle DLP themselves. Equivalent to `calculate_ciphertext_mg`.
    pub fn decrypt_with_pk(
        ciphertext: &TwistedElGamalCiphertext,
        private_key: &TwistedEd25519PrivateKey,
    ) -> RistrettoPoint {
        // Movement TS convention: C = v*G + r*H, D = r*PK, PK = (1/s)*H.
        // s*D = s*r*(1/s)*H = r*H, so C - s*D = v*G.
        let s = private_key.as_scalar();
        ciphertext.c - s * ciphertext.d
    }
    /// Homomorphic addition of two ciphertexts.
    pub fn add(
        a: &TwistedElGamalCiphertext,
        b: &TwistedElGamalCiphertext,
    ) -> TwistedElGamalCiphertext {
        TwistedElGamalCiphertext::new(a.c + b.c, a.d + b.d)
    }
    /// Homomorphic subtraction of two ciphertexts.
    pub fn sub(
        a: &TwistedElGamalCiphertext,
        b: &TwistedElGamalCiphertext,
    ) -> TwistedElGamalCiphertext {
        TwistedElGamalCiphertext::new(a.c - b.c, a.d - b.d)
    }
    // Re-encrypt a ciphertext under a new public key (for key rotation).
    // Given C = r*G + v*H, D = r*old_pk
    // New: C' = C + r'*G, D' = D + r'*new_pk
    // Wait, that's not quite right. For key rotation we need:
    // C stays the same (amount doesn't change)
    // D' = r * new_pk
    // But we don't know r. So we use:
    // C' = C + delta_r * G  (but then we change the randomness)
    // Actually the TS code does it differently.
    //
    // For re-keying: new_D = old_D + (old_pk_inv * new_pk - 1) * ...
    // Actually, the simplest approach: we know dk_old, we decrypt v*H, then re-encrypt.
    // But that loses the homomorphic property.
    //
    // The actual key rotation in the TS code:
    // It creates new randomness and re-encrypts from the decrypted value.
    // See confidential_key_rotation.ts for the actual logic.
}
