// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0
use super::h_ristretto;
use crate::utils::ed25519_gen_random;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
/// Twisted Ed25519 private key (a Ristretto scalar).
#[derive(Clone, Debug)]
pub struct TwistedEd25519PrivateKey {
    scalar: Scalar,
}
/// Twisted Ed25519 public key (a Ristretto point).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwistedEd25519PublicKey {
    point: RistrettoPoint,
}
/// Derivation message used to derive a confidential decryption key from an account signature.
pub const DECRYPTION_KEY_DERIVATION_MESSAGE: &[u8] =
    b"MovementConfidentialAsset::DecryptionKeyDerivation";
impl TwistedEd25519PrivateKey {
    /// Generate a new random private key.
    pub fn generate() -> Self {
        Self {
            scalar: ed25519_gen_random(),
        }
    }
    /// Create from raw 32-byte LE scalar bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            scalar: Scalar::from_bytes_mod_order(*bytes),
        }
    }
    /// Create from a Scalar directly.
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self { scalar }
    }
    /// Get the corresponding public key.
    ///
    /// Matches Movement TS: `pk = s⁻¹ · H` with fixed `H` (`h_ristretto` / `HASH_BASE_POINT`),
    /// not `s · G`.
    pub fn public_key(&self) -> TwistedEd25519PublicKey {
        let inv = self.scalar.invert();
        TwistedEd25519PublicKey {
            point: h_ristretto() * inv,
        }
    }
    /// Get the raw scalar reference.
    pub fn as_scalar(&self) -> &Scalar {
        &self.scalar
    }
    /// Get the scalar as bytes (32 bytes LE).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }
}
impl TwistedEd25519PublicKey {
    /// Create from raw 32-byte compressed Ristretto point bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, String> {
        use curve25519_dalek::ristretto::CompressedRistretto;
        let compressed = CompressedRistretto(*bytes);
        let point = compressed
            .decompress()
            .ok_or("Invalid Ristretto point bytes")?;
        Ok(Self { point })
    }
    /// Create from a RistrettoPoint directly.
    pub fn from_point(point: RistrettoPoint) -> Self {
        Self { point }
    }
    /// Get the underlying Ristretto point.
    pub fn as_point(&self) -> &RistrettoPoint {
        &self.point
    }
    /// Get compressed bytes (32 bytes).
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.compress().to_bytes()
    }
    /// Get raw bytes as `Vec<u8>`.
    pub fn to_uint8_array(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
}
