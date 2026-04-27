//! Twisted Ed25519 encryption keys (Ristretto255 scalar).
//!
//! Used by Movement confidential assets and adjacent protocols. The private key is a
//! Ristretto255 scalar `s`; the corresponding public ("encryption") key is `pk = s⁻¹·H`
//! where `H` is the domain-separated secondary generator
//! [`H_RISTRETTO_COMPRESSED`] (= TS `HASH_BASE_POINT`, also the on-chain constant).
//!
//! This is **not** an Ed25519 signing key. It produces no signatures; it's a key for the
//! Twisted `ElGamal` encryption scheme used by confidential-assets et al.
//!
//! # Security
//!
//! The private key zeroizes on drop (`curve25519-dalek` `Scalar` implements `Zeroize`)
//! and has a redacted `Debug` impl so accidental logging never leaks key bytes.

use crate::error::{MovementError, MovementResult};
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use std::fmt;
use zeroize::Zeroize;

/// Length, in bytes, of a Twisted Ed25519 private key (a Ristretto255 scalar).
pub const TWISTED_ED25519_PRIVATE_KEY_LENGTH: usize = 32;
/// Length, in bytes, of a Twisted Ed25519 public key (a compressed Ristretto255 point).
pub const TWISTED_ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Domain string signed by an account's Ed25519 key to derive a deterministic
/// confidential decryption key.
pub const DECRYPTION_KEY_DERIVATION_MESSAGE: &[u8] =
    b"MovementConfidentialAsset::DecryptionKeyDerivation";

/// Compressed encoding of the secondary generator **H** for Twisted `ElGamal` /
/// Twisted Ed25519. Matches TS `HASH_BASE_POINT` and the on-chain constant.
pub const H_RISTRETTO_COMPRESSED: [u8; TWISTED_ED25519_PUBLIC_KEY_LENGTH] = [
    0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc, 0x65, 0xc3, 0x77, 0xa1, 0x04, 0x8d, 0x74, 0x5f,
    0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd, 0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34,
];

/// Decompressed form of [`H_RISTRETTO_COMPRESSED`].
///
/// # Panics
///
/// Never in practice: [`H_RISTRETTO_COMPRESSED`] is a hard-coded canonical Ristretto255
/// encoding. The `expect` is a build-time invariant; the `tests::h_matches_compressed_constant`
/// test pins it.
pub fn h_ristretto() -> RistrettoPoint {
    CompressedRistretto(H_RISTRETTO_COMPRESSED)
        .decompress()
        .expect("H_RISTRETTO_COMPRESSED is a valid Ristretto encoding")
}

/// A Twisted Ed25519 private key (Ristretto255 scalar).
///
/// The private key is zeroized when dropped to prevent sensitive data from
/// remaining in memory, and `Debug` is redacted to avoid accidental leaks.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct TwistedEd25519PrivateKey {
    scalar: Scalar,
}

impl TwistedEd25519PrivateKey {
    /// Generates a new random private key from `OsRng`.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 64];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let scalar = Scalar::from_bytes_mod_order_wide(&bytes);
        bytes.zeroize();
        Self { scalar }
    }

    /// Creates a private key from raw bytes (32 bytes, little-endian, reduced mod
    /// the Ristretto255 group order).
    ///
    /// # Errors
    ///
    /// Returns [`MovementError::InvalidPrivateKey`] if the byte slice length is
    /// not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> MovementResult<Self> {
        if bytes.len() != TWISTED_ED25519_PRIVATE_KEY_LENGTH {
            return Err(MovementError::InvalidPrivateKey(format!(
                "expected {} bytes, got {}",
                TWISTED_ED25519_PRIVATE_KEY_LENGTH,
                bytes.len()
            )));
        }
        let mut buf = [0u8; TWISTED_ED25519_PRIVATE_KEY_LENGTH];
        buf.copy_from_slice(bytes);
        let scalar = Scalar::from_bytes_mod_order(buf);
        // SECURITY: zeroize the temporary buffer that held private key material.
        buf.zeroize();
        Ok(Self { scalar })
    }

    /// Creates a private key from a hex string (with or without `0x` prefix).
    ///
    /// # Errors
    ///
    /// Returns [`MovementError::Hex`] if the hex string is invalid, or
    /// [`MovementError::InvalidPrivateKey`] if the decoded length is not 32 bytes.
    pub fn from_hex(hex_str: &str) -> MovementResult<Self> {
        let bytes = const_hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Wraps an existing Ristretto255 scalar as a private key.
    pub fn from_scalar(scalar: Scalar) -> Self {
        Self { scalar }
    }

    /// Returns the corresponding encryption (public) key, `pk = s⁻¹·H`.
    pub fn public_key(&self) -> TwistedEd25519PublicKey {
        TwistedEd25519PublicKey {
            point: h_ristretto() * self.scalar.invert(),
        }
    }

    /// Borrows the underlying scalar for σ-protocol provers.
    pub fn as_scalar(&self) -> &Scalar {
        &self.scalar
    }

    /// Returns the private key as 32 little-endian bytes.
    ///
    /// **Warning**: handle the returned bytes carefully to avoid leaking
    /// sensitive key material.
    pub fn to_bytes(&self) -> [u8; TWISTED_ED25519_PRIVATE_KEY_LENGTH] {
        self.scalar.to_bytes()
    }

    /// Returns the private key as a hex string (lowercase, `0x`-prefixed).
    ///
    /// **Warning**: handle the returned string carefully — it contains private
    /// key material in plaintext.
    pub fn to_hex(&self) -> String {
        const_hex::encode_prefixed(self.to_bytes())
    }
}

impl fmt::Debug for TwistedEd25519PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TwistedEd25519PrivateKey([REDACTED])")
    }
}

/// A Twisted Ed25519 public (encryption) key — a Ristretto255 point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwistedEd25519PublicKey {
    point: RistrettoPoint,
}

impl TwistedEd25519PublicKey {
    /// Decodes a public key from a 32-byte compressed Ristretto255 encoding.
    ///
    /// # Errors
    ///
    /// Returns [`MovementError::InvalidPublicKey`] if the bytes are not a valid
    /// canonical Ristretto255 encoding.
    pub fn from_bytes(bytes: &[u8; TWISTED_ED25519_PUBLIC_KEY_LENGTH]) -> MovementResult<Self> {
        let point = CompressedRistretto(*bytes)
            .decompress()
            .ok_or_else(|| MovementError::InvalidPublicKey("invalid Ristretto encoding".into()))?;
        Ok(Self { point })
    }

    /// Wraps an existing Ristretto255 point as a public key.
    pub fn from_point(point: RistrettoPoint) -> Self {
        Self { point }
    }

    /// Borrows the underlying Ristretto255 point.
    pub fn as_point(&self) -> &RistrettoPoint {
        &self.point
    }

    /// Returns the public key as 32 compressed Ristretto255 bytes.
    pub fn to_bytes(&self) -> [u8; TWISTED_ED25519_PUBLIC_KEY_LENGTH] {
        self.point.compress().to_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn h_matches_compressed_constant() {
        assert_eq!(h_ristretto().compress().to_bytes(), H_RISTRETTO_COMPRESSED);
    }

    #[test]
    fn debug_is_redacted() {
        let key = TwistedEd25519PrivateKey::generate();
        let debug = format!("{key:?}");
        assert!(
            debug.contains("REDACTED"),
            "private-key Debug must be redacted, got: {debug}"
        );
        // Bytes must not appear in any rendering.
        let hex = key.to_hex();
        let stripped = hex.trim_start_matches("0x");
        assert!(
            !debug.contains(stripped),
            "private-key Debug must not contain key bytes"
        );
    }

    #[test]
    fn from_bytes_length_check() {
        assert!(TwistedEd25519PrivateKey::from_bytes(&[0u8; 31]).is_err());
        assert!(TwistedEd25519PrivateKey::from_bytes(&[0u8; 33]).is_err());
        assert!(TwistedEd25519PrivateKey::from_bytes(&[0u8; 32]).is_ok());
    }

    #[test]
    fn roundtrip_bytes() {
        let key = TwistedEd25519PrivateKey::generate();
        let bytes = key.to_bytes();
        let key2 = TwistedEd25519PrivateKey::from_bytes(&bytes).expect("32 bytes");
        assert_eq!(key.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn public_key_decodes_canonical_only() {
        let pk = TwistedEd25519PrivateKey::generate().public_key();
        let bytes = pk.to_bytes();
        assert!(TwistedEd25519PublicKey::from_bytes(&bytes).is_ok());
        // 0xff..ff is not a canonical Ristretto encoding.
        assert!(TwistedEd25519PublicKey::from_bytes(&[0xffu8; 32]).is_err());
    }
}
