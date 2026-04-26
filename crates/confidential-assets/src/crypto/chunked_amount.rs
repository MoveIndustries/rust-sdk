// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

/// Bits per chunk (matches TS `CHUNK_BITS`).
pub const CHUNK_BITS: u32 = 16;
/// Number of chunks for confidential **balance** (TS `AVAILABLE_BALANCE_CHUNK_COUNT`).
pub const AVAILABLE_BALANCE_CHUNK_COUNT: usize = 8;
/// Number of chunks for transfer / withdraw amount (TS `TRANSFER_AMOUNT_CHUNK_COUNT`).
pub const TRANSFER_AMOUNT_CHUNK_COUNT: usize = AVAILABLE_BALANCE_CHUNK_COUNT / 2;
/// Maximum plaintext transfer amount: `2^(TRANSFER_AMOUNT_CHUNK_COUNT * CHUNK_BITS) - 1`.
pub const MAX_CONFIDENTIAL_TRANSFER_PLAINTEXT: u128 =
    (1u128 << (TRANSFER_AMOUNT_CHUNK_COUNT as u32 * CHUNK_BITS)) - 1;

const CHUNK_MASK: u128 = (1u128 << CHUNK_BITS) - 1;

/// Chunked amount matching the TypeScript `ChunkedAmount` layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkedAmount {
    chunks: Vec<u64>,
}

impl ChunkedAmount {
    fn amount_to_chunks(amount: u128, chunks_count: usize) -> Vec<u64> {
        let mut chunks = Vec::with_capacity(chunks_count);
        for i in 0..chunks_count {
            let shift = CHUNK_BITS * (i as u32);
            let chunk = ((amount >> shift) & CHUNK_MASK) as u64;
            chunks.push(chunk);
        }
        chunks
    }

    /// Balance: default 8 chunks × 16 bits (fits `u128`).
    pub fn from_amount(amount: u128) -> Self {
        Self {
            chunks: Self::amount_to_chunks(amount, AVAILABLE_BALANCE_CHUNK_COUNT),
        }
    }

    /// Transfer / withdraw amount: 4 chunks × 16 bits.
    pub fn from_transfer_amount(amount: u128) -> Self {
        Self {
            chunks: Self::amount_to_chunks(amount, TRANSFER_AMOUNT_CHUNK_COUNT),
        }
    }

    pub fn from_amount_with_chunks(amount: u128, chunk_count: usize) -> Self {
        Self {
            chunks: Self::amount_to_chunks(amount, chunk_count),
        }
    }

    pub fn from_chunks(chunks: Vec<u64>) -> Self {
        Self { chunks }
    }

    pub fn from_raw_chunks(chunks: Vec<u64>) -> Self {
        Self { chunks }
    }

    pub fn from_bigint_chunks(chunks: Vec<curve25519_dalek::scalar::Scalar>) -> Self {
        let u64_chunks: Vec<u64> = chunks
            .iter()
            .map(|s| {
                let b = s.to_bytes();
                u64::from_le_bytes(b[0..8].try_into().unwrap()) & (CHUNK_MASK as u64)
            })
            .collect();
        Self { chunks: u64_chunks }
    }

    pub fn chunks(&self) -> &[u64] {
        &self.chunks
    }

    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// Reconstruct `u128` from chunks: `sum_i chunk[i] * 2^(CHUNK_BITS * i)`.
    pub fn to_amount(&self) -> u128 {
        let mut result: u128 = 0;
        for (i, &chunk) in self.chunks.iter().enumerate() {
            result |= (chunk as u128) << (CHUNK_BITS * (i as u32));
        }
        result
    }

    pub fn to_scalars(&self) -> Vec<curve25519_dalek::scalar::Scalar> {
        use curve25519_dalek::scalar::Scalar;
        self.chunks.iter().map(|&v| Scalar::from(v)).collect()
    }
}
