// Tests for ElGamal encryption/decryption
// Ported from non-skipped tests in confidential-assets/tests/units/kangaroo-decryption.test.ts
use confidential_assets::crypto::encrypted_amount::EncryptedAmount;
use confidential_assets::crypto::twisted_ed25519::TwistedEd25519PrivateKey;
use rand::Rng;

fn generate_random_integer(bits: u32) -> u128 {
    let mut rng = rand::thread_rng();
    // `1u128 << bits` is only valid for bits < 128; at 128 bits the range is all u128 values.
    if bits > 128 {
        panic!("generate_random_integer only supports up to 128 bits");
    }
    let max = if bits == 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    };
    rng.gen_range(0..=max)
}

fn execution_balance(bits: u32, length: usize) -> Vec<(u128, u128)> {
    let mut results = Vec::with_capacity(length);
    for _ in 0..length {
        let balance = generate_random_integer(bits);
        let key = TwistedEd25519PrivateKey::generate();
        let pk = key.public_key();
        let encrypted = EncryptedAmount::from_amount_and_public_key(balance, &pk);
        let decrypted = encrypted.get_amount();
        results.push((balance, decrypted));
    }
    results
}

#[test]
fn decrypt_16_bit_amounts() {
    let results = execution_balance(16, 50);
    for (expected, actual) in &results {
        assert_eq!(expected, actual);
    }
}

#[test]
fn decrypt_32_bit_amounts() {
    let results = execution_balance(32, 50);
    for (expected, actual) in &results {
        assert_eq!(expected, actual);
    }
}

#[test]
fn decrypt_48_bit_amounts() {
    let results = execution_balance(48, 50);
    for (expected, actual) in &results {
        assert_eq!(expected, actual);
    }
}

#[test]
fn decrypt_64_bit_amounts() {
    let results = execution_balance(64, 50);
    for (expected, actual) in &results {
        assert_eq!(expected, actual);
    }
}

#[test]
fn decrypt_96_bit_amounts() {
    let results = execution_balance(96, 50);
    for (expected, actual) in &results {
        assert_eq!(expected, actual);
    }
}

#[test]
fn decrypt_128_bit_amounts() {
    let results = execution_balance(128, 50);
    for (expected, actual) in &results {
        assert_eq!(expected, actual);
    }
}
