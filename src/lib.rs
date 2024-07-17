pub mod error;
pub mod node;
pub mod tree;

use num::BigUint;
use num_traits::Num;
use sha2::{Digest, Sha256};

pub const MODULUS: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";

/// Computes the SHA256 hash of the given string.
///
/// This function takes a string reference as input and returns its SHA256 hash in hexadecimal format. We're using the `crypto-hash` crate to compute the hash.
/// It is used to ensure data integrity and uniqueness within the Merkle Tree structure.
///
/// # Arguments
/// * `input` - A reference to the string to be hashed.
///
/// # Returns
/// A `String` representing the hexadecimal SHA256 hash of the input.
/// TODO: Implement the `sha256` function that computes the SHA256 hash of the given string but with the `sha2` crate (should return a [u8; 32] bc we want to use that in the future everywhere instead of strings).
pub fn sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// Computes the SHA256 hash of the given string and reduces it modulo the BLS12-381 curve modulus.
///
/// This function takes a string reference as input, computes its SHA256 hash, and then reduces
/// the hash modulo the BLS12-381 curve modulus to ensure it fits within its field Fp.
/// The resulting value is returned in hexadecimal format.
///
/// # Arguments
/// * `input` - A reference to the string to be hashed.
///
/// # Returns
/// A `String` representing the hexadecimal SHA256 hash of the input reduced modulo the BLS12-381 curve modulus.
pub fn sha256_mod(input: &str) -> String {
    // Compute the SHA256 hash
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash_result = hasher.finalize();

    // Convert hash to BigUint
    let hash_bigint = BigUint::from_bytes_be(&hash_result);

    // Convert modulus to BigUint
    let modulus = BigUint::from_str_radix(MODULUS, 16).expect("Invalid modulus");

    // Compute hash modulo the modulus of BLS12-381 curve
    let modded_hash = hash_bigint % modulus;

    // Convert result to hexadecimal string and return
    hex::encode(modded_hash.to_bytes_be())
}
