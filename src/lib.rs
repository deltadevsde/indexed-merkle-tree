pub mod error;
pub mod node;
pub mod tree;

use crypto_hash::{hex_digest, Algorithm};
use sha2::{Digest, Sha256};

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
fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    Into::<[u8; 32]>::into(result)
}

fn concat_arrays(left: [u8; 32], right: [u8; 32]) -> [u8; 64] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(&left);
    combined[32..].copy_from_slice(&right);
    combined
}

fn concat_four_arrays(a: u8, b: [u8; 32], c: [u8; 32], d: [u8; 32]) -> [u8; 97] {
    let mut combined = [0u8; 97];
    combined[0] = a;
    combined[1..33].copy_from_slice(&b);
    combined[33..65].copy_from_slice(&c);
    combined[65..97].copy_from_slice(&d);
    combined
}
