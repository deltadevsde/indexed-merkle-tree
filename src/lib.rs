pub mod error;
pub mod node;
pub mod tree;

use crypto_hash::{hex_digest, Algorithm};

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
pub fn sha256(input: &str) -> String {
    hex_digest(Algorithm::SHA256, input.as_bytes())
}
