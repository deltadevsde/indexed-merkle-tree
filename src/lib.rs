#![no_std]
pub mod error;
pub mod node;
pub mod tree;

extern crate alloc;

use sha2::{Digest, Sha256};

use alloc::vec::Vec;

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
pub fn sha256(input: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    Into::<[u8; 32]>::into(result)
}

pub fn concat_slices(slices: Vec<&[u8]>) -> Vec<u8> {
    let total_length: usize = slices.iter().map(|s| s.len()).sum();
    let mut combined = Vec::with_capacity(total_length);

    for slice in slices {
        combined.extend_from_slice(slice);
    }

    combined
}
