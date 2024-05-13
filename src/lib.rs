#![cfg_attr(not(feature = "std"), no_std)]
pub mod error;
pub mod node;
pub mod tree;

extern crate alloc;

use sha2::{Digest, Sha256};

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Hash([u8; 32]);

impl Sha256Hash {
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
    pub fn new(input: impl AsRef<[u8]>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let result = hasher.finalize();
        Sha256Hash(Into::<[u8; 32]>::into(result))
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(slice);
            Some(Sha256Hash(arr))
        } else {
            None
        }
    }

    pub fn from_vec(vec: Vec<u8>) -> Option<Self> {
        if vec.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&vec);
            Some(Sha256Hash(arr))
        } else {
            None
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

pub fn concat_slices(slices: Vec<&[u8]>) -> Vec<u8> {
    let total_length: usize = slices.iter().map(|s| s.len()).sum();
    let mut combined = Vec::with_capacity(total_length);

    for slice in slices {
        combined.extend_from_slice(slice);
    }

    combined
}
