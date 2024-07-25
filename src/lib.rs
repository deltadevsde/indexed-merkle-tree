pub mod error;
pub mod node;
pub mod tree;

use borsh::{BorshDeserialize, BorshSerialize};
use num::BigUint;
use num_traits::Num;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
pub struct Hash([u8; 32]);

impl Hash {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    pub fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(hex)?;
        if bytes.len() != 32 {
            return Err(hex::FromHexError::InvalidStringLength);
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Hash(array))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

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
pub fn sha256(input: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(input);
    Hash(hasher.finalize().into())
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

pub fn sha256_mod(input: &[u8]) -> Hash {
    let hash = sha256(input);
    let hash_bigint = BigUint::from_bytes_be(hash.as_ref());
    let modulus = BigUint::from_str_radix(MODULUS, 16).expect("Invalid modulus");
    let modded_hash = hash_bigint % modulus;
    let mut bytes = modded_hash.to_bytes_be();
    if bytes.len() < 32 {
        bytes = std::iter::repeat(0)
            .take(32 - bytes.len())
            .chain(bytes)
            .collect();
    }
    Hash::new(bytes.try_into().unwrap())
}
