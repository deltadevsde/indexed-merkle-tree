use anyhow::Result;
use core::fmt;

#[derive(Debug)]
pub enum MerkleTreeError {
    NotFoundError(alloc::string::String),
    OrderingError,
    EmptyMerkleTreeError,
    IndexError(alloc::string::String),
    InvalidFormatError(alloc::string::String),
    MerkleProofError,
}

impl fmt::Display for MerkleTreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MerkleTreeError::NotFoundError(s) => write!(f, "{} not found", s),
            MerkleTreeError::OrderingError => write!(f, "Failed to order merkle tree nodes"),
            MerkleTreeError::EmptyMerkleTreeError => write!(f, "The Merkle tree is empty"),
            MerkleTreeError::IndexError(s) => {
                write!(f, "Failed to retrieve the node at index {}", s)
            }
            MerkleTreeError::InvalidFormatError(s) => write!(f, "Invalid format error: {}", s),
            MerkleTreeError::MerkleProofError => write!(f, "Failed to generate Merkle proof"),
        }
    }
}

pub type MerkleTreeResult<T> = Result<T>;
