use thiserror::Error;

#[derive(Error, Debug)]
pub enum MerkleTreeError {
    #[error("{0} not found")]
    NotFoundError(String),
    #[error("Failed to order merkle tree nodes")]
    OrderingError,
    #[error("The Merkle tree is empty")]
    EmptyMerkleTreeError,
    #[error("Failed to retrieve the node at index {0}")]
    IndexError(String),
    #[error("Invalid format error: {0}")]
    InvalidFormatError(String),
    #[error("Failed to generate Merkle proof")]
    MerkleProofError,
}
