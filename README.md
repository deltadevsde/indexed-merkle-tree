# Indexed Merkle Tree

## Overview

The Indexed Merkle Tree crate provides a robust implementation of indexed Merkle trees in particular described for [Transparency Dictionaries](https://eprint.iacr.org/2021/1263.pdf) that can be used for various cryptographic applications. Compared to normal Merkle trees, this implementation provides proofs for both membership and non-membership, ensuring uniqueness of leaf nodes.

# Indexed Merkle Tree

## Overview

The Indexed Merkle Tree crate provides a robust implementation of indexed Merkle trees in particular described for [Transparency Dictionaries](https://eprint.iacr.org/2021/1263.pdf) that can be used for various cryptographic applications. Compared to normal Merkle trees, this implementation provides proofs for both membership and non-membership, ensuring uniqueness of leaf nodes.

## Breaking Changes in Version 0.5.0

Version 0.5.0 introduces breaking changes:

- **Hash Value Type Change**: The crate no longer uses `String` for hash values. Instead, a custom `Hash` struct is implemented:
  
  ```rust
  #[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
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
  }```

## Breaking Changes in Version 0.4.0

Version 0.4.0 introduces breaking changes:

- Hash Value Mapping: Hash values are now computed and then taken modulo the order of the BLS12-381 curve to ensure they are mapped into the valid value range.

## Features

- Efficient membership and non-membership proof generation.
- Update and insertion operations with verifiable proofs.
- Tree size doubling for dynamic data insertion.
- High integrity and order verification in data structures.

## Usage

tbd

## Installation

```bash
cargo add indexed_merkle_tree
```

## Contributing

Contributions are welcome! Please feel free to get in touch.
