## Changes in Version 0.6.2

Version 0.6.2 introduces the `bls` feature, which allows for the `Hash` type to be converted into a `bls32_381::Scalar` using `TryInto`. This is a default feature.

Additionally, all methods now return `anyhow::Error` instead of a `MerkleTreeError`. All underlying errors are still MerkleTreeErrors, though.

## Changes in Version 0.6.1

Version 0.6.1 introduces `no_std` support, allowing the crate to be used in environments without the standard library. To enable this, simply disable the default features in your `Cargo.toml`:

```toml
[dependencies]
indexed_merkle_tree = { version = "0.6.1", default-features = false }
```

## Breaking Changes in Version 0.6.0

Version 0.6.0 introduces significant breaking changes:

- **Removal of Active Flag**: The `is_active` flag has been removed from leaf nodes. This changes how node activity is determined and affects the hash calculation of nodes.

- **New Inactive Node Identification**: Inactive nodes are now identified by their `next` pointer being set to `Node::HEAD`. This replaces the previous `is_active` flag mechanism.

- **Special First Node**: The first node in the tree now has a special configuration to ensure correct non-membership proofs:
  - Label: `Node::HEAD` (0x00000...)
  - Value: `Node::HEAD` (0x00000...)
  - Next: `Node::TAIL` (0xFFFF...)

- **Hash Calculation Change**: Due to the removal of the `is_active` flag, the hash calculation for nodes has changed. This means that trees created with previous versions will have different hash values in version 0.6.0.

These changes improve the efficiency and logical consistency of the Indexed Merkle Tree implementation while maintaining its core functionality. Users upgrading to this version will need to rebuild their trees and update any code that relies on the previous activity checking mechanism.

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
