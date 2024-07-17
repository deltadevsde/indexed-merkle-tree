# Indexed Merkle Tree

## Overview

The Indexed Merkle Tree crate provides a robust implementation of indexed Merkle trees in particular described for [Transparency Dictionaries](https://eprint.iacr.org/2021/1263.pdf) that can be used for various cryptographic applications. Compared to normal Merkle trees, this implementation provides proofs for both membership and non-membership, ensuring uniqueness of leaf nodes.

## Breaking Changes in Version 0.5.0

Version 0.5.0 introduces breaking changes:

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
