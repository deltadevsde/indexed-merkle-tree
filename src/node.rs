use serde::{Deserialize, Serialize};

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::{sha256_mod, Hash};

/// Represents an inner node in the indexed Merkle Tree.
///
/// This structure is used for non-leaf nodes in the tree, containing references to its
/// left and right children along with its own hash value. There is no difference between
/// inner nodes of an indexed Merkle Tree and a classic Merkle Tree.
///
/// Fields:
/// - `hash`: The hash of the current node, derived from its children.
/// - `is_left_sibling`: Indicates whether this node is a left child of its parent.
/// - `left`: A reference-counted pointer to the left child node.
/// - `right`: A reference-counted pointer to the right child node.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct InnerNode {
    pub hash: Hash,
    pub is_left_sibling: bool,
    pub left: Arc<Node>,
    pub right: Arc<Node>,
}

impl InnerNode {
    /// Creates a new inner node.
    ///
    /// This function generates an inner node from two child nodes (left and right) and an index.
    /// The index determines the new node's left sibling status. The hash for the inner node is
    /// calculated based on its children. This is crucial for constructing the tree and updating its structure.
    ///
    /// # Arguments
    /// * `left` - The left child node.
    /// * `right` - The right child node.
    /// * `index` - The position index of the new node in the tree.
    ///
    /// # Returns
    /// An `InnerNode` representing the newly created inner node.
    pub fn new(left: Node, right: Node, index: usize) -> Self {
        // we need to use the .as_ref() method to convert the Hash to a slice of bytes ([u8])
        let hash = sha256_mod(&[left.get_hash().as_ref(), right.get_hash().as_ref()].concat());
        InnerNode {
            hash,
            is_left_sibling: index % 2 == 0,
            left: Arc::new(left),
            right: Arc::new(right),
        }
    }
}

/// Represents a leaf node in the indexed Merkle Tree.
///
/// Leaf nodes contain the actual data stored in the tree structure as well as metadata that,
/// among other things, ensures the integrity and order of the tree structure.
/// Each leaf node contains a hash of its metadata consisting of a SHA256 value,
/// a link to neighboring elements for efficient traversal and verification.
/// The links lead to the label field which is also a SHA256 value, making it sortable, which is crucial for e.g. Non-Membership proofs.
/// For more information see https://eprint.iacr.org/2021/1263.pdf.
///
/// Fields:
/// - `hash`: The hash of the values below, expect of the is_left_sibling-value.
/// - `is_left_sibling`: Indicates if this node is a left child in its parent node.
/// - `value`: The actual data value stored in the node.
/// - `label`: A unique identifier for the node. This is used to sort by size and to link nodes together.
/// - `next`: A reference to the next node in the tree.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct LeafNode {
    pub hash: Hash,
    pub is_left_sibling: bool,
    pub value: Hash,
    pub label: Hash,
    pub next: Hash,
}

impl LeafNode {
    /// Initializes a new leaf node with the specified properties.
    ///
    /// This function creates a leaf node with above defined attributes. The hash is generated based on
    /// its label, value, and next pointer. Additionally, the node is marked as a left sibling or not.
    ///
    /// # Arguments
    /// * `is_left` - Boolean indicating if this is a left sibling.
    /// * `label` - Unique 256 bit identifier for the leaf.
    /// * `value` - 256 Bit data value of the leaf.
    /// * `next` - Reference to the next largest node (identified by the label value) in the sequence.
    ///
    /// # Returns
    /// * A new leaf node with the specified properties.
    pub fn new(is_left: bool, label: Hash, value: Hash, next: Hash) -> Self {
        let hash = sha256_mod(&[label.as_ref(), value.as_ref(), next.as_ref()].concat());
        LeafNode {
            hash,
            is_left_sibling: is_left,
            value,
            label,
            next,
        }
    }

    pub fn is_active(&self) -> bool {
        self.next != Node::HEAD
    }
}

impl Default for LeafNode {
    fn default() -> Self {
        LeafNode::new(false, Node::HEAD, Node::HEAD, Node::HEAD)
    }
}

/// An enum representing the types of nodes in the indexed Merkle Tree.
///
/// This enum allows for the differentiation between inner and leaf nodes in the tree,
/// facilitating operations like traversal, insertion, and proof generation.
/// It encapsulates either an `InnerNode` or a `LeafNode`, depending on the node's position
/// and role in the tree.
///
/// Variants:
/// - `Inner(InnerNode)`: An inner node of the tree, containing references to child nodes.
/// - `Leaf(LeafNode)`: A leaf node, containing the actual data (hash of its metadata).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Inner(InnerNode),
    Leaf(LeafNode),
}

impl Default for Node {
    fn default() -> Self {
        Node::Leaf(LeafNode::default())
    }
}

impl Node {
    /// This constant represents the smallest possible value in the field Fp for the BLS12-381 curve.
    ///
    /// In the context of a Merkle tree with 256-bit SHA-256 hash outputs, this value is used to designate
    /// the first element or a null value. This is because the smallest possible value that can be generated
    /// by SHA-256 is zero, which is also the smallest value in the field Fp for the BLS12-381 curve.
    ///
    /// The value `HEAD` is used in the following ways:
    /// - As the starting point or initial value in the Merkle tree.
    /// - As a placeholder for empty or null nodes.
    pub const HEAD: Hash = Hash::new([0; 32]);

    /// This constant represents the largest possible value in the field Fp for the BLS12-381 curve.
    ///
    /// In the context of a Merkle tree with 256-bit SHA-256 hash outputs, this value is used to designate
    /// the last element. This is because we need to ensure that all values are within the field Fp for the
    /// BLS12-381 curve, and the largest possible value that we can use is just below the modulus.
    ///
    /// The value `TAIL` is used in the following ways:
    /// - As the next pointer from the largest label in the current Merkle tree.
    /// - As the next pointer from inactive leaf nodes, effectively "pointing" to it.
    ///
    /// The specific value of `TAIL` is:
    ///
    /// 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000
    ///
    /// This ensures that no value in the Merkle tree exceeds the modulus, maintaining proper order
    /// and integrity within the BLS12-381 field.
    pub const TAIL: Hash = Hash::new([
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8,
        0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
        0x00, 0x00,
    ]);

    /// Convenience method for creating a new leaf node.
    /// See `LeafNode::new` for more information.
    pub fn new_leaf(is_left: bool, label: Hash, value: Hash, next: Hash) -> Self {
        Node::Leaf(LeafNode::new(is_left, label, value, next))
    }

    /// Convenience method for creating a new inner node.
    /// See `InnerNode::new` for more information.
    pub fn new_inner(left: Node, right: Node, index: usize) -> Self {
        Node::Inner(InnerNode::new(left, right, index))
    }

    /// Returns the hash of the node.
    ///
    /// This function returns the hash of either an inner node or a leaf node, depending on the node type.
    pub fn get_hash(&self) -> Hash {
        match self {
            Node::Inner(inner_node) => inner_node.hash,
            Node::Leaf(leaf) => leaf.hash,
        }
    }

    /// Determines if the node is a left sibling.
    ///
    /// This function checks whether the node (either inner or leaf) is a left sibling
    /// in its parent node's context. This information is important in the tree's traversal
    /// and structure maintenance, ensuring the correct positioning and integrity of the nodes.
    pub fn is_left_sibling(&self) -> bool {
        match self {
            Node::Inner(inner_node) => inner_node.is_left_sibling,
            Node::Leaf(leaf) => leaf.is_left_sibling,
        }
    }

    /// Determines if the node is active.
    ///
    /// For inner nodes, this function always returns true. For leaf nodes, it checks the `active` flag.
    /// This method is important to understand the current state of a node within the tree,
    /// especially for insert operations to recognize the need for capacity duplication of the tree if necessary.
    pub fn is_active(&self) -> bool {
        match self {
            Node::Inner(_) => true,
            Node::Leaf(leaf) => leaf.is_active(),
        }
    }

    /// Returns the `next` node identifier.
    ///
    /// This function retrieves the `next` node identifier for a leaf node, or returns the `TAIL` identifier
    /// if the node is not a leaf. This is useful for traversing linked lists of leaf nodes.
    pub fn get_next(&self) -> Hash {
        match self {
            Node::Leaf(leaf) => leaf.next,
            _ => Node::TAIL,
        }
    }

    /// Sets the `next` node identifier.
    ///
    /// This function sets the `next` node identifier for a leaf node. This is important for maintaining
    /// the linked list structure of leaf nodes within the tree, enabling efficient traversal and modifications.
    pub fn set_next(&mut self, next: Hash) {
        if let Node::Leaf(leaf) = self {
            leaf.next = next;
        }
    }

    /// Returns the `label` of the node.
    ///
    /// This function retrieves the `label` for a leaf node, or returns the `EMPTY_HASH` identifier
    /// if the node is not a leaf. This is useful for accessing the label of leaf nodes within the tree,
    /// which may represent some data or key associated with that node.
    pub fn get_label(&self) -> Hash {
        match self {
            Node::Leaf(leaf) => leaf.label,
            _ => Node::HEAD,
        }
    }

    /// Sets the left sibling status of the node.
    ///
    /// This function updates whether the node (inner or leaf) is considered a left sibling.
    /// This is crucial for maintaining the structural integrity of the tree, especially when nodes
    /// are inserted or reorganized.
    pub fn set_left_sibling_value(&mut self, is_left: bool) {
        match self {
            Node::Inner(inner_node) => inner_node.is_left_sibling = is_left,
            Node::Leaf(leaf) => leaf.is_left_sibling = is_left,
        }
    }

    /// Attaches a node as the left child of an inner node.
    ///
    /// This function sets the provided node as the left child of the current inner node.
    ///
    /// # Arguments
    /// * `left` - An `Arc<Self>` pointing to the node to be set as the left child.
    pub fn add_left(&mut self, left: Arc<Self>) {
        if let Node::Inner(inner) = self {
            inner.left = left;
        }
    }

    /// Attaches a node as the right child of an inner node.
    ///
    /// This function sets the provided node as the right child of the current inner node.
    ///
    /// # Arguments
    /// * `right` - An `Arc<Self>` pointing to the node to be set as the right child.
    pub fn add_right(&mut self, right: Arc<Self>) {
        if let Node::Inner(inner) = self {
            inner.right = right;
        }
    }

    /// Updates the 'next' pointer of a leaf node.
    ///
    /// This function is used to update the reference to the next node in the indexed Merkle Tree.
    ///
    /// # Arguments
    /// * `existing_node` - The leaf node to update.
    /// * `new_node` - The new node whose label will be used for the 'next' pointer.
    pub fn update_next_pointer(existing_node: &mut Self, new_node: &Self) {
        if let Self::Leaf(ref mut existing_leaf) = existing_node {
            if let Self::Leaf(new_leaf) = new_node {
                existing_leaf.next = new_leaf.label;
            }
        }
    }

    /// Generates and updates the hash for the node.
    ///
    /// @todo: Deprecate this function by creating proper constructors for the nodes
    ///
    /// This function computes the hash of a node based on its type and properties.
    /// For an inner node, the hash is generated from the concatenated hashes of its left and right children in form of:
    ///     SHA256(left_child_hash || right_child_hash)
    /// For a leaf node, the hash is based on its label, value, and the reference to the next node in the tree:
    ///     SHA256(label || value || next)
    pub fn generate_hash(&mut self) {
        match self {
            Node::Inner(node) => {
                let hash = sha256_mod(
                    &[
                        node.left.get_hash().as_ref(),
                        node.right.get_hash().as_ref(),
                    ]
                    .concat(),
                );
                node.hash = hash;
            }
            Node::Leaf(leaf) => {
                let hash = sha256_mod(
                    &[leaf.label.as_ref(), leaf.value.as_ref(), leaf.next.as_ref()].concat(),
                );
                leaf.hash = hash;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_node_creation() {
        let label = Hash::new([1; 32]);
        let value = Hash::new([2; 32]);
        let next = Hash::new([3; 32]);
        let leaf = LeafNode::new(true, label, value, next);

        assert!(leaf.is_active());
        assert!(leaf.is_left_sibling);
        assert_eq!(leaf.label, label);
        assert_eq!(leaf.value, value);
        assert_eq!(leaf.next, next);
    }

    #[test]
    fn test_inner_node_creation() {
        let left = Node::new_leaf(
            true,
            Hash::new([1; 32]),
            Hash::new([2; 32]),
            Hash::new([3; 32]),
        );
        let right = Node::new_leaf(
            false,
            Hash::new([4; 32]),
            Hash::new([5; 32]),
            Hash::new([6; 32]),
        );
        let inner = Node::new_inner(left.clone(), right.clone(), 0);

        if let Node::Inner(inner_node) = inner {
            assert!(inner_node.is_left_sibling);
            assert_eq!(*inner_node.left, left);
            assert_eq!(*inner_node.right, right);
        } else {
            panic!("Expected Inner node");
        }
    }

    #[test]
    fn test_node_is_active() {
        let active_leaf = Node::new_leaf(
            true,
            Hash::new([1; 32]),
            Hash::new([2; 32]),
            Hash::new([3; 32]),
        );
        let inactive_leaf = Node::new_leaf(true, Node::HEAD, Node::HEAD, Node::HEAD);
        let inner_node = Node::new_inner(active_leaf.clone(), inactive_leaf.clone(), 0);

        assert!(active_leaf.is_active());
        assert!(!inactive_leaf.is_active());
        assert!(inner_node.is_active());
    }

    #[test]
    fn test_node_get_next() {
        let leaf = Node::new_leaf(
            true,
            Hash::new([1; 32]),
            Hash::new([2; 32]),
            Hash::new([3; 32]),
        );
        let inner = Node::new_inner(leaf.clone(), leaf.clone(), 0);

        assert_eq!(leaf.get_next(), Hash::new([3; 32]));
        assert_eq!(inner.get_next(), Node::TAIL);
    }

    #[test]
    fn test_node_set_next() {
        let mut leaf = Node::new_leaf(
            true,
            Hash::new([1; 32]),
            Hash::new([2; 32]),
            Hash::new([3; 32]),
        );
        let new_next = Hash::new([4; 32]);
        leaf.set_next(new_next);

        if let Node::Leaf(leaf_node) = leaf {
            assert_eq!(leaf_node.next, new_next);
        } else {
            panic!("Expected Leaf node");
        }
    }

    #[test]
    fn test_node_update_next_pointer() {
        let mut existing_node = Node::new_leaf(
            true,
            Hash::new([1; 32]),
            Hash::new([2; 32]),
            Hash::new([3; 32]),
        );
        let new_node = Node::new_leaf(
            false,
            Hash::new([4; 32]),
            Hash::new([5; 32]),
            Hash::new([6; 32]),
        );

        Node::update_next_pointer(&mut existing_node, &new_node);

        if let Node::Leaf(leaf_node) = existing_node {
            assert_eq!(leaf_node.next, Hash::new([4; 32]));
        } else {
            panic!("Expected Leaf node");
        }
    }

    #[test]
    fn test_node_generate_hash() {
        let mut leaf = Node::new_leaf(
            true,
            Hash::new([1; 32]),
            Hash::new([2; 32]),
            Hash::new([3; 32]),
        );
        let original_hash = leaf.get_hash();

        if let Node::Leaf(ref mut leaf_node) = leaf {
            leaf_node.value = Hash::new([4; 32]);
        }

        leaf.generate_hash();
        let new_hash = leaf.get_hash();

        assert_ne!(original_hash, new_hash);
    }
}
