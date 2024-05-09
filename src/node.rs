use crate::{concat_slices, sha256};
use alloc::vec::Vec;

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::sync::Arc;
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
#[cfg(feature = "std")]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InnerNode {
    pub hash: [u8; 32],
    pub is_left_sibling: bool,
    pub left: Arc<Node>,
    pub right: Arc<Node>,
}

#[cfg(not(feature = "std"))]
#[derive(Serialize, Deserialize, Debug, Clone)]
/// Represents an inner node in the indexed Merkle Tree.
///
/// This structure is used for non-leaf nodes in the tree, containing references to its
/// left and right children along with its own hash value. There is no difference between
/// inner nodes of an indexed Merkle Tree and a classic Merkle Tree.
///
/// Fields:
/// - `hash`: The hash of the current node, derived from its children.
/// - `is_left_sibling`: Indicates whether this node is a left child of its parent.
/// - `left`: The hash of the left child node.
/// - `right`: The hash of the right child node.
pub struct InnerNode {
    pub hash: [u8; 32],
    pub is_left_sibling: bool,
    pub left: [u8; 32],
    pub right: [u8; 32],
}

#[cfg(feature = "std")]
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
        InnerNode {
            hash: sha256(&concat_slices(vec![&left.get_hash(), &right.get_hash()])),
            is_left_sibling: index % 2 == 0,
            left: Arc::new(left),
            right: Arc::new(right),
        }
    }
}

#[cfg(not(feature = "std"))]
impl InnerNode {
    pub fn new(left: [u8; 32], right: [u8; 32], index: usize) -> Self {
        let mut combined = Vec::new();
        combined.extend_from_slice(&left);
        combined.extend_from_slice(&right);
        InnerNode {
            hash: sha256(&concat_slices(combined)),
            is_left_sibling: index % 2 == 0,
            left,
            right,
        }
    }
}

/// Represents a leaf node in the indexed Merkle Tree.
///
/// Leaf nodes contain the actual data stored in the tree structure as well as metadata that,
/// among other things, ensures the integrity and order of the tree structure.
/// Each leaf node contains a hash of its metadata consisting of a SHA256 value,
/// an active flag that indicates whether the leaf is active or not and links to neighboring elements for efficient traversal and verification.
/// The links lead to the label field which is also a SHA256 value, making it sortable, which is crucial for e.g. Non-Membership proofs.
/// For more information see https://eprint.iacr.org/2021/1263.pdf.
///
/// Fields:
/// - `hash`: The hash of the values below, expect of the is_left_sibling-value.
/// - `is_left_sibling`: Indicates if this node is a left child in its parent node.
/// - `active`: Status flag to indicate if the node is active in the tree.
/// - `value`: The actual data value stored in the node.
/// - `label`: A unique identifier for the node. This is used to sort by size and to link nodes together.
/// - `next`: A reference to the next node in the tree.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LeafNode {
    pub hash: [u8; 32],
    pub is_left_sibling: bool,
    pub active: bool,
    pub value: [u8; 32],
    pub label: [u8; 32],
    pub next: [u8; 32],
}

impl LeafNode {
    /// Initializes a new leaf node with the specified properties.
    ///
    /// This function creates a leaf node with above defined attributes. The hash is generated based on
    /// its active status, label, value, and next pointer. Additionally, the node is marked as a left sibling or not.
    ///
    /// # Arguments
    /// * `active` - Boolean indicating if the leaf is active.
    /// * `is_left` - Boolean indicating if this is a left sibling.
    /// * `label` - Unique 256 bit identifier for the leaf.
    /// * `value` - 256 Bit data value of the leaf.
    /// * `next` - Reference to the next largest node (identified by the label value) in the sequence.
    ///
    /// # Returns
    /// * A new leaf node with the specified properties.
    pub fn new(
        active: bool,
        is_left: bool,
        label: [u8; 32],
        value: [u8; 32],
        next: [u8; 32],
    ) -> Self {
        let mut combined = Vec::new();
        combined.extend_from_slice(&[active as u8]);
        combined.extend_from_slice(&label);
        combined.extend_from_slice(&value);
        combined.extend_from_slice(&next);

        LeafNode {
            hash: sha256(&combined),
            is_left_sibling: is_left,
            active,
            value,
            label,
            next,
        }
    }
}

#[cfg(feature = "std")]
impl Default for LeafNode {
    fn default() -> Self {
        LeafNode::new(
            false,
            // default leaf nodes are not left siblings
            false,
            Node::EMPTY_HASH,
            Node::EMPTY_HASH,
            Node::TAIL,
        )
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
#[cfg(feature = "std")]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Node {
    Inner(InnerNode),
    Leaf(LeafNode),
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
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg(not(feature = "std"))]
pub enum Node {
    Inner(InnerNode),
    Leaf(LeafNode),
}

#[cfg(feature = "std")]
impl Default for Node {
    fn default() -> Self {
        Node::Leaf(LeafNode::default())
    }
}

impl Node {
    /// A placeholder for label/value values in inactive (empty) leaf nodes in the indexed Merkle Tree.
    /// It's also the fixed label of the first element in the indexed Merkle tree, because it's the
    /// lowest possible number in with 256 output bits from sha256.
    pub const EMPTY_HASH: [u8; 32] = [0; 32];

    /// This constant is used to designate the last element (because it's the highest possible number in with 256 output bits from sha256)
    /// in the indexed Merkle tree. The next pointer from the largest label in the current tree, as well as the next pointer from inactive leaf nodes "point" to it.
    pub const TAIL: [u8; 32] = [0xFF; 32];

    /// Convenience method for creating a new leaf node.
    /// See `LeafNode::new` for more information.
    pub fn new_leaf(
        active: bool,
        is_left: bool,
        label: [u8; 32],
        value: [u8; 32],
        next: [u8; 32],
    ) -> Self {
        return Node::Leaf(LeafNode::new(active, is_left, label, value, next));
    }

    /// Convenience method for creating a new inner node.
    /// See `InnerNode::new` for more information.
    pub fn new_inner(left: Node, right: Node, index: usize) -> Self {
        return Node::Inner(InnerNode::new(left, right, index));
    }

    /// Returns the hash of the node.
    ///
    /// This function returns the hash of either an inner node or a leaf node, depending on the node type.
    pub fn get_hash(&self) -> [u8; 32] {
        match self {
            Node::Inner(inner_node) => inner_node.hash.clone(),
            Node::Leaf(leaf) => leaf.hash.clone(),
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
            Node::Leaf(leaf) => leaf.active,
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

    /// Activates a leaf node.
    ///
    /// This function sets the `active` flag of a leaf node to true. It has no effect on inner nodes, because they are always active.
    /// Activating a leaf node can be an important operation when managing the data within the indexed Merkle Tree,
    /// especially in scenarios involving data updates or dynamic tree modifications.
    pub fn set_node_active(&mut self) {
        match self {
            Node::Inner(_) => (),
            Node::Leaf(ref mut leaf) => leaf.active = true,
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
                existing_leaf.next = new_leaf.label.clone();
            }
        }
    }
}

#[cfg(feature = "std")]
impl Node {
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

    /// Generates and updates the hash for the node.
    ///
    /// @todo: Deprecate this function by creating proper constructors for the nodes
    ///
    /// This function computes the hash of a node based on its type and properties.
    /// For an inner node, the hash is generated from the concatenated hashes of its left and right children in form of:
    ///     SHA256(left_child_hash || right_child_hash)
    /// For a leaf node, the hash is based on its active status, label, value, and the reference to the next node in the tree:
    ///     SHA256(active || label || value || next)
    pub fn generate_hash(&mut self) {
        match self {
            Node::Inner(node) => {
                let hash = concat_slices(vec![&node.left.get_hash(), &node.right.get_hash()]);
                node.hash = sha256(&hash);
            }
            Node::Leaf(leaf) => {
                let hash = concat_slices(vec![
                    &[leaf.active as u8],
                    &leaf.label,
                    &leaf.value,
                    &leaf.next,
                ]);
                leaf.hash = sha256(&hash);
            }
        }
    }
}

#[cfg(not(feature = "std"))]
impl Node {
    /// Attaches a node as the left child of an inner node.
    ///
    /// This function sets the provided node as the left child of the current inner node.
    ///
    /// # Arguments
    /// * `left` - An `Arc<Self>` pointing to the node to be set as the left child.
    pub fn add_left(&mut self, left: [u8; 32]) {
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
    pub fn add_right(&mut self, right: [u8; 32]) {
        if let Node::Inner(inner) = self {
            inner.right = right;
        }
    }

    /// Generates and updates the hash for the node.
    ///
    /// @todo: Deprecate this function by creating proper constructors for the nodes
    ///
    /// This function computes the hash of a node based on its type and properties.
    /// For an inner node, the hash is generated from the concatenated hashes of its left and right children in form of:
    ///     SHA256(left_child_hash || right_child_hash)
    /// For a leaf node, the hash is based on its active status, label, value, and the reference to the next node in the tree:
    ///     SHA256(active || label || value || next)
    pub fn generate_hash(&mut self) {
        match self {
            Node::Inner(node) => {
                let mut combined = Vec::new();
                combined.extend_from_slice(&node.left);
                combined.extend_from_slice(&node.right);

                node.hash = sha256(&combined);
            }
            Node::Leaf(leaf) => {
                let mut combined = Vec::new();
                combined.push(leaf.active as u8);
                combined.extend_from_slice(&leaf.label);
                combined.extend_from_slice(&leaf.value);
                combined.extend_from_slice(&leaf.next);

                leaf.hash = sha256(&combined);
            }
        }
    }
}
