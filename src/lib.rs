pub mod error;

use crypto_hash::{hex_digest, Algorithm};
use num::{BigInt, Num};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use error::MerkleTreeError;

// The Merkle Proof is a tuple of the root hash and the path from the leaf to the root containing the sibling nodes
pub type MerkleProof = (Option<String>, Option<Vec<Node>>);
// The Update Proof is a tuple of the old Merkle Proof and the new Merkle Proof after the update operation
pub type UpdateProof = (MerkleProof, MerkleProof);
// The Insert Proof is a tuple of the Merkle Proof of the non-membership of the new node (to guarantee uniqueness), the first update proof and the second update proof
// The first update proof is the proof of the update of the next pointer of the previous node sorted by label and the second update proof is the proof of the update of the new node
pub type InsertProof = (MerkleProof, UpdateProof, UpdateProof);

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
pub fn sha256(input: &String) -> String {
    hex_digest(Algorithm::SHA256, input.as_bytes())
}

/// Represents the variant of the proof in the indexed Merkle Tree.
///
/// This enum differentiates between the types of proofs that can be generated in the context
/// of an indexed Merkle Tree (proofs of update and insert operations).
///
/// Variants:
/// - `Update(UpdateProof)`: Represents a proof for an update operation.
/// - `Insert(InsertProof)`: Represents a proof for an insert operation.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ProofVariant {
    Update(UpdateProof),
    Insert(InsertProof),
}

/// Represents a (classic) cryptographic merkle proof, which is not specific for indexed Merkle Trees.
///
/// This structure encapsulates the path and root hashes before and after the modification which 
/// are necessary information to verify changes in the tree.
///
/// Fields:
/// - `old_root`: The root hash of the tree before the modification.
/// - `old_path`: The path in the tree before the modification.
/// - `new_root`: The root hash of the tree after the modification.
/// - `new_path`: The path in the tree after the modification.
pub struct Proof {
    pub old_root: String,
    pub old_path: Vec<Node>,
    pub new_root: String,
    pub new_path: Vec<Node>,
}

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
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InnerNode {
    pub hash: String,
    pub is_left_sibling: bool,
    pub left: Arc<Node>,
    pub right: Arc<Node>,
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
    pub hash: String,
    pub is_left_sibling: bool,
    pub active: bool,
    pub value: String,
    pub label: String,
    pub next: String,
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
pub enum Node {
    Inner(InnerNode),
    Leaf(LeafNode),
}

impl Node {
    /// A placeholder for label/value values in inactive (empty) leaf nodes in the indexed Merkle Tree.
    /// It's also the fixed label of the first element in the indexed Merkle tree, because it's the 
    /// lowest possible number in with 256 output bits from sha256.
    pub const EMPTY_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    /// This constant is used to designate the last element (because it's the highest possible number in with 256 output bits from sha256) 
    /// in the indexed Merkle tree. The next pointer from the largest label in the current tree, as well as the next pointer from inactive leaf nodes "point" to it.
    pub const TAIL: &'static str =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";

    /// Returns the hash of the node.
    ///
    /// This function returns the hash of either an inner node or a leaf node, depending on the node type. 
    pub fn get_hash(&self) -> String {
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
    pub fn initialize_leaf(
        active: bool,
        is_left: bool,
        label: String,
        value: String,
        next: String,
    ) -> Self {
        let hash = format!("{}, {}, {}, {}", active, label, value, next);
        let leaf = LeafNode {
            hash: sha256(&hash),
            is_left_sibling: is_left,
            active,
            value,
            label,
            next,
        };
        Node::Leaf(leaf)
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
                existing_leaf.next = new_leaf.label.clone();
            }
        }
    }

    /// Generates and updates the hash for the node.
    ///
    /// This function computes the hash of a node based on its type and properties.
    /// For an inner node, the hash is generated from the concatenated hashes of its left and right children in form of:
    ///     SHA256(left_child_hash || right_child_hash)
    /// For a leaf node, the hash is based on its active status, label, value, and the reference to the next node in the tree:
    ///     SHA256(active || label || value || next)
    pub fn generate_hash(&mut self) {
        match self {
            Node::Inner(inner_node) => {
                let hash = format!(
                    "{} || {}",
                    inner_node.left.get_hash(),
                    inner_node.right.get_hash()
                );
                inner_node.hash = sha256(&hash);
            }
            Node::Leaf(leaf) => {
                let hash = format!(
                    "{}, {}, {}, {}",
                    leaf.active, leaf.label, leaf.value, leaf.next
                );
                leaf.hash = sha256(&hash);
            }
        }
    }
}

/// Represents an Indexed Merkle Tree.
///
/// This structure encapsulates a Merkle Tree where nodes are indexed, facilitating efficient
/// updates and proofs, especially Non-Membership proofs. 
///
/// Fields:
/// - `nodes`: A vector of `Node` elements, representing the nodes of the indexed Merkle Tree.

#[derive(Serialize, Deserialize, Clone)]
pub struct IndexedMerkleTree {
    nodes: Vec<Node>,
}

/// Updates the position attributes of nodes in a vector.
///
/// This function iterates over a vector of nodes, updating each node's left sibling status
/// based on its index. It's crucial for correctly setting up the structural properties of the nodes
/// in the tree, especially after modifications that might alter the node order.
///
/// # Arguments
/// * `nodes` - A vector of `Node` elements to update.
///
/// # Returns
/// A `Vec<Node>` with updated left sibling status for each node.
pub fn set_left_sibling_status_for_nodes(nodes: Vec<Node>) -> Vec<Node> {
    nodes
        .into_iter()
        .enumerate()
        .map(|(i, mut node)| {
            let is_left_sibling = i % 2 == 0;
            node.set_left_sibling_value(is_left_sibling);
            node
        })
        .collect()
}

impl IndexedMerkleTree {
    /// Creates a new `IndexedMerkleTree` from a given `nodes` vector.
    ///
    /// # Arguments
    ///
    /// * `nodes` - A vector of nodes from which the Merkle tree will be built.
    ///
    /// # Returns
    ///
    /// * `Self` - A new IndexedMerkleTree
    pub fn new(nodes: Vec<Node>) -> Result<Self, MerkleTreeError> {
        let parsed_nodes = set_left_sibling_status_for_nodes(nodes);

        let tree = Self {
            nodes: parsed_nodes,
        };
        Ok(tree.calculate_root()?)
    }

    /// Calculates the commitment of an empty Merkle tree of a given size.
    ///
    /// This function initializes an empty Indexed Merkle Tree with a specified number of nodes,
    /// all set to inactive except for the first one (so an active treeper definition). 
    /// It then computes the tree's commitment, which represents the root hash of the empty tree. 
    ///
    /// # Arguments
    /// * `size` - The number of nodes in the tree.
    ///
    /// # Returns
    /// A `Result<String, MerkleTreeError>` representing the tree's commitment or an error.
    pub fn calculate_empty_tree_commitment_from_size(size: usize) -> Result<String, MerkleTreeError> {
        let mut nodes: Vec<Node> = Vec::new();

        for i in 0..size {
            let is_active_leaf = i == 0;
            let is_left_sibling = i % 2 == 0;
            let value = Node::EMPTY_HASH.to_string();
            let label = Node::EMPTY_HASH.to_string();
            let node = Node::initialize_leaf(
                is_active_leaf,
                is_left_sibling,
                value,
                label,
                Node::TAIL.to_string(),
            );
            nodes.push(node);
        }

        let tree = IndexedMerkleTree::new(nodes)?;
        tree.get_commitment()
    }

    /// Resorts nodes based on a specified input order.
    ///
    /// This function rearranges a given vector of nodes to match an input order defined by a vector of labels.
    /// It filters out inner nodes and so it sorts only leaf nodes based on their label's position in the input vector.
    ///
    /// # Arguments
    /// * `nodes` - A vector of `Node` elements to be sorted.
    /// * `input_order` - A vector of strings representing the desired order of leaf labels.
    ///
    /// # Returns
    /// A `Result<Vec<Node>, MerkleTreeError>` representing the sorted nodes or an error.
    pub fn resort_nodes_by_input_order(
        nodes: Vec<Node>,
        input_order: Vec<String>,
    ) -> Result<Vec<Node>, MerkleTreeError> {
        let valid_nodes: Vec<_> = nodes.into_iter()
            .filter_map(|node| { // we dont want to sort directly, when we only sort valid nodes so we dont have to handle results in the sorting function
                let label = match &node {
                    Node::Inner(_) => None,
                    Node::Leaf(leaf) => Some(leaf.label.clone()),
                };
    
                // if there is a valid label search for the index in the ordered_derived_dict_keys and return it with the node
                label.and_then(|l| {
                    input_order.iter().position(|k| k == &l)
                        .map(|index| (index, node))
                })
            })
            .collect();
    
        let mut sorted_nodes = valid_nodes;
        sorted_nodes.sort_by_key(|(index, _)| *index); // sort by the index
        let sorted_nodes = sorted_nodes.into_iter().map(|(_, node)| node).collect(); // remove the index from the tuple, we want the list of nodes
    
        Ok(sorted_nodes)
    }

    /// Creates a new inner node in the Merkle Tree.
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
    /// A `Node` representing the newly created inner node.
    pub fn create_inner_node(left: Node, right: Node, index: usize) -> Node {
        let mut new_node = Node::Inner(InnerNode {
            hash: String::from("H()"),
            is_left_sibling: index % 2 == 0,
            left: Arc::new(left),
            right: Arc::new(right),
        });
        new_node.generate_hash();
        new_node
    }

    /// Calculates the next level of the Merkle tree by aggregating the hash values of the
    /// current level nodes in pairs, creating new inner nodes and adding them to the indexed merkle tree nodes.
    ///
    /// # Arguments
    ///
    /// * `current_nodes` - A vector of nodes representing the current level of the tree.
    ///
    /// # Returns
    ///
    /// A vector of nodes representing the next level of the Merkle tree.
    pub fn calculate_next_level(&mut self, current_nodes: Vec<Node>) -> Vec<Node> {
        let mut next_level_nodes: Vec<Node> = Vec::new();

        for (index, node) in current_nodes.chunks(2).enumerate() {
            let new_node =
                IndexedMerkleTree::create_inner_node(node[0].clone(), node[1].clone(), index);
            next_level_nodes.push(new_node.clone());
            self.nodes.push(new_node);
        }

        next_level_nodes
    }

    /// Calculates the root of an IndexedMerkleTree by aggregating the tree's nodes.
    ///
    /// The function performs the followig (main) steps:
    /// 1. Extracts all the leaf nodes from the tree.
    /// 2. Resets the tree's nodes to the extracted leaves.
    /// 3. Iteratively constructs parent nodes from pairs of child nodes until there is only one node left (the root).
    ///
    /// # Arguments
    ///
    /// * `self` - The mutable reference to the IndexedMerkleTree instance.
    ///
    /// # Returns
    ///
    /// * `IndexedMerkleTree` - The updated IndexedMerkleTree instance with the calculated root.
    fn calculate_root(mut self) -> Result<IndexedMerkleTree, MerkleTreeError> {
        // first get all leaves (= nodes with no children)
        let leaves: Vec<Node> = self
            .nodes
            .clone()
            .into_iter()
            .filter(|node| matches!(node, Node::Leaf(_)))
            .collect();
        // "reset" own nodes
        self.nodes = leaves.clone();

        let mut parents: Vec<Node> = self.calculate_next_level(leaves);

        while parents.len() > 1 {
            let processed_parents: Vec<Node> = self.calculate_next_level(parents);
            parents = processed_parents;
        }

        // set root not as left sibling
        let root = self.nodes.last_mut().ok_or(MerkleTreeError::EmptyMerkleTreeError)?; // TODO: are there possible other Errors? is it possible at all to have an empty tree at this point?
        root.set_left_sibling_value(false);

        Ok(self)
    }

    /// # Returns
    ///
    /// The current root node of the Indexed Merkle tree.
    pub fn get_root(&self) -> Result<&Node, MerkleTreeError> {
        self.nodes.last().ok_or(MerkleTreeError::EmptyMerkleTreeError)
    }

    /// # Returns
    ///
    /// The current commitment (hash of the root node) of the Indexed Merkle tree.
    pub fn get_commitment(&self) -> Result<String, MerkleTreeError> {
        Ok(self.get_root()?.get_hash()) 
    }

    /// Finds the index of a specific node in the indexed Merkle Tree.
    ///
    /// This function searches through the tree's nodes to find the index of a given node.
    /// It compares leaf nodes by label and inner nodes by hash. The function returns the node's
    /// index if found, or `None` if the node is not present in the tree.
    ///
    /// # Arguments
    /// * `node` - A reference to the `Node` whose index is being searched for.
    ///
    /// # Returns
    /// An `Option<usize>` indicating the index of the node if found.
    // TODO: is it better to return a Result here and in the next function?
    pub fn find_node_index(&self, node: &Node) -> Option<usize> {
        self.nodes
            .iter()
            .enumerate()
            .find_map(|(index, current_node)| match (current_node, node) {
                (Node::Leaf(current_leaf), Node::Leaf(leaf)) => {
                    if current_leaf.label == leaf.label {
                        Some(index)
                    } else {
                        None
                    }
                }
                (Node::Inner(current_inner), Node::Inner(inner)) => {
                    if current_inner.hash == inner.hash {
                        Some(index)
                    } else {
                        None
                    }
                }
                _ => None,
            })
    }

    /// Searches for a leaf node by its label in the indexed Merkle Tree.
    ///
    /// This function iterates through the tree's nodes to find a leaf node that matches the given label.
    /// If a matching leaf is found, it is returned, otherwise the function returns `None`.
    ///
    /// # Arguments
    /// * `label` - A reference to the string label of the leaf node to find.
    ///
    /// # Returns
    /// An `Option<Node>` representing the found leaf node, if any.
    pub fn find_leaf_by_label(&self, label: &String) -> Option<Node> {
        self.nodes.iter().find_map(|node| match node {
            Node::Leaf(leaf) => {
                if &leaf.label == label {
                    Some(node.clone())
                } else {
                    None
                }
            }
            _ => None,
        })
    }

    /// Doubles the size of the Merkle Tree.
    ///
    /// This function adds as many new inactive nodes to the tree as it currently contains,
    /// effectively doubling its size. This is necessary when no inactive node is available for
    /// the insertion of a new node. Each new node is marked inactive and initialized with
    /// default values.
    pub fn double_tree_size(&mut self) {
        let current_size = self.nodes.len();
        for _ in 0..current_size {
            let new_node = Node::initialize_leaf(
                false, // inactive
                false, // is_left_sibling will be set later
                Node::EMPTY_HASH.to_string(),
                Node::EMPTY_HASH.to_string(),
                Node::TAIL.to_string(),
            );
            self.nodes.push(new_node);
        }
        // update sibling status
        let new_nodes = set_left_sibling_status_for_nodes(self.nodes.clone());
        self.nodes = new_nodes;
    }


    /// Generates a proof of membership for a node at a given index in the indexed Merkle Tree.
    ///
    /// This function constructs a path of hashes leading from a specific node to the root of the tree,
    /// serving as a merkle proof of the node's membership in the tree. If the index is invalid,
    /// it returns an error, because the node doesnt exist and cant be proved as a member.
    ///
    /// # Arguments
    /// * `index` - The index of the node in the tree for which the proof is to be generated.
    ///
    /// # Returns
    /// A `Result<MerkleProof, MerkleTreeError>` containing the membership proof or an error.
    pub fn generate_proof_of_membership(&self, index: usize) -> Result<MerkleProof, MerkleTreeError> {
        // if the index is outside of the valid range of the tree, there is no proof
        if index >= self.nodes.len() {
            return Err(MerkleTreeError::IndexError(index.to_string()));
        }

        // create a vec with hashes on the way to the root as proof (proof-list so to say)
        let mut proof_path: Vec<Node> = vec![];
        let mut current_index = index;

        // add the leaf node itself to the proof list
        let leaf_node = self.nodes[current_index].clone();
        proof_path.push(leaf_node);

        // climb the tree until we reach the root and add each parent node sibling of the current node to the proof list
        while current_index < self.nodes.len() - 1 {
            // if the current node is divisible by 2, it is a left node, then the sibling is right (index + 1) and vice versa
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };
            let sibling_node = self.nodes[sibling_index].clone();
            proof_path.push(sibling_node);
            // we have to round up, because if there are e.g. 15 elements (8 leaves) the parent of index 0 would be 7 (or 7.5)
            // but the actual parent of index 0 is 8
            current_index =
                ((current_index as f64 + self.nodes.len() as f64) / 2.0).ceil() as usize;
        }
        let root = self.get_commitment()?;

        Ok((Some(root.clone()), Some(proof_path)))
    }

    /// Generates a non-membership proof for a given node in the indexed Merkle Tree.
    ///
    /// This function verifies that a node is not part of the tree. It does so by finding a place in the
    /// tree where the given node *should* exist based on its label and proving it is not there. Suitable
    /// for scenarios where proving the absence of data is required, e.g. important for guaranteeing uniqueness.
    ///
    /// # Arguments
    /// * `node` - A reference to the `Node` for which the non-membership proof is required.
    ///
    /// # Returns
    /// A `Result<(MerkleProof, Option<usize>), MerkleTreeError>` containing the non-membership proof and
    /// the index of the "closest" valid node, or an error.
    pub fn generate_non_membership_proof(&self, node: &Node) -> Result<(MerkleProof, Option<usize>), MerkleTreeError> {
        let given_node_as_leaf = match node {
            Node::Leaf(leaf) => leaf,
            _ => return Err(MerkleTreeError::NotFoundError(format!("Leaf"))),
        };
    
        let mut found_index = None;
        for (index, current_node) in self.nodes.iter().enumerate() {
            if let Node::Leaf(current_leaf) = current_node {
                let current_label = BigInt::from_str_radix(&current_leaf.label, 16);
                let current_next = BigInt::from_str_radix(&current_leaf.next, 16);
                let new_label = BigInt::from_str_radix(&given_node_as_leaf.label, 16);
    
                if let (Ok(current_label), Ok(current_next), Ok(new_label)) = (current_label, current_next, new_label) {
                    if current_label < new_label && new_label < current_next {
                        found_index = Some(index);
                        break;
                    }
                } else {
                    return Err(MerkleTreeError::InvalidFormatError(format!("BigInt from label or next pointer")));
                }
            }
        }
    
        match found_index {
            Some(index) => Ok((self.generate_proof_of_membership(index)?, Some(index))),
            None => Err(MerkleTreeError::MerkleProofError),
        }
    }


    /// Generates a proof of update for a node at a given index in the indexed Merkle Tree.
    ///
    /// This function first generates a proof of membership for the old node state, updates the node,
    /// recalculates the root, and then generates a new proof of membership for the updated node. It returns
    /// both the old and new proofs along with the updated tree. 
    ///
    /// # Arguments
    /// * `index` - The index of the node to be updated.
    /// * `new_node` - The new state of the node.
    ///
    /// # Returns
    /// A `Result<(UpdateProof, Self), MerkleTreeError>` containing the the old root, the old proof, the new root and the new proof, the updated tree.
    pub fn generate_update_proof(mut self, index: usize, new_node: Node) -> Result<(UpdateProof, Self), MerkleTreeError> {
        // generate old proof
        let old_proof = self.generate_proof_of_membership(index)?;

        // update node and calculate new root
        self.nodes[index] = new_node;
        self = self.clone().calculate_root()?;

        // generate new proof
        let new_proof = self.clone().generate_proof_of_membership(index)?;

        // return old and new proof
        Ok(((old_proof, new_proof), self))
    }

    /// Generates proofs required for inserting a node into the indexed Merkle Tree.
    ///
    /// This function starts with a non-membership check to ensure that the index (i.e. the label) does not yet exist in the tree 
    /// and thus to determine the index of the node to be changed.
    /// It then generates two update proofs: one for updating the next pointer of the existing node, and another
    /// for the actual insertion of the new node, i.e. updating an inactive and therefore empty leaf node. 
    /// If there are no more empty leaf nodes, the capacity in the tree is doubled.
    ///
    /// # Arguments
    /// * `new_node` - The new node to be inserted.
    ///
    /// # Returns
    /// A `Result<(MerkleProof, UpdateProof, UpdateProof), MerkleTreeError>` containing the non-membership proof and two update proofs.
    pub fn generate_proof_of_insert(
        &mut self,
        new_node: &Node,
    ) -> Result<(MerkleProof, UpdateProof, UpdateProof), MerkleTreeError> {
        // perform non-membership check in order to return the index of the node to be changed
        let (proof_of_non_membership, old_index) =
            self.clone().generate_non_membership_proof(new_node)?;

        if old_index.is_none() {
            return Err(MerkleTreeError::MerkleProofError);
        }

        // we know that the index is valid, so we can unwrap it
        let old_index = old_index.unwrap();

        // generate first update proof, changing only the next pointer from the old node
        let mut new_old_node = self.nodes[old_index].clone();
        Node::update_next_pointer(&mut new_old_node, new_node);
        new_old_node.generate_hash();
        let (first_update_proof, updated_self) = self
            .clone()
            .generate_update_proof(old_index, new_old_node.clone())?;

        *self = updated_self;

        // we checked if the found index in the non-membership is from an incative node, if not we have to search for another inactive node to update and if we cant find one, we have to double the tree
        let mut new_index = None;
        for (i, node) in self.nodes.iter_mut().enumerate() {
            if !node.is_active() {
                new_index = Some(i);
                break;
            }
        }

        let new_index = match new_index {
            Some(index) => index,
            None => {
                // double the tree
                self.double_tree_size();
                // take the first inactive node
                self.nodes.iter_mut().enumerate().find(|(_, node)| !node.is_active()).map(|(i, _)| i).expect("New inactive node not found after doubling the tree.")
            }
        };

        // generate second update proof
        let (second_update_proof, updated_self) = self
            .clone()
            .generate_update_proof(new_index, new_node.clone())?;

        *self = updated_self;

        Ok((
            proof_of_non_membership,
            first_update_proof,
            second_update_proof,
        ))
    }

    /// Verifies a Merkle proof against a given root hash.
    ///
    /// This function takes a Merkle proof and verifies that the hashes in the proof's path, when
    /// combined in the correct order, match the given root hash. It's critical for ensuring the integrity
    /// and correctness of proofs in the (indexed) Merkle Tree.
    ///
    /// # Arguments
    /// * `proof` - A reference to the `MerkleProof` to be verified.
    ///
    /// # Returns
    /// `true` if the proof is valid and matches the root hash, `false` otherwise.
    fn verify_merkle_proof(proof: &MerkleProof) -> bool {
        match proof {
            (Some(root), Some(path)) => {
                // save the first now as current hash and skip it in the loop to start with the second
                let mut current_hash = path[0].get_hash();

                for node in path.iter().skip(1) {
                    let hash = if node.is_left_sibling() {
                        format!("{} || {}", node.get_hash(), current_hash)
                    } else {
                        format!("{} || {}", current_hash, node.get_hash())
                    };
                    current_hash = sha256(&hash);
                }
                return &current_hash == root;
            }
            _ => false,
        }
    }

    /// Verifies an update proof in the indexed Merkle Tree.
    ///
    /// This function checks both the old and new "state" proofs of a node to ensure that the update
    /// operation has been performed correctly and the tree's integrity is maintained.
    ///
    /// # Arguments
    /// * `old_proof` - The proof of the node's state before the update.
    /// * `new_proof` - The proof of the node's state after the update.
    ///
    /// # Returns
    /// `true` if both proofs are valid, `false` otherwise.
    pub fn verify_update_proof((old_proof, new_proof): &UpdateProof) -> bool {
        IndexedMerkleTree::verify_merkle_proof(old_proof)
            && IndexedMerkleTree::verify_merkle_proof(new_proof)
    }

    /// Verifies the proofs associated with a node insertion in the indexed Merkle Tree.
    ///
    /// This function confirms the non-membership of the node before insertion, and then verifies
    /// the two update proofs representing the tree's state changes due to the insertion. Essential for
    /// validating insert operations in the tree.
    ///
    /// # Arguments
    /// * `non_membership_proof` - The proof of the node's non-membership before insertion.
    /// * `first_proof` - The first update proof (pointer update of existing ("closest") node).
    /// * `second_proof` - The second update proof (update of empty inactive node with new values).
    ///
    /// # Returns
    /// `true` if all proofs are valid, `false` otherwise.
    pub fn verify_insert_proof(
        non_membership_proof: &MerkleProof,
        first_proof: &UpdateProof,
        second_proof: &UpdateProof,
    ) -> bool {
        IndexedMerkleTree::verify_merkle_proof(non_membership_proof)
            && IndexedMerkleTree::verify_update_proof(first_proof)
            && IndexedMerkleTree::verify_update_proof(second_proof)
    }
}
