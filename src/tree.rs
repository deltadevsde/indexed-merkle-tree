use num::{BigInt, Num};
use serde::{Deserialize, Serialize};

use crate::error::MerkleTreeError;
use crate::node::{self, InnerNode, LeafNode, Node};
use crate::sha256;

// `MerkleProof` contains the root hash and a `Vec<Node>>` following the path from the leaf to the root.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MerkleProof {
    // Root hash of the Merkle Tree.
    pub root_hash: String,
    // Path from the leaf to the root.
    pub path: Vec<Node>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NonMembershipProof {
    // Root hash of the Merkle Tree.
    pub merkle_proof: MerkleProof,
    // Path from the leaf to the root.
    pub missing_node: LeafNode,
    pub missing_node_index: usize,
}

// `UpdateProof` contains the old `MerkleProof` and the new `MerkleProof` after the update operation
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateProof {
    // Merkle proof before the update.
    pub old_proof: MerkleProof,
    // Merkle proof after the update.
    pub new_proof: MerkleProof,
}

// `InsertProof` contains the non-membership proof of the new `Node` (to guarantee uniqueness), and two `UpdateProof`s.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InsertProof {
    // Non-membership proof of the new node.
    pub non_membership_proof: NonMembershipProof,
    // Update proof of the previous node's next pointer.
    pub first_proof: UpdateProof,
    // Update proof of the new node.
    pub second_proof: UpdateProof,
}

impl NonMembershipProof {
    /// Verifies the non-membership proof of a node in the indexed Merkle Tree.
    ///
    /// This function checks the non-membership proof of a node to ensure that the node is not present in the tree.
    /// It verifies the proof's path and the absence of the node in the tree.
    ///
    /// # Returns
    /// `true` if the proof is valid and the node is not present, `false` otherwise.
    pub fn verify(&self) -> bool {
        if let Some(Node::Leaf(leaf)) = self.merkle_proof.path.first() {
            if self.merkle_proof.verify()
                && self.missing_node.label > leaf.label
                && self.missing_node.label < leaf.next
            {
                return true;
            }
        }
        false
    }
}

impl InsertProof {
    /// Verifies the proofs associated with a node insertion in the indexed Merkle Tree.
    ///
    /// This function confirms the non-membership of the node before insertion, and then verifies
    /// the two update proofs representing the tree's state changes due to the insertion. Essential for
    /// validating insert operations in the tree.
    ///
    /// # Returns
    /// `true` if all proofs are valid, `false` otherwise.
    pub fn verify(&self) -> bool {
        self.non_membership_proof.verify()
            && self.first_proof.verify()
            && self.second_proof.verify()
    }
}

impl UpdateProof {
    /// Verifies an update proof in the indexed Merkle Tree.
    ///
    /// This function checks both the old and new "state" proofs of a node to ensure that the update
    /// operation has been performed correctly and the tree's integrity is maintained.
    ///
    /// # Returns
    /// `true` if both proofs are valid, `false` otherwise.
    pub fn verify(&self) -> bool {
        self.old_proof.verify() && self.new_proof.verify()
    }
}

impl MerkleProof {
    /// Verifies a Merkle proof against a given root hash.
    ///
    /// This function takes a Merkle proof and verifies that the hashes in the proof's path, when
    /// combined in the correct order, match the given root hash. It's critical for ensuring the integrity
    /// and correctness of proofs in the (indexed) Merkle Tree.
    ///
    /// # Returns
    /// `true` if the proof is valid and matches the root hash, `false` otherwise.
    pub fn verify(&self) -> bool {
        match (&self.root_hash, &self.path) {
            (root, path) if !path.is_empty() => {
                // save the first now as current hash and skip it in the loop to start with the second
                let mut current_hash = path[0].get_hash();

                for node in path.iter().skip(1) {
                    let hash = if node.is_left_sibling() {
                        format!("{}{}", node.get_hash(), current_hash)
                    } else {
                        format!("{}{}", current_hash, node.get_hash())
                    };
                    current_hash = sha256(&hash);
                }
                return &current_hash == root;
            }
            _ => false,
        }
    }
}

/// Represents different Proof variants of an `IndexedMerkleTree`.
///
/// Variants:
/// - `Update(UpdateProof)`: Represents a proof for an update operation.
/// - `Insert(InsertProof)`: Represents a proof for an insert operation.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Proof {
    Update(UpdateProof),
    Insert(InsertProof),
}

/// Represents an indexed merkle tree.
///
/// This structure encapsulates a merkle tree where `Node`s are indexed, facilitating efficient
/// updates and proofs, especially non-membership proofs.
///
/// Fields:
/// - `nodes`: A vector of `Node` elements, representing the nodes of the indexed merkle tree.
#[derive(Serialize, Deserialize, Clone)]
pub struct IndexedMerkleTree {
    pub nodes: Vec<Node>,
}

impl IndexedMerkleTree {
    /// Creates a new `IndexedMerkleTree` from a given `nodes` vector.
    ///
    /// # Arguments
    /// * `nodes` - A vector of `Node` elements from which the Merkle tree will be built.
    ///
    /// # Returns
    /// A `Result<Self, MerkleTreeError>` representing the initialized tree or an error.
    pub fn new(nodes: Vec<Node>) -> Result<Self, MerkleTreeError> {
        // TODO(@distractedm1nd): Issue #3
        let parsed_nodes = set_left_sibling_status_for_nodes(nodes);

        let mut tree = Self {
            nodes: parsed_nodes,
        };
        tree.calculate_root()?;
        Ok(tree)
    }

    /// Creates a new `IndexedMerkleTree` of a given size
    ///
    /// # Arguments
    /// * `size` - The number of nodes in the tree.
    ///
    /// # Returns
    /// A `Result<Self, MerkleTreeError>` representing the initialized tree or an error.
    pub fn new_with_size(size: usize) -> Result<Self, MerkleTreeError> {
        let mut nodes: Vec<Node> = Vec::with_capacity(2 * size + 1);
        let empty_hash = Node::EMPTY_HASH.to_string();
        let tail = Node::TAIL.to_string();

        let active_node = Node::new_leaf(
            true,
            true,
            empty_hash.clone(),
            empty_hash.clone(),
            tail.clone(),
        );
        nodes.push(active_node);

        let left_inactive_node = Node::new_leaf(
            false,
            true,
            empty_hash.clone(),
            empty_hash.clone(),
            tail.clone(),
        );
        let right_inactive_node =
            Node::new_leaf(false, false, empty_hash.clone(), empty_hash, tail);

        let alternates = vec![left_inactive_node, right_inactive_node]
            .into_iter()
            .cycle();

        nodes.extend(alternates.take(size - 1)); // 'size - 1' because one node is already pushed.

        IndexedMerkleTree::new(nodes)
    }

    /// Recursively creates the inner nodes to the root of the indexed merkle tree from the passed nodes.
    ///
    /// When called, this function expects the passed nodes to be leaf nodes.
    /// It assumes these are the only nodes present in `self.nodes`.
    fn rehash_inner_nodes(&mut self, current_layer: &Vec<Node>) {
        for (index, node) in current_layer.chunks(2).enumerate() {
            let new_node = Node::Inner(InnerNode::new(node[0].clone(), node[1].clone(), index));
            self.nodes.push(new_node);
        }

        let remaining = current_layer.len() / 2;
        if remaining > 1 {
            self.rehash_inner_nodes(&self.nodes[self.nodes.len() - remaining..].to_vec());
        }
    }

    /// Rehashes the inner nodes of the indexed merkle tree from the existing leaf nodes.
    ///
    /// This is done when first initializing the tree, as well as when nodes are updated.
    fn rebuild_tree_from_leaves(&mut self) {
        // let leafcount = (self.nodes.len() + 1) / 2;
        // Will always be truncated so the default value doesnt matter
        self.nodes.retain(|node| matches!(node, Node::Leaf(_)));
        // self.nodes.resize(leafcount, Node::default());
        self.rehash_inner_nodes(&self.nodes.clone());
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
    /// * `Result<(), MerkleTreeError>` - A result indicating the success or failure of the operation.
    fn calculate_root(&mut self) -> Result<(), MerkleTreeError> {
        self.rebuild_tree_from_leaves();

        // set root not as left sibling
        let root = self
            .nodes
            .last_mut()
            .ok_or(MerkleTreeError::EmptyMerkleTreeError)?; // TODO: are there possible other Errors? is it possible at all to have an empty tree at this point?
        root.set_left_sibling_value(false);

        Ok(())
    }

    /// # Returns
    ///
    /// The current root node of the Indexed Merkle tree.
    pub fn get_root(&self) -> Result<&Node, MerkleTreeError> {
        self.nodes
            .last()
            .ok_or(MerkleTreeError::EmptyMerkleTreeError)
    }

    /// # Returns
    ///
    /// The current commitment (hash of the root node) of the Indexed Merkle tree.
    pub fn get_commitment(&self) -> Result<String, MerkleTreeError> {
        Ok(self.get_root()?.get_hash().to_string())
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
    pub fn double_tree_size(&mut self) -> Result<(), MerkleTreeError> {
        let current_size = (self.nodes.len() + 1) / 2;
        self.nodes = self.nodes[0..current_size].to_vec();
        self.nodes
            .extend(std::iter::repeat_with(|| Node::default()).take(current_size));
        // update sibling status
        self.nodes = set_left_sibling_status_for_nodes(self.nodes.clone());
        self.calculate_root()
    }

    /// Generates a membership proof for a node at a given index in the indexed merkle tree.
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
    pub fn generate_membership_proof(&self, index: usize) -> Result<MerkleProof, MerkleTreeError> {
        // if the index is outside of the valid range of the tree, there is no proof
        if index >= self.nodes.len() {
            return Err(MerkleTreeError::IndexError(index.to_string()));
        }

        let mut proof_path: Vec<Node> = vec![];
        let mut current_index = index;

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

        Ok(MerkleProof {
            root_hash: root,
            path: proof_path,
        })
    }

    /// Generates a non-membership proof for a given node in the indexed merkle tree.
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
    pub fn generate_non_membership_proof(
        &self,
        node: &Node,
    ) -> Result<NonMembershipProof, MerkleTreeError> {
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

                if let (Ok(current_label), Ok(current_next), Ok(new_label)) =
                    (current_label, current_next, new_label)
                {
                    if current_label < new_label && new_label < current_next {
                        found_index = Some(index);
                        break;
                    }
                } else {
                    return Err(MerkleTreeError::InvalidFormatError(format!(
                        "BigInt from label or next pointer"
                    )));
                }
            }
        }

        // Verify that the node itself does not exist by searching through the tree's nodes.
        if self.find_leaf_by_label(&given_node_as_leaf.label).is_some() {
            return Err(MerkleTreeError::MerkleProofError);
        }

        match found_index {
            Some(index) => Ok(NonMembershipProof {
                merkle_proof: self.generate_membership_proof(index)?,
                missing_node_index: index,
                missing_node: given_node_as_leaf.clone(),
            }),
            None => Err(MerkleTreeError::MerkleProofError),
        }
    }

    /// Updates the node with the given index in the merkle tree, returning the update proof.
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
    /// A `Result<UpdateProof, MerkleTreeError>` containing the the old root, the old proof, the new root and the new proof.
    pub fn update_node(
        &mut self,
        index: usize,
        new_node: Node,
    ) -> Result<UpdateProof, MerkleTreeError> {
        // generate old proof
        let old_proof = self.generate_membership_proof(index)?;

        // update node and calculate new root
        self.nodes[index] = new_node;
        self.calculate_root()?;

        // generate new proof
        let new_proof = self.generate_membership_proof(index)?;

        // return old and new proof
        Ok(UpdateProof {
            old_proof,
            new_proof,
        })
    }

    /// Inserts a node into the merkle tree, returning the insertion proof.
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
    pub fn insert_node(&mut self, new_node: &Node) -> Result<InsertProof, MerkleTreeError> {
        // perform non-membership check in order to return the index of the node to be changed
        let non_membership_proof = self.generate_non_membership_proof(new_node)?;

        if non_membership_proof.merkle_proof.path.first().is_none() {
            return Err(MerkleTreeError::MerkleProofError);
        }

        let old_index = non_membership_proof.missing_node_index;

        // check for an inactive node to use for the update, otherwise double the tree size
        let mut new_index = None;
        for (i, node) in self.nodes.iter().enumerate() {
            if !node.is_active() {
                new_index = Some(i);
                break;
            }
        }

        let new_index = match new_index {
            Some(index) => index,
            None => {
                // double the tree
                self.double_tree_size()?;
                // take the first inactive node
                self.nodes
                    .iter_mut()
                    .enumerate()
                    .find(|(_, node)| !node.is_active())
                    .map(|(i, _)| i)
                    .expect("New inactive node not found after doubling the tree.")
            }
        };

        // generate first update proof, changing only the next pointer from the old node
        let mut new_old_node = self.nodes[old_index].clone();
        Node::update_next_pointer(&mut new_old_node, new_node);
        new_old_node.generate_hash();

        let first_proof = self.update_node(old_index, new_old_node.clone())?;
        let second_proof = self.update_node(new_index, new_node.clone())?;

        Ok(InsertProof {
            non_membership_proof,
            first_proof,
            second_proof,
        })
    }
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
    let new: Vec<Node> = nodes
        .into_iter()
        .enumerate()
        .map(|(i, mut node)| {
            let is_left_sibling = i % 2 == 0;
            node.set_left_sibling_value(is_left_sibling);
            node
        })
        .collect();
    new
}

/// Resorts based on a specified input order.
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
    let valid_nodes: Vec<_> = nodes
        .into_iter()
        .filter_map(|node| {
            // we dont want to sort directly, when we only sort valid nodes so we dont have to handle results in the sorting function
            let label = match &node {
                Node::Inner(_) => None,
                Node::Leaf(leaf) => Some(leaf.label.clone()),
            };

            // if there is a valid label search for the index in the ordered_derived_dict_keys and return it with the node
            label.and_then(|l| {
                input_order
                    .iter()
                    .position(|k| k == &l)
                    .map(|index| (index, node))
            })
        })
        .collect();

    let mut sorted_nodes = valid_nodes;
    sorted_nodes.sort_by_key(|(index, _)| *index); // sort by the index
    let sorted_nodes = sorted_nodes.into_iter().map(|(_, node)| node).collect(); // remove the index from the tuple, we want the list of nodes

    Ok(sorted_nodes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TREE_SIZE: usize = 4;

    fn test_node() -> Node {
        Node::new_leaf(
            true,
            true,
            sha256("test_label"),
            sha256("test_value"),
            Node::TAIL.to_string(),
        )
    }

    fn create_random_nodes(count: usize) -> Vec<Node> {
        (0..count)
            .map(|i| {
                Node::new_leaf(
                    true,
                    true,
                    sha256(&format!("test_label_{}", i)),
                    sha256(&format!("test_value_{}", i)),
                    Node::TAIL.to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn test_new_with_size() {
        let n = 4;
        let tree = IndexedMerkleTree::new_with_size(n).unwrap();
        assert_eq!(tree.nodes.len(), 2 * n - 1);
    }

    #[test]
    fn test_membership_proofs() {
        let mut tree = IndexedMerkleTree::new_with_size(TREE_SIZE).unwrap();
        let node = test_node();

        let mut non_membership_proof = tree.generate_non_membership_proof(&node);
        assert!(non_membership_proof.is_ok());
        assert_eq!(non_membership_proof.unwrap().verify(), true);

        tree.insert_node(&node).unwrap();

        let membership_proof = tree.generate_membership_proof(1);
        assert!(membership_proof.is_ok());
        let proof = membership_proof.unwrap();
        assert_eq!(proof.clone().path.len(), 3);
        assert_eq!(proof.verify(), true);

        non_membership_proof = tree.generate_non_membership_proof(&node);
        assert!(non_membership_proof.is_err());
    }

    #[test]
    fn test_find_node_index() {
        let mut tree = IndexedMerkleTree::new_with_size(TREE_SIZE).unwrap();
        let node = test_node();

        let mut index = tree.find_node_index(&node);
        assert_eq!(index, None);

        tree.insert_node(&node).unwrap();

        index = tree.find_node_index(&node);
        assert_eq!(index, Some(1));
    }

    #[test]
    fn test_insert_node() {
        let mut tree = IndexedMerkleTree::new_with_size(TREE_SIZE).unwrap();
        let node = test_node();

        let result = tree.insert_node(&node);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().verify(), true);
    }

    #[test]
    fn test_update_node() {
        let mut tree = IndexedMerkleTree::new_with_size(TREE_SIZE).unwrap();
        let node = test_node();

        tree.insert_node(&node).unwrap();

        let new_node = Node::new_leaf(
            true,
            true,
            sha256("new_label"),
            sha256("new_value"),
            Node::TAIL.to_string(),
        );

        let result = tree.update_node(1, new_node);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().verify(), true);
    }

    #[test]
    fn test_find_leaf_by_label() {
        let mut tree = IndexedMerkleTree::new_with_size(TREE_SIZE).unwrap();
        let node = test_node();

        let found_node = tree.find_leaf_by_label(&sha256("test_label"));
        assert!(found_node.is_none());

        tree.insert_node(&node).unwrap();

        let found_node = tree.find_leaf_by_label(&sha256("test_label"));
        assert!(found_node.is_some())
    }

    #[test]
    fn test_double_tree_size() {
        let mut tree = IndexedMerkleTree::new_with_size(TREE_SIZE).unwrap();
        let node = test_node();

        tree.insert_node(&node).unwrap();

        assert_eq!(tree.nodes.len(), TREE_SIZE * 2 - 1);
        let res = tree.double_tree_size();
        assert!(res.is_ok());
        assert_eq!(tree.nodes.len(), (TREE_SIZE * 2 - 1) * 2 + 1);

        let found_node = tree.find_leaf_by_label(&sha256("test_label"));
        assert!(found_node.is_some());
    }

    #[test]
    fn test_insert_node_doubles_tree_size() {
        let mut tree = IndexedMerkleTree::new_with_size(TREE_SIZE).unwrap();
        let nodes = create_random_nodes(TREE_SIZE);

        nodes.iter().for_each(|node| {
            tree.insert_node(node).unwrap();
        });

        let node_count = TREE_SIZE * 2 - 1;
        assert_eq!(tree.nodes.len(), node_count * 2 + 1);
    }
}
