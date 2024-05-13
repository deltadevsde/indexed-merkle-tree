use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

extern crate alloc;

use crate::{
    node::{LeafNode, ZkNode},
    sha256,
};

#[cfg(feature = "std")]
use {
    crate::error::MerkleTreeError,
    crate::node::{InnerNode, Node},
};

// `MerkleProof` contains the root hash and a `Vec<Node>>` following the path from the leaf to the root.
#[cfg(feature = "std")]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MerkleProof {
    // Root hash of the Merkle Tree.
    pub root_hash: [u8; 32],
    // Path from the leaf to the root.
    pub path: Vec<Node>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZkMerkleProof {
    // Root hash of the Merkle Tree.
    pub root_hash: [u8; 32],
    // Path from the leaf to the root.
    pub path: Vec<ZkNode>,
}

// `NonMembershipProof` contains the `MerkleProof` of the node where the returned `missing_node: LeafNode` would be found.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg(feature = "std")]
pub struct NonMembershipProof {
    // Merkle proof of the node that `missing_node` would be found between `label` and `next`.
    pub merkle_proof: MerkleProof,
    // Index of the node that `missing_node` would be found between `label` and `next`.
    pub closest_index: usize,
    // Node that would be found in the place of the node proved in `merkle_proof`.
    pub missing_node: LeafNode,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct ZkNonMembershipProof {
    pub node_to_prove: LeafNode,
    pub merkle_proof: ZkMerkleProof,
    pub closest_index: usize,
    pub missing_node: [u8; 32],
}

// `UpdateProof` contains the old `MerkleProof` and the new `MerkleProof` after the update operation
#[cfg(feature = "std")]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UpdateProof {
    // Merkle proof before the update.
    pub old_proof: MerkleProof,
    // Merkle proof after the update.
    pub new_proof: MerkleProof,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct ZkUpdateProof {
    pub old_proof: ZkMerkleProof,
    pub new_proof: ZkMerkleProof,
}

// `InsertProof` contains the non-membership proof of the new `Node` (to guarantee uniqueness), and two `UpdateProof`s.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg(feature = "std")]
pub struct InsertProof {
    // Non-membership proof of the new node.
    pub non_membership_proof: NonMembershipProof,
    // Update proof of the previous node's next pointer.
    pub first_proof: UpdateProof,
    // Update proof of the new node.
    pub second_proof: UpdateProof,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct ZkInsertProof {
    pub non_membership_proof: ZkNonMembershipProof,
    pub first_proof: ZkUpdateProof,
    pub second_proof: ZkUpdateProof,
}

#[cfg(feature = "std")]
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
                && self.missing_node.label < leaf.label
                && self.missing_node.label < leaf.next
            {
                return true;
            }
        }
        false
    }
}

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
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
                    let mut combined = Vec::new();
                    let hash = if node.is_left_sibling() {
                        combined.extend_from_slice(&node.get_hash());
                        combined.extend_from_slice(&current_hash);
                        combined
                    } else {
                        combined.extend_from_slice(&current_hash);
                        combined.extend_from_slice(&node.get_hash());
                        combined
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
#[cfg(feature = "std")]
pub enum Proof {
    Update(UpdateProof),
    Insert(InsertProof),
}

#[derive(Serialize, Deserialize, Clone)]
pub enum ZkProof {
    Update(ZkUpdateProof),
    Insert(ZkInsertProof),
}

#[cfg(feature = "std")]
impl Proof {
    pub fn prepare_for_snark(&self) -> ZkProof {
        match self {
            Proof::Update(update_proof) => ZkProof::Update(ZkUpdateProof {
                old_proof: ZkMerkleProof {
                    root_hash: update_proof.old_proof.root_hash,
                    path: update_proof
                        .old_proof
                        .path
                        .iter()
                        .map(|n| n.create_zk_node())
                        .collect(),
                },
                new_proof: ZkMerkleProof {
                    root_hash: update_proof.new_proof.root_hash,
                    path: update_proof
                        .new_proof
                        .path
                        .iter()
                        .map(|n| n.create_zk_node())
                        .collect(),
                },
            }),
            Proof::Insert(insert_proof) => ZkProof::Insert(ZkInsertProof {
                non_membership_proof: ZkNonMembershipProof {
                    node_to_prove: insert_proof.non_membership_proof.missing_node.clone(),
                    merkle_proof: ZkMerkleProof {
                        root_hash: insert_proof.non_membership_proof.merkle_proof.root_hash,
                        path: insert_proof
                            .non_membership_proof
                            .merkle_proof
                            .path
                            .iter()
                            .map(|n| n.create_zk_node())
                            .collect(),
                    },
                    closest_index: insert_proof.non_membership_proof.closest_index,
                    missing_node: insert_proof.non_membership_proof.missing_node.label,
                },
                first_proof: ZkUpdateProof {
                    old_proof: ZkMerkleProof {
                        root_hash: insert_proof.first_proof.old_proof.root_hash,
                        path: insert_proof
                            .first_proof
                            .old_proof
                            .path
                            .iter()
                            .map(|n| n.create_zk_node())
                            .collect(),
                    },
                    new_proof: ZkMerkleProof {
                        root_hash: insert_proof.first_proof.new_proof.root_hash,
                        path: insert_proof
                            .first_proof
                            .new_proof
                            .path
                            .iter()
                            .map(|n| n.create_zk_node())
                            .collect(),
                    },
                },
                second_proof: ZkUpdateProof {
                    old_proof: ZkMerkleProof {
                        root_hash: insert_proof.second_proof.old_proof.root_hash,
                        path: insert_proof
                            .second_proof
                            .old_proof
                            .path
                            .iter()
                            .map(|n| n.create_zk_node())
                            .collect(),
                    },
                    new_proof: ZkMerkleProof {
                        root_hash: insert_proof.second_proof.new_proof.root_hash,
                        path: insert_proof
                            .second_proof
                            .new_proof
                            .path
                            .iter()
                            .map(|n| n.create_zk_node())
                            .collect(),
                    },
                },
            }),
        }
    }
}

/// Represents an indexed merkle tree.
///
/// This structure encapsulates a merkle tree where `Node`s are indexed, facilitating efficient
/// updates and proofs, especially non-membership proofs.
///
/// Fields:
/// - `nodes`: A vector of `Node` elements, representing the nodes of the indexed merkle tree.
#[cfg(feature = "std")]
#[derive(Serialize, Deserialize, Clone)]
pub struct IndexedMerkleTree {
    pub nodes: Vec<Node>,
}

#[cfg(feature = "std")]
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
        let empty_hash = Node::EMPTY_HASH;
        let tail = Node::TAIL;

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
        self.nodes.retain(|node| matches!(node, Node::Leaf(_)));
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
        // self.rebuild_tree_from_leaves();
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
    pub fn get_commitment(&self) -> Result<[u8; 32], MerkleTreeError> {
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
    pub fn find_leaf_by_label(&self, label: &[u8; 32]) -> Option<Node> {
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
        self.nodes.resize(current_size * 2 + 1, Node::default());
        // update sibling status
        let new_nodes = set_left_sibling_status_for_nodes(self.nodes.clone());
        self.nodes = new_nodes;
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

        let mut proof_path: Vec<Node> = Vec::new();
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
                if &current_leaf.label < &given_node_as_leaf.label
                    && given_node_as_leaf.label < current_leaf.next
                {
                    found_index = Some(index);
                    break;
                }
            }
        }

        match found_index {
            Some(index) => Ok(NonMembershipProof {
                merkle_proof: self.generate_membership_proof(found_index.unwrap())?,
                closest_index: found_index.unwrap(),
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

        // generate first update proof, changing only the next pointer from the old node
        let mut new_old_node = self.nodes[non_membership_proof.closest_index].clone();
        Node::update_next_pointer(&mut new_old_node, new_node);
        new_old_node.generate_hash();
        let first_proof =
            self.update_node(non_membership_proof.closest_index, new_old_node.clone())?;

        // we checked if the found index in the non-membership is from an incative node, if not we have to search for another inactive node to update and if we cant find one, we have to double the tree
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
                self.double_tree_size();
                // take the first inactive node
                self.nodes
                    .iter_mut()
                    .enumerate()
                    .find(|(_, node)| !node.is_active())
                    .map(|(i, _)| i)
                    .expect("New inactive node not found after doubling the tree.")
            }
        };

        // generate second update proof
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
#[cfg(feature = "std")]
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
#[cfg(feature = "std")]
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
                    .position(|k| {
                        // TODO: remove unwrap
                        let mut bytes = [0u8; 32];
                        hex::decode_to_slice(k, &mut bytes).unwrap();
                        bytes == l
                    })
                    .map(|index| (index, node))
            })
        })
        .collect();

    let mut sorted_nodes = valid_nodes;
    sorted_nodes.sort_by_key(|(index, _)| *index); // sort by the index
    let sorted_nodes = sorted_nodes.into_iter().map(|(_, node)| node).collect(); // remove the index from the tuple, we want the list of nodes

    Ok(sorted_nodes)
}

#[cfg(feature = "std")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_size() {
        let n = 4;
        let tree = IndexedMerkleTree::new_with_size(n).unwrap();
        assert_eq!(tree.nodes.len(), 2 * n - 1);
    }
}
