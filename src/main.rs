use sha2::{Digest, Sha256};
use std::fmt;

/// A node in the Merkle tree
#[derive(Debug, Clone)]
struct Node {
    hash: Vec<u8>,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

impl Node {
    /// Creates a new leaf node with the given data
    fn new_leaf(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize().to_vec();
        
        Node {
            hash,
            left: None,
            right: None,
        }
    }
    
    /// Creates a new internal node from two child nodes
    fn new_internal(left: Node, right: Node) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&left.hash);
        hasher.update(&right.hash);
        let hash = hasher.finalize().to_vec();
        
        Node {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }
}

/// Display implementation to show hash as hex string
impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.hash))
    }
}

/// A Merkle tree structure
pub struct MerkleTree {
    root: Option<Node>,
}

impl MerkleTree {
    /// Creates a new Merkle tree from a list of data items
    pub fn new(data: Vec<Vec<u8>>) -> Self {
        if data.is_empty() {
            return MerkleTree { root: None };
        }
        
        // Create leaf nodes
        let mut nodes: Vec<Node> = data.iter()
            .map(|item| Node::new_leaf(item))
            .collect();
        
        // Handle odd number of nodes by duplicating the last one
        if nodes.len() % 2 == 1 {
            nodes.push(nodes.last().unwrap().clone());
        }
        
        // Build the tree bottom-up
        while nodes.len() > 1 {
            let mut next_level = Vec::new();
            
            for i in (0..nodes.len()).step_by(2) {
                let left = nodes[i].clone();
                let right = nodes[i + 1].clone();
                let parent = Node::new_internal(left, right);
                next_level.push(parent);
            }
            
            nodes = next_level;
        }
        
        MerkleTree { root: Some(nodes.remove(0)) }
    }
    
    /// Returns the Merkle root hash, if it exists
    pub fn root_hash(&self) -> Option<Vec<u8>> {
        self.root.as_ref().map(|node| node.hash.clone())
    }
    
    /// Returns the Merkle root hash as a hex string
    pub fn root_hash_hex(&self) -> Option<String> {
        self.root_hash().map(|hash| hex::encode(hash))
    }
    
    /// Generates a proof that a leaf with given data exists in the tree
    pub fn generate_proof(&self, data: &[u8]) -> Option<MerkleProof> {
        let leaf_hash = {
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().to_vec()
        };
        
        let mut proof = Vec::new();
        let mut found = false;
        
        // Helper function to traverse the tree and build the proof
        fn build_proof(
            node: &Node, 
            target_hash: &[u8], 
            proof: &mut Vec<(Vec<u8>, bool)>, 
            found: &mut bool
        ) -> bool {
            // If we're at a leaf node
            if node.left.is_none() && node.right.is_none() {
                return node.hash == target_hash;
            }
            
            // Check left subtree
            if let Some(left) = &node.left {
                if build_proof(left, target_hash, proof, found) {
                    *found = true;
                    // Add right sibling to the proof
                    if let Some(right) = &node.right {
                        proof.push((right.hash.clone(), false)); // false means it's a right sibling
                    }
                    return true;
                }
            }
            
            // Check right subtree
            if let Some(right) = &node.right {
                if build_proof(right, target_hash, proof, found) {
                    *found = true;
                    // Add left sibling to the proof
                    if let Some(left) = &node.left {
                        proof.push((left.hash.clone(), true)); // true means it's a left sibling
                    }
                    return true;
                }
            }
            
            false
        }
        
        if let Some(root) = &self.root {
            build_proof(root, &leaf_hash, &mut proof, &mut found);
            
            if found {
                return Some(MerkleProof {
                    proof_hashes: proof,
                    leaf_hash,
                    root_hash: root.hash.clone(),
                });
            }
        }
        
        None
    }
    
    /// Verifies whether data is included in the tree using a proof
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        if let Some(root) = &self.root {
            proof.verify(&root.hash)
        } else {
            false
        }
    }
}

/// A proof that a particular data item is in the Merkle tree
pub struct MerkleProof {
    proof_hashes: Vec<(Vec<u8>, bool)>, // (hash, is_left)
    leaf_hash: Vec<u8>,
    root_hash: Vec<u8>,
}

impl MerkleProof {
    /// Verifies the proof against the given root hash
    pub fn verify(&self, root_hash: &[u8]) -> bool {
        let mut current_hash = self.leaf_hash.clone();
        
        for (sibling_hash, is_left) in &self.proof_hashes {
            let mut hasher = Sha256::new();
            
            if *is_left {
                // Sibling is on the left
                hasher.update(sibling_hash);
                hasher.update(&current_hash);
            } else {
                // Sibling is on the right
                hasher.update(&current_hash);
                hasher.update(sibling_hash);
            }
            
            current_hash = hasher.finalize().to_vec();
        }
        
        current_hash == root_hash
    }
}

fn main() {
    println!("Merkle Tree Example");
    
    // Create some example data
    let data = vec![
        b"Transaction 1".to_vec(),
        b"Transaction 2".to_vec(),
        b"Transaction 3".to_vec(),
        b"Transaction 4".to_vec(),
    ];
    
    // Build a Merkle tree from the data
    let tree = MerkleTree::new(data.clone());
    
    // Print the root hash
    println!("Merkle Root: {}", tree.root_hash_hex().unwrap());
    
    // Generate a proof for the second transaction
    let proof = tree.generate_proof(&b"Transaction 2".to_vec())
        .expect("Failed to generate proof!");
    
    // Verify the proof
    let is_valid = tree.verify_proof(&proof);
    println!("Proof verification: {}", if is_valid { "Valid" } else { "Invalid" });
    
    // Try with invalid data
    let is_valid = tree.generate_proof(&b"Transaction 0".to_vec()).is_none();
    println!("Invalid data test: {}", if is_valid { "Passed" } else { "Failed" });
}