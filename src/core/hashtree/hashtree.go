// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/hashtree/hashtree.go
package hashtree

import (
	"fmt"
	"io/ioutil"
	"os"
	"syscall"

	"github.com/holiman/uint256"
	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/syndtr/goleveldb/leveldb"
)

// SIPS-0011 https://github.com/sphinxorg/SIPS/wiki/sips0011

var maxFileSize = 1 << 30 // 1 GiB max file size for memory mapping

// HashTreeNode represents a node in the hash tree
// HashTreeNode represents a node in the hash tree
type HashTreeNode struct {
	Hash   *uint256.Int  `json:"hash"`             // 256-bit Hash of the node's data
	Left   *HashTreeNode `json:"left,omitempty"`   // Left child node
	Right  *HashTreeNode `json:"right,omitempty"`  // Right child node
	Parent *HashTreeNode `json:"parent,omitempty"` // Parent node
}

// NewHashTree creates a new HashTree instance with the given leaves.
func NewHashTree(leaves [][]byte) *HashTree {
	return &HashTree{
		Leaves: leaves,
		Root:   nil,
	}
}

// HashTree represents the Merkle hash tree.
type HashTree struct {
	Leaves [][]byte      // The leaves of the tree
	Root   *HashTreeNode // The root node of the tree
}

// Build constructs the Merkle hash tree from the leaves.
func (tree *HashTree) Build() error {
	tree.Root = BuildHashTree(tree.Leaves)
	return nil
}

// Compute the hash of a given data slice using SphinxHash and return a uint256 value.
func computeUint256(data []byte) *uint256.Int {
	// Compute the hash using SpxHash
	hash := common.SpxHash(data)

	// Convert the resulting hash (32 bytes for 256-bit) to uint256
	return uint256.NewInt(0).SetBytes(hash)
}

// HashToBytes32 returns the canonical 32-byte big-endian encoding of a
// uint256 hash value, preserving leading zero bytes.
//
// WARNING: (*uint256.Int).Bytes() returns the minimal-length representation
// (it strips leading 0x00 bytes), so a hash that happens to start with 0x00
// would silently become 31 (or fewer) bytes. Every consumer of a merkle root
// in the signing pipeline (TransactionAuthBundle.MerkleRootHash, proof
// leaves, P2P discovery messages, consensus serialization, multisig stores)
// requires exactly 32 bytes and rejects anything else with
// "invalid merkle root hash length: expected 32, got N" (surfaced to wallets
// as JSON-RPC -32602). Always use this helper — never .Bytes() — when a
// fixed 32-byte hash is needed.
func HashToBytes32(h *uint256.Int) []byte {
	if h == nil {
		return make([]byte, 32)
	}
	b := h.Bytes32()
	out := make([]byte, 32)
	copy(out, b[:])
	return out
}

// RootBytes32 returns the canonical 32-byte big-endian encoding of a
// HashTreeNode's hash. See HashToBytes32 for why .Hash.Bytes() must not be
// used directly.
func (node *HashTreeNode) RootBytes32() []byte {
	if node == nil || node.Hash == nil {
		return make([]byte, 32)
	}
	return HashToBytes32(node.Hash)
}

// GetSiblingNode returns the sibling of the current node if it exists.
func (node *HashTreeNode) GetSiblingNode(leafIndex int) (*HashTreeNode, error) {
	// If the current node is a leaf, we can check its sibling based on its position
	// This assumes that the leaf nodes are at the bottom level of the tree.
	if node.Left != nil && node.Right != nil {
		if leafIndex%2 == 0 {
			return node.Right, nil // Return right child if the current index is even (left child)
		} else {
			return node.Left, nil // Return left child if the current index is odd (right child)
		}
	}
	return nil, fmt.Errorf("no sibling found for the given node")
}

// BuildHashTree builds a Merkle hash tree from leaf nodes.
// It returns the root node of the hash tree, which is computed by repeatedly
// combining and hashing pairs of leaf nodes and intermediate nodes.
func BuildHashTree(leaves [][]byte) *HashTreeNode {
	// Create an array of hash tree nodes, where each leaf node is hashed.
	nodes := make([]*HashTreeNode, len(leaves))
	for i, leaf := range leaves {
		nodes[i] = &HashTreeNode{Hash: computeUint256(leaf)}
	}

	// Continue building the tree until there is only one node left, the root.
	for len(nodes) > 1 {
		var nextLevel []*HashTreeNode

		// Iterate over the current level two nodes at a time.
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				// Combine the hashes of two sibling nodes (left and right).
				left, right := nodes[i], nodes[i+1]
				// Concatenate the two hashes and compute the hash of the result to create the parent node.
				//
				// CONSENSUS-FROZEN LEGACY BEHAVIOR — DO NOT "FIX" by switching
				// to fixed 32-byte concatenation:
				// (*uint256.Int).Bytes() is minimal-length (strips leading
				// 0x00), so this hashes a 62/63/64-byte preimage depending on
				// the child hashes. Fixed-width padding would compute a
				// DIFFERENT parent hash (and therefore a different receipt
				// root) for ~3% of trees — any tree where a non-root node
				// hash starts with 0x00. The stored receipt root is re-derived
				// from sigParts during stateless replay verification
				// (RebuildCanonicalReplayEvidence → VerifyTransactionAuthStateless
				// → buildHashTreeFromSignature → VerifyCommitmentInRoot) and
				// compared against the stored root, so old and new code MUST
				// compute byte-identical trees or historical txs fail replay.
				// The 31-byte export bug is fixed at the export boundary
				// (HashToBytes32) instead — safe because the 32-byte admission
				// gate rejects anything shorter, so no stored data could ever
				// have depended on the old export behavior.
				hash := computeUint256(append(left.Hash.Bytes(), right.Hash.Bytes()...))
				// Create the parent node and set the parent pointers for the children
				parent := &HashTreeNode{Hash: hash, Left: left, Right: right}
				left.Parent = parent
				right.Parent = parent
				// Append the new parent node to the next level, storing references to its children.
				nextLevel = append(nextLevel, parent)
			} else {
				// If there is an odd number of nodes, do not duplicate the last node, carry it over as is.
				// We could either keep it unchanged or mark it as invalid if desired.
				nextLevel = append(nextLevel, nodes[i])
			}
		}

		// Move up one level, using the newly created nodes as the current level.
		nodes = nextLevel
	}

	// Return the single remaining node, which is the root of the hash tree.
	return nodes[0]
}

// Save root hash to file
func SaveRootHashToFile(root *HashTreeNode, filename string) error {
	// Save the root hash (as a byte array) to a file.
	// Use the fixed 32-byte encoding: .Hash.Bytes() would drop a leading
	// zero byte and write a 31-byte file ~1/256 of the time.
	return ioutil.WriteFile(filename, root.RootBytes32(), 0644)
}

// Load root hash from file
func LoadRootHashFromFile(filename string) ([]byte, error) {
	// Read the root hash from a file and return as a byte array
	return ioutil.ReadFile(filename)
}

// SaveLeavesToDB saves leaf node data to LevelDB.
func SaveLeavesToDB(db *leveldb.DB, leaves [][]byte) error {
	// Iterate over the leaves to be saved to the database
	for i, leaf := range leaves {
		// Generate a unique key for each leaf using a formatted string with its index
		key := fmt.Sprintf("leaf-%d", i)
		// Store the leaf node in LevelDB using the generated key
		err := db.Put([]byte(key), leaf, nil)
		if err != nil {
			return err // Return the error to the caller
		}
	}
	// Return nil to indicate that all leaf nodes were saved successfully
	return nil
}

// Fetch leaf from LevelDB
func FetchLeafFromDB(db *leveldb.DB, key string) ([]byte, error) {
	// Retrieve leaf node from LevelDB using the key
	return db.Get([]byte(key), nil)
}

// leafKeyPrefix scopes every saved leaf key. Keys are formed as
// leaf:<messageID>:<index>, where messageID is the signer-provided evidence ID
// (a hash of the signed message). This keeps one signed message's leaves from
// colliding with another's when a shared LevelDB serves many signers.
const leafKeyPrefix = "leaf:"

// PruneOldLeaves removes leaf nodes for ONE evidence batch (identified by id)
// from the LevelDB. Because keys are prefixed with the batch's id, pruning one
// message's leaves can never touch another message's leaves.
func PruneOldLeaves(db *leveldb.DB, id string, numLeaves int) error {
	if db == nil {
		return fmt.Errorf("leveldb is nil")
	}
	// Loop over the number of leaves to be deleted
	for i := 0; i < numLeaves; i++ {
		// Generate the key for the leaf node within this evidence batch
		key := fmt.Sprintf("%s%s:%d", leafKeyPrefix, id, i)
		// Attempt to delete the leaf node by key
		err := db.Delete([]byte(key), nil)
		// If an error occurs, return it, except for the ErrNotFound case
		if err != nil && err != leveldb.ErrNotFound {
			return err
		}
	}
	// Return nil if no errors occurred
	return nil
}

// SaveLeavesBatchToDB performs batch operations for LevelDB to save leaf nodes
// efficiently. id scopes the batch (e.g. a hash of the signed message), so each
// signed message's five leaves are individually addressable in a shared DB.
func SaveLeavesBatchToDB(db *leveldb.DB, id string, leaves [][]byte) error {
	if db == nil {
		return fmt.Errorf("leveldb is nil")
	}
	// Create a new batch to accumulate multiple write operations
	batch := new(leveldb.Batch)
	// Iterate over the leaves to be added
	for i, leaf := range leaves {
		// Generate the key for each leaf node within this evidence batch
		key := fmt.Sprintf("%s%s:%d", leafKeyPrefix, id, i)
		// Add the leaf node to the batch
		batch.Put([]byte(key), leaf)
	}
	// Execute the batch write to LevelDB
	return db.Write(batch, nil)
}

// FetchLeafConcurrent retrieves a leaf node from LevelDB while ensuring safe concurrent access.
func FetchLeafConcurrent(db *leveldb.DB, key string) ([]byte, error) {
	// Retrieve the leaf node from LevelDB
	return db.Get([]byte(key), nil)
}

// MemoryMapFile maps a file into memory with size checks
func MemoryMapFile(filename string) ([]byte, error) {
	// Open the file for reading
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	// Obtain file descriptor and file stats
	fd := int(file.Fd())
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("error getting file info: %w", err)
	}
	// Check if the file exceeds the max allowed size
	if stat.Size > int64(maxFileSize) {
		return nil, fmt.Errorf("file size exceeds maximum allowed size of %d bytes", maxFileSize)
	}

	// Memory map the file into the memory and return the bytes
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}
	return data, nil
}
