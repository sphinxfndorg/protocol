// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/core/transaction/block.go
package types

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/sphinxorg/protocol/src/common"
	logger "github.com/sphinxorg/protocol/src/log"
)

// NewBlockHeader creates a new BlockHeader with proper parent-uncle relationships
// Parameters:
//   - height: Block height in the chain (0 for genesis)
//   - parentHash: Hash of the previous block
//   - difficulty: Mining difficulty for this block
//   - txsRoot: Merkle root of all transactions
//   - stateRoot: Merkle root of the state after applying transactions
//   - gasLimit: Maximum gas allowed in this block
//   - gasUsed: Actual gas used by transactions
//   - extraData: Additional data included in the block
//   - miner: Address of the miner who created the block
//   - timestamp: Block creation time (Unix timestamp)
//   - uncles: List of uncle block headers
//
// Returns: Initialized BlockHeader pointer
func NewBlockHeader(height uint64, parentHash []byte, difficulty *big.Int, txsRoot, stateRoot []byte, gasLimit, gasUsed *big.Int,
	extraData, miner []byte, timestamp int64, uncles []*BlockHeader) *BlockHeader {

	// Use time service if timestamp is 0 (auto-generate)
	// If no timestamp provided, use current time from the central time service
	if timestamp == 0 {
		timestamp = common.GetCurrentTimestamp()
	}

	// Calculate uncles hash with block height context
	// Create a cryptographic hash of all uncle blocks, including the current height for context
	unclesHash := CalculateUnclesHash(uncles, height) // Pass height here

	// Ensure extraData is never nil
	// Prevent nil pointer issues by providing empty slice if nil
	if extraData == nil {
		extraData = []byte{}
	}

	// Ensure miner is never nil
	// Prevent nil pointer issues by providing default zero address if nil
	if miner == nil {
		miner = make([]byte, 20) // Default zero address (20 bytes for Ethereum-style address)
	}

	// For genesis block, parentHash should be empty
	// Genesis block has no parent, so use empty 32-byte hash
	if height == 0 && len(parentHash) == 0 {
		parentHash = make([]byte, 32) // Empty hash for genesis
	}

	// Start with nonce 2 for regular blocks (genesis is 1)
	// Nonce is used in consensus to find a valid block hash
	var nonce string
	if height == 0 {
		// Genesis block uses nonce 1
		nonce = common.FormatNonce(1)
	} else {
		// Regular blocks start from nonce 2 and will be incremented during consensus
		nonce = common.FormatNonce(2)
	}

	// Return fully initialized block header
	return &BlockHeader{
		Version:    1,          // Block version (for protocol upgrades)
		Block:      height,     // Block number (deprecated, use Height)
		Height:     height,     // Block height in chain
		Timestamp:  timestamp,  // Block creation time
		ParentHash: parentHash, // Main chain continuity - using ParentHash consistently
		Hash:       []byte{},   // Block hash (will be calculated later)
		Difficulty: difficulty, // Mining difficulty
		Nonce:      nonce,      // Consensus nonce (string format for flexibility)
		TxsRoot:    txsRoot,    // Merkle root of transactions
		StateRoot:  stateRoot,  // Merkle root of state
		GasLimit:   gasLimit,   // Maximum gas allowed
		GasUsed:    gasUsed,    // Actual gas consumed
		UnclesHash: unclesHash, // References side blocks (uncles)
		ExtraData:  extraData,  // Additional arbitrary data
		Miner:      miner,      // Address of block creator
	}
}

// NewBlockBody creates a new BlockBody with transactions and actual uncle blocks
// Parameters:
//   - txsList: List of transactions to include in the block
//   - uncles: List of uncle block headers
//
// Returns: Initialized BlockBody pointer
func NewBlockBody(txsList []*Transaction, uncles []*BlockHeader) *BlockBody {
	// For block body, we don't have height context, so use 0 (will be overridden later)
	// Or you can modify this function to accept height if needed
	unclesHash := CalculateUnclesHash(uncles, 0) // Pass 0 as default

	// Return fully initialized block body
	return &BlockBody{
		TxsList:    txsList,    // List of transactions
		Uncles:     uncles,     // List of uncle blocks
		UnclesHash: unclesHash, // Merkle root of uncle blocks
	}
}

// NewBlock creates a new Block using the given header and body.
// Parameters:
//   - header: Block header containing metadata
//   - body: Block body containing transactions and uncles
//
// Returns: Initialized Block pointer
func NewBlock(header *BlockHeader, body *BlockBody) *Block {
	return &Block{
		Header: header, // Block metadata
		Body:   *body,  // Block content (transactions, uncles)
	}
}

// IncrementNonce increments the block nonce and updates the hash
// This is used during consensus to find a valid block hash
// Returns: Error if nonce increment fails
func (b *Block) IncrementNonce() error {
	// Check if block header exists
	if b.Header == nil {
		return fmt.Errorf("block header is nil")
	}

	// Parse current nonce from string to uint64
	// Convert the string representation to a numeric value for incrementing
	currentNonce, err := common.ParseNonce(b.Header.Nonce)
	if err != nil {
		return fmt.Errorf("failed to parse current nonce: %w", err)
	}

	// Increment nonce by 1
	newNonce := currentNonce + 1
	// Convert back to string format and store
	b.Header.Nonce = common.FormatNonce(newNonce)

	// Regenerate block hash with new nonce
	// Recalculate the block hash after nonce change
	b.FinalizeHash()

	// Log the nonce increment for debugging
	logger.Debug("Incremented nonce for block %s: %s -> %s",
		b.GetHash(), common.FormatNonce(currentNonce), b.Header.Nonce)

	return nil
}

// GetCurrentNonce returns the current nonce as uint64
// Returns: Current nonce as uint64 and error if parsing fails
func (b *Block) GetCurrentNonce() (uint64, error) {
	// Check if block header exists
	if b.Header == nil {
		return 0, fmt.Errorf("block header is nil")
	}
	// Parse and return the nonce
	return common.ParseNonce(b.Header.Nonce)
}

// CalculateUnclesHash calculates the Merkle root of uncle block headers
// Parameters:
//   - uncles: List of uncle block headers
//   - blockHeight: Height of the current block (for special handling)
//
// Returns: Hash of uncle blocks as byte slice
func CalculateUnclesHash(uncles []*BlockHeader, blockHeight uint64) []byte {
	// SPECIAL CASE: Genesis block uses your specific hardcoded hash
	// For block 0, we use a predetermined hash for consistency across all nodes
	if blockHeight == 0 {
		// Decode the hardcoded genesis uncles hash from hex string
		genesisUnclesHash, _ := hex.DecodeString("3916d45c66e84c612c8a4a403702ec44cc575fc2383dbe4e861dd29ef892bee3")
		log.Printf("🔷 Genesis block %d - Using hardcoded uncles hash: %x", blockHeight, genesisUnclesHash)
		return genesisUnclesHash
	}

	// For non-genesis blocks with empty uncles
	// If there are no uncle blocks, create a hash of "empty_uncles_list"
	if len(uncles) == 0 {
		// Use a different hash for non-genesis empty uncles
		emptyHash := common.SpxHash([]byte("empty_uncles_list"))
		log.Printf("🔷 Block %d - Using standard empty uncles hash: %x", blockHeight, emptyHash)
		return emptyHash
	}

	// Calculate Merkle root of uncle block headers (existing logic)
	// Collect all uncle block hashes
	var uncleHashes [][]byte
	for _, uncle := range uncles {
		// Only include uncles that have valid hashes
		if uncle != nil && len(uncle.Hash) > 0 {
			uncleHashes = append(uncleHashes, uncle.Hash)
		}
	}

	// If no valid uncle hashes, return hash of empty byte slice
	if len(uncleHashes) == 0 {
		return common.SpxHash([]byte{})
	}

	// Calculate Merkle root from the collected hashes
	return CalculateMerkleRootFromHashes(uncleHashes)
}

// CalculateMerkleRootFromHashes calculates Merkle root from a list of hashes
// Parameters:
//   - hashes: List of hash byte slices
//
// Returns: Merkle root as byte slice
func CalculateMerkleRootFromHashes(hashes [][]byte) []byte {
	// Handle empty list - return hash of empty data
	if len(hashes) == 0 {
		return common.SpxHash([]byte{})
	}
	// Handle single hash - return it directly (no need to hash)
	if len(hashes) == 1 {
		return hashes[0]
	}

	// Build Merkle tree from hashes
	// Create leaf nodes for each hash
	var nodes []*MerkleNode
	for _, hash := range hashes {
		nodes = append(nodes, &MerkleNode{Hash: hash, IsLeaf: true})
	}

	// Build tree level by level until only root remains
	for len(nodes) > 1 {
		var newLevel []*MerkleNode
		// Process pairs of nodes at current level
		for i := 0; i < len(nodes); i += 2 {
			if i+1 < len(nodes) {
				// Hash concatenation of left and right
				// Combine left and right child hashes and hash them
				combined := append(nodes[i].Hash, nodes[i+1].Hash...)
				newNode := &MerkleNode{
					Left:  nodes[i],                 // Left child
					Right: nodes[i+1],               // Right child
					Hash:  common.SpxHash(combined), // Parent hash
				}
				newLevel = append(newLevel, newNode)
			} else {
				// Odd number, duplicate the last one
				// When odd number of nodes, duplicate the last node
				combined := append(nodes[i].Hash, nodes[i].Hash...)
				newNode := &MerkleNode{
					Left:  nodes[i],                         // Left child (original)
					Right: &MerkleNode{Hash: nodes[i].Hash}, // Right child (duplicate)
					Hash:  common.SpxHash(combined),         // Parent hash
				}
				newLevel = append(newLevel, newNode)
			}
		}
		nodes = newLevel // Move to next level
	}

	// Return root hash
	return nodes[0].Hash
}

// GenerateBlockHash generates the block hash with proper parent-uncle relationships
// Returns: Block hash as byte slice
func (b *Block) GenerateBlockHash() []byte {
	// Check if header exists
	if b.Header == nil {
		return []byte{}
	}

	// Ensure UnclesHash is calculated from actual uncle blocks WITH HEIGHT
	// Verify that the uncles hash matches the actual uncles
	calculatedUnclesHash := CalculateUnclesHash(b.Body.Uncles, b.Header.Height) // Pass height here
	if !bytes.Equal(b.Header.UnclesHash, calculatedUnclesHash) {
		log.Printf("WARNING: UnclesHash doesn't match calculated uncles, updating UnclesHash")
		b.Header.UnclesHash = calculatedUnclesHash // Update if mismatch
	}

	// Ensure TxsRoot is calculated from Merkle tree
	// Verify that the transaction root matches the actual transactions
	if len(b.Body.TxsList) > 0 {
		calculatedMerkleRoot := b.CalculateTxsRoot()
		if !bytes.Equal(b.Header.TxsRoot, calculatedMerkleRoot) {
			log.Printf("WARNING: TxsRoot doesn't match calculated Merkle root, updating TxsRoot")
			b.Header.TxsRoot = calculatedMerkleRoot // Update if mismatch
		}
	} else {
		// For empty blocks, ensure TxsRoot is the hash of empty data
		emptyHash := common.SpxHash([]byte{})
		if len(b.Header.TxsRoot) == 0 || !bytes.Equal(b.Header.TxsRoot, emptyHash) {
			b.Header.TxsRoot = emptyHash // Set to empty hash
		}
	}

	// Convert numeric fields to byte arrays for hashing
	versionBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(versionBytes, b.Header.Version) // Version as 8 bytes

	blockNumBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumBytes, b.Header.Block) // Block number as 8 bytes

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(b.Header.Timestamp)) // Timestamp as 8 bytes

	// FIX: Convert string nonce to bytes properly
	nonceBytes, err := common.NonceToBytes(b.Header.Nonce)
	if err != nil {
		// Fallback: use zero nonce if conversion fails
		logger.Warn("Failed to convert nonce to bytes: %v, using zero nonce", err)
		nonceBytes = make([]byte, 8) // 8 zero bytes as fallback
	}

	// Include ALL important header fields in the hash calculation
	// Concatenate all header fields for hashing
	headerData := versionBytes                                      // Version (8 bytes)
	headerData = append(headerData, blockNumBytes...)               // Block number/height (8 bytes)
	headerData = append(headerData, timestampBytes...)              // Timestamp (8 bytes)
	headerData = append(headerData, b.Header.ParentHash...)         // Parent hash (32 bytes)
	headerData = append(headerData, b.Header.TxsRoot...)            // Transactions Merkle root (32 bytes)
	headerData = append(headerData, b.Header.StateRoot...)          // State Merkle root (32 bytes)
	headerData = append(headerData, nonceBytes...)                  // Nonce (as bytes, 8 bytes)
	headerData = append(headerData, b.Header.Difficulty.Bytes()...) // Difficulty (variable)
	headerData = append(headerData, b.Header.GasLimit.Bytes()...)   // Gas limit (variable)
	headerData = append(headerData, b.Header.GasUsed.Bytes()...)    // Gas used (variable)
	headerData = append(headerData, b.Header.UnclesHash...)         // Uncles hash (32 bytes)
	headerData = append(headerData, b.Header.ExtraData...)          // Extra data (variable)
	headerData = append(headerData, b.Header.Miner...)              // Miner address (20 bytes)

	// Use common.SpxHash to hash the concatenated data
	// Create the final hash using the SpxHash algorithm
	hashBytes := common.SpxHash(headerData)

	// ALWAYS return hex-encoded hash to avoid non-printable characters
	// Convert raw bytes to hex string for readability
	hexHash := hex.EncodeToString(hashBytes)

	// SPECIAL CASE: Only for genesis block (height 0), prefix with "GENESIS_"
	// This makes genesis blocks easily identifiable
	if b.Header.Height == 0 {
		genesisHash := "GENESIS_" + hexHash
		log.Printf("🔷 Genesis block hash created: %s", genesisHash)
		log.Printf("🔷 Genesis ParentHash: %x (empty)", b.Header.ParentHash)
		log.Printf("🔷 Genesis UnclesHash: %x", b.Header.UnclesHash)
		return []byte(genesisHash)
	}

	// For all other blocks, return hex-encoded hash
	// Log hash creation details for debugging
	log.Printf("🔷 Normal block %d hash created", b.Header.Height)
	log.Printf("🔷 ParentHash: %x", b.Header.ParentHash)
	log.Printf("🔷 UnclesHash: %x (%d uncles)", b.Header.UnclesHash, len(b.Body.Uncles))
	return []byte(hexHash)
}

// GetHash returns the block hash as string
// Returns: Block hash as string, empty string if no hash
func (b *Block) GetHash() string {
	// Check if hash exists
	if b.Header == nil || len(b.Header.Hash) == 0 {
		return ""
	}

	hashStr := string(b.Header.Hash)

	// Check if it's already a valid hex string (for normal blocks)
	if isHexString(hashStr) {
		return hashStr // Return as-is if valid hex
	}

	// Check if it's a genesis hash in text format
	if len(hashStr) > 8 && hashStr[:8] == "GENESIS_" {
		// Verify the part after GENESIS_ is hex
		hexPart := hashStr[8:]
		if isHexString(hexPart) {
			return hashStr // Return full genesis hash
		}
	}

	// If we get here, the hash contains non-printable characters
	// Convert it to hex encoding for safety
	hexHash := hex.EncodeToString(b.Header.Hash)
	log.Printf("⚠️ Converted non-printable hash to hex: %s", hexHash)
	return hexHash
}

// SetHash sets the block hash
// Parameters:
//   - hash: Hash string to set
func (b *Block) SetHash(hash string) {
	// Check if header exists
	if b.Header == nil {
		return
	}
	// Store hash as byte slice
	b.Header.Hash = []byte(hash)
}

// isHexString checks if a string is hex-encoded
// Parameters:
//   - s: String to check
//
// Returns: true if string is valid hex
func isHexString(s string) bool {
	// Hex strings must have even length (each byte = 2 chars)
	if len(s)%2 != 0 {
		return false
	}
	// Check each character is a valid hex digit
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// IsGenesisHash checks if this block has a genesis hash format
// Returns: true if block is genesis
func (b *Block) IsGenesisHash() bool {
	hash := b.GetHash()
	// Check for "GENESIS_" prefix
	return len(hash) > 8 && hash[:8] == "GENESIS_"
}

// CalculateTxsRoot calculates the Merkle root of all transactions in the block
// Returns: Merkle root as byte slice
func (b *Block) CalculateTxsRoot() []byte {
	// Delegate to CalculateMerkleRoot function
	return CalculateMerkleRoot(b.Body.TxsList)
}

// FinalizeHash ensures all roots are properly set before finalizing the block hash
func (b *Block) FinalizeHash() {
	// Check if header exists
	if b.Header == nil {
		return
	}

	// Ensure TxsRoot is calculated before generating the final hash
	b.Header.TxsRoot = b.CalculateTxsRoot()

	// Ensure UnclesHash is calculated from actual uncle blocks WITH HEIGHT
	b.Header.UnclesHash = CalculateUnclesHash(b.Body.Uncles, b.Header.Height)

	// ========== STEP 1: Calculate RAW hash (32 bytes) ==========
	// Collect all header fields for hashing
	versionBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(versionBytes, b.Header.Version)

	blockNumBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockNumBytes, b.Header.Block)

	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(b.Header.Timestamp))

	nonceBytes, err := common.NonceToBytes(b.Header.Nonce)
	if err != nil {
		logger.Warn("Failed to convert nonce to bytes: %v, using zero nonce", err)
		nonceBytes = make([]byte, 8)
	}

	// Concatenate all header fields
	headerData := versionBytes
	headerData = append(headerData, blockNumBytes...)
	headerData = append(headerData, timestampBytes...)
	headerData = append(headerData, b.Header.ParentHash...)
	headerData = append(headerData, b.Header.TxsRoot...)
	headerData = append(headerData, b.Header.StateRoot...)
	headerData = append(headerData, nonceBytes...)
	headerData = append(headerData, b.Header.Difficulty.Bytes()...)
	headerData = append(headerData, b.Header.GasLimit.Bytes()...)
	headerData = append(headerData, b.Header.GasUsed.Bytes()...)
	headerData = append(headerData, b.Header.UnclesHash...)
	headerData = append(headerData, b.Header.ExtraData...)
	headerData = append(headerData, b.Header.Miner...)

	// Calculate RAW hash (32 bytes) - THIS IS WHAT GETS SIGNED
	rawHash := common.SpxHash(headerData)

	// ========== STEP 2: Store RAW hash in SigDataHash (for signing) ==========
	b.Header.SigDataHash = rawHash // 32 raw bytes

	// ========== STEP 3: Convert to hex string for JSON display ==========
	hexHash := hex.EncodeToString(rawHash)

	// SPECIAL CASE: Genesis block
	if b.Header.Height == 0 {
		hexHash = "GENESIS_" + hexHash
	}

	b.Header.Hash = []byte(hexHash) // Store hex string for display

	log.Printf("✅ Finalized block %d", b.Header.Height)
	log.Printf("   Raw hash (signed): %x", rawHash)
	log.Printf("   Hex hash (display): %s", hexHash)
	log.Printf("   ParentHash: %x", b.Header.ParentHash)
	log.Printf("   UnclesHash: %x (%d uncles)", b.Header.UnclesHash, len(b.Body.Uncles))
}

// ValidateUnclesHash validates that UnclesHash matches the calculated uncles
// Returns: Error if validation fails
func (b *Block) ValidateUnclesHash() error {
	// Check if header exists
	if b.Header == nil {
		return fmt.Errorf("block header is nil")
	}

	// Calculate expected uncles hash
	calculatedUnclesHash := CalculateUnclesHash(b.Body.Uncles, b.Header.Height) // Pass height here
	// Compare with stored hash
	if !bytes.Equal(b.Header.UnclesHash, calculatedUnclesHash) {
		return fmt.Errorf("UnclesHash validation failed: expected %x, got %x (uncles count: %d)",
			calculatedUnclesHash, b.Header.UnclesHash, len(b.Body.Uncles))
	}
	return nil
}

// AddUncle adds an uncle block to the block
// Parameters:
//   - uncle: Uncle block header to add
func (b *Block) AddUncle(uncle *BlockHeader) {
	// Only add non-nil uncles
	if uncle != nil {
		b.Body.Uncles = append(b.Body.Uncles, uncle)
		// Recalculate uncles hash WITH HEIGHT after adding
		b.Header.UnclesHash = CalculateUnclesHash(b.Body.Uncles, b.Header.Height) // Pass height here
	}
}

// GetUncles returns the list of uncle blocks
// Returns: Slice of uncle block headers
func (b *Block) GetUncles() []*BlockHeader {
	return b.Body.Uncles
}

// ValidateTxsRoot validates that TxsRoot matches the calculated Merkle root
// Returns: Error if validation fails
func (b *Block) ValidateTxsRoot() error {
	// Check if header exists
	if b.Header == nil {
		return fmt.Errorf("block header is nil")
	}

	// Calculate expected transaction root
	calculatedMerkleRoot := b.CalculateTxsRoot()
	// Compare with stored root
	if !bytes.Equal(b.Header.TxsRoot, calculatedMerkleRoot) {
		return fmt.Errorf("TxsRoot validation failed: expected %x, got %x",
			calculatedMerkleRoot, b.Header.TxsRoot)
	}
	return nil
}

// AddTxs adds a transaction to the block's body.
// Parameters:
//   - tx: Transaction to add
func (b *Block) AddTxs(tx *Transaction) {
	b.Body.TxsList = append(b.Body.TxsList, tx)
}

// NewTxs creates a new transaction and adds it to the block
// Parameters:
//   - to: Recipient address
//   - from: Sender address
//   - fee: Transaction fee
//   - storage: Storage data
//   - nonce: Transaction nonce
//   - gasLimit: Gas limit for transaction
//   - gasPrice: Gas price for transaction
//   - block: Block to add transaction to
//   - key: Key for transaction creation
//
// Returns: Error if transaction creation fails
func NewTxs(to, from string, fee float64, storage string, nonce uint64, gasLimit, gasPrice *big.Int, block *Block, key string) error {
	// Create a new Note
	// Notes are a specific transaction type in Sphinx protocol
	note, err := NewNote(to, from, fee, storage, key)
	if err != nil {
		return err
	}

	// Convert the Note to a Transaction
	tx := note.ToTxs(nonce, gasLimit, gasPrice)

	// Add the Transaction to the Block
	block.AddTxs(tx)

	return nil
}

// GetDifficulty returns the block difficulty
// Returns: Difficulty as big.Int
func (b *Block) GetDifficulty() *big.Int {
	// Check if header exists and has difficulty
	if b.Header != nil {
		return b.Header.Difficulty
	}
	// Default difficulty of 1 for genesis
	return big.NewInt(1)
}

// Validate performs basic block validation
// Returns: Error if validation fails
func (b *Block) Validate() error {
	// Delegate to SanityCheck
	return b.SanityCheck()
}

// GetFormattedTimestamps returns both local and UTC formatted timestamps
// Returns: Local time string and UTC time string
func (b *Block) GetFormattedTimestamps() (localTime, utcTime string) {
	// Use common time service for consistent formatting
	return common.FormatTimestamp(b.Header.Timestamp)
}

// GetTimeInfo returns comprehensive time information
// Returns: TimeInfo struct with various time formats
func (b *Block) GetTimeInfo() *common.TimeInfo {
	// Get detailed time information from central time service
	return common.GetTimeService().GetTimeInfo(b.Header.Timestamp)
}

// MarshalJSON custom marshaling for BlockHeader
// Provides custom JSON encoding with hex-encoded fields
func (h *BlockHeader) MarshalJSON() ([]byte, error) {
	type Alias BlockHeader
	return json.Marshal(&struct {
		Hash              string `json:"hash"`
		TxsRoot           string `json:"txs_root"`
		StateRoot         string `json:"state_root"`
		ParentHash        string `json:"parent_hash"`
		UnclesHash        string `json:"uncles_hash"`
		ExtraData         string `json:"extra_data"`
		Miner             string `json:"miner"`
		Nonce             string `json:"nonce"` // Correctly handles string nonce
		ProposerSignature string `json:"proposer_signature"`
		ProposerID        string `json:"proposer_id"`
		*Alias
	}{
		// Convert byte fields to hex strings for JSON compatibility
		Hash:              string(h.Hash),                          // Hash as string
		TxsRoot:           common.Bytes2Hex(h.TxsRoot),             // Hex-encoded transaction root
		StateRoot:         common.Bytes2Hex(h.StateRoot),           // Hex-encoded state root
		ParentHash:        common.Bytes2Hex(h.ParentHash),          // Hex-encoded parent hash
		UnclesHash:        common.Bytes2Hex(h.UnclesHash),          // Hex-encoded uncles hash
		ExtraData:         string(h.ExtraData),                     // Extra data as string
		Miner:             common.Bytes2Hex(h.Miner),               // Hex-encoded miner address
		Nonce:             h.Nonce,                                 // Nonce as string
		ProposerSignature: hex.EncodeToString(h.ProposerSignature), // Hex-encoded signature
		ProposerID:        h.ProposerID,                            // Proposer ID as string
		Alias:             (*Alias)(h),                             // Embed original fields
	})
}

// UnmarshalJSON custom unmarshaling for BlockHeader
// Handles hex-encoded fields during JSON parsing
func (h *BlockHeader) UnmarshalJSON(data []byte) error {
	type Alias BlockHeader
	aux := &struct {
		Hash              string `json:"hash"`
		TxsRoot           string `json:"txs_root"`
		StateRoot         string `json:"state_root"`
		ParentHash        string `json:"parent_hash"`
		UnclesHash        string `json:"uncles_hash"`
		ExtraData         string `json:"extra_data"`
		Miner             string `json:"miner"`
		Nonce             string `json:"nonce"`
		ProposerSignature string `json:"proposer_signature"` // string, not []byte
		ProposerID        string `json:"proposer_id"`
		*Alias
	}{
		Alias: (*Alias)(h), // Initialize with existing header
	}

	// Parse JSON into auxiliary struct
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	var err error
	// Convert hex strings back to byte slices
	h.Hash = []byte(aux.Hash) // Hash as bytes
	h.TxsRoot, err = hex.DecodeString(aux.TxsRoot)
	if err != nil {
		return fmt.Errorf("failed to decode txs_root: %w", err)
	}
	h.StateRoot, err = hex.DecodeString(aux.StateRoot)
	if err != nil {
		return fmt.Errorf("failed to decode state_root: %w", err)
	}
	h.ParentHash, err = hex.DecodeString(aux.ParentHash)
	if err != nil {
		return fmt.Errorf("failed to decode parent_hash: %w", err)
	}
	h.UnclesHash, err = hex.DecodeString(aux.UnclesHash)
	if err != nil {
		return fmt.Errorf("failed to decode uncles_hash: %w", err)
	}
	h.ExtraData = []byte(aux.ExtraData) // Extra data as bytes
	h.Miner, err = hex.DecodeString(aux.Miner)
	if err != nil {
		return fmt.Errorf("failed to decode miner: %w", err)
	}
	h.Nonce = aux.Nonce // Nonce as string

	// ProposerSignature may be empty for legacy/genesis blocks
	if aux.ProposerSignature != "" {
		h.ProposerSignature, err = hex.DecodeString(aux.ProposerSignature)
		if err != nil {
			return fmt.Errorf("failed to decode proposer_signature: %w", err)
		}
	}
	h.ProposerID = aux.ProposerID

	return nil
}

// MarshalJSON for Block
// Custom JSON marshaling for Block type
func (b *Block) MarshalJSON() ([]byte, error) {
	type Alias Block
	return json.Marshal(&struct {
		Header *BlockHeader `json:"header"`
		Body   *BlockBody   `json:"body"`
		*Alias
	}{
		Header: b.Header,    // Block header
		Body:   &b.Body,     // Block body
		Alias:  (*Alias)(b), // Embed original fields
	})
}

// UnmarshalJSON for Block
// Custom JSON unmarshaling for Block type
func (b *Block) UnmarshalJSON(data []byte) error {
	type Alias Block
	aux := &struct {
		Header *BlockHeader `json:"header"`
		Body   *BlockBody   `json:"body"`
		*Alias
	}{
		Alias: (*Alias)(b), // Initialize with existing block
	}

	// Parse JSON
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Set parsed values
	b.Header = aux.Header
	b.Body = *aux.Body
	return nil
}

// MarshalJSON for BlockBody
// Custom JSON marshaling for BlockBody
func (b *BlockBody) MarshalJSON() ([]byte, error) {
	type Alias BlockBody
	return json.Marshal(&struct {
		Uncles     []*BlockHeader `json:"uncles"`
		UnclesHash string         `json:"uncles_hash"`
		*Alias
	}{
		Uncles:     b.Uncles,                         // Uncle blocks
		UnclesHash: hex.EncodeToString(b.UnclesHash), // Hex-encoded uncles hash
		Alias:      (*Alias)(b),                      // Embed original fields
	})
}

// UnmarshalJSON for BlockBody
// Custom JSON unmarshaling for BlockBody
func (b *BlockBody) UnmarshalJSON(data []byte) error {
	type Alias BlockBody
	aux := &struct {
		Uncles     []*BlockHeader `json:"uncles"`
		UnclesHash string         `json:"uncles_hash"`
		*Alias
	}{
		Alias: (*Alias)(b), // Initialize with existing body
	}

	// Parse JSON
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Set parsed values
	b.Uncles = aux.Uncles
	var err error
	// Decode hex-encoded uncles hash
	b.UnclesHash, err = hex.DecodeString(aux.UnclesHash)
	if err != nil {
		return err
	}

	return nil
}

// Enhanced SanityCheck that validates both TxsRoot and UnclesHash
// Performs comprehensive block validation
// Returns: Error if any validation check fails
func (b *Block) SanityCheck() error {
	// Check if header exists
	if b.Header == nil {
		return fmt.Errorf("block header is nil")
	}

	// Validate timestamp using centralized service
	// Ensure timestamp is within acceptable range
	if err := common.ValidateBlockTimestamp(b.Header.Timestamp); err != nil {
		return fmt.Errorf("invalid block timestamp: %w", err)
	}

	// Ensure ParentHash is not empty (except for the genesis block)
	if b.Header.Height > 0 && len(b.Header.ParentHash) == 0 {
		return fmt.Errorf("parent hash is missing for block number: %d", b.Header.Height)
	}

	// Check if Difficulty is non-negative
	if b.Header.Difficulty.Sign() == -1 {
		return fmt.Errorf("invalid difficulty: %s", b.Header.Difficulty.String())
	}

	// VALIDATE THAT TxsRoot = MerkleRoot
	// Verify transaction root matches actual transactions
	if err := b.ValidateTxsRoot(); err != nil {
		return fmt.Errorf("transaction root validation failed: %w", err)
	}

	// VALIDATE THAT UnclesHash matches actual uncles
	// Verify uncles hash matches actual uncle blocks
	if err := b.ValidateUnclesHash(); err != nil {
		return fmt.Errorf("uncles hash validation failed: %w", err)
	}

	// Check GasUsed does not exceed GasLimit
	// Ensure block doesn't consume more gas than allowed
	if b.Header.GasUsed.Cmp(b.Header.GasLimit) > 0 {
		return fmt.Errorf("gas used (%s) exceeds gas limit (%s)", b.Header.GasUsed.String(), b.Header.GasLimit.String())
	}

	// Ensure all transactions in the body are valid
	// Validate each transaction individually
	for _, tx := range b.Body.TxsList {
		if err := tx.SanityCheck(); err != nil {
			return fmt.Errorf("invalid transaction: %v", err)
		}
	}

	// Validate uncle blocks
	// Ensure all uncle blocks are properly formed
	for i, uncle := range b.Body.Uncles {
		if uncle == nil {
			return fmt.Errorf("uncle block %d is nil", i)
		}
		if len(uncle.Hash) == 0 {
			return fmt.Errorf("uncle block %d has empty hash", i)
		}
	}

	// Log successful validation
	log.Printf("✓ Block %d validation passed:", b.Header.Height)
	log.Printf("  TxsRoot = MerkleRoot = %x", b.Header.TxsRoot)
	log.Printf("  UnclesHash validated with %d uncle blocks", len(b.Body.Uncles))
	log.Printf("  ParentHash: %x", b.Header.ParentHash)

	return nil
}

// SanityCheck verifies the validity of a transaction.
// Performs basic transaction validation
// Returns: Error if validation fails
func (tx *Transaction) SanityCheck() error {
	// Validate timestamp using centralized service
	// Ensure transaction timestamp is within acceptable range
	if err := common.ValidateTransactionTimestamp(tx.Timestamp); err != nil {
		return fmt.Errorf("invalid transaction timestamp: %w", err)
	}

	// Ensure sender and receiver addresses are not empty
	if tx.Sender == "" {
		return fmt.Errorf("transaction sender is missing")
	}
	if tx.Receiver == "" {
		return fmt.Errorf("transaction receiver is missing")
	}

	// Ensure the amount is non-negative
	if tx.Amount.Sign() == -1 {
		return fmt.Errorf("transaction amount is negative")
	}

	// Check gas limit and gas price are non-negative
	if tx.GasLimit.Sign() == -1 {
		return fmt.Errorf("invalid gas limit: %s", tx.GasLimit.String())
	}
	if tx.GasPrice.Sign() == -1 {
		return fmt.Errorf("invalid gas price: %s", tx.GasPrice.String())
	}
	if tx.SignatureHash != nil && len(tx.SignatureHash) != 32 {
		return errors.New("signature hash must be 32 bytes")
	}
	return nil
}
