// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/helper.go
package types

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/sphinxfndorg/protocol/src/common"
)

// Ensure your Block type has these methods to implement consensus.Block
// GetHeight returns the block's chain height.
//
// ★ IT READS Header.Block, NOT Header.Height. The two fields are documented as
// equal, with JSON tags "nblock" and "height", so a block built with only one of
// them set looks plausible and silently reads as height 0 — i.e. GENESIS. That
// is not hypothetical: a header literal missing `Block:` produces exactly this,
// and every genesis-exempt path (attestation verification, epoch derivation)
// then treats a real block as block 0.
//
// The reconciliation below repairs a malformed header. Header.Block stays
// authoritative; Height is brought into line. Constructors should set BOTH —
// NewBlockHeader does.
func (b *Block) GetHeight() uint64 {
	if b.Header == nil {
		return 0
	}
	// Header.Block wins. If only Height was populated, mirror it up so the
	// block does not masquerade as genesis.
	if b.Header.Block == 0 && b.Header.Height > 0 {
		return b.Header.Height
	}
	return b.Header.Block
}

// ValidateHeightFields reports an error when Header.Block and Header.Height
// disagree, i.e. the header is malformed and a hash over it will not match what
// peers compute.
//
// It deliberately does NOT auto-fix: silently repairing a height during
// validation would accept a block whose committed fields disagree, and that
// disagreement is exactly what a header commitment would catch.
func (b *Block) ValidateHeightFields() error {
	if b.Header == nil {
		return fmt.Errorf("block has no header")
	}
	if b.Header.Block != b.Header.Height {
		return fmt.Errorf("block height fields disagree: Header.Block=%d, Header.Height=%d "+
			"(GetHeight reads Block, so a header built with only Height set reads as height %d)",
			b.Header.Block, b.Header.Height, b.GetHeight())
	}
	return nil
}

// NormalizeHeights makes the two height fields agree, preferring Header.Block.
// It is called on the JSON decode path only, where a producer may have emitted
// one field or the other. It is NOT called during validation.
func (b *Block) NormalizeHeights() {
	if b.Header == nil {
		return
	}
	switch {
	case b.Header.Block == 0 && b.Header.Height > 0:
		b.Header.Block = b.Header.Height
	case b.Header.Height == 0 && b.Header.Block > 0:
		b.Header.Height = b.Header.Block
	}
}

// GetPrevHash returns the parent block hash as printable string
// This method provides the parent hash for chain continuity verification
func (b *Block) GetPrevHash() string {
	if b.Header == nil || len(b.Header.ParentHash) == 0 {
		return ""
	}

	// Check if it's already a valid string
	parentHashStr := string(b.Header.ParentHash)

	// If it's a genesis hash in text format, return as-is
	if len(parentHashStr) > 8 && parentHashStr[:8] == "GENESIS_" {
		return parentHashStr
	}

	// Otherwise, check if it contains non-printable characters
	for _, r := range parentHashStr {
		if r < 32 || r > 126 {
			// Contains non-printable chars, convert to hex
			return hex.EncodeToString(b.Header.ParentHash)
		}
	}

	// It's already a printable string
	return parentHashStr
}

func (b *Block) GetTimestamp() int64 {
	return b.Header.Timestamp
}

func (b *Block) GetBody() *BlockBody {
	return &b.Body
}

// ValidateHashFormat validates that a hash is in acceptable format
func (b *Block) ValidateHashFormat() error {
	hash := b.GetHash()

	if hash == "" {
		return fmt.Errorf("block hash is empty")
	}

	// Check for non-printable characters
	for i, r := range hash {
		if r < 32 || r > 126 {
			return fmt.Errorf("hash contains non-printable character at position %d: %d", i, r)
		}
	}

	// Check for invalid filename characters
	invalidChars := []rune{'/', '\\', ':', '*', '?', '"', '<', '>', '|', '\x00'}
	for _, char := range invalidChars {
		for _, r := range hash {
			if r == char {
				return fmt.Errorf("hash contains invalid character: %q", char)
			}
		}
	}

	return nil
}

// GetTxsRoot returns the transaction root hash
func (b *Block) GetTxsRoot() []byte {
	if b.Header == nil {
		return nil
	}
	return b.Header.TxsRoot
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

// SetCommitStatus sets the commit status of the block
func (b *Block) SetCommitStatus(status string) {
	if b.Header != nil {
		b.Header.CommitStatus = status
	}
}

// SetSigValid sets the signature validity flag
func (b *Block) SetSigValid(valid bool) {
	if b.Header != nil {
		b.Header.SigValid = valid
	}
}

// GetCommitStatus returns the commit status of the block
func (b *Block) GetCommitStatus() string {
	if b.Header == nil {
		return ""
	}
	return b.Header.CommitStatus
}

// GetSigValid returns whether the signature is valid
func (b *Block) GetSigValid() bool {
	if b.Header == nil {
		return false
	}
	return b.Header.SigValid
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

// GetParentHash returns the parent block hash as string
func (b *Block) GetParentHash() string {
	if b.Header == nil || len(b.Header.ParentHash) == 0 {
		return ""
	}
	// Try to interpret as string
	parentHashStr := string(b.Header.ParentHash)
	// If it contains non-printable chars, convert to hex
	for _, r := range parentHashStr {
		if r < 32 || r > 126 {
			return hex.EncodeToString(b.Header.ParentHash)
		}
	}
	return parentHashStr
}

// SetHeight sets the block height
func (b *Block) SetHeight(height uint64) {
	if b.Header != nil {
		b.Header.Height = height
		b.Header.Block = height
	}
}

// GetUncles returns the list of uncle blocks
// Returns: Slice of uncle block headers
func (b *Block) GetUncles() []*BlockHeader {
	return b.Body.Uncles
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
