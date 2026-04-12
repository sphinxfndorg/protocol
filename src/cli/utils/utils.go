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

// go/src/cli/utils/utils.go
package utils

import (
	"encoding/hex"

	"github.com/sphinxorg/protocol/src/consensus"
	"github.com/sphinxorg/protocol/src/core"
	logger "github.com/sphinxorg/protocol/src/log"
)

// inspectConsensusTypes logs the consensus message types for debugging
// This helps verify the correct types are being used in the consensus layer
func inspectConsensusTypes() {
	logger.Info("=== CONSENSUS TYPE INSPECTION ===")
	// Create empty instances of each consensus message type
	proposal := &consensus.Proposal{}
	vote := &consensus.Vote{}
	timeout := &consensus.TimeoutMsg{}
	// Log their types for debugging
	logger.Info("Proposal type: %T", proposal)
	logger.Info("Vote type: %T", vote)
	logger.Info("TimeoutMsg type: %T", timeout)
	logger.Info("=== END TYPE INSPECTION ===")
}

// PrintBlockchainData prints detailed blockchain data for a node
// This provides comprehensive information about a node's blockchain state
func PrintBlockchainData(bc *core.Blockchain, nodeID string) {
	// Get latest block
	latestBlock := bc.GetLatestBlock()
	if latestBlock == nil {
		logger.Info("Node %s: No blocks available", nodeID)
		return
	}

	// Get chain parameters
	chainParams := bc.GetChainParams()

	// Extract block details using BlockHelper if available
	if blockAdapter, ok := latestBlock.(*core.BlockHelper); ok {
		underlyingBlock := blockAdapter.GetUnderlyingBlock()
		// Get merkle roots for comparison
		txsRoot := hex.EncodeToString(underlyingBlock.Header.TxsRoot)
		calculatedMerkleRoot := hex.EncodeToString(underlyingBlock.CalculateTxsRoot())
		rootsMatch := txsRoot == calculatedMerkleRoot

		// Print comprehensive block information
		logger.Info("=== NODE %s BLOCKCHAIN DATA ===", nodeID)
		logger.Info("Block Height: %d", latestBlock.GetHeight())
		logger.Info("Block Hash: %s", latestBlock.GetHash())
		logger.Info("TxsRoot (from header): %s", txsRoot)
		logger.Info("MerkleRoot (calculated): %s", calculatedMerkleRoot)
		logger.Info("TxsRoot = MerkleRoot: %v", rootsMatch)
		logger.Info("Magic Number: 0x%x", chainParams.MagicNumber)
		logger.Info("Timestamp: %d", underlyingBlock.Header.Timestamp)
		logger.Info("Difficulty: %s", underlyingBlock.Header.Difficulty.String())
		logger.Info("Nonce: %s", underlyingBlock.Header.Nonce)
		logger.Info("Gas Limit: %s", underlyingBlock.Header.GasLimit.String())
		logger.Info("Gas Used: %s", underlyingBlock.Header.GasUsed.String())
		logger.Info("Transaction Count: %d", len(underlyingBlock.Body.TxsList))
		logger.Info("Chain ID: %d", chainParams.ChainID)
		logger.Info("Chain Name: %s", chainParams.ChainName)
		logger.Info("=================================")

		// Warn if merkle roots don't match
		if !rootsMatch {
			logger.Warn("❌ WARNING: TxsRoot does not match MerkleRoot!")
		}
	}
}
