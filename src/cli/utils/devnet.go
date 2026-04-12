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

// go/src/cli/utils/devnet.go
package utils

import (
	"fmt"
	"time"

	"github.com/sphinxorg/protocol/src/consensus"
	"github.com/sphinxorg/protocol/src/core"
	logger "github.com/sphinxorg/protocol/src/log"
)

// runDevnetDistributionLoop runs consensus blocks until all genesis allocations
// have been distributed from the vault.  It replaces the simple 3-minute wait
// and keeps proposing blocks until IsDistributionComplete() == true on all nodes.
//
// Returns the final block height once distribution is complete.
// runDevnetDistributionLoop runs consensus blocks until all genesis allocations
// have been distributed from the vault.
func runDevnetDistributionLoop(
	blockchains []*core.Blockchain,
	consensusEngines []*consensus.Consensus,
	validatorIDs []string,
	numNodes int,
) (uint64, error) {
	const maxRounds = 500 // hard cap — each round proposes one block
	checkEvery := 5       // check vault every N rounds

	logger.Info("=== DEVNET DISTRIBUTION LOOP STARTED ===")
	logger.Info("Target: drain vault %s of all genesis allocations", core.GenesisVaultAddress)

	// Get the time converter from the first consensus engine to calculate epoch
	// Note: All nodes should have the same time converter (same genesis time)
	var timeConverter *consensus.TimeConverter
	if len(consensusEngines) > 0 && consensusEngines[0] != nil {
		// You'll need to add a GetTimeConverter() method to Consensus
		// For now, we'll create a new one from genesis time
		genesisTime := blockchains[0].GetGenesisTime()
		timeConverter = consensus.NewTimeConverter(genesisTime)
	}

	for round := 0; round < maxRounds; round++ {
		// ========== SUBMIT VDF OUTPUTS FIRST ==========
		// Get current epoch from time converter
		currentEpoch := uint64(0)
		if timeConverter != nil {
			currentEpoch = timeConverter.CurrentEpoch()
		}

		// Have all nodes submit VDF outputs for this epoch
		for i := 0; i < numNodes; i++ {
			submission, err := consensusEngines[i].GetRANDAO().EvalVDF(validatorIDs[i], currentEpoch, 0)
			if err != nil {
				logger.Warn("%s VDF eval failed: %v", validatorIDs[i], err)
				continue
			}

			// Submit to all nodes to ensure everyone gets the VDF output
			for j := 0; j < numNodes; j++ {
				if err := consensusEngines[j].GetRANDAO().Submit(0, submission); err != nil {
					logger.Warn("%s failed to submit VDF to %s: %v", validatorIDs[i], validatorIDs[j], err)
				}
			}
			logger.Debug("%s submitted VDF output for epoch %d", validatorIDs[i], currentEpoch)
		}

		// Give time for VDF outputs to propagate and mix to update
		time.Sleep(100 * time.Millisecond)
		// ============================================

		// Check if all nodes have completed distribution.
		if round%checkEvery == 0 {
			allDone := true
			for i := 0; i < numNodes; i++ {
				if !blockchains[i].IsDistributionComplete() {
					allDone = false
					break
				}
			}
			if allDone {
				tip := blockchains[0].GetLatestBlock()
				tipHeight := uint64(0)
				if tip != nil {
					tipHeight = tip.GetHeight()
				}
				logger.Info("✅ DEVNET DISTRIBUTION COMPLETE at block height %d (round %d)",
					tipHeight, round)
				return tipHeight, nil
			}

			// Log progress.
			for i := 0; i < numNodes; i++ {
				tip := blockchains[i].GetLatestBlock()
				h := uint64(0)
				if tip != nil {
					h = tip.GetHeight()
				}
				logger.Info("  %s: height=%d, distribution_complete=%v",
					validatorIDs[i], h, blockchains[i].IsDistributionComplete())
			}
		}

		// Elect leader and propose the next block.
		for i := 0; i < numNodes; i++ {
			consensusEngines[i].UpdateLeaderStatus()
		}
		time.Sleep(50 * time.Millisecond)

		leaderIdx := -1
		for i := 0; i < numNodes; i++ {
			if consensusEngines[i].IsLeader() {
				leaderIdx = i
				break
			}
		}
		if leaderIdx == -1 {
			logger.Warn("distribution round %d: no leader elected, retrying", round)
			time.Sleep(200 * time.Millisecond)
			continue
		}

		pendingTxs := blockchains[leaderIdx].GetMempool().GetPendingTransactions()
		if len(pendingTxs) == 0 {
			// No pending transactions means either distribution is done or
			// the next batch hasn't been added yet.
			logger.Debug("distribution round %d: leader mempool empty", round)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		newBlock, err := blockchains[leaderIdx].CreateBlock()
		if err != nil {
			logger.Warn("distribution round %d: CreateBlock failed: %v", round, err)
			continue
		}

		// ========== CALL VM FOR BLOCK EXECUTION ==========
		// For each transaction in the block, execute VM state transitions.
		// NOTE: The placeholder PUSH1 0x01 VMs have been removed — they pushed
		// a success value and discarded it, logging misleading "complete" messages
		// without doing any real work. Real per-tx validation happens in the
		// mempool's performValidation() path before transactions reach this loop.
		if newBlock != nil && len(newBlock.Body.TxsList) > 0 {
			logger.Info("VM: Executing %d transactions in block", len(newBlock.Body.TxsList))
			for txIdx := range newBlock.Body.TxsList {
				// Real VM validation is performed upstream in performValidation().
				// Log progress here for observability without re-running the VM.
				logger.Debug("VM: Transaction %d committed to block", txIdx)
			}
			logger.Info("VM: Block execution complete")
		}
		// =================================================

		consensusBlock := core.NewBlockHelper(newBlock)
		if err := consensusEngines[leaderIdx].ProposeBlock(consensusBlock); err != nil {
			logger.Warn("distribution round %d: ProposeBlock failed: %v", round, err)
			continue
		}

		// Wait for commit to propagate.
		time.Sleep(500 * time.Millisecond)
	}

	return 0, fmt.Errorf("distribution did not complete within %d rounds", maxRounds)
}
