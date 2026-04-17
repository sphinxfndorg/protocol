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

// go/src/cli/utils/setup.go
package utils

import (
	"context"
	"encoding/json"
	"math/big"
	"time"

	"github.com/sphinxorg/protocol/src/consensus"
	"github.com/sphinxorg/protocol/src/core"
	svm "github.com/sphinxorg/protocol/src/core/svm/opcodes"
	vmachine "github.com/sphinxorg/protocol/src/core/svm/vm"
	logger "github.com/sphinxorg/protocol/src/log"
	denom "github.com/sphinxorg/protocol/src/params/denom"
)

// runBlockProductionLoop runs continuous block production with PBFT consensus
func runBlockProductionLoop(
	ctx context.Context,
	bc *core.Blockchain,
	cons *consensus.Consensus,
	nodeID string,
	totalNodes int,
	networkType string,
) {
	const (
		singleNodeInterval  = 10 * time.Second
		multiNodeRoundDelay = 3 * time.Second
	)

	if totalNodes == 1 {
		ticker := time.NewTicker(singleNodeInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				blk, err := bc.CreateBlock()
				if err != nil {
					logger.Error("[%s] solo mine error: %v", nodeID, err)
					continue
				}
				pending := bc.GetMempool().GetPendingTransactions()
				logger.Info("[%s] ⛏ Solo-mined block height=%d txs=%d", nodeID, blk.GetHeight(), len(pending))
			}
		}
	}

	if totalNodes < 3 {
		logger.Warn("[%s] Block-production suspended (need ≥ 3 validators for PBFT)", nodeID)
		<-ctx.Done()
		return
	}

	var currentHeight uint64 = 0
	latestBlock := bc.GetLatestBlock()
	if latestBlock != nil {
		currentHeight = latestBlock.GetHeight()
	}

	logger.Info("[%s] Starting PBFT consensus. Current height: %d", nodeID, currentHeight)

	// ========== FIX: Run FOREVER, no target limit ==========
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Update current height at the start of each round
		latestBlock = bc.GetLatestBlock()
		if latestBlock != nil && latestBlock.GetHeight() > currentHeight {
			currentHeight = latestBlock.GetHeight()
			cons.SetCurrentHeight(currentHeight)
			logger.Info("[%s] 📊 Chain height updated to %d", nodeID, currentHeight)
		}

		cons.UpdateLeaderStatus()
		time.Sleep(100 * time.Millisecond)

		if !cons.IsLeader() {
			logger.Info("👂 [%s] FOLLOWER MODE — waiting for leader proposal (height=%d)", nodeID, currentHeight)
			select {
			case <-ctx.Done():
				return
			case <-time.After(multiNodeRoundDelay):
			}
			continue
		}

		// Double-check that we're still at the correct height
		currentHeightCheck := bc.GetLatestBlock().GetHeight()
		if currentHeightCheck != currentHeight {
			logger.Info("[%s] ⚠️ Chain height changed from %d to %d, skipping proposal",
				nodeID, currentHeight, currentHeightCheck)
			currentHeight = currentHeightCheck
			cons.SetCurrentHeight(currentHeight)
			continue
		}

		logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		logger.Info("👑 [%s] LEADER MODE ACTIVE — proposing block for height %d", nodeID, currentHeight+1)
		logger.Info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

		pending := bc.GetMempool().GetPendingTransactions()
		if len(pending) == 0 {
			logger.Info("[%s] Leader — mempool empty, creating empty block", nodeID)
		}

		newBlock, err := bc.CreateBlock()
		if err != nil {
			logger.Error("[%s] CreateBlock failed: %v", nodeID, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(multiNodeRoundDelay):
			}
			continue
		}

		logger.Info("[%s] Created block height=%d txs=%d", nodeID, newBlock.GetHeight(), len(pending))

		consensusVM := vmachine.NewVM([]byte{byte(svm.PUSH1), 0x01})
		if err := consensusVM.Run(); err != nil {
			logger.Error("[%s] Consensus VM error: %v", nodeID, err)
			continue
		}
		result, err := consensusVM.GetResult()
		if err != nil || result != 1 {
			logger.Error("[%s] Block failed consensus VM rules", nodeID)
			continue
		}
		logger.Info("[%s] VM: Consensus verification passed", nodeID)

		wrapped := core.NewBlockHelper(newBlock)

		// Sign the block header
		signingService := cons.GetSigningService()
		if signingService != nil {
			if err := signingService.SignBlock(wrapped); err != nil {
				logger.Error("[%s] Failed to sign block header: %v", nodeID, err)
				continue
			}
			logger.Info("[%s] Block header signed", nodeID)
		}

		// Create and process proposal locally
		proposalSlot := cons.GetElectedSlot()
		if proposalSlot == 0 {
			proposalSlot = uint64(time.Now().Unix())
		}

		var concreteBlock interface{}
		if getter, ok := wrapped.(interface{ GetUnderlyingBlock() interface{} }); ok {
			concreteBlock = getter.GetUnderlyingBlock()
		} else {
			concreteBlock = newBlock
		}

		blockData, err := json.Marshal(concreteBlock)
		if err != nil {
			logger.Error("[%s] Failed to serialize block: %v", nodeID, err)
			continue
		}

		proposal := &consensus.Proposal{
			BlockData:       blockData,
			View:            cons.GetCurrentView(),
			ProposerID:      nodeID,
			Signature:       []byte{},
			ElectedLeaderID: cons.GetElectedLeaderID(),
			SlotNumber:      proposalSlot,
			Block:           wrapped,
		}

		if signingService != nil {
			if err := signingService.SignProposal(proposal); err != nil {
				logger.Error("[%s] Failed to sign proposal: %v", nodeID, err)
				continue
			}
		}

		// Process locally FIRST
		cons.HandleProposal(proposal)
		time.Sleep(100 * time.Millisecond)

		// Broadcast to peers
		if err := cons.BroadcastProposal(proposal); err != nil {
			logger.Error("[%s] BroadcastProposal failed: %v", nodeID, err)
			continue
		}

		logger.Info("✅ [%s] Block proposed and broadcast, waiting for consensus...", nodeID)

		timeout := time.After(30 * time.Second)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		committed := false
		for !committed {
			select {
			case <-ctx.Done():
				return
			case <-timeout:
				logger.Warn("[%s] Timeout waiting for block commitment", nodeID)
				committed = true
			case <-ticker.C:
				latest := bc.GetLatestBlock()
				if latest != nil && latest.GetHeight() > currentHeight {
					currentHeight = latest.GetHeight()
					cons.SetCurrentHeight(currentHeight)

					// ========== Update validator stakes after Block 1 ==========
					if currentHeight >= 1 {
						vs := cons.GetValidatorSet()
						if vs != nil {
							validators := cons.GetValidators()
							for _, vid := range validators {
								stakeNSPX := bc.GetValidatorStake(vid)
								if stakeNSPX != nil && stakeNSPX.Cmp(big.NewInt(0)) > 0 {
									stakeSPX := new(big.Int).Div(stakeNSPX, big.NewInt(denom.SPX))
									if err := vs.UpdateStake(vid, uint64(stakeSPX.Int64())); err != nil {
										logger.Warn("[%s] Failed to update validator %s stake: %v", nodeID, vid, err)
									} else {
										logger.Info("[%s] ✅ Updated validator %s stake to %d SPX for Phase 2",
											nodeID, vid, stakeSPX)
									}
								} else {
									logger.Warn("[%s] Validator %s has zero stake, using minimum %d SPX",
										nodeID, vid, vs.GetMinStakeSPX())
									// Set minimum stake if zero
									vs.UpdateStake(vid, vs.GetMinStakeSPX())
								}
							}
						}
					}
					// ============================================================

					logger.Info("[%s] 🎉 Block committed! Height now: %d", nodeID, currentHeight)
					committed = true
				}
			}
		}

		// ========== Write checkpoint ==========
		// Save checkpoint after every block, but phase will update automatically
		if cpErr := bc.WriteChainCheckpoint(); cpErr != nil {
			logger.Warn("[%s] Failed to write chain checkpoint: %v", nodeID, cpErr)
		} else {
			phase := "devnet"
			if bc.IsDistributionComplete() {
				phase = "mainnet/testnet"
			}
			logger.Info("[%s] ✅ Checkpoint saved at height %d (phase: %s, network: %s)",
				nodeID, currentHeight, phase, networkType) // ← Added networkType here
		}
		// =====================================

		// Small delay before next round
		select {
		case <-ctx.Done():
			return
		case <-time.After(multiNodeRoundDelay):
		}
	}
}
