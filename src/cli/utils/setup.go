// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

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

// initializePhase2Stakes reads actual balances from state DB and sets validator stakes
func initializePhase2Stakes(bc *core.Blockchain, cons *consensus.Consensus, nodeID string) bool {
	logger.Info("[%s] 🔓 PHASE 2 INITIALIZATION - Reading stakes from genesis allocations", nodeID)

	vs := cons.GetValidatorSet()
	if vs == nil {
		logger.Error("[%s] ❌ ValidatorSet is nil!", nodeID)
		return false
	}

	stateDB, err := bc.NewStateDB()
	if err != nil {
		logger.Error("[%s] ❌ Failed to open StateDB: %v", nodeID, err)
		return false
	}

	// Map validator ID to genesis allocation address
	// Map validator ID to genesis allocation address with CORRECT stakes
	validatorAddressMap := map[string]string{
		"Node-127.0.0.1:32307": "1000000000000000000000000000000000000001", // Founder - 30M SPX
		"Node-127.0.0.1:32308": "2000000000000000000000000000000000000001", // CoFounder - 95M SPX
		"Node-127.0.0.1:32309": "3000000000000000000000000000000000000001", // Development - 200M SPX
	}

	// Get validators from the consensus engine
	validators := cons.GetValidators()
	logger.Info("[%s] Found %d validators to initialize", nodeID, len(validators))

	if len(validators) == 0 {
		logger.Error("[%s] ❌ No validators found! Cannot initialize Phase 2 stakes.", nodeID)
		return false
	}

	successCount := 0
	totalBalanceSPX := uint64(0)
	minStakeSPX := vs.GetMinStakeSPX()

	for _, vid := range validators {
		var address string
		var ok bool
		if address, ok = validatorAddressMap[vid]; !ok {
			address = vid
			logger.Warn("[%s] No mapping found for validator %s, using ID as address", nodeID, vid)
		} else {
			logger.Info("[%s] Validator %s mapped to genesis address %s", nodeID, vid, address)
		}

		balanceNSPX, err := stateDB.GetBalance(address)
		var stakeSPX uint64

		if err != nil {
			logger.Warn("[%s] Failed to get balance for address %s (validator %s): %v",
				nodeID, address, vid, err)
			stakeSPX = minStakeSPX
		} else if balanceNSPX != nil && balanceNSPX.Cmp(big.NewInt(0)) > 0 {
			stakeSPX = uint64(new(big.Int).Div(balanceNSPX, big.NewInt(denom.SPX)).Int64())
			logger.Info("[%s] Validator %s (address %s) has balance %d SPX from genesis allocation",
				nodeID, vid, address, stakeSPX)
		} else {
			stakeSPX = minStakeSPX
			logger.Info("[%s] Validator %s (address %s) has zero balance, using minimum %d SPX",
				nodeID, vid, address, stakeSPX)
		}

		if err := vs.AddValidator(vid, stakeSPX); err != nil {
			logger.Warn("[%s] Failed to set stake for validator %s: %v", nodeID, vid, err)
		} else {
			logger.Info("[%s] ✅ Validator %s stake set to %d SPX", nodeID, vid, stakeSPX)
			successCount++
			totalBalanceSPX += stakeSPX
		}
	}

	logger.Info("[%s] 📊 Total stake from balances: %d SPX (success: %d/%d validators)",
		nodeID, totalBalanceSPX, successCount, len(validators))

	totalStake := vs.GetTotalStake()
	if totalStake.Sign() == 0 {
		logger.Error("[%s] ⚠️ CRITICAL: Total stake is 0 after reading balances!", nodeID)
		return false
	}

	totalSPX := new(big.Int).Div(totalStake, big.NewInt(denom.SPX))
	logger.Info("[%s] ✅ Phase 2 stakes initialized with %s SPX total", nodeID, totalSPX.String())

	return true
}

// tryInitPhase2 runs the Phase 2 initialization and advances the consensus view.
// It is safe to call from both the outer poll loop (followers) and the inner
// commit-wait loop (leader). Returns true if initialization succeeded.
func tryInitPhase2(bc *core.Blockchain, cons *consensus.Consensus, nodeID string) bool {
	logger.Info("[%s] 🔓 BLOCK 1 COMMITTED — Initializing Phase 2 stakes", nodeID)

	// FIX 3: Small sleep so the StateDB flush from block 1's execution has
	// time to land before we read balances. Without this, balances may still
	// read as zero on the committing node.
	time.Sleep(500 * time.Millisecond)

	if !initializePhase2Stakes(bc, cons, nodeID) {
		logger.Error("[%s] ❌ Phase 2 initialization failed!", nodeID)
		return false
	}

	// FIX 3 (cont): Advance the consensus view so block 2's proposal uses
	// view 1, not view 0 (which was already used for block 1). Without this,
	// followers reject the block 2 proposal as a stale/duplicate view.
	cons.UpdateLeaderStatus()

	newLeader := cons.GetElectedLeaderID()
	if newLeader != "" {
		logger.Info("[%s] 📊 Phase 2 leader elected: %s (isLeader=%v)",
			nodeID, newLeader, cons.IsLeader())
	} else {
		logger.Warn("[%s] ⚠️ No leader after Phase 2 init — will retry next loop", nodeID)
	}
	return true
}

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

	phase2Initialized := false

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Get fresh chain state
		latestBlock = bc.GetLatestBlock()
		if latestBlock != nil {
			chainHeight := latestBlock.GetHeight()
			if chainHeight > currentHeight {
				currentHeight = chainHeight
				cons.SetCurrentHeight(currentHeight)
				logger.Info("[%s] 📊 Chain height updated to %d", nodeID, currentHeight)

				// FIX 2 (follower path): followers detect block 1 here via the
				// outer poll since they never enter the inner commit-wait loop.
				if currentHeight == 1 && !phase2Initialized {
					if tryInitPhase2(bc, cons, nodeID) {
						phase2Initialized = true
					}
				}
			}
		}

		// Check if we got a valid leader
		electedLeader := cons.GetElectedLeaderID()
		if electedLeader == "" {
			logger.Warn("[%s] No elected leader found, forcing re-election...", nodeID)
			time.Sleep(200 * time.Millisecond)
			cons.UpdateLeaderStatus()
			electedLeader = cons.GetElectedLeaderID()
			if electedLeader == "" {
				logger.Warn("[%s] Still no elected leader, waiting...", nodeID)
				select {
				case <-ctx.Done():
					return
				case <-time.After(2 * time.Second):
				}
				continue
			}
		}

		if !cons.IsLeader() {
			logger.Info("👂 [%s] FOLLOWER MODE — waiting for leader proposal (height=%d, electedLeader=%s)",
				nodeID, currentHeight, electedLeader)
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

		signingService := cons.GetSigningService()
		if signingService != nil {
			if err := signingService.SignBlock(wrapped); err != nil {
				logger.Error("[%s] Failed to sign block header: %v", nodeID, err)
				continue
			}
			logger.Info("[%s] Block header signed", nodeID)
		}

		proposalSlot := cons.GetCurrentView()
		logger.Info("[%s] Using view %d as proposal slot for block proposal", nodeID, proposalSlot)

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

		cons.HandleProposal(proposal)
		time.Sleep(100 * time.Millisecond)

		if err := cons.BroadcastProposal(proposal); err != nil {
			logger.Error("[%s] BroadcastProposal failed: %v", nodeID, err)
			continue
		}

		logger.Info("✅ [%s] Block proposed and broadcast, waiting for consensus...", nodeID)

		// FIX 1: Do NOT use defer for the ticker — it leaks across loop
		// iterations and only fires when the entire function returns.
		commitTimeout := time.After(60 * time.Second)
		commitTicker := time.NewTicker(1 * time.Second)

		committed := false
		for !committed {
			select {
			case <-ctx.Done():
				commitTicker.Stop() // FIX 1: explicit stop on early exit
				return
			case <-commitTimeout:
				logger.Warn("[%s] ⚠️ Timeout waiting for block commitment at height %d", nodeID, currentHeight+1)
				committed = true
			case <-commitTicker.C:
				latest := bc.GetLatestBlock()
				if latest != nil && latest.GetHeight() > currentHeight {
					currentHeight = latest.GetHeight()
					cons.SetCurrentHeight(currentHeight)

					if bc.GetTPSMonitor() != nil {
						stats := bc.GetTPSMonitor().GetStats()
						logger.Info("📊 [%s] TPS STATS after block %d: blocks_processed=%v, total_txs=%v, avg_txs_per_block=%.2f",
							nodeID, currentHeight,
							stats["blocks_processed"],
							stats["total_transactions"],
							stats["avg_transactions_per_block"])
					}

					logger.Info("[%s] 🎉 Block committed! Height now: %d", nodeID, currentHeight)

					// FIX 2 (leader path): the leader updates currentHeight here
					// inside the inner loop, so the outer poll's
					// "chainHeight > currentHeight" check will be false next
					// iteration and Phase 2 init would be skipped. We must
					// handle it here for the leader.
					if currentHeight == 1 && !phase2Initialized {
						if tryInitPhase2(bc, cons, nodeID) {
							phase2Initialized = true
						}
					}

					committed = true
				}
			}
		}
		commitTicker.Stop() // FIX 1: always stop after inner loop exits

		if cpErr := bc.WriteChainCheckpoint(); cpErr != nil {
			logger.Warn("[%s] Failed to write chain checkpoint: %v", nodeID, cpErr)
		} else {
			phase := "devnet"
			if bc.IsDistributionComplete() {
				phase = "mainnet/testnet"
			}
			logger.Info("[%s] ✅ Checkpoint saved at height %d (phase: %s, network: %s)",
				nodeID, currentHeight, phase, networkType)
		}

		cons.UpdateLeaderStatus()
		electedLeader = cons.GetElectedLeaderID()
		if electedLeader == "" {
			logger.Warn("[%s] ⚠️ No leader elected after commit, will retry next loop", nodeID)
		} else {
			logger.Info("[%s] 📊 Next leader: %s (isLeader=%v)", nodeID, electedLeader, cons.IsLeader())
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(multiNodeRoundDelay):
		}
	}
}
