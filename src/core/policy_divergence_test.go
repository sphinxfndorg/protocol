// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	txtypes "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// Regression guard for the block-3 state-divergence bug class.
//
// Every dynamic monetary-policy input added by the dynamic-policy work —
// (1) the height-decayed block reward, (2) the usage-responsive fee-burn
// rate rolled from the previous finalized block's committed gas, and (3) the
// stake-responsive epoch-inflation multiplier fed by the committed validator
// snapshot — must be a pure function of committed chain state. If any of them
// ever reads live peer state, wall-clock time, or node-local data, two
// independent replays of the same blocks diverge here, at the state root,
// exactly like the original late-joiner fork at block 3.
//
// The replay drives the REAL execution path (ExecuteBlock →
// applyBlockTransitions → burn-rate roll → applyTransactions → gas snapshot
// → mintBlockReward → mintEpochInflation) on two fully independent
// storage+LevelDB+StateDB stacks, through TWO epoch boundaries (heights 3
// and 6 with the default BlocksPerEpoch = 3), and asserts byte-identical
// state roots at every height plus the exact per-block mint amounts.
func TestPolicyReplayIdenticalStateRootsAcrossInstances(t *testing.T) {
	const (
		gasLimit   = int64(10_000_000)
		fatTxCount = 250 // 250 * 24200 = 6.05M gas > 50% of the 10M limit
	)

	p := policy.NewPolicyParameters()
	blocksPerEpoch := p.BlocksPerEpoch // 3
	if blocksPerEpoch == 0 {
		t.Fatal("policy must define BlocksPerEpoch")
	}

	buildChain := func(t *testing.T) (*Blockchain, *database.DB) {
		t.Helper()
		dir := t.TempDir()
		db, err := database.NewLevelDB(dir + "/state")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		bc := mkIB(t, dir, db)
		// mintBlockReward (and every policy consumer) requires real chain
		// parameters; without them the executor is in test mode and mints
		// nothing. Devnet carries the default 10M block gas limit and the
		// default governance policy.
		bc.chainParams = GetDevnetChainParams()

		// Identical genesis seeding on both instances: payer funds and a
		// committed validator stake (the epoch-boundary snapshot the
		// stake-responsive multiplier reads). SetBalance alone does not
		// touch the supply counter — that's IncrementTotalSupply's job.
		s := NewStateDB(db)
		payerFunds := new(big.Int).Mul(big.NewInt(10_000), big.NewInt(1_000_000_000_000_000_000))
		s.SetBalance("payer", payerFunds)
		s.IncrementTotalSupply(payerFunds)
		s.SetValidatorStake("validator-1", new(big.Int).Mul(big.NewInt(7), big.NewInt(1_000_000_000_000_000_000)))
		if _, err := s.Commit(); err != nil {
			t.Fatal(err)
		}
		return bc, db
	}

	payTx := func(nonce uint64) *txtypes.Transaction {
		return &txtypes.Transaction{
			Sender: "payer", Receiver: "receiver", Nonce: nonce,
			Amount: big.NewInt(1), Timestamp: common.GetCurrentTimestamp(),
			GasLimit: big.NewInt(24_200), GasPrice: big.NewInt(1_000_000_000),
		}
	}
	bigBlock := func(height uint64, firstNonce uint64) *txtypes.Block {
		txs := make([]*txtypes.Transaction, 0, fatTxCount)
		for i := uint64(0); i < fatTxCount; i++ {
			txs = append(txs, payTx(firstNonce+i))
		}
		blk := blockWith(t, height, txs...)
		blk.Header.ProposerID = "validator-1"
		return blk
	}
	oneTxBlock := func(height, nonce uint64) *txtypes.Block {
		blk := blockWith(t, height, payTx(nonce))
		blk.Header.ProposerID = "validator-1"
		return blk
	}

	bcA, dbA := buildChain(t)
	bcB, dbB := buildChain(t)

	// totalStaked is constant across the whole replay: the validator stake
	// was committed before block 1 and no stake txs occur.
	totalStaked := new(big.Int).Mul(big.NewInt(7), big.NewInt(1_000_000_000_000_000_000))

	// wantBurnFee is the expected committed burn rate after each block:
	//   b1: no committed signal → hold 500
	//   b2, b3: ~24 BPS utilization (below 50% target) → 495, 490
	//   b4: b3 was 60.5% full (above target) → step back UP to 495
	//   b5, b6: quiet again → 490, 485
	wantBurnFee := []uint64{500, 495, 490, 495, 490, 485}

	// supplyOf reads the committed total supply of a chain's state DB.
	supplyOf := func(db *database.DB) *big.Int {
		return NewStateDB(db).GetTotalSupply()
	}

	// Track the supply after each executed block so per-block mints can be
	// pinned exactly. Baseline: the identical genesis seeding.
	lastSupply := supplyOf(dbA)
	if lastSupply.Cmp(supplyOf(dbB)) != 0 {
		t.Fatalf("seeded supplies diverged before replay: %s vs %s", lastSupply, supplyOf(dbB))
	}
	if lastSupply.Sign() <= 0 {
		t.Fatalf("seeded supply must be positive, got %s", lastSupply)
	}
	firstNonce := uint64(0)
	for h := uint64(1); h <= 2*blocksPerEpoch; h++ {
		isBoundary := h%blocksPerEpoch == 0
		var blkA, blkB *txtypes.Block
		if h == blocksPerEpoch { // fat block: pushes utilization ABOVE the 50% target
			blkA, blkB = bigBlock(h, firstNonce), bigBlock(h, firstNonce)
			firstNonce += fatTxCount
		} else {
			blkA, blkB = oneTxBlock(h, firstNonce), oneTxBlock(h, firstNonce)
			firstNonce++
		}

		rootA, err := bcA.ExecuteBlock(blkA)
		if err != nil {
			t.Fatalf("chain A ExecuteBlock(%d): %v", h, err)
		}
		rootB, err := bcB.ExecuteBlock(blkB)
		if err != nil {
			t.Fatalf("chain B ExecuteBlock(%d): %v", h, err)
		}
		if len(rootA) == 0 {
			t.Fatalf("height %d: empty state root", h)
		}
		if !bytes.Equal(rootA, rootB) {
			t.Fatalf("height %d: STATE ROOTS DIVERGED between independent instances (block-3 bug class):\nA=%x\nB=%x", h, rootA, rootB)
		}

		// ── Inputs 1+3: the exact supply delta must equal the policy math.
		// The executor mints the height-decayed reward first, then feeds the
		// post-reward supply into the stake-multiplied epoch inflation. ──
		supplyA, supplyB := supplyOf(dbA), supplyOf(dbB)
		if supplyA.Cmp(supplyB) != 0 {
			t.Fatalf("height %d: total supply diverged: %s vs %s", h, supplyA, supplyB)
		}
		delta := new(big.Int).Sub(supplyA, lastSupply)
		reward := bcA.PolicyBlockReward(h)
		wantDelta := new(big.Int).Set(reward)
		var boundaryInflation *big.Int
		if isBoundary {
			supplyAfterReward := new(big.Int).Add(lastSupply, reward)
			inflation := p.CalculateEpochInflationExact(supplyAfterReward, totalStaked, h/p.GetBlocksPerYear()+1)
			wantDelta = new(big.Int).Add(wantDelta, inflation.TotalMinted)
			boundaryInflation = inflation.TotalMinted
		}
		if delta.Cmp(wantDelta) != 0 {
			t.Fatalf("height %d: minted %s nSPX, want exactly %s (policy reward + boundary inflation)", h, delta, wantDelta)
		}

		// ── Input 2: the committed burn rate must match the deterministic
		// walk on both instances — down-steps on quiet blocks, UP on the
		// block following the fat one. ──
		for name, db := range map[string]*database.DB{"A": dbA, "B": dbB} {
			if got := NewStateDB(db).GetBurnFeeBPS(p.BurnFeeBPS); got != wantBurnFee[h-1] {
				t.Fatalf("chain %s height %d: committed burn fee = %d, want %d", name, h, got, wantBurnFee[h-1])
			}
		}

		// ── Input 3 engaged: at each epoch boundary the stake-responsive
		// multiplier must have actually deviated from 1.0x given the ~0.07%
		// staked snapshot — the minted inflation must differ from a plain
		// 1.0x epoch, and the multiplier must be in the 1.7x neighborhood. ──
		if isBoundary {
			supplyAfterReward := new(big.Int).Add(lastSupply, reward) // lastSupply is still the PRE-block supply
			mult := p.CalculateStakeAdjustedMultiplierBPS(totalStaked, supplyAfterReward)
			if mult == 10000 || mult < 16000 || mult > 17000 {
				t.Fatalf("height %d: stake multiplier for the ~0%% staked snapshot = %d, want ~1.7x (engaged, not 1.0x)", h, mult)
			}
			onTarget := new(big.Int).Set(supplyAfterReward)
			onTarget.Div(onTarget, big.NewInt(10)).Mul(onTarget, big.NewInt(7)) // exactly 70% → 1.0x
			flat := p.CalculateEpochInflationExact(supplyAfterReward, onTarget, h/p.GetBlocksPerYear()+1)
			if flat.TotalMinted.Cmp(boundaryInflation) == 0 {
				t.Fatalf("height %d: stake multiplier failed to move epoch inflation off the 1.0x amount", h)
			}
		}

		lastSupply.Set(supplyA)
	}

	// The committed validator snapshot must still be exactly what was seeded.
	for name, db := range map[string]*database.DB{"A": dbA, "B": dbB} {
		s := NewStateDB(db)
		stake, err := s.GetValidatorStake("validator-1")
		if err != nil || stake == nil || stake.Cmp(totalStaked) != 0 {
			t.Fatalf("chain %s: validator stake snapshot corrupted: %v (want %s)", name, stake, totalStaked)
		}
	}
}
