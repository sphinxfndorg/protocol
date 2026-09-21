// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// TestCirculatingSupplyMatchesBurnAccounting locks the protocol's
// burn-accounting invariant at the StateDB level.
//
// Every protocol burn — the fee-allocation burn slice (BurnFeeBPS), the
// block-reward burn slice (BlockRewardBurnBPS), and manual user burns to the
// DEAD address — relocates nSPX to the canonical burn address via AddBalance.
// No production path calls DecrementTotalSupply any more, so the burned amount
// stays inside StateDB.totalSupply. Circulating supply is therefore defined as
//
//	circulating = GetTotalSupply() - GetBalance(DEAD)
//
// and must equal exactly the sum of every non-DEAD account balance: no value
// created, destroyed, or double-counted. This test drives the exact mutations
// executor.go performs (genesis funding, mintBlockReward's split,
// applyTransactions' fee distribution, a user Transfer to DEAD) and re-checks
// that identity after each step, including across a Commit + reload — the path
// StoreChainState, GetSupplyStatus and the explorer API all read.
func TestCirculatingSupplyMatchesBurnAccounting(t *testing.T) {
	db, err := database.NewLevelDB(t.TempDir() + "/state")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	s := NewStateDB(db)
	p := policy.NewPolicyParameters()
	dead := common.CanonicalAddress(common.DefaultBurnAddress)

	// Guard: with zero burn rates every identity below would be vacuously true.
	// Fail loudly if the defaults stop burning, so this coverage is not lost
	// silently by an unrelated policy change.
	if p.BurnFeeBPS == 0 || p.BlockRewardBurnBPS == 0 {
		t.Fatalf("default policy must burn a non-zero slice to exercise this test (fee_bps=%d reward_bps=%d)",
			p.BurnFeeBPS, p.BlockRewardBurnBPS)
	}

	// ledger mirrors every non-DEAD balance this test creates so the check can
	// compare totalSupply−DEAD against the sum of non-DEAD balances.
	ledger := map[string]*big.Int{}
	bump := func(addr string, delta *big.Int) {
		if addr == dead || delta == nil || delta.Sign() == 0 {
			return
		}
		cur, ok := ledger[addr]
		if !ok {
			cur = big.NewInt(0)
			ledger[addr] = cur
		}
		cur.Add(cur, delta)
	}
	sumNonDead := func() *big.Int {
		sum := big.NewInt(0)
		for _, v := range ledger {
			sum.Add(sum, v)
		}
		return sum
	}
	circulating := func(sdb *StateDB) *big.Int {
		burned, err := sdb.GetBalance(dead)
		if err != nil || burned == nil {
			burned = big.NewInt(0)
		}
		c := new(big.Int).Sub(sdb.GetTotalSupply(), burned)
		if c.Sign() < 0 {
			c = big.NewInt(0)
		}
		return c
	}
	check := func(stage string, want *big.Int) {
		t.Helper()
		got := circulating(s)
		if want != nil && got.Cmp(want) != 0 {
			t.Fatalf("%s: circulating = %s, want %s", stage, got, want)
		}
		if sum := sumNonDead(); got.Cmp(sum) != 0 {
			t.Fatalf("%s: circulating %s != sum(non-DEAD balances) %s", stage, got, sum)
		}
	}

	// ── 1. Genesis: fund the vault and mint the genesis supply (no burn yet). ──
	alloc := new(big.Int).Mul(big.NewInt(1000), big.NewInt(1e18)) // 1000 SPX
	s.SetBalance(GenesisVaultAddress, alloc)
	s.IncrementTotalSupply(alloc)
	bump(GenesisVaultAddress, alloc)
	check("after genesis", alloc)

	// ── 2. Block reward: mint the full reward, then split miner/burn. The full
	// reward enters totalSupply; only the miner slice is spendable. ──
	reward := new(big.Int).Mul(big.NewInt(5), big.NewInt(1e18)) // 5 SPX
	split := p.SplitBlockReward(reward)
	if split.Total.Cmp(reward) != 0 || new(big.Int).Add(split.Miner, split.Burned).Cmp(reward) != 0 {
		t.Fatalf("block reward split must sum to the reward: %+v", split)
	}
	s.AddBalance("miner", split.Miner)
	if split.Burned.Sign() > 0 {
		s.AddBalance(dead, split.Burned)
	}
	s.IncrementTotalSupply(reward)
	bump("miner", split.Miner)
	wantAfterReward := new(big.Int).Add(alloc, new(big.Int).Sub(reward, split.Burned))
	check("after block-reward split", wantAfterReward)

	// ── 3. Fee burn: a funded payer pays a gas fee; the burn slice of that fee
	// (BurnFeeBPS) is relocated to DEAD. totalSupply is unchanged — the fee
	// already existed — so circulating drops by exactly the burn slice. ──
	payerGrant := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)) // 100 SPX from genesis
	if err := s.Transfer(GenesisVaultAddress, "payer", payerGrant); err != nil {
		t.Fatal(err)
	}
	bump(GenesisVaultAddress, new(big.Int).Neg(payerGrant))
	bump("payer", payerGrant)
	check("after vault distribution", wantAfterReward)

	gasFee := big.NewInt(1e15) // 0.001 SPX
	if err := s.SubBalance("payer", gasFee); err != nil {
		t.Fatal(err)
	}
	bump("payer", new(big.Int).Neg(gasFee))

	dist := p.DistributeFees(gasFee)
	feeTotal := big.NewInt(0)
	feeTotal.Add(feeTotal, dist.Validators)
	feeTotal.Add(feeTotal, dist.Stakers)
	feeTotal.Add(feeTotal, dist.Treasury)
	feeTotal.Add(feeTotal, dist.Burned)
	if feeTotal.Cmp(gasFee) != 0 {
		t.Fatalf("fee distribution must sum to the fee: %+v", dist)
	}
	s.AddBalance("validator", dist.Validators)
	s.AddBalance("staking", dist.Stakers)
	s.AddBalance("treasury", dist.Treasury)
	if dist.Burned.Sign() > 0 {
		s.AddBalance(dead, dist.Burned)
	}
	bump("validator", dist.Validators)
	bump("staking", dist.Stakers)
	bump("treasury", dist.Treasury)
	wantAfterFees := new(big.Int).Sub(wantAfterReward, dist.Burned)
	check("after fee burn", wantAfterFees)

	// ── 4. Manual burn: a user sends funds to the DEAD address. totalSupply is
	// unchanged; circulating drops by exactly the amount sent. ──
	userAmt := new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)) // 100 SPX
	if err := s.Transfer(GenesisVaultAddress, "user", userAmt); err != nil {
		t.Fatal(err)
	}
	bump(GenesisVaultAddress, new(big.Int).Neg(userAmt))
	bump("user", userAmt)
	if err := s.Transfer("user", dead, userAmt); err != nil {
		t.Fatal(err)
	}
	bump("user", new(big.Int).Neg(userAmt))
	wantAfterManual := new(big.Int).Sub(wantAfterFees, userAmt)
	check("after manual burn", wantAfterManual)

	// ── 5. Persistence: the identity must survive Commit + reload, which is the
	// path StoreChainState, GetSupplyStatus and the explorer API all read. ──
	if _, err := s.Commit(); err != nil {
		t.Fatal(err)
	}
	reloaded := NewStateDB(db)
	if got := circulating(reloaded); got.Cmp(wantAfterManual) != 0 {
		t.Fatalf("after reload: circulating = %s, want %s", got, wantAfterManual)
	}
	if got, sum := circulating(reloaded), sumNonDead(); got.Cmp(sum) != 0 {
		t.Fatalf("after reload: circulating %s != sum(non-DEAD balances) %s", got, sum)
	}

	// DEAD must hold exactly the sum of every burn credited above.
	burned, err := reloaded.GetBalance(dead)
	if err != nil {
		t.Fatal(err)
	}
	wantBurned := new(big.Int).Add(split.Burned, dist.Burned)
	wantBurned.Add(wantBurned, userAmt)
	if burned.Cmp(wantBurned) != 0 {
		t.Fatalf("DEAD balance = %s, want %s", burned, wantBurned)
	}
	// And the document formula must reproduce the same number.
	totalSupply := reloaded.GetTotalSupply()
	if calc := new(big.Int).Sub(totalSupply, burned); calc.Cmp(wantAfterManual) != 0 {
		t.Fatalf("totalSupply-DEAD = %s, want %s", calc, wantAfterManual)
	}
}
