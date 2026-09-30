// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"math/big"
	"path/filepath"
	"strings"
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

// ============================================================================
// funded_accounts supply accounting (Checkpoint 1, decision 1)
//
// A funded_accounts row is NOT a block-0 allocation: it is not in block 0's
// TxsRoot, no vault balance moves, and the account did not previously hold the
// coins. Crediting the balance without creating matching supply would leave
// spendable value the ledger does not account for. seedGenesisFileAllocations
// therefore increments total supply by exactly the amount it credits.
// ============================================================================

// TestFundedAccounts_IncrementSupplyExactly drives the real production path
// (a real genesis document + Blockchain.seedGenesisFileAllocations) and asserts:
//
//  1. circulating supply AFTER == the credited total (nothing unaccounted);
//  2. the burn identity still holds (burns are totalSupply - balance(DEAD)).
func TestFundedAccounts_IncrementSupplyExactly(t *testing.T) {
	dir := tempDir(t, "funded-supply")
	previousDataDir := common.GetDataDir()
	common.SetDataDir(dir)
	defer common.SetDataDir(previousDataDir)

	// A real bootstrap document: one self-stake row + one faucet row.
	if err := CreateGenesisForSelf(dir, "Node-a", strings.Repeat("ab", 32),
		strings.Repeat("11", 20), strings.Repeat("22", 20)); err != nil {
		t.Fatalf("CreateGenesisForSelf: %v", err)
	}
	gf, err := LoadGenesisFile(dir)
	if err != nil || gf == nil {
		t.Fatalf("LoadGenesisFile: %v", err)
	}
	if !gf.HasValidatorSet() || !gf.Bootstrap {
		t.Fatalf("expected a bootstrap document with a validator set; got set=%v bootstrap=%v",
			gf.HasValidatorSet(), gf.Bootstrap)
	}
	wantCredited := big.NewInt(0)
	for _, a := range gf.FundedAccounts {
		b, perr := parseDecimalNSPX(a.BalanceNSPX)
		if perr != nil {
			t.Fatalf("row %s: %v", a.Address, perr)
		}
		wantCredited.Add(wantCredited, b)
	}
	if wantCredited.Sign() <= 0 {
		t.Fatal("expected the bootstrap document to fund at least the self-stake account")
	}

	bc := newMinimalBlockchain(t)
	// Use the *core.StateDB (not bc.NewStateDB, which returns the narrower
	// pool.StateDB interface) because total-supply accounting lives on the
	// concrete type.
	db, err := database.NewLevelDB(filepath.Join(t.TempDir(), "supply-state"))
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	defer db.Close()
	sdb := NewStateDB(db)

	dead := common.CanonicalAddress(common.DefaultBurnAddress)
	totalBefore := sdb.GetTotalSupply()
	deadBefore, _ := sdb.GetBalance(dead)

	bc.seedGenesisFileAllocations(sdb)

	totalAfter := sdb.GetTotalSupply()
	deadAfter, _ := sdb.GetBalance(dead)

	// (1) circulating supply rose by EXACTLY the credited amount.
	circulatingDelta := new(big.Int).Sub(
		new(big.Int).Sub(totalAfter, deadAfter),
		new(big.Int).Sub(totalBefore, deadBefore))
	if circulatingDelta.Cmp(wantCredited) != 0 {
		t.Errorf("circulating supply rose by %s, want exactly the credited %s",
			circulatingDelta, wantCredited)
	}

	// (2) The balances really exist and equal the credited total.
	sumNonDead := big.NewInt(0)
	for _, a := range gf.FundedAccounts {
		addr := common.CanonicalSPIFAddress(a.Address)
		if b, gerr := sdb.GetBalance(addr); gerr == nil && b != nil {
			sumNonDead.Add(sumNonDead, b)
		}
	}
	if sumNonDead.Cmp(wantCredited) != 0 {
		t.Errorf("funded balances total %s, want %s", sumNonDead, wantCredited)
	}

	// (3) THE BURN IDENTITY HOLDS: circulating == sum of non-DEAD balances.
	burned := new(big.Int).Sub(deadAfter, deadBefore)
	identity := new(big.Int).Sub(totalAfter, deadAfter)
	if identity.Cmp(sumNonDead) != 0 {
		t.Errorf("burn identity broken: totalSupply-DEAD = %s, but funded balances = %s", identity, sumNonDead)
	}
	t.Logf("credited=%s circulatingDelta=%s totalSupply=%s burned=%s",
		wantCredited, circulatingDelta, totalAfter, burned)
}



// TestFundedAccounts_RefusedOnNonBootstrapDocument covers decision 2: a
// `genesis create` document (Bootstrap=false) carrying funded_accounts is
// refused, because such rows create supply outside block 0's allocation
// schedule and are invisible to the genesis hash.
func TestFundedAccounts_RefusedOnNonBootstrapDocument(t *testing.T) {
	dir := tempDir(t, "funded-refuse")
	previousDataDir := common.GetDataDir()
	common.SetDataDir(dir)
	defer common.SetDataDir(previousDataDir)

	minStake := SelfGenesisStakeNSPX()
	// Bootstrap=false -> a `genesis create`-shaped document. It needs >= 3
	// validators to pass Validate(), so name three.
	mk := func(bootstrap bool) *GenesisStateFile {
		return &GenesisStateFile{
			Version:   genesisStateFileVersion,
			Bootstrap: bootstrap,
			Chain: GenesisChainParams{
				ChainID: DevnetChainID, Network: "devnet",
				EpochBlocks: DevnetEpochBlocks, MinStakeNSPX: minStake,
			},
			Validators: []GenesisStakedValidator{
				{NodeID: "Node-a", StakeNSPX: minStake},
				{NodeID: "Node-b", StakeNSPX: minStake},
				{NodeID: "Node-c", StakeNSPX: minStake},
			},
			FundedAccounts: []GenesisFundedAccount{
				{Address: strings.Repeat("33", 20), BalanceNSPX: minStake, Label: "test"},
			},
		}
	}

	// (a) A bootstrap document with funded_accounts validates.
	if err := mk(true).Validate(); err != nil {
		t.Fatalf("a bootstrap document with funded_accounts must validate: %v", err)
	}

	// (b) A non-bootstrap document with funded_accounts: the SEEDING path must
	//     refuse — no balance, no supply.
	if err := WriteGenesisFile(dir, mk(false)); err != nil {
		t.Fatalf("WriteGenesisFile: %v", err)
	}
	bc := newMinimalBlockchain(t)
	// Use the *core.StateDB (not bc.NewStateDB, which returns the narrower
	// pool.StateDB interface) because total-supply accounting lives on the
	// concrete type.
	db, err := database.NewLevelDB(filepath.Join(t.TempDir(), "supply-state"))
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	defer db.Close()
	sdb := NewStateDB(db)

	addr := strings.Repeat("33", 20)
	totalBefore := sdb.GetTotalSupply()
	bc.seedGenesisFileAllocations(sdb)
	totalAfter := sdb.GetTotalSupply()

	if bal, gerr := sdb.GetBalance(addr); gerr == nil && bal != nil && bal.Sign() > 0 {
		t.Errorf("non-bootstrap funded_accounts must NOT be seeded, but %s holds %s", addr, bal)
	}
	if totalAfter.Cmp(totalBefore) != 0 {
		t.Errorf("refused funded_accounts must not create supply (%s -> %s)", totalBefore, totalAfter)
	}
	t.Logf("non-bootstrap funded_accounts refused: balance 0, supply unchanged at %s", totalAfter)
}

// TestGenesisDocumentIdentityGap_DemonstratesTheGap is decision 3, part 1.
//
// ★ THE GAP. funded_accounts and validators are NOT inputs to block 0's hash.
// FinalizeHash covers only header fields, and block 0's header is built from
// DefaultGenesisState() — the genesis document is never read there. So two nodes
// holding DIFFERENT genesis_state.json files compute the SAME block-0 hash.
//
// The key-exchange genesis check compares exactly that hash, so two nodes with
// different membership and different funded balances PASS the check and then
// disagree about who may vote and who holds coins.
//
// This demonstrates it rather than arguing it.
func TestGenesisDocumentIdentityGap_DemonstratesTheGap(t *testing.T) {
	minStake := SelfGenesisStakeNSPX()
	mkChain := func() GenesisChainParams {
		return GenesisChainParams{
			ChainID: DevnetChainID, Network: "devnet",
			EpochBlocks: DevnetEpochBlocks, MinStakeNSPX: minStake,
		}
	}

	// Document A: ONE validator, one funded account.
	docA := &GenesisStateFile{
		Version:   genesisStateFileVersion,
		Bootstrap: true,
		Chain:     mkChain(),
		Validators: []GenesisStakedValidator{
			{NodeID: "Node-A", StakeNSPX: minStake},
		},
		FundedAccounts: []GenesisFundedAccount{
			{Address: strings.Repeat("aa", 20), BalanceNSPX: minStake, Label: "A"},
		},
	}
	// Document B: FOUR different validators and a different funded account.
	docB := &GenesisStateFile{
		Version:   genesisStateFileVersion,
		Bootstrap: true,
		Chain:     mkChain(),
		Validators: []GenesisStakedValidator{
			{NodeID: "Node-W", StakeNSPX: minStake},
			{NodeID: "Node-X", StakeNSPX: minStake},
			{NodeID: "Node-Y", StakeNSPX: minStake},
			{NodeID: "Node-Z", StakeNSPX: minStake},
		},
		FundedAccounts: []GenesisFundedAccount{
			{Address: strings.Repeat("bb", 20), BalanceNSPX: minStake, Label: "B"},
		},
	}

	// Both documents are valid and genuinely different.
	if err := docA.Validate(); err != nil {
		t.Fatalf("doc A must be valid: %v", err)
	}
	if err := docB.Validate(); err != nil {
		t.Fatalf("doc B must be valid: %v", err)
	}
	if len(docA.Validators) == len(docB.Validators) {
		t.Fatal("test setup is wrong: the documents should differ in membership")
	}
	if docA.FundedAccounts[0].Address == docB.FundedAccounts[0].Address {
		t.Fatal("test setup is wrong: the funded accounts should differ")
	}

	// THE PROOF. Neither document is an input: block 0 is built from the
	// canonical DefaultGenesisState(), so the hash is the same regardless of
	// which document (if any) sits in the datadir.
	hashWithNoDocument := GetGenesisHash()

	// Write each document in turn and re-read the hash. It must not move.
	dirA, dirB := t.TempDir(), t.TempDir()
	prev := common.GetDataDir()

	common.SetDataDir(dirA)
	if err := WriteGenesisFile(dirA, docA); err != nil {
		t.Fatalf("write doc A: %v", err)
	}
	hashA := GetGenesisHash()

	common.SetDataDir(dirB)
	if err := WriteGenesisFile(dirB, docB); err != nil {
		t.Fatalf("write doc B: %v", err)
	}
	hashB := GetGenesisHash()
	common.SetDataDir(prev)

	if hashA != hashB {
		t.Errorf("expected the block-0 hash to be identical for both documents; got %s vs %s", hashA, hashB)
	}
	if hashA != hashWithNoDocument {
		t.Errorf("expected the block-0 hash to be identical with and without a document; got %s vs %s",
			hashA, hashWithNoDocument)
	}

	t.Logf("doc A: %d validator(s), funded %s", len(docA.Validators), docA.FundedAccounts[0].Address)
	t.Logf("doc B: %d validator(s), funded %s", len(docB.Validators), docB.FundedAccounts[0].Address)
	t.Logf("block-0 hash identical for doc A, doc B and no document at all: %s", hashA)
	t.Logf("=> differing documents PASS the key-exchange genesis check, then disagree on membership and balances")
}

