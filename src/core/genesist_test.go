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

// go/src/core/genesis_test.go
package core

import (
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/sphinxorg/protocol/src/common"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	storage "github.com/sphinxorg/protocol/src/state"
)

// ============================================================================
// Test helpers
// ============================================================================

// tempDir creates a throwaway directory and registers cleanup.
func tempDir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("tempDir: MkdirAll(%s): %v", dir, err)
	}
	return dir
}

// minimalGenesisState returns a GenesisState with only 2 allocations.
//
// WHY: common.SpxHash uses argon2 (a memory-hard KDF).  Each call takes
// ~8 s on typical hardware.  Building the Merkle tree for the full 15-entry
// DefaultGenesisAllocations requires ~28 argon2 calls per BuildBlock
// invocation (≈ 224 s) — well beyond any test timeout.
//
// Using 2 allocations keeps the Merkle tree to 3 nodes (2 leaves + 1 root),
// reducing BuildBlock to ~3 argon2 calls (≈ 24 s), which fits a 60 s timeout.
//
// Tests that only inspect GenesisState fields without calling BuildBlock
// may still use DefaultGenesisState() safely.
func minimalGenesisState() *GenesisState {
	return &GenesisState{
		ChainID:           7331,
		ChainName:         "Sphinx Mainnet",
		Symbol:            "SPX",
		Timestamp:         1732070400, // Nov 20 2024 00:00:00 UTC — deterministic
		ExtraData:         []byte("Sphinx Network Genesis Block - Decentralized Future"),
		InitialDifficulty: big.NewInt(17179869184),
		InitialGasLimit:   big.NewInt(5000),
		Nonce:             common.FormatNonce(1), // "0000000000000001"
		// Two allocations only — enough to exercise Merkle logic.
		Allocations: []*GenesisAllocation{
			NewFounderAlloc("1000000000000000000000000000000000000001", 50_000_000),
			NewReserveAlloc("2000000000000000000000000000000000000001", 150_000_000),
		},
		InitialValidators: []*GenesisValidator{},
	}
}

// newMinimalBlockchain builds a *Blockchain containing only the storage layer
// and mutex — the minimum ApplyGenesis requires.
// No goroutines, no consensus engine, no state machine, no mempool are started.
func newMinimalBlockchain(t *testing.T) *Blockchain {
	t.Helper()
	dir := tempDir(t, "bc-minimal")

	store, err := storage.NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}

	bc := &Blockchain{
		storage: store,
		chain:   []*types.Block{},
		lock:    sync.RWMutex{},
	}

	t.Cleanup(func() { _ = store.Close() })
	return bc
}

// defaultGS returns DefaultGenesisState with an optional mutation.
// NOTE: never call BuildBlock on the result — use minimalGenesisState()
// for any test that invokes BuildBlock.
func defaultGS(t *testing.T, mutate func(*GenesisState)) *GenesisState {
	t.Helper()
	gs := DefaultGenesisState()
	if mutate != nil {
		mutate(gs)
	}
	return gs
}

// containsSubstring avoids importing "strings" in the test package.
func containsSubstring(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ============================================================================
// 1. GenesisState field defaults  (no BuildBlock — fast)
// ============================================================================

// TestDefaultGenesisState_Fields verifies every required field carries a
// non-zero, sensible value.
func TestDefaultGenesisState_Fields(t *testing.T) {
	gs := DefaultGenesisState()

	if gs.ChainID == 0 {
		t.Error("ChainID must be non-zero")
	}
	if gs.ChainName == "" {
		t.Error("ChainName must not be empty")
	}
	if gs.Symbol == "" {
		t.Error("Symbol must not be empty")
	}
	if gs.Timestamp <= 0 {
		t.Errorf("Timestamp must be positive, got %d", gs.Timestamp)
	}
	if len(gs.ExtraData) == 0 {
		t.Error("ExtraData must not be empty")
	}
	if gs.InitialDifficulty == nil || gs.InitialDifficulty.Sign() <= 0 {
		t.Error("InitialDifficulty must be a positive *big.Int")
	}
	if gs.InitialGasLimit == nil || gs.InitialGasLimit.Sign() <= 0 {
		t.Error("InitialGasLimit must be a positive *big.Int")
	}
	if gs.Nonce == "" {
		t.Error("Nonce must not be empty")
	}
	if gs.Nonce != common.FormatNonce(1) {
		t.Errorf("Nonce mismatch: want %q, got %q", common.FormatNonce(1), gs.Nonce)
	}
}

// TestDefaultGenesisState_MainnetConstants confirms the hard-coded mainnet
// values that every node must agree on.
func TestDefaultGenesisState_MainnetConstants(t *testing.T) {
	gs := DefaultGenesisState()

	const wantChainID = uint64(7331)
	if gs.ChainID != wantChainID {
		t.Errorf("ChainID: want %d, got %d", wantChainID, gs.ChainID)
	}

	const wantTimestamp = int64(1732070400) // Nov 20 2024 00:00:00 UTC
	if gs.Timestamp != wantTimestamp {
		t.Errorf("Timestamp: want %d, got %d", wantTimestamp, gs.Timestamp)
	}

	wantDiff := big.NewInt(17179869184)
	if gs.InitialDifficulty.Cmp(wantDiff) != 0 {
		t.Errorf("InitialDifficulty: want %s, got %s",
			wantDiff.String(), gs.InitialDifficulty.String())
	}
}

// ============================================================================
// 2. GenesisStateFromChainParams  (no BuildBlock — fast)
// ============================================================================

func TestGenesisStateFromChainParams_Mainnet(t *testing.T) {
	p := GetSphinxChainParams()
	gs := GenesisStateFromChainParams(p)

	if gs.ChainID != p.ChainID {
		t.Errorf("ChainID: want %d, got %d", p.ChainID, gs.ChainID)
	}
	if gs.ChainName != p.ChainName {
		t.Errorf("ChainName: want %q, got %q", p.ChainName, gs.ChainName)
	}
	if gs.Symbol != p.Symbol {
		t.Errorf("Symbol: want %q, got %q", p.Symbol, gs.Symbol)
	}
	if gs.Timestamp != p.GenesisTime {
		t.Errorf("Timestamp: want %d, got %d", p.GenesisTime, gs.Timestamp)
	}
}

func TestGenesisStateFromChainParams_Devnet(t *testing.T) {
	p := GetDevnetChainParams()
	gs := GenesisStateFromChainParams(p)

	if gs.ChainName != "Sphinx Devnet" {
		t.Errorf("ChainName: want %q, got %q", "Sphinx Devnet", gs.ChainName)
	}
	if gs.ChainID != p.ChainID {
		t.Errorf("ChainID: want %d, got %d", p.ChainID, gs.ChainID)
	}
}

func TestGenesisStateFromChainParams_GenesisConfigOverrides(t *testing.T) {
	p := GetSphinxChainParams()
	customExtra := []byte("custom-extra-data-for-test")
	customDiff := big.NewInt(999)
	customGas := big.NewInt(12345)

	p.GenesisConfig = &GenesisConfig{
		GenesisExtraData:  customExtra,
		InitialDifficulty: customDiff,
		InitialGasLimit:   customGas,
	}

	gs := GenesisStateFromChainParams(p)

	if string(gs.ExtraData) != string(customExtra) {
		t.Errorf("ExtraData: want %q, got %q", customExtra, gs.ExtraData)
	}
	if gs.InitialDifficulty.Cmp(customDiff) != 0 {
		t.Errorf("InitialDifficulty: want %s, got %s",
			customDiff.String(), gs.InitialDifficulty.String())
	}
	if gs.InitialGasLimit.Cmp(customGas) != 0 {
		t.Errorf("InitialGasLimit: want %s, got %s",
			customGas.String(), gs.InitialGasLimit.String())
	}
}

// ============================================================================
// 3. AddValidator fluent builder  (no BuildBlock — fast)
// ============================================================================

func TestGenesisState_AddValidator(t *testing.T) {
	gs := DefaultGenesisState()

	if len(gs.InitialValidators) != 0 {
		t.Fatalf("expected empty validators, got %d", len(gs.InitialValidators))
	}

	gs.
		AddValidator("Node-127.0.0.1:32307", "1000000000000000000000000000000000000001", 32, "").
		AddValidator("Node-127.0.0.1:32308", "2000000000000000000000000000000000000002", 32, "pubkey-hex")

	if len(gs.InitialValidators) != 2 {
		t.Fatalf("expected 2 validators, got %d", len(gs.InitialValidators))
	}

	v0 := gs.InitialValidators[0]
	if v0.NodeID != "Node-127.0.0.1:32307" {
		t.Errorf("validator[0].NodeID: want %q, got %q", "Node-127.0.0.1:32307", v0.NodeID)
	}
	want0 := NewGenesisValidatorStake(32)
	if v0.StakeNSPX.Cmp(want0) != 0 {
		t.Errorf("validator[0].StakeNSPX: want %s, got %s", want0.String(), v0.StakeNSPX.String())
	}

	v1 := gs.InitialValidators[1]
	if v1.PublicKey != "pubkey-hex" {
		t.Errorf("validator[1].PublicKey: want %q, got %q", "pubkey-hex", v1.PublicKey)
	}
}

// TestNewGenesisValidatorStake checks the SPX→nSPX conversion helper.
func TestNewGenesisValidatorStake(t *testing.T) {
	cases := []struct {
		spx      int64
		wantNSPX string
	}{
		{1, "1000000000000000000"},
		{32, "32000000000000000000"},
		{1000, "1000000000000000000000"},
	}
	for _, tc := range cases {
		got := NewGenesisValidatorStake(tc.spx)
		if got.String() != tc.wantNSPX {
			t.Errorf("NewGenesisValidatorStake(%d): want %s, got %s",
				tc.spx, tc.wantNSPX, got.String())
		}
	}
}

// ============================================================================
// 4. allocationToTx  (one SpxHash call per test — fast)
// ============================================================================

// TestAllocationToTx_Fields checks sender, receiver, amount and zero gas.
func TestAllocationToTx_Fields(t *testing.T) {
	alloc := NewGenesisAllocationSPX("abcdef1234567890abcdef1234567890abcdef12", 50_000_000, "Test")
	tx := allocationToTx(alloc, 0, 1732070400)

	if tx.Sender != "genesis" {
		t.Errorf("Sender: want %q, got %q", "genesis", tx.Sender)
	}
	if tx.Receiver != alloc.Address {
		t.Errorf("Receiver: want %q, got %q", alloc.Address, tx.Receiver)
	}
	if tx.Amount.Cmp(alloc.BalanceNSPX) != 0 {
		t.Errorf("Amount: want %s, got %s", alloc.BalanceNSPX.String(), tx.Amount.String())
	}
	if tx.GasLimit.Sign() != 0 {
		t.Errorf("GasLimit: want 0, got %s", tx.GasLimit.String())
	}
	if tx.GasPrice.Sign() != 0 {
		t.Errorf("GasPrice: want 0, got %s", tx.GasPrice.String())
	}
	if tx.Nonce != 0 {
		t.Errorf("Nonce: want 0, got %d", tx.Nonce)
	}
	if tx.Timestamp != 1732070400 {
		t.Errorf("Timestamp: want 1732070400, got %d", tx.Timestamp)
	}
	if tx.ID == "" {
		t.Error("ID must not be empty")
	}
}

// TestAllocationToTx_DeterministicID — same inputs always produce same ID.
func TestAllocationToTx_DeterministicID(t *testing.T) {
	alloc := NewGenesisAllocationSPX("abcdef1234567890abcdef1234567890abcdef12", 100, "T")
	tx1 := allocationToTx(alloc, 3, 1732070400)
	tx2 := allocationToTx(alloc, 3, 1732070400)

	if tx1.ID != tx2.ID {
		t.Errorf("allocationToTx not deterministic: %q != %q", tx1.ID, tx2.ID)
	}
}

// TestAllocationToTx_DifferentIndex — different index → different ID.
func TestAllocationToTx_DifferentIndex(t *testing.T) {
	alloc := NewGenesisAllocationSPX("abcdef1234567890abcdef1234567890abcdef12", 100, "T")
	tx0 := allocationToTx(alloc, 0, 1732070400)
	tx1 := allocationToTx(alloc, 1, 1732070400)

	if tx0.ID == tx1.ID {
		t.Error("different indexes produced identical transaction IDs")
	}
}

// TestAllocationToTx_AmountCopy — post-creation mutation must not propagate.
func TestAllocationToTx_AmountCopy(t *testing.T) {
	alloc := NewGenesisAllocationSPX("abcdef1234567890abcdef1234567890abcdef12", 100, "T")
	original := new(big.Int).Set(alloc.BalanceNSPX)
	tx := allocationToTx(alloc, 0, 1732070400)

	alloc.BalanceNSPX.SetInt64(999)

	if tx.Amount.Cmp(original) != 0 {
		t.Errorf("allocationToTx did not copy balance: got %s, want %s",
			tx.Amount.String(), original.String())
	}
}

// ============================================================================
// 5. BuildBlock — uses minimalGenesisState (2 allocations, ~3 argon2 calls)
// ============================================================================

// TestBuildBlock_Determinism — identical state → identical hash.
func TestBuildBlock_Determinism(t *testing.T) {
	gs := minimalGenesisState()
	b1 := gs.BuildBlock()
	b2 := gs.BuildBlock()

	if b1.GetHash() != b2.GetHash() {
		t.Errorf("BuildBlock not deterministic: %s != %s", b1.GetHash(), b2.GetHash())
	}
}

// TestBuildBlock_Fields — header fields copied faithfully from GenesisState.
func TestBuildBlock_Fields(t *testing.T) {
	gs := minimalGenesisState()
	block := gs.BuildBlock()

	if block.GetHeight() != 0 {
		t.Errorf("height: want 0, got %d", block.GetHeight())
	}
	if block.GetHash() == "" {
		t.Error("hash must not be empty after BuildBlock")
	}

	ub := block.Header
	if ub == nil {
		t.Fatal("block header is nil")
	}
	if ub.Timestamp != gs.Timestamp {
		t.Errorf("Timestamp: want %d, got %d", gs.Timestamp, ub.Timestamp)
	}
	if ub.Nonce != gs.Nonce {
		t.Errorf("Nonce: want %q, got %q", gs.Nonce, ub.Nonce)
	}
	if ub.Difficulty.Cmp(gs.InitialDifficulty) != 0 {
		t.Errorf("Difficulty: want %s, got %s",
			gs.InitialDifficulty.String(), ub.Difficulty.String())
	}
	if ub.GasLimit.Cmp(gs.InitialGasLimit) != 0 {
		t.Errorf("GasLimit: want %s, got %s",
			gs.InitialGasLimit.String(), ub.GasLimit.String())
	}
	if string(ub.ExtraData) != string(gs.ExtraData) {
		t.Errorf("ExtraData: want %q, got %q", gs.ExtraData, ub.ExtraData)
	}
}

// TestBuildBlock_ParentHashZero — genesis ParentHash is 32 zero bytes.
func TestBuildBlock_ParentHashZero(t *testing.T) {
	block := minimalGenesisState().BuildBlock()
	parent := block.Header.ParentHash

	if len(parent) != 32 {
		t.Errorf("ParentHash length: want 32, got %d", len(parent))
	}
	for i, b := range parent {
		if b != 0 {
			t.Errorf("ParentHash[%d] = %d, want 0 (genesis must have zero parent)", i, b)
		}
	}
}

// TestBuildBlock_BodyPopulated — one transaction per allocation.
// This guards the core bug: txs_list was always empty before the fix.
func TestBuildBlock_BodyPopulated(t *testing.T) {
	gs := minimalGenesisState()
	block := gs.BuildBlock()

	wantTxCount := len(gs.Allocations) // 2
	gotTxCount := len(block.Body.TxsList)
	if gotTxCount != wantTxCount {
		t.Errorf("txs_list length: want %d (one per allocation), got %d",
			wantTxCount, gotTxCount)
	}
}

// TestBuildBlock_TxsRootMatchesBody — header TxsRoot == Merkle(body txs).
func TestBuildBlock_TxsRootMatchesBody(t *testing.T) {
	gs := minimalGenesisState()
	block := gs.BuildBlock()

	// CalculateTxsRoot is the same function used by ValidateBlock.
	calculatedRoot := block.CalculateTxsRoot()
	storedRoot := block.Header.TxsRoot

	if hex.EncodeToString(storedRoot) != hex.EncodeToString(calculatedRoot) {
		t.Errorf("TxsRoot mismatch:\n  header : %x\n  body   : %x",
			storedRoot, calculatedRoot)
	}
}

// TestBuildBlock_TxSenderIsGenesis — all genesis txs use "genesis" as sender.
func TestBuildBlock_TxSenderIsGenesis(t *testing.T) {
	block := minimalGenesisState().BuildBlock()
	for i, tx := range block.Body.TxsList {
		if tx.Sender != "genesis" {
			t.Errorf("txs_list[%d].Sender: want %q, got %q", i, "genesis", tx.Sender)
		}
	}
}

// TestBuildBlock_TxReceiversMatchAllocations — receiver[i] == allocation[i].Address.
func TestBuildBlock_TxReceiversMatchAllocations(t *testing.T) {
	gs := minimalGenesisState()
	block := gs.BuildBlock()

	for i, tx := range block.Body.TxsList {
		want := gs.Allocations[i].Address
		if tx.Receiver != want {
			t.Errorf("txs_list[%d].Receiver: want %q, got %q", i, want, tx.Receiver)
		}
	}
}

// TestBuildBlock_TxAmountsMatchAllocations — amount[i] == allocation[i].BalanceNSPX.
func TestBuildBlock_TxAmountsMatchAllocations(t *testing.T) {
	gs := minimalGenesisState()
	block := gs.BuildBlock()

	for i, tx := range block.Body.TxsList {
		want := gs.Allocations[i].BalanceNSPX
		if tx.Amount.Cmp(want) != 0 {
			t.Errorf("txs_list[%d].Amount: want %s, got %s", i, want.String(), tx.Amount.String())
		}
	}
}

// TestBuildBlock_DifferentGenesisStates — ExtraData change → different hash.
func TestBuildBlock_DifferentGenesisStates(t *testing.T) {
	gs1 := minimalGenesisState()
	gs2 := minimalGenesisState()
	gs2.ExtraData = []byte("completely-different-extra-data")

	h1 := gs1.BuildBlock().GetHash()
	h2 := gs2.BuildBlock().GetHash()

	if h1 == h2 {
		t.Error("different ExtraData produced the same block hash — builder is not sensitive to ExtraData changes")
	}
}

// TestBuildBlock_NewHashIsSelfConsistent — ValidateTxsRoot passes; root ≠ empty hash.
func TestBuildBlock_NewHashIsSelfConsistent(t *testing.T) {
	gs := minimalGenesisState()
	block := gs.BuildBlock()

	// The block must pass its own TxsRoot validation.
	if err := block.ValidateTxsRoot(); err != nil {
		t.Errorf("BuildBlock produced a block that fails ValidateTxsRoot: %v", err)
	}

	// TxsRoot must NOT be the empty hash because allocations are present.
	emptyHash := common.SpxHash([]byte{})
	if hex.EncodeToString(block.Header.TxsRoot) == hex.EncodeToString(emptyHash) {
		t.Error("TxsRoot should NOT be the empty hash when allocations are present")
	}
}

// ============================================================================
// 6. ApplyGenesis — uses minimalGenesisState (fast)
// ============================================================================

// TestApplyGenesis_StoresBlock — genesis block persisted to storage.
func TestApplyGenesis_StoresBlock(t *testing.T) {
	bc := newMinimalBlockchain(t)
	gs := minimalGenesisState()

	if err := ApplyGenesis(bc, gs); err != nil {
		t.Fatalf("ApplyGenesis: %v", err)
	}

	latest, err := bc.storage.GetLatestBlock()
	if err != nil {
		t.Fatalf("GetLatestBlock: %v", err)
	}
	if latest == nil {
		t.Fatal("GetLatestBlock returned nil after ApplyGenesis")
	}
	if latest.GetHeight() != 0 {
		t.Errorf("genesis height: want 0, got %d", latest.GetHeight())
	}
	if latest.GetHash() == "" {
		t.Error("genesis hash must not be empty")
	}
}

// TestApplyGenesis_BodyContainsAllocations — in-memory chain seeded with correct tx count.
func TestApplyGenesis_BodyContainsAllocations(t *testing.T) {
	bc := newMinimalBlockchain(t)
	gs := minimalGenesisState()

	if err := ApplyGenesis(bc, gs); err != nil {
		t.Fatalf("ApplyGenesis: %v", err)
	}

	bc.lock.RLock()
	chainLen := len(bc.chain)
	bc.lock.RUnlock()

	if chainLen == 0 {
		t.Fatal("bc.chain is empty after ApplyGenesis")
	}

	bc.lock.RLock()
	genesisBlock := bc.chain[0]
	bc.lock.RUnlock()

	if len(genesisBlock.Body.TxsList) != len(gs.Allocations) {
		t.Errorf("txs_list length: want %d, got %d",
			len(gs.Allocations), len(genesisBlock.Body.TxsList))
	}
}

// TestApplyGenesis_Idempotent — calling twice must not return an error.
func TestApplyGenesis_Idempotent(t *testing.T) {
	bc := newMinimalBlockchain(t)
	gs := minimalGenesisState()

	if err := ApplyGenesis(bc, gs); err != nil {
		t.Fatalf("first ApplyGenesis: %v", err)
	}
	if err := ApplyGenesis(bc, gs); err != nil {
		t.Fatalf("second ApplyGenesis (should be idempotent): %v", err)
	}
}

// TestApplyGenesis_ConflictReturnsError — conflicting genesis on existing chain → error.
func TestApplyGenesis_ConflictReturnsError(t *testing.T) {
	bc := newMinimalBlockchain(t)

	if err := ApplyGenesis(bc, minimalGenesisState()); err != nil {
		t.Fatalf("initial ApplyGenesis: %v", err)
	}

	// Build a conflicting genesis with different extra data.
	conflicting := minimalGenesisState()
	conflicting.ExtraData = []byte("conflicting-chain-extra-data-abc")

	if err := ApplyGenesis(bc, conflicting); err == nil {
		t.Error("expected error when applying conflicting genesis, got nil")
	}
}

// TestApplyGenesis_WritesGenesisStateJSON — genesis_state.json is written and non-empty.
func TestApplyGenesis_WritesGenesisStateJSON(t *testing.T) {
	bc := newMinimalBlockchain(t)

	if err := ApplyGenesis(bc, minimalGenesisState()); err != nil {
		t.Fatalf("ApplyGenesis: %v", err)
	}

	jsonPath := filepath.Join(bc.storage.GetStateDir(), "genesis_state.json")
	info, err := os.Stat(jsonPath)
	if err != nil {
		t.Fatalf("genesis_state.json not found at %s: %v", jsonPath, err)
	}
	if info.Size() == 0 {
		t.Error("genesis_state.json is empty")
	}
}

// TestApplyGenesis_JSONContainsAllocations — genesis_state.json holds real allocation data.
// Directly guards the blank-array regression that was the original bug.
func TestApplyGenesis_JSONContainsAllocations(t *testing.T) {
	bc := newMinimalBlockchain(t)

	if err := ApplyGenesis(bc, minimalGenesisState()); err != nil {
		t.Fatalf("ApplyGenesis: %v", err)
	}

	jsonPath := filepath.Join(bc.storage.GetStateDir(), "genesis_state.json")
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	content := string(raw)
	for _, key := range []string{`"address"`, `"balance_spx"`, `"total_allocated_spx"`} {
		if !containsSubstring(content, key) {
			t.Errorf("genesis_state.json missing key %s — allocations array is blank", key)
		}
	}
}

// TestApplyGenesis_NilBlockchain — nil blockchain → error, no panic.
func TestApplyGenesis_NilBlockchain(t *testing.T) {
	if err := ApplyGenesis(nil, minimalGenesisState()); err == nil {
		t.Error("expected error for nil blockchain, got nil")
	}
}

// TestApplyGenesis_NilGenesisState — nil genesis state → error, no panic.
func TestApplyGenesis_NilGenesisState(t *testing.T) {
	bc := newMinimalBlockchain(t)
	if err := ApplyGenesis(bc, nil); err == nil {
		t.Error("expected error for nil GenesisState, got nil")
	}
}

// ============================================================================
// 7. ValidateGenesisState  (no BuildBlock — fast)
// ============================================================================

func TestValidateGenesisState_ValidDefault(t *testing.T) {
	if err := ValidateGenesisState(DefaultGenesisState()); err != nil {
		t.Errorf("DefaultGenesisState failed validation: %v", err)
	}
}

func TestValidateGenesisState_Nil(t *testing.T) {
	if err := ValidateGenesisState(nil); err == nil {
		t.Error("expected error for nil GenesisState")
	}
}

func TestValidateGenesisState_ZeroChainID(t *testing.T) {
	gs := defaultGS(t, func(g *GenesisState) { g.ChainID = 0 })
	if err := ValidateGenesisState(gs); err == nil {
		t.Error("expected error for ChainID=0")
	}
}

func TestValidateGenesisState_EmptyChainName(t *testing.T) {
	gs := defaultGS(t, func(g *GenesisState) { g.ChainName = "" })
	if err := ValidateGenesisState(gs); err == nil {
		t.Error("expected error for empty ChainName")
	}
}

func TestValidateGenesisState_ZeroTimestamp(t *testing.T) {
	gs := defaultGS(t, func(g *GenesisState) { g.Timestamp = 0 })
	if err := ValidateGenesisState(gs); err == nil {
		t.Error("expected error for Timestamp=0")
	}
}

func TestValidateGenesisState_NilDifficulty(t *testing.T) {
	gs := defaultGS(t, func(g *GenesisState) { g.InitialDifficulty = nil })
	if err := ValidateGenesisState(gs); err == nil {
		t.Error("expected error for nil InitialDifficulty")
	}
}

func TestValidateGenesisState_NilGasLimit(t *testing.T) {
	gs := defaultGS(t, func(g *GenesisState) { g.InitialGasLimit = nil })
	if err := ValidateGenesisState(gs); err == nil {
		t.Error("expected error for nil InitialGasLimit")
	}
}

func TestValidateGenesisState_EmptyNonce(t *testing.T) {
	gs := defaultGS(t, func(g *GenesisState) { g.Nonce = "" })
	if err := ValidateGenesisState(gs); err == nil {
		t.Error("expected error for empty Nonce")
	}
}

func TestValidateGenesisState_DuplicateAllocationAddress(t *testing.T) {
	addr := "1000000000000000000000000000000000000001"
	gs := defaultGS(t, func(g *GenesisState) {
		g.Allocations = []*GenesisAllocation{
			NewFounderAlloc(addr, 100),
			NewFounderAlloc(addr, 200), // duplicate
		}
	})
	if err := ValidateGenesisState(gs); err == nil {
		t.Error("expected error for duplicate allocation address")
	}
}

func TestValidateGenesisState_DuplicateValidatorNodeID(t *testing.T) {
	gs := defaultGS(t, func(g *GenesisState) {
		g.InitialValidators = []*GenesisValidator{
			{NodeID: "Node-A", StakeNSPX: NewGenesisValidatorStake(32)},
			{NodeID: "Node-A", StakeNSPX: NewGenesisValidatorStake(32)}, // duplicate
		}
	})
	if err := ValidateGenesisState(gs); err == nil {
		t.Error("expected error for duplicate validator NodeID")
	}
}

func TestValidateGenesisState_ValidatorZeroStake(t *testing.T) {
	gs := defaultGS(t, func(g *GenesisState) {
		g.InitialValidators = []*GenesisValidator{
			{NodeID: "Node-A", StakeNSPX: big.NewInt(0)},
		}
	})
	if err := ValidateGenesisState(gs); err == nil {
		t.Error("expected error for validator with zero stake")
	}
}

// ============================================================================
// 8. VerifyGenesisBlockHash — uses minimalGenesisState (fast)
// ============================================================================

func TestVerifyGenesisBlockHash_Match(t *testing.T) {
	gs := minimalGenesisState()
	expected := gs.BuildBlock().GetHash()

	if err := VerifyGenesisBlockHash(gs, expected); err != nil {
		t.Errorf("VerifyGenesisBlockHash: unexpected error: %v", err)
	}
}

func TestVerifyGenesisBlockHash_Mismatch(t *testing.T) {
	gs := minimalGenesisState()
	if err := VerifyGenesisBlockHash(gs, "completely-wrong-hash"); err == nil {
		t.Error("expected error for hash mismatch, got nil")
	}
}

// ============================================================================
// 9. buildAllocationRoot — uses minimalGenesisState (fast)
// ============================================================================

// TestBuildAllocationRoot_EmptyAllocations — empty list → SpxHash([]byte{}).
func TestBuildAllocationRoot_EmptyAllocations(t *testing.T) {
	gs := minimalGenesisState()
	gs.Allocations = nil
	root := gs.buildAllocationRoot()

	want := common.SpxHash([]byte{})
	if hex.EncodeToString(root) != hex.EncodeToString(want) {
		t.Errorf("empty allocation root: want %x, got %x", want, root)
	}
}

// TestBuildAllocationRoot_Deterministic — same list → same root, always.
func TestBuildAllocationRoot_Deterministic(t *testing.T) {
	gs := minimalGenesisState()
	r1 := gs.buildAllocationRoot()
	r2 := gs.buildAllocationRoot()

	if hex.EncodeToString(r1) != hex.EncodeToString(r2) {
		t.Error("buildAllocationRoot is not deterministic")
	}
}

// TestBuildAllocationRoot_ChangeSensitive — extra allocation → different root.
func TestBuildAllocationRoot_ChangeSensitive(t *testing.T) {
	gs1 := minimalGenesisState()
	gs2 := minimalGenesisState()
	gs2.Allocations = append(gs2.Allocations,
		NewCommunityAlloc("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1))

	r1 := hex.EncodeToString(gs1.buildAllocationRoot())
	r2 := hex.EncodeToString(gs2.buildAllocationRoot())

	if r1 == r2 {
		t.Error("adding an allocation did not change the allocation root")
	}
}

// TestBuildAllocationRoot_MatchesTxsRoot — root == block.Header.TxsRoot.
// This is the critical consistency check.
func TestBuildAllocationRoot_MatchesTxsRoot(t *testing.T) {
	gs := minimalGenesisState()
	root := gs.buildAllocationRoot()
	block := gs.BuildBlock()

	if hex.EncodeToString(root) != hex.EncodeToString(block.Header.TxsRoot) {
		t.Errorf("buildAllocationRoot != block.Header.TxsRoot\n  root : %x\n  txs  : %x",
			root, block.Header.TxsRoot)
	}
}

// ============================================================================
// 10. merkleRootFromLeaves  (small fixed leaf count — fast)
// ============================================================================

func TestMerkleRootFromLeaves_Empty(t *testing.T) {
	root := merkleRootFromLeaves(nil)
	if len(root) == 0 {
		t.Error("merkleRootFromLeaves(nil) returned empty slice")
	}
}

func TestMerkleRootFromLeaves_SingleLeaf(t *testing.T) {
	leaf := []byte("hello-sphinx")
	root := merkleRootFromLeaves([][]byte{leaf})
	if len(root) == 0 {
		t.Error("single-leaf Merkle root is empty")
	}
	// Single-leaf tree = SpxHash(leaf).
	want := common.SpxHash(leaf)
	if hex.EncodeToString(root) != hex.EncodeToString(want) {
		t.Errorf("single-leaf root: want %x, got %x", want, root)
	}
}

func TestMerkleRootFromLeaves_OddLeafCount(t *testing.T) {
	leaves := [][]byte{
		[]byte("leaf-one"),
		[]byte("leaf-two"),
		[]byte("leaf-three"),
	}
	root := merkleRootFromLeaves(leaves)
	if len(root) == 0 {
		t.Error("odd-count Merkle root is empty")
	}
	// Must be deterministic.
	root2 := merkleRootFromLeaves(leaves)
	if hex.EncodeToString(root) != hex.EncodeToString(root2) {
		t.Error("merkleRootFromLeaves is not deterministic for odd leaf counts")
	}
}
