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

// go/src/core/genesis.go
package core

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/sphinxorg/protocol/src/common"
	types "github.com/sphinxorg/protocol/src/core/transaction"
	logger "github.com/sphinxorg/protocol/src/log"
)

// NewGenesisValidatorStake converts a whole-SPX amount to the nSPX big.Int
// representation expected by GenesisValidator.StakeNSPX.
//
//	stake := NewGenesisValidatorStake(32) // 32 SPX → 32 × 10^18 nSPX
func NewGenesisValidatorStake(spx int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(spx), big.NewInt(1e18))
}

// DefaultGenesisState returns the canonical genesis configuration used by all
// nodes on the Sphinx Mainnet. Every field is deterministic so that independent
// invocations on different machines produce byte-for-byte identical genesis blocks.
//
// To customise for testnet / devnet, call GetTestnetChainParams() /
// GetDevnetChainParams() and pass the result to GenesisStateFromChainParams().
func DefaultGenesisState() *GenesisState {
	return &GenesisState{
		ChainID:           7331,
		ChainName:         "Sphinx Mainnet",
		Symbol:            "SPX",
		Timestamp:         1732070400, // Nov 20 2024 00:00:00 UTC — MUST match genesisBlockDefinition
		ExtraData:         []byte("Sphinx Network Genesis Block - Decentralized Future"),
		InitialDifficulty: big.NewInt(17179869184),
		InitialGasLimit:   big.NewInt(5000),
		Nonce:             common.FormatNonce(1), // "0000000000000001"
		Allocations:       DefaultGenesisAllocations(),
		InitialValidators: []*GenesisValidator{},
	}
}

// GenesisStateFromChainParams builds a GenesisState whose identity fields
// (ChainID, ChainName, Symbol, Timestamp, difficulty, gas limit, extra data)
// are sourced from the supplied SphinxChainParameters. The Allocations are
// taken from DefaultGenesisAllocations() unless overridden afterwards.
//
// This is the preferred entry-point for testnet / devnet nodes:
//
//	state := GenesisStateFromChainParams(GetTestnetChainParams())
func GenesisStateFromChainParams(p *SphinxChainParameters) *GenesisState {
	extraData := []byte("Sphinx Network Genesis Block - Decentralized Future")
	initialDiff := big.NewInt(17179869184)
	initialGas := big.NewInt(5000)

	// Override with values from GenesisConfig if present.
	if p.GenesisConfig != nil {
		if p.GenesisConfig.GenesisExtraData != nil {
			extraData = p.GenesisConfig.GenesisExtraData
		}
		if p.GenesisConfig.InitialDifficulty != nil {
			initialDiff = new(big.Int).Set(p.GenesisConfig.InitialDifficulty)
		}
		if p.GenesisConfig.InitialGasLimit != nil {
			initialGas = new(big.Int).Set(p.GenesisConfig.InitialGasLimit)
		}
	}

	return &GenesisState{
		ChainID:           p.ChainID,
		ChainName:         p.ChainName,
		Symbol:            p.Symbol,
		Timestamp:         p.GenesisTime,
		ExtraData:         extraData,
		InitialDifficulty: initialDiff,
		InitialGasLimit:   initialGas,
		Nonce:             common.FormatNonce(1),
		Allocations:       DefaultGenesisAllocations(),
		InitialValidators: []*GenesisValidator{},
	}
}

// AddValidator appends a validator entry to gs.InitialValidators.
// It is a fluent convenience wrapper for building genesis state in tests:
//
//	gs := DefaultGenesisState().
//	    AddValidator("Node-127.0.0.1:32307", "0xabc...", 32, "").
//	    AddValidator("Node-127.0.0.1:32308", "0xdef...", 32, "")
func (gs *GenesisState) AddValidator(nodeID, address string, stakeInSPX int64, pubKeyHex string) *GenesisState {
	gs.InitialValidators = append(gs.InitialValidators, &GenesisValidator{
		NodeID:    nodeID,
		Address:   address,
		StakeNSPX: NewGenesisValidatorStake(stakeInSPX),
		PublicKey: pubKeyHex,
	})
	return gs
}

// ----------------------------------------------------------------------------
// Allocation → Transaction conversion
// ----------------------------------------------------------------------------

// allocationToTx converts a single GenesisAllocation into a genesis funding
// transaction that is placed in the block body.
//
// Convention:
//   - Sender   : "genesis" (no real signing key at block 0)
//   - Receiver : the allocation address (hex, no 0x prefix)
//   - Amount   : allocation.BalanceNSPX (in nSPX)
//   - Nonce    : sequential index i, so every transaction is unique
//   - Timestamp: genesis block timestamp
//   - ID       : deterministic — hex(SpxHash(address || balance_bytes || nonce_bytes))
//
// The ID is fully deterministic so the Merkle root computed from the
// transaction list always matches the TxsRoot in the block header.
func allocationToTx(alloc *GenesisAllocation, index uint64, genesisTimestamp int64) *types.Transaction {
	// Build a deterministic ID from address + balance + index so the same
	// allocation always produces the same transaction ID on every node.
	idInput := []byte(alloc.Address)
	if alloc.BalanceNSPX != nil {
		idInput = append(idInput, alloc.BalanceNSPX.Bytes()...)
	}
	indexBytes := make([]byte, 8)
	indexBytes[0] = byte(index >> 56)
	indexBytes[1] = byte(index >> 48)
	indexBytes[2] = byte(index >> 40)
	indexBytes[3] = byte(index >> 32)
	indexBytes[4] = byte(index >> 24)
	indexBytes[5] = byte(index >> 16)
	indexBytes[6] = byte(index >> 8)
	indexBytes[7] = byte(index)
	idInput = append(idInput, indexBytes...)

	txID := hex.EncodeToString(common.SpxHash(idInput))

	// Copy amount so callers cannot mutate the allocation.
	amount := new(big.Int)
	if alloc.BalanceNSPX != nil {
		amount.Set(alloc.BalanceNSPX)
	}

	return &types.Transaction{
		ID:        txID,             // Deterministic unique identifier
		Sender:    "genesis",        // No real sender at block 0
		Receiver:  alloc.Address,    // The pre-funded account
		Amount:    amount,           // Initial balance in nSPX
		GasLimit:  big.NewInt(0),    // Genesis transactions consume no gas
		GasPrice:  big.NewInt(0),    // Genesis transactions have zero gas price
		Nonce:     index,            // Sequential to make each tx unique
		Timestamp: genesisTimestamp, // Anchored to genesis time
		Signature: []byte{},         // No signature for genesis funding transactions
	}
}

// allocationsToTxList converts the complete ordered allocation list into a
// slice of *types.Transaction suitable for the block body.
// The order of the output slice matches the order of gs.Allocations exactly,
// which is required for the Merkle root to be deterministic.
func (gs *GenesisState) allocationsToTxList() []*types.Transaction {
	txs := make([]*types.Transaction, len(gs.Allocations))
	for i, alloc := range gs.Allocations {
		txs[i] = allocationToTx(alloc, uint64(i), gs.Timestamp)
	}
	return txs
}

// ----------------------------------------------------------------------------
// Block construction
// ----------------------------------------------------------------------------

// BuildBlock materialises a *types.Block from the GenesisState.
//
// The genesis block body now contains one transaction per GenesisAllocation
// so that txs_list in the stored JSON is populated and the TxsRoot in the
// header is derived from those transactions — making the file self-consistent
// and human-readable.
//
// The resulting block is deterministic: identical GenesisState inputs on any
// node always produce the same hash.  The block is NOT stored to disk; that
// is the caller's responsibility (see ApplyGenesis).
func (gs *GenesisState) BuildBlock() *types.Block {
	// Convert allocations into genesis funding transactions.
	// These transactions are stored in the block body (txs_list) so that
	// the stored JSON shows the genesis allocation data, and the TxsRoot
	// in the header is computed from them — not from an empty list.
	genesisTxs := gs.allocationsToTxList()

	// Calculate the TxsRoot (Merkle root) from the transaction list.
	// We use a temporary block body to leverage the existing CalculateTxsRoot
	// implementation so the root is computed identically to how non-genesis
	// blocks compute it.
	tempBody := types.NewBlockBody(genesisTxs, []*types.BlockHeader{})
	tempBlock := types.NewBlock(&types.BlockHeader{}, tempBody)
	txsRoot := tempBlock.CalculateTxsRoot()

	header := &types.BlockHeader{
		Version:    1,
		Block:      0,
		Height:     0,
		Timestamp:  gs.Timestamp,
		Difficulty: new(big.Int).Set(gs.InitialDifficulty),
		Nonce:      gs.Nonce,
		TxsRoot:    txsRoot, // Derived from the funding transactions in the body
		StateRoot:  common.SpxHash([]byte("sphinx-genesis-state-root")),
		GasLimit:   new(big.Int).Set(gs.InitialGasLimit),
		GasUsed:    big.NewInt(0),
		ExtraData:  append([]byte{}, gs.ExtraData...),
		Miner:      make([]byte, 20), // zero address at genesis
		ParentHash: make([]byte, 32), // no parent
		UnclesHash: common.SpxHash([]byte("genesis-no-uncles")),
		Hash:       []byte{},
	}

	// Build the real block body with the allocation transactions.
	body := types.NewBlockBody(genesisTxs, []*types.BlockHeader{})
	block := types.NewBlock(header, body)
	block.FinalizeHash()

	logger.Info("GenesisState.BuildBlock: hash=%s, height=%d, nonce=%s, txs=%d, txs_root=%s",
		block.GetHash(), block.GetHeight(), block.Header.Nonce,
		len(genesisTxs), hex.EncodeToString(txsRoot))

	return block
}

// buildAllocationRoot computes a deterministic Merkle root over all genesis
// allocations using the transaction-based approach so the root always matches
// what BuildBlock embeds in the header.
//
// This method is kept for backward-compatibility with tests that call it
// directly.  It now delegates to allocationsToTxList + CalculateTxsRoot so
// the result is byte-for-byte identical to the TxsRoot produced by BuildBlock.
func (gs *GenesisState) buildAllocationRoot() []byte {
	if len(gs.Allocations) == 0 {
		// Empty body → standard empty Merkle root.
		return common.SpxHash([]byte{})
	}

	// Build the same transaction list that BuildBlock uses so the root matches.
	genesisTxs := gs.allocationsToTxList()
	tempBody := types.NewBlockBody(genesisTxs, []*types.BlockHeader{})
	tempBlock := types.NewBlock(&types.BlockHeader{}, tempBody)
	return tempBlock.CalculateTxsRoot()
}

// merkleRootFromLeaves reduces a slice of leaf hashes to a single root using a
// simple binary Merkle tree. Odd-length layers are padded by duplicating the
// last element — the same convention used in the transaction Merkle tree.
// Retained for use by the test suite.
func merkleRootFromLeaves(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return common.SpxHash([]byte{})
	}

	layer := make([][]byte, len(leaves))
	for i, l := range leaves {
		layer[i] = common.SpxHash(l)
	}

	for len(layer) > 1 {
		if len(layer)%2 != 0 {
			layer = append(layer, layer[len(layer)-1]) // duplicate last
		}
		next := make([][]byte, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			combined := append(layer[i], layer[i+1]...)
			next[i/2] = common.SpxHash(combined)
		}
		layer = next
	}

	return layer[0]
}

// ----------------------------------------------------------------------------
// ApplyGenesis — storage integration
// ----------------------------------------------------------------------------

// ApplyGenesis stores the genesis block produced by gs into bc's storage layer
// and sets bc.chain[0]. It also writes a genesis_state.json file alongside the
// block index so the configuration is human-readable and auditable.
//
// The genesis block body now contains one funding transaction per allocation
// (see allocationsToTxList) so the stored JSON shows the full genesis token
// distribution and the TxsRoot header field is self-consistent.
//
// ApplyGenesis is idempotent: if a block at height 0 already exists in storage
// and its hash matches the one produced by gs, the function returns nil without
// overwriting anything.
func ApplyGenesis(bc *Blockchain, gs *GenesisState) error {
	if bc == nil {
		return fmt.Errorf("ApplyGenesis: blockchain is nil")
	}
	if gs == nil {
		return fmt.Errorf("ApplyGenesis: genesis state is nil")
	}

	block := gs.BuildBlock()

	// Idempotency check — skip if we already have a matching genesis.
	existing, err := bc.storage.GetLatestBlock()
	if err == nil && existing != nil && existing.GetHeight() == 0 {
		if existing.GetHash() == block.GetHash() {
			logger.Info("ApplyGenesis: genesis block already present (%s), skipping", block.GetHash())
			return nil
		}
		return fmt.Errorf("ApplyGenesis: conflicting genesis block exists (stored=%s, new=%s)",
			existing.GetHash(), block.GetHash())
	}

	// Persist to storage.
	if err := bc.storage.StoreBlock(block); err != nil {
		return fmt.Errorf("ApplyGenesis: failed to store genesis block: %w", err)
	}

	// Seed the in-memory chain.
	bc.lock.Lock()
	bc.chain = []*types.Block{block}
	bc.lock.Unlock()

	// Persist a human-readable genesis_state.json for auditing.
	if writeErr := gs.writeGenesisStateFile(bc.storage.GetStateDir()); writeErr != nil {
		// Non-fatal: log and continue.
		logger.Warn("ApplyGenesis: failed to write genesis_state.json: %v", writeErr)
	}

	logger.Info("✅ ApplyGenesis: genesis block applied — hash=%s, allocations=%d, validators=%d, txs_in_body=%d",
		block.GetHash(), len(gs.Allocations), len(gs.InitialValidators), len(block.Body.TxsList))

	return nil
}

// ApplyGenesisWithCachedBlock is like ApplyGenesis but accepts a pre-built
// genesis block so BuildBlock() (argon2) is not called again.
// Use this when multiple nodes start in the same process.
func ApplyGenesisWithCachedBlock(bc *Blockchain, gs *GenesisState, cachedBlock *types.Block) error {
	if bc == nil {
		return fmt.Errorf("blockchain is nil")
	}
	if gs == nil {
		return fmt.Errorf("genesis state is nil")
	}
	if cachedBlock == nil {
		return ApplyGenesis(bc, gs)
	}

	// Check if genesis already applied
	latest, err := bc.storage.GetLatestBlock()
	if err == nil && latest != nil && latest.GetHeight() == 0 {
		existingHash := latest.GetHash()
		newHash := cachedBlock.GetHash()
		if existingHash == newHash {
			logger.Info("ApplyGenesis: genesis block already present (%s), skipping", existingHash)
			if len(bc.chain) == 0 {
				bc.chain = []*types.Block{latest}
			}
			return nil
		}
		return fmt.Errorf("genesis conflict: stored=%s new=%s", existingHash, newHash)
	}

	// Store the cached block
	if err := bc.storage.StoreBlock(cachedBlock); err != nil {
		return fmt.Errorf("failed to store cached genesis block: %w", err)
	}

	// Seed the in-memory chain
	bc.lock.Lock()
	bc.chain = []*types.Block{cachedBlock}
	bc.lock.Unlock()

	// Write genesis_state.json
	if writeErr := gs.writeGenesisStateFile(bc.storage.GetStateDir()); writeErr != nil {
		logger.Warn("ApplyGenesis (cached): failed to write genesis_state.json: %v", writeErr)
	}

	logger.Info("✅ ApplyGenesis (cached): genesis block applied — hash=%s, allocations=%d, txs_in_body=%d",
		cachedBlock.GetHash(), len(gs.Allocations), len(cachedBlock.Body.TxsList))

	return nil
}

// writeGenesisStateFile serialises the GenesisState to a JSON file at
// <stateDir>/genesis_state.json. The file is created with 0644 permissions.
//
// FIX: now writes the complete per-account allocation list and per-validator
// list so genesis_state.json contains real data instead of blank arrays.
func (gs *GenesisState) writeGenesisStateFile(stateDir string) error {
	if err := os.MkdirAll(stateDir, 0755); err != nil {
		return fmt.Errorf("cannot create state dir: %w", err)
	}

	// Build per-account rows and compute total allocated supply.
	total := new(big.Int)
	allocEntries := make([]genesisAllocationEntry, len(gs.Allocations))
	for i, a := range gs.Allocations {
		if a.BalanceNSPX != nil {
			total.Add(total, a.BalanceNSPX)
		}
		// Express balance in both nSPX and whole SPX for human readability.
		balSPX := new(big.Int)
		nspxStr := "0"
		if a.BalanceNSPX != nil {
			balSPX.Div(a.BalanceNSPX, big.NewInt(1e18))
			nspxStr = a.BalanceNSPX.String()
		}
		allocEntries[i] = genesisAllocationEntry{
			Address:     a.Address,
			BalanceNSPX: nspxStr,
			BalanceSPX:  balSPX.String(),
			Label:       a.Label,
		}
	}
	totalSPX := new(big.Int).Div(total, big.NewInt(1e18))

	// Build per-validator rows.
	valEntries := make([]genesisValidatorEntry, len(gs.InitialValidators))
	for i, v := range gs.InitialValidators {
		stakeSPX := new(big.Int)
		stakeNSPXStr := "0"
		if v.StakeNSPX != nil {
			stakeSPX.Div(v.StakeNSPX, big.NewInt(1e18))
			stakeNSPXStr = v.StakeNSPX.String()
		}
		valEntries[i] = genesisValidatorEntry{
			NodeID:    v.NodeID,
			Address:   v.Address,
			StakeNSPX: stakeNSPXStr,
			StakeSPX:  stakeSPX.String(),
			PublicKey: v.PublicKey,
		}
	}

	// Produce a JSON-friendly snapshot with string representations of big.Int
	// fields so the file is readable without a Go runtime.
	snapshot := genesisStateSnapshot{
		ChainID:            gs.ChainID,
		ChainName:          gs.ChainName,
		Symbol:             gs.Symbol,
		Timestamp:          gs.Timestamp,
		TimestampISO:       time.Unix(gs.Timestamp, 0).UTC().Format(time.RFC3339),
		ExtraData:          string(gs.ExtraData),
		InitialDifficulty:  gs.InitialDifficulty.String(),
		InitialGasLimit:    gs.InitialGasLimit.String(),
		Nonce:              gs.Nonce,
		TotalAllocations:   len(gs.Allocations),
		TotalAllocatedNSPX: total.String(),
		TotalAllocatedSPX:  totalSPX.String(),
		TotalValidators:    len(gs.InitialValidators),
		// Full ordered allocation list — previously missing, now populated.
		Allocations: allocEntries,
		// Full validator list — previously missing, now populated.
		InitialValidators: valEntries,
	}

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal error: %w", err)
	}

	path := filepath.Join(stateDir, "genesis_state.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write error: %w", err)
	}

	logger.Info("Genesis state written to %s (%d allocations, total supply %s SPX)",
		path, len(gs.Allocations), totalSPX.String())
	return nil
}

// ----------------------------------------------------------------------------
// Validation helpers
// ----------------------------------------------------------------------------

// ValidateGenesisState performs a thorough sanity check of the GenesisState
// before it is used to build or apply a genesis block. It returns the first
// error encountered so callers can surface meaningful diagnostics.
func ValidateGenesisState(gs *GenesisState) error {
	if gs == nil {
		return fmt.Errorf("genesis state is nil")
	}
	if gs.ChainID == 0 {
		return fmt.Errorf("chain_id cannot be zero")
	}
	if gs.ChainName == "" {
		return fmt.Errorf("chain_name cannot be empty")
	}
	if gs.Symbol == "" {
		return fmt.Errorf("symbol cannot be empty")
	}
	if gs.Timestamp <= 0 {
		return fmt.Errorf("timestamp must be a positive Unix epoch value")
	}
	if gs.InitialDifficulty == nil || gs.InitialDifficulty.Sign() <= 0 {
		return fmt.Errorf("initial_difficulty must be a positive integer")
	}
	if gs.InitialGasLimit == nil || gs.InitialGasLimit.Sign() <= 0 {
		return fmt.Errorf("initial_gas_limit must be a positive integer")
	}
	if gs.Nonce == "" {
		return fmt.Errorf("nonce cannot be empty")
	}

	// Validate every allocation.
	seenAddresses := make(map[string]bool)
	for i, a := range gs.Allocations {
		if err := a.validate(); err != nil {
			return fmt.Errorf("allocation[%d] (%s): %w", i, a.Address, err)
		}
		lower := toLower(a.Address)
		if seenAddresses[lower] {
			return fmt.Errorf("allocation[%d]: duplicate address %s", i, a.Address)
		}
		seenAddresses[lower] = true
	}

	// Validate every initial validator.
	seenValidators := make(map[string]bool)
	for i, v := range gs.InitialValidators {
		if v.NodeID == "" {
			return fmt.Errorf("initial_validator[%d]: node_id cannot be empty", i)
		}
		if seenValidators[v.NodeID] {
			return fmt.Errorf("initial_validator[%d]: duplicate node_id %s", i, v.NodeID)
		}
		seenValidators[v.NodeID] = true
		if v.StakeNSPX == nil || v.StakeNSPX.Sign() <= 0 {
			return fmt.Errorf("initial_validator[%d] (%s): stake must be positive", i, v.NodeID)
		}
	}

	return nil
}

// VerifyGenesisBlockHash rebuilds the genesis block from gs and compares its
// hash to expectedHash. This is useful for nodes that load a genesis
// configuration from disk and want to confirm it matches the network standard.
func VerifyGenesisBlockHash(gs *GenesisState, expectedHash string) error {
	block := gs.BuildBlock()
	actual := block.GetHash()
	if actual != expectedHash {
		return fmt.Errorf("genesis hash mismatch: expected=%s, actual=%s", expectedHash, actual)
	}
	return nil
}

// toLower lowercases a string without importing strings in the test path.
func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
