// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/state_db.go
package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/sphinxfndorg/protocol/src/common"
	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/core/rawdb"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/pool"
)

// Ensure StateDB implements pool.StateDB
var _ pool.StateDB = (*StateDB)(nil)

// Close implements pool.StateDB - closes the underlying database connection
func (db *StateDB) Close() error {
	// StateDB is a lightweight wrapper around Blockchain's shared LevelDB
	// handle. Callers create short-lived wrappers during mempool validation,
	// checkpoint writes, and Phase 2 stake initialization; closing one wrapper
	// must not close the process-wide database.
	return nil
}

// transactionTimestampKey generates the storage key for the last transaction timestamp
const transactionTimestampKey = "tx_ts_"

// GetLastTransactionTimestamp returns the timestamp of the most recent transaction
// for the given address. It reads from both the state DB (committed transactions)
// and the pending map (uncommitted transactions in the current batch).
func (s *StateDB) GetLastTransactionTimestamp(address string) (int64, error) {
	if address == "" {
		return 0, errors.New("address cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// First check if we have pending transactions for this address
	// The pending map contains in-memory changes not yet flushed to disk
	if entry, ok := s.pending[address]; ok && entry.lastTxTimestamp > 0 {
		return entry.lastTxTimestamp, nil
	}

	// Check storage for the last transaction timestamp
	// This key stores the timestamp in Unix seconds format
	key := transactionTimestampKey + address
	data, err := s.db.Get(key)
	if err != nil {
		// No timestamp stored yet for this address
		return 0, nil
	}

	// Parse the timestamp
	var ts int64
	if _, err := fmt.Sscanf(string(data), "%d", &ts); err != nil {
		logger.Warn("GetLastTransactionTimestamp: invalid timestamp format for %s: %v", address, err)
		return 0, nil
	}

	return ts, nil
}

// GetLastNonce implements pool.StateDB
func (db *StateDB) GetLastNonce(address string) (uint64, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Load the account entry
	entry := db.load(address)
	if entry == nil {
		return 0, nil // No previous transactions
	}

	// Get the last nonce from the account
	// For now, return the current nonce (which represents the last used nonce + 1)
	// If you want the last used nonce, subtract 1
	nonce := entry.nonce
	if nonce > 0 {
		return nonce - 1, nil // Return the last used nonce
	}
	return 0, nil // No previous transactions
}

// NewStateDB - Update to restore reward tracking
func NewStateDB(db *database.DB) *StateDB {
	s := &StateDB{
		db:              db,
		pending:         make(map[string]*accountEntry),
		contractPending: make(map[string][]byte),
		totalSupply:     big.NewInt(0),
		genesisSupply:   big.NewInt(0),
		rewardsMinted:   big.NewInt(0),
	}

	// Restore persisted total supply
	if data, err := db.Get(totalSupplyKey); err == nil && len(data) > 0 {
		n, ok := new(big.Int).SetString(string(data), 10)
		if ok {
			s.totalSupply.Set(n)
		}
	}

	// NEW: Restore genesis supply
	if data, err := db.Get(genesisSupplyKey); err == nil && len(data) > 0 {
		n, ok := new(big.Int).SetString(string(data), 10)
		if ok {
			s.genesisSupply.Set(n)
		}
	}

	// NEW: Restore rewards minted
	if data, err := db.Get(rewardsMintedKey); err == nil && len(data) > 0 {
		n, ok := new(big.Int).SetString(string(data), 10)
		if ok {
			s.rewardsMinted.Set(n)
		}
	}

	return s
}

// GetContractValue returns consensus contract state. Contract keys are kept
// separate from accounts but included in the state root.
func (s *StateDB) GetContractValue(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if value, ok := s.contractPending[key]; ok {
		return append([]byte(nil), value...), nil
	}

	value, err := s.db.Get(contractPrefix + key)
	if err != nil {
		return nil, err
	}

	return append([]byte(nil), value...), nil
}

// GetContractCode exposes deployed bytecode to mempool admission and tooling.
// Contract code is stored under the same composite key used by the consensus
// contract store.
func (s *StateDB) GetContractCode(address string) ([]byte, error) {
	return s.GetContractValue(address + ":code:")
}

// SetContractValue stages a contract-state write for the enclosing block.
func (s *StateDB) SetContractValue(key string, value []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.contractPending[key] = append([]byte(nil), value...)
}

// ContractExists checks whether a contract address has been deployed.
// It checks both pending writes (in the current block's state) and the
// committed store. This is used by mempool validation to reject calls to
// non-existent contracts before they enter the pending pool.
//
// Contracts are stored under a composite key address:meta: (see contractKey
// in contract_runtime.go and contractStore.ContractExists). To stay
// consistent with the execution-time check, every accepted rendering of the
// incoming address is consulted (canonical grouped form, raw as-supplied, and
// the legacy 20-byte form) via contractAddressRenderings, so a caller passing
// the spaced display form, bare raw hex, mixed case, or a legacy address all
// resolve to the same key.
func (s *StateDB) ContractExists(address string) bool {
	if address == "" {
		return false
	}
	renderings := contractAddressRenderings(address)
	metaKeys := make([]string, 0, len(renderings))
	for _, rendering := range renderings {
		metaKeys = append(metaKeys, rendering+":meta:")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check pending writes first — contracts are keyed as address:meta:
	for _, metaKey := range metaKeys {
		if _, ok := s.contractPending[metaKey]; ok {
			return true
		}
	}

	// Check the committed store — on-disk key is contract:address:meta:
	for _, metaKey := range metaKeys {
		if _, err := s.db.Get(contractPrefix + metaKey); err == nil {
			return true
		}
	}
	return false
}

// ----------------------------------------------------------------------------
// Validator stake state (deterministic, part of the state root)
//
// Validator stakes are stored in the same deterministic contract-state
// namespace as contract code/storage (contract:validator:<id>), so they are
// hashed into the state root and replayed identically from genesis. This is
// what lets epoch inflation be computed from REAL stake instead of the policy
// target ratio (the executor reads these records at epoch boundaries).
// ----------------------------------------------------------------------------

// validatorStakePrefix is the on-disk prefix for validator stake records.
const validatorStakePrefix = contractPrefix + validatorPrefix

// SetValidatorStake records a validator's stake in nSPX. The write is staged
// until Commit like any other contract-state write. Non-positive stakes are
// ignored (a validator with no stake simply has no record, which distribution
// treats as "not eligible this epoch").
func (s *StateDB) SetValidatorStake(id string, stakeNSPX *big.Int) {
	if id == "" || stakeNSPX == nil || stakeNSPX.Sign() <= 0 {
		return
	}
	s.SetContractValue(validatorPrefix+id, []byte(stakeNSPX.String()))
}

// GetValidatorStake returns the persisted stake for a validator in nSPX, or
// nil when no record exists.
func (s *StateDB) GetValidatorStake(id string) (*big.Int, error) {
	if id == "" {
		return nil, errors.New("validator id cannot be empty")
	}
	value, err := s.GetContractValue(validatorPrefix + id)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, nil
	}
	stake, ok := new(big.Int).SetString(string(value), 10)
	if !ok {
		return nil, fmt.Errorf("corrupt validator stake record for %s: %q", id, string(value))
	}
	return stake, nil
}

// GetAllValidatorStakes returns a snapshot of every persisted validator stake
// keyed by validator ID. Pending (not-yet-committed) writes take precedence
// over the committed store, so an executor distributing epoch rewards uses
// exactly the state it is about to commit.
func (s *StateDB) GetAllValidatorStakes() (map[string]*big.Int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stakes := make(map[string]*big.Int)

	// Pending writes staged for the enclosing block.
	for key, value := range s.contractPending {
		if !strings.HasPrefix(key, validatorPrefix) {
			continue
		}
		id := strings.TrimPrefix(key, validatorPrefix)
		if id == "" {
			continue
		}
		if stake, ok := new(big.Int).SetString(string(value), 10); ok {
			stakes[id] = stake
		}
	}

	// Committed store.
	keys, err := s.db.ListKeysWithPrefix(validatorStakePrefix)
	if err != nil {
		return nil, fmt.Errorf("GetAllValidatorStakes: %w", err)
	}
	for _, k := range keys {
		id := strings.TrimPrefix(k, validatorStakePrefix)
		if id == "" {
			continue
		}
		if _, seen := stakes[id]; seen {
			continue // pending write wins for this block
		}
		data, err := s.db.Get(k)
		if err != nil {
			continue
		}
		if stake, ok := new(big.Int).SetString(string(data), 10); ok {
			stakes[id] = stake
		}
	}

	return stakes, nil
}

// ----------------------------------------------------------------------------
// Deterministic policy state (burn-rate feedback), part of the state root
//
// The usage-responsive fee-burn rate and the previous finalized block's gas
// footprint are persisted in the same deterministic contract-state namespace
// as validator stakes, so they are hashed into the state root and replayed
// identically from genesis. The executor reads the committed pair at the
// start of block N to roll the rate for block N from block N-1's finalized
// gas — never from live peer state, wall-clock time, or the in-progress
// block (see the block-3 divergence ★ FIX in executor.go for the class of
// bug this design keeps closed).
// ----------------------------------------------------------------------------

const (
	// policyStateBurnFeeKey persists the burn rate in effect for fee
	// distribution after the most recent roll.
	policyStateBurnFeeKey = "policy:burn_fee_bps"
	// policyStatePrevGasUsedKey persists the previous finalized block's
	// total gas used (from its header once execution finalized it).
	policyStatePrevGasUsedKey = "policy:prev_gas_used"
	// policyStatePrevGasLimitKey persists the previous finalized block's
	// gas limit (the utilization denominator).
	policyStatePrevGasLimitKey = "policy:prev_gas_limit"
)

// GetBurnFeeBPS returns the persisted fee-burn rate, or defaultBPS when no
// rate has been committed yet (fresh genesis / legacy state).
func (s *StateDB) GetBurnFeeBPS(defaultBPS uint64) uint64 {
	value, err := s.GetContractValue(policyStateBurnFeeKey)
	if err != nil || len(value) == 0 {
		return defaultBPS
	}
	rate, ok := new(big.Int).SetString(string(value), 10)
	if !ok || rate.Sign() < 0 || !rate.IsUint64() {
		return defaultBPS
	}
	return rate.Uint64()
}

// SetBurnFeeBPS stages the fee-burn rate for the enclosing block; the write
// is committed — and hashed into the state root — together with that block.
func (s *StateDB) SetBurnFeeBPS(bps uint64) {
	s.SetContractValue(policyStateBurnFeeKey, []byte(new(big.Int).SetUint64(bps).String()))
}

// GetPrevBlockGas returns the previous finalized block's committed gas
// footprint as (used, limit). Missing or corrupt records yield zeros, which
// the policy roll treats as "no signal" (rate holds apart from clamping).
func (s *StateDB) GetPrevBlockGas() (*big.Int, *big.Int) {
	used, limit := big.NewInt(0), big.NewInt(0)
	if value, err := s.GetContractValue(policyStatePrevGasUsedKey); err == nil && len(value) > 0 {
		if v, ok := new(big.Int).SetString(string(value), 10); ok && v.Sign() >= 0 {
			used = v
		}
	}
	if value, err := s.GetContractValue(policyStatePrevGasLimitKey); err == nil && len(value) > 0 {
		if v, ok := new(big.Int).SetString(string(value), 10); ok && v.Sign() >= 0 {
			limit = v
		}
	}
	return used, limit
}

// SetPrevBlockGas stages the enclosing block's finalized gas footprint so the
// NEXT block's burn-rate roll reads it from committed state. nil fields are
// normalized to zero so leader preview and verifier execution always persist
// byte-identical values.
func (s *StateDB) SetPrevBlockGas(used, limit *big.Int) {
	if used == nil || used.Sign() < 0 {
		used = big.NewInt(0)
	}
	if limit == nil || limit.Sign() < 0 {
		limit = big.NewInt(0)
	}
	s.SetContractValue(policyStatePrevGasUsedKey, []byte(used.String()))
	s.SetContractValue(policyStatePrevGasLimitKey, []byte(limit.String()))
}

// ----------------------------------------------------------------------------
// Deterministic CGE (coins event generation) state
//
// The CGE clock's origin (the genesis block timestamp) and the
// cumulative-released counters live in the same deterministic
// contract-state namespace as validator stakes and policy state, so they are
// hashed into the state root and replayed identically from genesis.
// ----------------------------------------------------------------------------

const (
	// cgeStateGenesisTsKey persists the timestamp the CGE schedules count
	// from (block 0's sealed header timestamp). Written once when block 0
	// executes; read by every later block.
	cgeStateGenesisTsKey = "cge:genesis_ts"
	// cgeStateReleasedPrefix prefixes the per-address cumulative amount
	// already released from policy.CGEEscrowAddress (decimal nSPX string).
	cgeStateReleasedPrefix = "cge:released:"
)

// SetCGEGenesisTimestamp persists the genesis block timestamp that every CGE
// schedule counts from.
func (s *StateDB) SetCGEGenesisTimestamp(ts int64) {
	s.SetContractValue(cgeStateGenesisTsKey, []byte(big.NewInt(ts).String()))
}

// GetCGEGenesisTimestamp returns the persisted genesis timestamp, or 0
// when block 0 has not written it yet (fresh state, legacy chains — callers
// fall back to CanonicalGenesisTimestamp).
func (s *StateDB) GetCGEGenesisTimestamp() int64 {
	value, err := s.GetContractValue(cgeStateGenesisTsKey)
	if err != nil || len(value) == 0 {
		return 0
	}
	ts, ok := new(big.Int).SetString(string(value), 10)
	if !ok || !ts.IsInt64() || ts.Sign() < 0 {
		return 0
	}
	return ts.Int64()
}

// GetCGEReleased returns the cumulative nSPX already released from
// policy.CGEEscrowAddress to address. Missing or corrupt records yield zero —
// the release loop treats that as "nothing released yet".
func (s *StateDB) GetCGEReleased(address string) *big.Int {
	if address == "" {
		return big.NewInt(0)
	}
	value, err := s.GetContractValue(cgeStateReleasedPrefix + address)
	if err != nil || len(value) == 0 {
		return big.NewInt(0)
	}
	released, ok := new(big.Int).SetString(string(value), 10)
	if !ok || released.Sign() < 0 {
		return big.NewInt(0)
	}
	return released
}

// SetCGEReleased stages the new cumulative released total for address; the
// write is committed — and hashed into the state root — together with the
// block whose timestamp triggered the release.
func (s *StateDB) SetCGEReleased(address string, amount *big.Int) {
	if address == "" || amount == nil || amount.Sign() < 0 {
		return
	}
	s.SetContractValue(cgeStateReleasedPrefix+address, []byte(amount.String()))
}

// ClearValidatorStakes removes all validator stake records from both the
// pending map and the committed store. Used by state rebuilds so replay
// recomputes validator stake records from scratch.
func (s *StateDB) ClearValidatorStakes() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for key := range s.contractPending {
		if strings.HasPrefix(key, validatorPrefix) {
			delete(s.contractPending, key)
		}
	}
	keys, err := s.db.ListKeysWithPrefix(validatorStakePrefix)
	if err != nil {
		return fmt.Errorf("ClearValidatorStakes: %w", err)
	}
	for _, k := range keys {
		if err := s.db.Delete(k); err != nil {
			return fmt.Errorf("ClearValidatorStakes: deleting %s: %w", k, err)
		}
	}
	return nil
}

// NEW: SetGenesisSupply - Set the genesis allocation amount
func (s *StateDB) SetGenesisSupply(amount *big.Int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.genesisSupply.Set(amount)
}

// NEW: GetGenesisSupply - Get the genesis allocation amount
func (s *StateDB) GetGenesisSupply() *big.Int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return new(big.Int).Set(s.genesisSupply)
}

// NEW: GetRewardsMinted - Get the total rewards minted so far
func (s *StateDB) GetRewardsMinted() *big.Int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return new(big.Int).Set(s.rewardsMinted)
}

// NEW: IncrementRewardsMinted - Add to rewards minted counter
func (s *StateDB) IncrementRewardsMinted(amount *big.Int) {
	if amount == nil || amount.Sign() <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rewardsMinted.Add(s.rewardsMinted, amount)
}

// SetBlockchain sets the blockchain reference for mempool access.
func (s *StateDB) SetBlockchain(bc *Blockchain) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blockchain = bc
}

// ----------------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------------

// load returns the accountEntry for address, checking the dirty cache first,
// then LevelDB, then returning a zeroed entry for new addresses.
func (s *StateDB) load(address string) *accountEntry {
	if e, ok := s.pending[address]; ok {
		return e
	}
	key := accountPrefix + address
	data, err := s.db.Get(key)
	if err != nil || len(data) == 0 {
		return &accountEntry{balance: big.NewInt(0)}
	}
	var rec accountRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		logger.Warn("StateDB: unmarshal %s: %v", address, err)
		return &accountEntry{balance: big.NewInt(0)}
	}
	bal, ok := new(big.Int).SetString(rec.Balance, 10)
	if !ok {
		bal = big.NewInt(0)
	}
	return &accountEntry{balance: bal, nonce: rec.Nonce}
}

// dirty returns a mutable *accountEntry for address.
func (s *StateDB) dirty(address string) *accountEntry {
	if e, ok := s.pending[address]; ok {
		return e
	}
	src := s.load(address)
	e := &accountEntry{
		balance: new(big.Int).Set(src.balance),
		nonce:   src.nonce,
	}
	s.pending[address] = e
	return e
}

// ----------------------------------------------------------------------------
// Public read methods - Core Account State
// ----------------------------------------------------------------------------

// GetBalance returns the current balance of address in nSPX.
func (s *StateDB) GetBalance(address string) (*big.Int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if address == "" {
		return nil, errors.New("address cannot be empty")
	}
	return new(big.Int).Set(s.load(address).balance), nil
}

// GetNonce returns the current nonce for address.
func (s *StateDB) GetNonce(address string) (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if address == "" {
		return 0, errors.New("address cannot be empty")
	}
	return s.load(address).nonce, nil
}

// GetTotalSupply returns the current circulating supply in nSPX.
func (s *StateDB) GetTotalSupply() *big.Int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return new(big.Int).Set(s.totalSupply)
}

// GetBalanceResult returns the confirmed, pending, and unlocked balance for an address.
func (s *StateDB) GetBalanceResult(address string) (*pool.BalanceResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if address == "" {
		return nil, errors.New("address cannot be empty")
	}

	result := &pool.BalanceResult{
		Confirmed: big.NewInt(0),
		Pending:   big.NewInt(0),
		Unlocked:  big.NewInt(0),
	}

	// Get confirmed balance from StateDB
	balanceNSPX := s.load(address).balance
	if balanceNSPX != nil {
		result.Confirmed.Set(balanceNSPX)
		result.Unlocked.Set(balanceNSPX)
	}

	// Check mempool for pending transactions
	if s.blockchain != nil && s.blockchain.mempool != nil {
		for _, tx := range s.blockchain.mempool.GetPendingTransactions() {
			if tx == nil {
				continue
			}
			if tx.Sender == address {
				amount := tx.Amount
				gasFee := tx.GetGasFee()
				totalOut := new(big.Int).Add(amount, gasFee)
				if result.Pending.Cmp(totalOut) < 0 {
					result.Pending.SetInt64(0)
				} else {
					result.Pending.Sub(result.Pending, totalOut)
				}
			}
			if tx.Receiver == address {
				result.Pending.Add(result.Pending, tx.Amount)
			}
		}
	}

	return result, nil
}

// GetTransactionHistory returns recent transactions involving the given
// address, newest first, capped at limit.
//
// It reads the rawdb address→tx index, which is a single bounded reverse
// scan over that address's entries — so the cost is the number of
// transactions returned, not the length of the chain, and activity older
// than the old 1000-block window is no longer silently missing.
//
// Nodes whose chain predates the index fall back to the original bounded
// in-memory block scan, so an un-backfilled node returns exactly what it
// did before.
func (s *StateDB) GetTransactionHistory(address string, limit int) ([]*types.Transaction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if address == "" {
		return nil, errors.New("address cannot be empty")
	}
	if limit <= 0 {
		limit = 20
	}

	var txs []*types.Transaction
	txMap := make(map[string]bool)

	if s.blockchain == nil {
		return txs, nil
	}

	// Indexed path.
	if s.db != nil {
		entries, err := rawdb.ReadAddressTxHistory(s.db, address, limit)
		if err != nil {
			logger.Debug("GetTransactionHistory(%s): address index unavailable: %v",
				shortAddress(address), err)
		}
		for _, entry := range entries {
			if len(txs) >= limit {
				break
			}
			if txMap[entry.TxID] {
				continue
			}
			tx, err := s.blockchain.storage.GetTransaction(entry.TxID)
			if err != nil || tx == nil {
				continue // index entry for a block that has since been pruned
			}
			txMap[entry.TxID] = true
			txs = append(txs, tx)
		}
	}

	// Fallback path, only when the index yielded nothing.
	if len(txs) == 0 {
		txs = s.scanRecentBlocksForAddress(address, limit, txMap)
	}

	// Check mempool for pending transactions
	if s.blockchain.mempool != nil {
		for _, tx := range s.blockchain.mempool.GetPendingTransactions() {
			if tx == nil {
				continue
			}
			if (tx.Sender == address || tx.Receiver == address) && len(txs) < limit {
				if !txMap[tx.ID] {
					txMap[tx.ID] = true
					txs = append(txs, tx)
				}
			}
		}
	}

	// Sort by timestamp descending (newest first)
	sort.Slice(txs, func(i, j int) bool {
		return txs[i].Timestamp > txs[j].Timestamp
	})

	logger.Debug("GetTransactionHistory(%s): found %d transactions",
		shortAddress(address), len(txs))

	return txs, nil
}

// scanRecentBlocksForAddress is the pre-index history lookup: walk the most
// recent maxBlocksToScan blocks newest-first, collecting non-nil
// transactions that reference address as sender or receiver. Kept as the
// fallback for nodes whose address index has not been backfilled.
func (s *StateDB) scanRecentBlocksForAddress(address string, limit int, seen map[string]bool) []*types.Transaction {
	const maxBlocksToScan = uint64(1000)

	var txs []*types.Transaction
	height := s.blockchain.GetBlockCount()
	blocksScanned := uint64(0)

	for height > 0 && len(txs) < limit && blocksScanned < maxBlocksToScan {
		block := s.blockchain.GetBlockByNumber(height)
		height--
		if block == nil {
			continue
		}
		blocksScanned++

		for i := len(block.Body.TxsList) - 1; i >= 0; i-- {
			tx := block.Body.TxsList[i]
			if tx == nil {
				continue
			}
			if tx.Sender != address && tx.Receiver != address {
				continue
			}
			if seen[tx.ID] {
				continue
			}
			seen[tx.ID] = true
			txs = append(txs, tx)
			if len(txs) >= limit {
				break
			}
		}
	}
	return txs
}

// shortAddress trims an address for logging. It tolerates addresses shorter
// than the trim width: the previous inline address[:16] panicked on any
// address under 16 characters, which is every short/test-style address
// passed in over RPC.
func shortAddress(address string) string {
	const keep = 16
	if len(address) <= keep {
		return address
	}
	return address[:keep] + "..."
}

// ============================================================================
// WALLET STATISTICS - For block explorer
// ============================================================================

// WalletStats holds comprehensive wallet statistics for the block explorer.
type WalletStats struct {
	TotalAccounts      uint64         `json:"total_accounts"`
	SPIFAddresses      uint64         `json:"spif_addresses"`
	LegacyAddresses    uint64         `json:"legacy_addresses"`
	ActiveWallets      uint64         `json:"active_wallets"`
	WalletsWithBalance uint64         `json:"wallets_with_balance"`
	TotalSupplyNSPX    string         `json:"total_supply_nspx"`
	TotalSupplySPX     string         `json:"total_supply_spx"`
	RichList           []*WalletEntry `json:"rich_list,omitempty"`
}

// WalletEntry represents a single wallet in the rich list.
type WalletEntry struct {
	Rank        uint64 `json:"rank"`
	Address     string `json:"address"`
	AddressType string `json:"address_type"` // "SPIF" or "Legacy"
	BalanceNSPX string `json:"balance_nspx"`
	BalanceSPX  string `json:"balance_spx"`
	Nonce       uint64 `json:"nonce"`
	IsActive    bool   `json:"is_active"`
}

// GetWalletStats returns comprehensive wallet statistics including rich list.
// It scans all accounts stored in LevelDB under the "acct:" prefix.
func (s *StateDB) GetWalletStats(richListLimit int) (*WalletStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &WalletStats{
		RichList: make([]*WalletEntry, 0),
	}

	// List all account keys from LevelDB
	keys, err := s.db.ListKeysWithPrefix(accountPrefix)
	if err != nil {
		return nil, fmt.Errorf("GetWalletStats: listing accounts: %w", err)
	}

	// Include pending (uncommitted) accounts too
	pendingSet := make(map[string]bool)
	for addr := range s.pending {
		pendingSet[addr] = true
	}

	// Collect all unique addresses
	addrSet := make(map[string]bool)
	for _, k := range keys {
		addr := k[len(accountPrefix):]
		if addr != "" {
			addrSet[addr] = true
		}
	}
	for addr := range pendingSet {
		addrSet[addr] = true
	}

	// Process each account
	type accountInfo struct {
		address string
		balance *big.Int
		nonce   uint64
	}

	var accounts []accountInfo

	for addr := range addrSet {
		entry := s.load(addr)
		if entry == nil {
			continue
		}

		stats.TotalAccounts++

		// Classify address type
		if len(addr) == 64 {
			stats.SPIFAddresses++
		} else if len(addr) == 40 {
			stats.LegacyAddresses++
		}

		// Check if active (has sent transactions)
		if entry.nonce > 0 {
			stats.ActiveWallets++
		}

		// Check if has balance
		if entry.balance != nil && entry.balance.Sign() > 0 {
			stats.WalletsWithBalance++
			accounts = append(accounts, accountInfo{
				address: addr,
				balance: new(big.Int).Set(entry.balance),
				nonce:   entry.nonce,
			})
		}
	}

	// Sort by balance descending for rich list
	sort.Slice(accounts, func(i, j int) bool {
		return accounts[i].balance.Cmp(accounts[j].balance) > 0
	})

	// Build rich list
	if richListLimit <= 0 || richListLimit > 100 {
		richListLimit = 100
	}
	for i, acc := range accounts {
		if uint64(i) >= uint64(richListLimit) {
			break
		}
		addrType := "Legacy"
		if len(acc.address) == 64 {
			addrType = common.SPIFPrefix
		}
		balanceSPX := new(big.Float).Quo(
			new(big.Float).SetInt(acc.balance),
			new(big.Float).SetFloat64(1e18),
		)
		stats.RichList = append(stats.RichList, &WalletEntry{
			Rank:        uint64(i + 1),
			Address:     acc.address,
			AddressType: addrType,
			BalanceNSPX: acc.balance.String(),
			BalanceSPX:  balanceSPX.Text('f', 6),
			Nonce:       acc.nonce,
			IsActive:    acc.nonce > 0,
		})
	}

	// Supply info
	if s.totalSupply != nil {
		stats.TotalSupplyNSPX = s.totalSupply.String()
		supplySPX := new(big.Float).Quo(
			new(big.Float).SetInt(s.totalSupply),
			new(big.Float).SetFloat64(1e18),
		)
		stats.TotalSupplySPX = supplySPX.Text('f', 6)
	}

	logger.Info("GetWalletStats: total=%d, %s=%d, legacy=%d, active=%d, with_balance=%d",
		stats.TotalAccounts, common.SPIFPrefix, stats.SPIFAddresses, stats.LegacyAddresses,
		stats.ActiveWallets, stats.WalletsWithBalance)

	return stats, nil
}

// ----------------------------------------------------------------------------
// Public write methods (buffered — flushed on Commit)
// ----------------------------------------------------------------------------

// SetBalance sets the balance of address to amount (nSPX).
// Used during genesis to credit allocations.
func (s *StateDB) SetBalance(address string, amount *big.Int) {
	current := s.load(address)
	prevBalance := current.balance // snapshot before change
	prevNonce := current.nonce
	RecordStateChange(address, prevBalance, prevNonce)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty(address).balance = new(big.Int).Set(amount)
}

// AddBalance adds amount (nSPX) to address. No-op for zero/nil amount.
func (s *StateDB) AddBalance(address string, amount *big.Int) {
	if amount == nil || amount.Sign() <= 0 {
		return
	}
	current := s.load(address)
	prevBalance := current.balance
	prevNonce := current.nonce
	RecordStateChange(address, prevBalance, prevNonce)
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.dirty(address)
	e.balance.Add(e.balance, amount)
}

// SubBalance subtracts amount (nSPX) from address.
// Returns an error if the resulting balance would be negative.
func (s *StateDB) SubBalance(address string, amount *big.Int) error {
	if amount == nil || amount.Sign() <= 0 {
		return nil
	}
	current := s.load(address)
	prevBalance := current.balance
	prevNonce := current.nonce
	RecordStateChange(address, prevBalance, prevNonce)
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.dirty(address)
	if e.balance.Cmp(amount) < 0 {
		return fmt.Errorf("insufficient balance: %s has %s nSPX, needs %s nSPX",
			address, e.balance.String(), amount.String())
	}
	e.balance.Sub(e.balance, amount)
	return nil
}

// SetNonce sets the nonce of address to the specified value.
// Used during rollback to restore previous nonce value.
func (s *StateDB) SetNonce(address string, nonce uint64) {
	current := s.load(address)
	prevBalance := current.balance
	prevNonce := current.nonce
	RecordStateChange(address, prevBalance, prevNonce)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty(address).nonce = nonce
}

// Transfer moves amount nSPX from `from` to `to` atomically.
// It validates sufficient balance, performs the debit/credit as a single
// logical operation, and returns an error if `from` has insufficient funds.
// The total supply is conserved: no value is created or destroyed.
//
// from == to (self-send) is allowed rather than rejected: the debit and
// credit apply to the same balance entry for the same amount, so it is a
// mathematical no-op (aside from requiring the balance to transiently cover
// `amount`) — it can't create, destroy, or move value anywhere. This is the
// execution-time counterpart of the mempool self-send exception in
// validation.go: wallets anchor data (see helper.go's AnchorMintReceipt) by
// self-sending a transaction whose ReturnData carries the payload, and that
// pattern must not fail here after already being admitted to the mempool.
func (s *StateDB) Transfer(from, to string, amount *big.Int) error {
	if from == "" || to == "" {
		return fmt.Errorf("transfer: empty address (from=%q, to=%q)", from, to)
	}
	if amount == nil || amount.Sign() <= 0 {
		return fmt.Errorf("transfer: amount must be positive, got %v", amount)
	}

	// Record state change for both addresses BEFORE modification
	fromCurrent := s.load(from)
	toCurrent := s.load(to)
	RecordStateChange(from, fromCurrent.balance, fromCurrent.nonce)
	if from != to {
		RecordStateChange(to, toCurrent.balance, toCurrent.nonce)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	fromEntry := s.dirty(from)
	if fromEntry.balance.Cmp(amount) < 0 {
		return fmt.Errorf("transfer: insufficient balance: %s has %s nSPX, needs %s nSPX",
			from, fromEntry.balance.String(), amount.String())
	}
	fromEntry.balance.Sub(fromEntry.balance, amount)

	toEntry := s.dirty(to)
	toEntry.balance.Add(toEntry.balance, amount)

	return nil
}

// IncrementNonce adds 1 to the nonce of address.
func (s *StateDB) IncrementNonce(address string) {
	current := s.load(address)
	prevBalance := current.balance
	prevNonce := current.nonce
	RecordStateChange(address, prevBalance, prevNonce)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty(address).nonce++
}

// DeleteAccount removes an account from the state database.
// Used during rollback when an account was created by the block being reverted.
func (s *StateDB) DeleteAccount(address string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.pending, address)
	if err := s.db.Delete(accountPrefix + address); err != nil {
		return fmt.Errorf("DeleteAccount: %w", err)
	}
	return nil
}

// IncrementTotalSupply adds amount to the tracked circulating supply.
func (s *StateDB) IncrementTotalSupply(amount *big.Int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totalSupply.Add(s.totalSupply, amount)
}

// DecrementTotalSupply removes permanently burned nSPX from the tracked
// circulating supply. Callers must only use this after the amount has already
// been removed from an account balance.
func (s *StateDB) DecrementTotalSupply(amount *big.Int) {
	if amount == nil || amount.Sign() <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.totalSupply.Cmp(amount) < 0 {
		s.totalSupply.SetInt64(0)
		return
	}
	s.totalSupply.Sub(s.totalSupply, amount)
}

// ----------------------------------------------------------------------------
// Commit
// ----------------------------------------------------------------------------

// Commit - Update to persist reward tracking
func (s *StateDB) Commit() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for address, e := range s.pending {
		rec := accountRecord{
			Balance: e.balance.String(),
			Nonce:   e.nonce,
		}
		data, err := json.Marshal(rec)
		if err != nil {
			return nil, fmt.Errorf("StateDB.Commit: marshal %s: %w", address, err)
		}
		if err := s.db.Put(accountPrefix+address, data); err != nil {
			return nil, fmt.Errorf("StateDB.Commit: put %s: %w", address, err)
		}
	}
	for key, value := range s.contractPending {
		if err := s.db.Put(contractPrefix+key, value); err != nil {
			return nil, fmt.Errorf("StateDB.Commit: put contract %s: %w", key, err)
		}
	}

	// Persist total supply
	if err := s.db.Put(totalSupplyKey, []byte(s.totalSupply.String())); err != nil {
		return nil, fmt.Errorf("StateDB.Commit: put total supply: %w", err)
	}

	// NEW: Persist genesis supply
	if err := s.db.Put(genesisSupplyKey, []byte(s.genesisSupply.String())); err != nil {
		return nil, fmt.Errorf("StateDB.Commit: put genesis supply: %w", err)
	}

	// NEW: Persist rewards minted
	if err := s.db.Put(rewardsMintedKey, []byte(s.rewardsMinted.String())); err != nil {
		return nil, fmt.Errorf("StateDB.Commit: put rewards minted: %w", err)
	}

	s.pending = make(map[string]*accountEntry)
	s.contractPending = make(map[string][]byte)

	stateRoot, err := s.computeStateRoot()
	if err != nil {
		return nil, err
	}

	logger.Info("StateDB committed: state_root=%x total_supply=%s nSPX, genesis_supply=%s nSPX, rewards_minted=%s nSPX",
		stateRoot, s.totalSupply.String(), s.genesisSupply.String(), s.rewardsMinted.String())
	return stateRoot, nil
}

// computeStateRoot builds a deterministic leaf-hash Merkle root over all
// account records in LevelDB.
func (s *StateDB) computeStateRoot() ([]byte, error) {
	keys, err := s.db.ListKeysWithPrefix(accountPrefix)
	if err != nil {
		return nil, fmt.Errorf("computeStateRoot: %w", err)
	}
	contractKeys, err := s.db.ListKeysWithPrefix(contractPrefix)
	if err != nil {
		return nil, fmt.Errorf("computeStateRoot contracts: %w", err)
	}
	keySet := make(map[string]struct{}, len(keys)+len(contractKeys)+len(s.pending)+len(s.contractPending))
	for _, k := range keys {
		keySet[k] = struct{}{}
	}
	for _, k := range contractKeys {
		keySet[k] = struct{}{}
	}
	for address := range s.pending {
		keySet[accountPrefix+address] = struct{}{}
	}
	for key := range s.contractPending {
		keySet[contractPrefix+key] = struct{}{}
	}

	if len(keySet) == 0 {
		return common.SpxHash([]byte("empty-state")), nil
	}

	keys = keys[:0]
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	leaves := make([][]byte, 0, len(keys))
	for _, k := range keys {
		var data []byte
		if address := strings.TrimPrefix(k, accountPrefix); strings.HasPrefix(k, accountPrefix) {
			if e, ok := s.pending[address]; ok {
				rec := accountRecord{
					Balance: e.balance.String(),
					Nonce:   e.nonce,
				}
				data, err = json.Marshal(rec)
				if err != nil {
					return nil, fmt.Errorf("computeStateRoot: marshal pending %s: %w", k, err)
				}
			} else {
				data, err = s.db.Get(k)
				if err != nil {
					continue
				}
			}
		} else if key := strings.TrimPrefix(k, contractPrefix); strings.HasPrefix(k, contractPrefix) {
			if value, ok := s.contractPending[key]; ok {
				data = append([]byte(nil), value...)
			} else {
				data, err = s.db.Get(k)
				if err != nil {
					continue
				}
			}
		} else {
			continue
		}
		leaves = append(leaves, common.SpxHash(append([]byte(k), data...)))
	}

	return merkleRootFromLeaves(leaves), nil
}
