// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/genesis.go
package core

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// NewGenesisValidatorStake converts a whole-SPX amount to the nSPX big.Int
// representation expected by GenesisValidator.StakeNSPX.
//
//	stake := NewGenesisValidatorStake(32) // 32 SPX → 32 × 10^18 nSPX
func NewGenesisValidatorStake(spx int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(spx), big.NewInt(1e18))
}

// CanonicalGenesisTimestamp is the fixed Unix timestamp used for the genesis
// block across ALL environments (devnet, testnet, mainnet). Using a hardcoded
// constant instead of wall-clock time ensures every node produces the exact
// same genesis block hash, regardless of when or where it starts.
//
// 2026-07-15 19:33:18 UTC — canonical genesis timestamp for ALL environments.
const CanonicalGenesisTimestamp int64 = 1784143998

// genesisSignerMu guards the two package-level values below.
var genesisSignerMu sync.Mutex

// genesisSigner and genesisSignerNodeID hold whichever node's SigningService
// is bootstrapping a fresh chain, registered via SetGenesisSigner. This is a
// package-level value — not a Blockchain struct field or a BuildBlock
// parameter — for the same reason CanonicalGenesisTimestamp is a constant:
// every existing call site (ApplyGenesis, ApplyGenesisWithCachedBlock,
// getCachedGenesisBlock) already calls gs.BuildBlock() with no arguments, and
// none of those need to change to pick this up.
var (
	genesisSigner       *consensus.SigningService
	genesisSignerNodeID string
)

// SetGenesisSigner registers the SigningService and node identity that will
// sign the genesis block when this node bootstraps a fresh chain (i.e. is
// not a late joiner — see Blockchain.IsLateJoiner in initializeChain, which
// skips createGenesisBlock/BuildBlock for late joiners entirely, so calling
// this on a late joiner is harmless but unnecessary).
//
// Call this once, in bind.StartNode, right after this node's own
// SigningService is constructed and BEFORE core.NewBlockchain(...) /
// FinishInit() runs — initializeChain() calls createGenesisBlock() ->
// BuildBlock() synchronously during blockchain construction, so the signer
// must already be registered by then.
func SetGenesisSigner(signer *consensus.SigningService, nodeID string) {
	genesisSignerMu.Lock()
	defer genesisSignerMu.Unlock()
	genesisSigner = signer
	genesisSignerNodeID = nodeID
}

func getGenesisSigner() (*consensus.SigningService, string) {
	genesisSignerMu.Lock()
	defer genesisSignerMu.Unlock()
	return genesisSigner, genesisSignerNodeID
}

// DefaultGenesisState returns the canonical genesis configuration used by all
// nodes on the Sphinx Mainnet. Every field is deterministic so that independent
// invocations on different machines produce byte-for-byte identical genesis blocks.
//
// To customise for testnet / devnet, call GetTestnetChainParams() /
// GetDevnetChainParams() and pass the result to GenesisStateFromChainParams().
func DefaultGenesisState() *GenesisState {
	return &GenesisState{
		ChainID:   7331,
		ChainName: "Sphinx Mainnet",
		Symbol:    "SPX",
		// FIXED timestamp — NOT wall-clock time. Using a hardcoded constant
		// guarantees that every node produces the identical genesis block hash.
		// Late joiners that download block 0 from peers will get this same
		// timestamp embedded in the block header.
		Timestamp: CanonicalGenesisTimestamp,

		ExtraData:         []byte("Sphinx: The personal ledger beyond it's economics participants. Privacy, sovereignty, and humanity."),
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
//
// GenesisStateFromChainParams builds a GenesisState for any network.
// Identity fields (ChainID, ChainName) are intentionally NOT embedded in
// the block hash — only the cryptographic fields below affect the hash.
// This means devnet, testnet, and mainnet all produce the same genesis hash
// as long as these four fields stay constant.
//
// Note: The canonical cryptographic fields (Timestamp, Difficulty, GasLimit)
// are frozen to ensure a consistent genesis hash across all environments.
// However, if p.GenesisConfig is provided, its values take precedence,
// allowing tests to override these fields.
func GenesisStateFromChainParams(p *SphinxChainParameters) *GenesisState {
	// These fields feed into BuildBlock() → FinalizeHash().
	// Timestamp uses p.GenesisTime (the actual minting time).
	// Difficulty and gas limit are frozen across all environments.
	const (
		canonicalDifficulty = int64(17179869184)
		canonicalGasLimit   = int64(5000)
	)
	canonicalExtraData := []byte("The Times 20/Nov/2024 Sphinx Genesis. Privacy, sovereignty, human dignity. No surveillance.")
	canonicalNonce := common.FormatNonce(1)

	// Apply test overrides if GenesisConfig is provided
	timestamp := p.GenesisTime // Actual wall-clock time when genesis is minted (trusted setup)
	extraData := canonicalExtraData
	difficulty := canonicalDifficulty
	gasLimit := canonicalGasLimit
	nonce := canonicalNonce

	if p.GenesisConfig != nil {
		// Override extra data if provided
		if len(p.GenesisConfig.GenesisExtraData) > 0 {
			extraData = p.GenesisConfig.GenesisExtraData
		}

		// Override difficulty if provided
		if p.GenesisConfig.InitialDifficulty != nil {
			difficulty = p.GenesisConfig.InitialDifficulty.Int64()
		}

		// Override gas limit if provided
		if p.GenesisConfig.InitialGasLimit != nil {
			gasLimit = p.GenesisConfig.InitialGasLimit.Int64()
		}

		// Override nonce if provided (convert from uint64 to formatted string)
		if p.GenesisConfig.GenesisNonce != 0 {
			nonce = common.FormatNonce(p.GenesisConfig.GenesisNonce)
		}
	}

	return &GenesisState{
		// These fields identify the chain but do NOT affect the block hash.
		ChainID:   p.ChainID,
		ChainName: p.ChainName,
		Symbol:    p.Symbol,

		// These fields feed into BuildBlock() and must be identical on every
		// environment so the genesis hash is the same on devnet, testnet, mainnet.
		Timestamp:         timestamp,
		ExtraData:         extraData,
		InitialDifficulty: big.NewInt(difficulty),
		InitialGasLimit:   big.NewInt(gasLimit),
		Nonce:             nonce,

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
// transaction that pays the recipient the FULL allocation amount — the
// liquid (CGE-unlocked) case. It delegates to allocationPartToTx with
// receiver = alloc.Address and amount = alloc.BalanceNSPX, so liquid
// allocations produce byte-identical transactions to the pre-CGE scheme.
//
// Convention:
//   - Sender   : GenesisVaultAddress (vault distributes to allocations)
//   - Receiver : the allocation address (hex, no 0x prefix)
//   - Amount   : allocation.BalanceNSPX (in nSPX)
//   - Nonce    : sequential index i, so every transaction is unique
//   - Timestamp: genesis block timestamp
//   - ID       : deterministic — hex(SpxHash(receiver || amount_bytes || nonce_bytes))
//
// The ID is fully deterministic so the Merkle root computed from the
// transaction list always matches the TxsRoot in the block header.
func allocationToTx(alloc *GenesisAllocation, index uint64, genesisTimestamp int64) *types.Transaction {
	return allocationPartToTx(alloc.Address, alloc.BalanceNSPX, index, genesisTimestamp)
}

// allocationPartToTx builds one genesis funding transaction for a slice of
// an allocation: it pays `amount` to `receiver` (either the recipient at CGE
// or policy.CGEEscrowAddress for the locked remainder) with the vault as
// sender. The allocation itself is not needed — every field of the
// transaction derives from receiver, amount, index and the genesis
// timestamp. Both the tx ID and the nonce are derived from the running tx
// index, so the emitted list stays deterministic and the vault's nonce
// sequence stays gap-free across every node.
func allocationPartToTx(receiver string, amount *big.Int, index uint64, genesisTimestamp int64) *types.Transaction {
	return allocationPartToTxAuthorized(receiver, amount, index, genesisTimestamp, 0, nil)
}

// allocationPartToTxAuthorized is allocationPartToTx plus the optional M-of-N
// custody authorization for the slice. chainID binds a witness to one chain and
// witness is the threshold signature set; both stay zero/nil on the legacy
// unsigned path, so that transaction still serialises byte-for-byte as before.
func allocationPartToTxAuthorized(receiver string, amount *big.Int, index uint64, genesisTimestamp int64, chainID uint64, witness *multisig.MultiSigWitness) *types.Transaction {
	// Deterministic ID from receiver + amount + index: the same funding slice
	// always produces the same transaction ID on every node, and the same
	// formula lets core/transaction recognize a genesis funding transaction
	// from the transaction alone (see Transaction.IsSystemTransaction).
	txID := types.GenesisAllocationTxID(receiver, amount, index)

	// Copy amount so callers cannot mutate the allocation.
	amt := new(big.Int)
	if amount != nil {
		amt.Set(amount)
	}

	return &types.Transaction{
		ID:              txID,                // Deterministic unique identifier
		ChainID:         chainID,             // Bound into any custody witness
		Sender:          GenesisVaultAddress, // Vault distributes to allocations
		Receiver:        receiver,            // Recipient at CGE, or the CGE escrow
		Amount:          amt,                 // Slice of the initial balance in nSPX
		GasLimit:        big.NewInt(0),       // Genesis transactions consume no gas
		GasPrice:        big.NewInt(0),       // Genesis transactions have zero gas price
		Nonce:           index,               // Sequential to make each tx unique
		Timestamp:       genesisTimestamp,    // Anchored to genesis time
		Signature:       []byte{},            // No single-key signature at genesis
		MultiSigWitness: witness,             // M-of-N authority when the vault is custody
	}
}

// allocationsToTxList converts the complete ordered allocation list into a
// slice of *types.Transaction suitable for the block body.
//
// Each allocation's BalanceNSPX is the CGE remainder (post-sale) for that
// category. The transaction actually paid out is bigger than that where the
// category sold coins in a funding round: policy.CGEGenesisDirectAmount adds
// back the sold amount (always liquid, never escrowed) on top of whatever
// the remainder's own schedule unlocks at CGE; policy.CGEGenesisEscrowAmount
// is the remainder's locked portion, unaffected by the sale. So the vault
// pays sold+unlocked-remainder to the recipient and locked-remainder to
// policy.CGEEscrowAddress, both in block 0 — the vault still drains
// completely and gross-per-category (sold + remainder) is conserved.
//
// The order of the output slice matches the order of gs.Allocations exactly,
// which is required for the Merkle root to be deterministic; nonces are the
// running transaction index so the vault's nonce sequence is gap-free.
func (gs *GenesisState) allocationsToTxList() []*types.Transaction {
	return gs.allocationsToTxListAuthorized(nil, 0)
}

// GenesisDistributionAuthorizer returns the M-of-N custody witness that
// authorizes one genesis distribution slice, identified by nonce (the running
// transaction index). Returning nil means this vault is not custody-owned and
// the legacy unsigned genesis exemption applies to that slice.
type GenesisDistributionAuthorizer func(receiver string, amount *big.Int, nonce uint64) *multisig.MultiSigWitness

// allocationsToTxListAuthorized is allocationsToTxList with optional M-of-N
// authorization: when auth is non-nil every slice is signed and bound to
// chainID. The tx list is otherwise identical, so the legacy path (auth == nil,
// chainID == 0) stays byte-for-byte unchanged.
func (gs *GenesisState) allocationsToTxListAuthorized(auth GenesisDistributionAuthorizer, chainID uint64) []*types.Transaction {
	txs := make([]*types.Transaction, 0, len(gs.Allocations))
	appendPart := func(receiver string, amount *big.Int) {
		index := uint64(len(txs))
		var w *multisig.MultiSigWitness
		if auth != nil {
			w = auth(receiver, amount, index)
		}
		txs = append(txs, allocationPartToTxAuthorized(receiver, amount, index, gs.Timestamp, chainID, w))
	}
	for _, alloc := range gs.Allocations {
		if alloc == nil || alloc.BalanceNSPX == nil || alloc.BalanceNSPX.Sign() <= 0 {
			continue // nothing to fund (validate() rejects these on-chain)
		}
		direct := policy.CGEGenesisDirectAmount(alloc.Label, alloc.BalanceNSPX)
		escrow := policy.CGEGenesisEscrowAmount(alloc.Label, alloc.BalanceNSPX)

		if direct.Sign() > 0 {
			appendPart(alloc.Address, direct)
		}
		if escrow.Sign() > 0 {
			appendPart(GetCGEEscrowAddress(), escrow)
		}
	}
	return txs
}

// ----------------------------------------------------------------------------
// Block construction
// ----------------------------------------------------------------------------

// legacyGenesisVaultAddress is the pre-multisig vault address. It remains the
// fallback when the genesis document carries no `multisig` section, so existing
// chains and tests keep byte-identical genesis block 0.
const legacyGenesisVaultAddress = "0000000000000000000000000000000000000001"

// GenesisVaultAddress is the active vault address. It defaults to the legacy
// value and is replaced by LoadGenesisVaultPolicy when the `multisig` section of
// the single genesis document is present.
var GenesisVaultAddress = legacyGenesisVaultAddress

// policyAutoLoadDisabled reports whether this process is a `go test` binary.
//
// ★ WHY: the `multisig` section of config/genesis_state.json and
// config/escrow_multisig.json are auto-loaded at package init, because that is
// what makes a live node derive its vault/escrow address from the operator's
// policy data. A developer who has just run the live custody demo
// (multisig devnet) therefore has that data on disk — and every test that
// assumes the default addresses would start failing for a reason that has
// nothing to do with the code under test.
// Tests that exercise the policy path load it explicitly
// (LoadGenesisVaultPolicy / LoadEscrowPolicy) and restore the previous state,
// so skipping only the implicit init-time auto-load keeps both behaviors.
func policyAutoLoadDisabled() bool {
	return flag.Lookup("test.v") != nil
}

func init() {
	if policyAutoLoadDisabled() {
		return
	}
	InitGenesisVaultAddress()
}

// BuildBlock builds a genesis block with NO allocation transactions in the body.
// Coins are minted to GenesisVaultAddress via mintBlockReward when block 0 is
// executed. Distribution happens in block 1.
// BuildBlock builds a genesis block with ALLOCATION TRANSACTIONS in the body.
// Each genesis allocation is converted to a transaction that sends funds from
// the genesis vault to the allocation address. This ensures the TxsRoot in the
// header matches the actual transaction list.
func (gs *GenesisState) BuildBlock() *types.Block {
	return gs.buildBlock(nil, 0)
}

// BuildBlockWithCustody builds the genesis block where every distribution
// transaction carries a threshold M-of-N custody witness from auth and is bound
// to chainID. This is the path a policy-owned genesis vault MUST use: block-0
// authorization fails closed once the vault resolves to a registered custody
// policy (see tx_auth.go), so an unsigned distribution set can never be
// committed. Witnesses are part of the transaction, hence part of block 0's
// TxsRoot, so every node that replays the block sees the identical authority.
func (gs *GenesisState) BuildBlockWithCustody(auth GenesisDistributionAuthorizer, chainID uint64) *types.Block {
	return gs.buildBlock(auth, chainID)
}

func (gs *GenesisState) buildBlock(auth GenesisDistributionAuthorizer, chainID uint64) *types.Block {
	// Build transaction list from allocations
	txs := gs.allocationsToTxListAuthorized(auth, chainID)

	// Create body with the allocation transactions
	body := types.NewBlockBody(txs, []*types.BlockHeader{}, 0)

	// Calculate TxsRoot from the actual transactions
	tempBlock := types.NewBlock(&types.BlockHeader{}, body)
	txsRoot := tempBlock.CalculateTxsRoot()

	header := &types.BlockHeader{
		Version:    1,
		Block:      0,
		Height:     0,
		Timestamp:  gs.Timestamp,
		Difficulty: new(big.Int).Set(gs.InitialDifficulty),
		Nonce:      gs.Nonce,
		TxsRoot:    txsRoot,
		StateRoot:  common.SpxHash([]byte("sphinx-genesis-state-root")),
		GasLimit:   new(big.Int).Set(gs.InitialGasLimit),
		GasUsed:    big.NewInt(0),
		ExtraData:  append([]byte{}, gs.ExtraData...),
		Miner:      make([]byte, 20),
		ParentHash: make([]byte, 32),
		UnclesHash: common.SpxHash([]byte("genesis-no-uncles")),
		ProposerID: GenesisVaultAddress,
		Hash:       []byte{},
	}

	block := types.NewBlock(header, body)
	block.PopulateLogsBloom()
	block.FinalizeHash() // hash finalized BEFORE any signature is attached

	// FIX: genesis previously left here with an empty ProposerSignature and
	// signature_valid=false permanently — BuildBlock never called SignBlock
	// at all, unlike every other block (see Consensus.SignBlockHeader's
	// signingService.SignBlock call, used from the solo-mining path in
	// executor.go and from ProposeBlock). That meant late joiners had no
	// producer signature to check on the one block that matters most.
	//
	// Sign here, using whichever node's SigningService called
	// SetGenesisSigner (the node bootstrapping a fresh chain) — the exact
	// same SignBlock call every other block goes through, no separate
	// "authority" identity. Signing happens strictly AFTER FinalizeHash, so
	// the signature bytes never affect the hash — genesis stays
	// byte-for-byte identical across every node regardless of who signs it.
	if signer, signerNodeID := getGenesisSigner(); signer != nil && signerNodeID != "" {
		header.ProposerID = signerNodeID
		wrapped := NewBlockHelper(block)
		if err := signer.SignBlock(wrapped); err != nil {
			logger.Warn("BuildBlock: failed to sign genesis block: %v", err)
		} else {
			wrapped.SetSigValid(true)
			logger.Info("SUCCESS Genesis block signed by %s", signerNodeID)
		}
	} else {
		// Not fatal and not unusual: getCachedGenesisBlock() calls
		// signGenesisIfPossible() on every lookup, so the block is signed as
		// soon as SetGenesisSigner runs — i.e. moments after this build on a
		// real node. Log at Info so a normal startup is not painted as a
		// problem; signGenesisIfPossible still WARNs if signing itself fails.
		logger.Info("BuildBlock: genesis block built unsigned; it will be signed lazily once SetGenesisSigner is registered")
	}

	logger.Info("GenesisState.BuildBlock: hash=%s, height=0, vault=%s, txs=%d",
		block.GetHash(), GenesisVaultAddress, len(txs))

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
		// Empty body → hash of empty input for consistency with SpxHash
		return common.SpxHash([]byte{})
	}

	// Build the same transaction list that BuildBlock uses so the root matches.
	genesisTxs := gs.allocationsToTxListAuthorized(nil, 0)
	tempBody := types.NewBlockBody(genesisTxs, []*types.BlockHeader{}, 0)
	tempBlock := types.NewBlock(&types.BlockHeader{}, tempBody)
	return tempBlock.CalculateTxsRoot()
}

// merkleRootFromLeaves reduces a slice of leaf hashes to a single root using a
// simple binary Merkle tree. Odd-length layers are padded by duplicating the
// last element — the same convention used in the transaction Merkle tree.
// Retained for use by the test suite.
func merkleRootFromLeaves(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return types.EmptyMerkleRoot
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

	// ── FIX: same pattern ──
	envGs := *gs
	if bc.chainParams != nil {
		envGs.ChainName = bc.chainParams.ChainName
		envGs.ChainID = bc.chainParams.ChainID
	}
	if writeErr := envGs.writeGenesisStateFile(common.GetDataDir()); writeErr != nil {
		logger.Warn("ApplyGenesis: failed to write genesis_state.json: %v", writeErr)
	}

	logger.Info("SUCCESS ApplyGenesis: genesis block applied — hash=%s, allocations=%d, validators=%d, txs_in_body=%d",
		block.GetHash(), len(gs.Allocations), len(gs.InitialValidators), len(block.Body.TxsList))

	return nil
}

// ApplyGenesisWithCachedBlock writes genesis_state.json using gs.ChainName,
// which must come from GenesisStateFromChainParams(bc.chainParams), not from
// DefaultGenesisState(). The caller (createGenesisBlock) is responsible for
// passing the environment-correct gs.
func ApplyGenesisWithCachedBlock(bc *Blockchain, gs *GenesisState, cachedBlock *types.Block) error {
	if bc == nil {
		return fmt.Errorf("blockchain is nil")
	}
	if gs == nil {
		return fmt.Errorf("genesis state is nil")
	}

	// If no cached block was provided, build one using the canonical
	// cryptographic inputs (NOT gs.BuildBlock() which would use gs.ChainName
	// in log output but more importantly could diverge from the cached hash).
	if cachedBlock == nil {
		cachedBlock = getCachedGenesisBlock()
	}

	latest, err := bc.storage.GetLatestBlock()
	if err == nil && latest != nil && latest.GetHeight() == 0 {
		existingHash := latest.GetHash()
		newHash := cachedBlock.GetHash()
		if existingHash == newHash {
			logger.Info("ApplyGenesis (%s): genesis block already present (%s), skipping",
				gs.ChainName, existingHash)
			if len(bc.chain) == 0 {
				bc.chain = []*types.Block{latest}
			}
			// Even on skip, rewrite genesis_state.json so ChainName is correct
			// for the current environment (devnet/testnet/mainnet).
			envGs := *gs // shallow copy
			if bc.chainParams != nil {
				envGs.ChainName = bc.chainParams.ChainName // stamp the actual running env
				envGs.ChainID = bc.chainParams.ChainID
			}
			// FIX: stamp the block-derived fields from the block that is
			// ACTUALLY on chain (`latest`/`cachedBlock`, same hash), not from
			// gs (built from bc.chainParams.GenesisConfig). gs.Nonce can
			// diverge from the real on-chain nonce because the genesis block
			// is built via DefaultGenesisState().BuildBlock() inside
			// getCachedGenesisBlock() — which hardcodes Nonce=1 and ignores
			// GenesisConfig entirely — while gs comes from
			// GenesisStateFromChainParams(), which honors
			// GenesisConfig.GenesisNonce. Without this, genesis_state.json
			// records a nonce that was never actually used to build the
			// hashed block, while WriteGenesisStateFromBlock (used by late
			// joiners syncing the real block) correctly reports the true
			// value — producing a mismatch between the bootstrap node's own
			// audit file and every late joiner's.
			envGs.Timestamp = cachedBlock.Header.Timestamp
			envGs.ExtraData = append([]byte{}, cachedBlock.Header.ExtraData...)
			envGs.InitialDifficulty = new(big.Int).Set(cachedBlock.Header.Difficulty)
			envGs.InitialGasLimit = new(big.Int).Set(cachedBlock.Header.GasLimit)
			envGs.Nonce = cachedBlock.Header.Nonce
			if writeErr := envGs.writeGenesisStateFile(common.GetDataDir()); writeErr != nil {
				logger.Warn("ApplyGenesis (cached, skip): failed to rewrite genesis_state.json: %v", writeErr)
			}
			return nil
		}
		return fmt.Errorf("genesis conflict: stored=%s new=%s", existingHash, newHash)
	}

	if err := bc.storage.StoreBlock(cachedBlock); err != nil {
		return fmt.Errorf("failed to store cached genesis block: %w", err)
	}

	bc.lock.Lock()
	bc.chain = []*types.Block{cachedBlock}
	bc.lock.Unlock()

	// ── FIX: stamp ChainName/ChainID on the first-write path too ──
	envGs := *gs
	if bc.chainParams != nil {
		envGs.ChainName = bc.chainParams.ChainName
		envGs.ChainID = bc.chainParams.ChainID
	}
	// FIX: see identical comment in the skip-path above — envGs's
	// block-derived fields must come from cachedBlock (what was actually
	// stored and hashed), not from gs (chain-params config), or the audit
	// file can record a nonce/extra-data/etc. that was never really used.
	envGs.Timestamp = cachedBlock.Header.Timestamp
	envGs.ExtraData = append([]byte{}, cachedBlock.Header.ExtraData...)
	envGs.InitialDifficulty = new(big.Int).Set(cachedBlock.Header.Difficulty)
	envGs.InitialGasLimit = new(big.Int).Set(cachedBlock.Header.GasLimit)
	envGs.Nonce = cachedBlock.Header.Nonce
	if writeErr := envGs.writeGenesisStateFile(common.GetDataDir()); writeErr != nil {
		logger.Warn("ApplyGenesis (cached): failed to write genesis_state.json: %v", writeErr)
	}

	logger.Info("SUCCESS ApplyGenesis (cached): %s genesis applied — hash=%s, allocations=%d",
		envGs.ChainName, cachedBlock.GetHash(), len(gs.Allocations))

	return nil
}

// writeGenesisStateFile merges the GenesisState audit view into the ONE genesis
// document at <datadir>/config/genesis_state.json (mode 0644).
//
// datadir — NOT the chain state dir — is the location because R9 makes
// genesis_state.json the single genesis file: the audit view, the chain
// parameters, the validator set, the funded accounts, the custody policy and
// the block-0 witness set all live in that one file under <datadir>/config/.
//
// It writes the complete per-account allocation list and per-validator list so
// the document contains real data instead of blank arrays, and it MERGES rather
// than replaces, so a node that already holds the sections written by
// `genesis create` or by custody provisioning keeps them.
//
// FIX: now writes the complete per-account allocation list and per-validator
// list so genesis_state.json contains real data instead of blank arrays.
func (gs *GenesisState) writeGenesisStateFile(datadir string) error {
	if err := os.MkdirAll(perNodePath(datadir, "config"), 0755); err != nil {
		return fmt.Errorf("cannot create config dir: %w", err)
	}

	// Build per-account rows and compute the supply block 0 mints. Each row
	// breaks the category into: remainder (the CGE schedule input), sold
	// (always liquid at genesis) and gross (what block 0 actually pays — the
	// two summed). Reporting the remainder alone would understate the minted
	// supply by the sold amount and contradict the chain.
	totalRemainder := new(big.Int)
	totalSold := new(big.Int)
	allocEntries := make([]genesisAllocationEntry, len(gs.Allocations))
	for i, a := range gs.Allocations {
		remainder := new(big.Int)
		if a.BalanceNSPX != nil {
			remainder.Set(a.BalanceNSPX)
		}
		sold := cgeSoldNSPX(a.Label)
		gross := new(big.Int).Add(remainder, sold)

		totalRemainder.Add(totalRemainder, remainder)
		totalSold.Add(totalSold, sold)

		// Express each figure in both nSPX and whole SPX for readability.
		allocEntries[i] = genesisAllocationEntry{
			Address:     a.Address,
			BalanceNSPX: remainder.String(),
			BalanceSPX:  new(big.Int).Div(remainder, big.NewInt(1e18)).String(),
			SoldNSPX:    sold.String(),
			SoldSPX:     new(big.Int).Div(sold, big.NewInt(1e18)).String(),
			GrossNSPX:   gross.String(),
			GrossSPX:    new(big.Int).Div(gross, big.NewInt(1e18)).String(),
			Label:       a.Label,
		}
	}
	totalGross := new(big.Int).Add(totalRemainder, totalSold)

	// Build the per-validator audit rows.
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

	// Merge the audit view into the ONE genesis document. This deliberately
	// only touches the top-level identity fields, the supply totals and the two
	// audit row arrays — the chain / validators / funded_accounts / multisig /
	// witnesses sections belong to other writers and must survive untouched.
	//
	// Every *big.Int is rendered as a decimal string first, so the file is
	// readable by tools with no Go runtime.
	audit := func(gf *GenesisStateFile) {
		gf.ChainID = gs.ChainID
		gf.ChainName = gs.ChainName
		gf.Symbol = gs.Symbol
		gf.Timestamp = time.Unix(gs.Timestamp, 0).UTC().Format(time.RFC3339)
		gf.ExtraData = string(gs.ExtraData)
		gf.InitialDifficulty = gs.InitialDifficulty.String()
		gf.InitialGasLimit = gs.InitialGasLimit.String()
		gf.Nonce = gs.Nonce

		gf.TotalAllocations = len(gs.Allocations)
		gf.TotalAllocatedNSPX = totalGross.String()
		gf.TotalAllocatedSPX = new(big.Int).Div(totalGross, big.NewInt(1e18)).String()
		gf.TotalRemainderNSPX = totalRemainder.String()
		gf.TotalRemainderSPX = new(big.Int).Div(totalRemainder, big.NewInt(1e18)).String()
		gf.TotalSoldNSPX = totalSold.String()
		gf.TotalSoldSPX = new(big.Int).Div(totalSold, big.NewInt(1e18)).String()
		gf.TotalValidators = len(gs.InitialValidators)
		// Full ordered allocation list — previously missing, now populated.
		gf.Allocations = allocEntries
		// Full validator list — previously missing, now populated.
		gf.InitialValidators = valEntries
	}
	if err := MutateGenesisFile(datadir, audit); err != nil {
		return err
	}

	logger.Info("Genesis state written to %s (%d allocations, genesis supply %s SPX = %s sold + %s remainder)",
		GenesisStateFilePathForDataDir(datadir), len(gs.Allocations),
		new(big.Int).Div(totalGross, big.NewInt(1e18)).String(),
		new(big.Int).Div(totalSold, big.NewInt(1e18)).String(),
		new(big.Int).Div(totalRemainder, big.NewInt(1e18)).String())
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

// WriteGenesisStateFromBlock writes the genesis_state.json file based on a downloaded genesis block.
// Used by late-joining nodes to create the audit file after syncing.
func (bc *Blockchain) WriteGenesisStateFromBlock(block *types.Block) error {
	if block == nil || block.Header == nil {
		return fmt.Errorf("invalid genesis block")
	}
	if bc.chainParams == nil {
		return fmt.Errorf("chain parameters not initialized")
	}

	gs := &GenesisState{
		ChainID:           bc.chainParams.ChainID,
		ChainName:         bc.chainParams.ChainName,
		Symbol:            bc.chainParams.Symbol,
		Timestamp:         block.Header.Timestamp,
		ExtraData:         block.Header.ExtraData,
		InitialDifficulty: new(big.Int).Set(block.Header.Difficulty),
		InitialGasLimit:   new(big.Int).Set(block.Header.GasLimit),
		Nonce:             block.Header.Nonce,
		Allocations:       DefaultGenesisAllocations(),
		InitialValidators: []*GenesisValidator{}, // not critical for late joiners
	}

	return gs.writeGenesisStateFile(common.GetDataDir())
}

// Registry for the M-of-N authorizer (and optional witness sink) used when the
// process-global cached genesis block is built. This is the seam that lets a
// policy-owned genesis vault produce a block 0 whose distributions carry
// threshold custody witnesses — see GenesisState.BuildBlockWithCustody for the
// builder and tx_auth.custodyPolicyOwns for the fail-closed check that makes
// such witnesses mandatory once the vault resolves to a registered policy.
//
// Why a package-level registry and not a Blockchain field: getCachedGenesisBlock
// (global.go) is a sync.Once value computed on the FIRST GetGenesisHash() call
// in the process, which happens during chain-parameter construction — before
// any Blockchain exists and before bind.StartNode reaches NewBlockchain. The
// authorizer therefore has to be registered by whoever resolves the network
// phase, exactly like SetGenesisSigner.

var genesisDistributionAuthMu sync.Mutex

var (
	genesisDistributionAuth        GenesisDistributionAuthorizer
	genesisDistributionAuthChainID uint64
	genesisWitnessSink             func(*types.Block) error
)

// SetGenesisDistributionAuthorizer registers the authorizer used for block 0's
// distribution transactions, bound to chainID. A nil auth restores the legacy
// unsigned genesis path, which is what a vault with no registered policy keeps.
//
// chainID is bound into every witness message (via multisig.SpendMessage), so
// it must be the chain the node will actually validate block 0 against —
// devnet 73310, not the mainnet default.
func SetGenesisDistributionAuthorizer(auth GenesisDistributionAuthorizer, chainID uint64) {
	genesisDistributionAuthMu.Lock()
	defer genesisDistributionAuthMu.Unlock()
	genesisDistributionAuth = auth
	if auth == nil {
		genesisDistributionAuthChainID = 0
	} else {
		genesisDistributionAuthChainID = chainID
	}
}

func getGenesisDistributionAuthorizer() (GenesisDistributionAuthorizer, uint64) {
	genesisDistributionAuthMu.Lock()
	defer genesisDistributionAuthMu.Unlock()
	return genesisDistributionAuth, genesisDistributionAuthChainID
}

// SetGenesisWitnessSink registers a callback invoked once with the freshly
// built custody-bearing genesis block, so the producer can persist the witness
// set for peers that hold no custodian keys. A nil sink unregisters it.
func SetGenesisWitnessSink(fn func(*types.Block) error) {
	genesisDistributionAuthMu.Lock()
	defer genesisDistributionAuthMu.Unlock()
	genesisWitnessSink = fn
}

func getGenesisWitnessSink() func(*types.Block) error {
	genesisDistributionAuthMu.Lock()
	defer genesisDistributionAuthMu.Unlock()
	return genesisWitnessSink
}

// GenesisDistributionAuthorizerConfigured reports whether block 0 will be
// built with custody witnesses (i.e. an authorizer is registered). Used by the
// devnet provisioning report and by tests.
func GenesisDistributionAuthorizerConfigured() bool {
	auth, _ := getGenesisDistributionAuthorizer()
	return auth != nil
}

// resetGenesisCustodyForTest clears the authorizer, the witness sink and the
// cached genesis block so a test can observe a first-build in isolation.
// Production code never calls this: the cache is intentionally permanent.
func resetGenesisCustody() {
	SetGenesisDistributionAuthorizer(nil, 0)
	SetGenesisWitnessSink(nil)
	genesisDistributionAuthMu.Lock()
	genesisOnce = sync.Once{}
	genesisCached = nil
	genesisHashValue = ""
	genesisTimestampValue = 0
	genesisDistributionAuthMu.Unlock()
	// Forget the process-level idempotence marker too, so a test can exercise a
	// fresh provisioning decision the way the next process start would.
	devnetCustodyMu.Lock()
	devnetCustodyApplied = nil
	devnetCustodyMu.Unlock()
}

// ----------------------------------------------------------------------------
// The ONE genesis document — <datadir>/config/genesis_state.json
//
// R9: a node has exactly ONE genesis file. It is the only place initial
// validator membership, chain parameters, the devnet genesis-vault custody
// policy and the pre-signed block-0 witness set are recorded. There is no
// separate genesis document, no separate multisig policy file and no separate
// witness book, and there is deliberately NO compatibility fallback that reads
// any of them.
//
// Four writers share this one file, in this order on a running node:
//
//  1. `genesis create` (the devnet helper — the ONLY place K is known) writes
//     the chain, validators and funded_accounts sections;
//  2. devnet custody provisioning merges in the multisig section (the genesis
//     vault policy) and, on the bootstrap node, the witnesses section;
//  3. the block-0 witness sink merges in the witnesses section after signing;
//  4. the block-0 audit writer merges in the top-level identity fields, the
//     supply totals and the CGE allocations / initial_validators audit rows.
//
// Every merge goes through MutateGenesisFile (load → mutate → atomic write), so
// no writer can clobber a section another writer owns, and a restarted node
// keeps all four.
//
// ★ NOT PART OF BLOCK 0's HASH INPUT — the one invariant this document must
// never break. Block 0's hash is types.Block.FinalizeHash(), which concatenates
// ONLY header fields: version, block number, timestamp, parentHash, txsRoot,
// stateRoot, nonce, difficulty, gasLimit, gasUsed, unclesHash, extraData and
// miner. It never reads this file and never marshals a GenesisState. The
// sections below therefore describe MEMBERSHIP, PARAMETERS and AUTHORIZATION
// only, and none of them can change the genesis hash.
// TestGenesisHash_UnaffectedByFile in genesis_test.go pins that.
//
// Note on the two "allocations" concepts. The top-level `allocations` array is
// the canonical CGE genesis distribution: it DOES feed block 0's TxsRoot, and
// its rows carry the per-category remainder/sold/gross breakdown. The
// `funded_accounts` array is the devnet pre-funding of reward addresses, applied
// to state during block-0 execution and never entering a header. They are
// different data with different hash consequences, so they are different
// sections; the field semantics of each are unchanged.
// ----------------------------------------------------------------------------

// GenesisStateFileName is the single genesis document's file name, and
// GenesisStateFileSubdir its per-node relative path under a datadir (the same
// perNodePath convention the escrow policy and spend-proposal inbox use).
const (
	GenesisStateFileName   = "genesis_state.json"
	GenesisStateFileSubdir = "config/" + GenesisStateFileName

	// genesisStateFileVersion is the consolidated document's schema version.
	genesisStateFileVersion = 2
)

// genesisFileMu serialises load → mutate → write cycles inside this process.
// On-disk writes are already atomic (temp+rename); this only stops two
// in-process writers (e.g. the witness sink and the block-0 audit writer) from
// reading the same base document and losing one section.
var genesisFileMu sync.Mutex

// GenesisChainParams are the chain parameters the genesis document carries.
// EpochBlocks is the epoch length IN BLOCKS (epoch(h) = h / EpochBlocks) that
// consensus reads from chain state — never from a flag. The production default
// is large; the devnet helper writes a small value so devnet epochs turn over
// quickly.
type GenesisChainParams struct {
	ChainID     uint64 `json:"chain_id"`
	Network     string `json:"network"`
	EpochBlocks uint64 `json:"epoch_blocks"`
	// MinStakeNSPX records the minimum stake the file was authored against
	// (decimal nSPX string) so a reader can detect parameter drift between the
	// file and the running chain params.
	MinStakeNSPX string `json:"min_stake_nspx"`
}

// GenesisStakedValidator is one initial validator: the node ID the consensus
// layer will use (Node-<tcp-addr>), that identity's SPHINCS+ public key, the
// initial stake in nSPX, and the reward address its block rewards accrue to.
type GenesisStakedValidator struct {
	NodeID        string `json:"node_id"`
	PublicKey     string `json:"public_key"`
	StakeNSPX     string `json:"stake_nspx"`
	RewardAddress string `json:"reward_address"`
}

// GenesisFundedAccount is one pre-funded reward address. BalanceNSPX is a
// decimal nSPX string. These are credited to state during block-0 execution
// (see Blockchain.seedGenesisFileAllocations) and never enter a block header.
type GenesisFundedAccount struct {
	Address     string `json:"address"`
	BalanceNSPX string `json:"balance_nspx"`
	Label       string `json:"label"`
}

// GenesisStateFile is the on-disk <datadir>/config/genesis_state.json document —
// the single genesis file described above.
type GenesisStateFile struct {
	Version int `json:"version"`

	// ── Block-0 identity and header template (audit view) ──────────────────
	// The human-readable record of what block 0 was built from. Written by the
	// block-0 audit path, never read back to build a block, and therefore
	// incapable of influencing the genesis hash.
	ChainID           uint64 `json:"chain_id"`
	ChainName         string `json:"chain_name,omitempty"`
	Symbol            string `json:"symbol,omitempty"`
	Timestamp         string `json:"timestamp,omitempty"`
	ExtraData         string `json:"extra_data,omitempty"`
	InitialDifficulty string `json:"initial_difficulty,omitempty"`
	InitialGasLimit   string `json:"initial_gas_limit,omitempty"`
	Nonce             string `json:"nonce,omitempty"`

	// ── Supply totals (audit view) ─────────────────────────────────────────
	TotalAllocations   int    `json:"total_allocations,omitempty"`
	TotalAllocatedNSPX string `json:"total_allocated_nspx,omitempty"`
	TotalAllocatedSPX  string `json:"total_allocated_spx,omitempty"`
	TotalRemainderNSPX string `json:"total_remainder_nspx,omitempty"`
	TotalRemainderSPX  string `json:"total_remainder_spx,omitempty"`
	TotalSoldNSPX      string `json:"total_sold_nspx,omitempty"`
	TotalSoldSPX       string `json:"total_sold_spx,omitempty"`
	TotalValidators    int    `json:"total_validators,omitempty"`
	// Allocations is the full ordered CGE distribution. This array DOES feed
	// block 0's TxsRoot; it is not the devnet reward-address pre-funding.
	Allocations []genesisAllocationEntry `json:"allocations,omitempty"`
	// InitialValidators is the full genesis validator list, for audit only.
	InitialValidators []genesisValidatorEntry `json:"initial_validators,omitempty"`

	// ── Membership and parameters (the sections a node actually reads) ─────

	// Chain carries the chain parameters. EpochBlocks is authoritative: it is
	// the value bind.StartNode hands to core.SetGenesisEpochBlocks before chain
	// params are constructed.
	Chain GenesisChainParams `json:"chain,omitempty"`

	// Validators is the initial validator set, sorted by NodeID. Every node in
	// the network must read the identical list. It is the ONLY source of initial
	// validator membership: no flag, peer count or synthesized roster ever names
	// a validator.
	Validators []GenesisStakedValidator `json:"validators,omitempty"`

	// FundedAccounts are the pre-funded reward addresses (validator reward
	// addresses plus the extra devnet ones used by later Stake transactions).
	FundedAccounts []GenesisFundedAccount `json:"funded_accounts,omitempty"`

	// ── Devnet block-0 authorization ───────────────────────────────────────

	// Multisig is the genesis vault custody policy (M-of-N over SPHINCS+
	// custodian keys). Its derived address becomes the block-0 distribution
	// sender, so it must be present before block 0 is built and is what a late
	// joiner must receive to rebuild an identical block 0.
	Multisig *multisig.MultiPartyPolicy `json:"multisig,omitempty"`

	// Witnesses is the pre-signed block-0 witness book: one threshold witness per
	// distribution slice plus the binding facts a replaying node must agree on.
	// It lets a node rebuild block 0 identically while holding no custodian keys.
	Witnesses *GenesisWitnessBook `json:"witnesses,omitempty"`
}

// HasValidatorSet reports whether this document names an initial validator set at
// all. A document with none is a block-0 audit record only: the network was not
// provisioned with `genesis create`, so membership comes from on-chain Stake
// transactions alone.
func (gf *GenesisStateFile) HasValidatorSet() bool {
	return gf != nil && len(gf.Validators) > 0
}

// GenesisStateFilePathForDataDir returns the absolute path of the single genesis
// document for one node's datadir. Empty datadir keeps the legacy shared-root
// layout.
func GenesisStateFilePathForDataDir(datadir string) string {
	return perNodePath(datadir, GenesisStateFileSubdir)
}

// LoadGenesisFile reads <datadir>/config/genesis_state.json. A missing file is
// not an error: it returns (nil, nil), which callers treat as "this network has
// no genesis document — fall back to the legacy behaviour". A present-but-invalid
// file is an error: refusing to start is the only safe response, because a node
// that guesses its validator set cannot agree with one that reads it.
func LoadGenesisFile(datadir string) (*GenesisStateFile, error) {
	path := GenesisStateFilePathForDataDir(datadir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read genesis file %s: %w", path, err)
	}
	var gf GenesisStateFile
	if err := ValidateGenesisFileBytes(data, &gf); err != nil {
		return nil, fmt.Errorf("genesis file %s: %w", path, err)
	}
	return &gf, nil
}

// ValidateGenesisFileBytes parses and validates raw genesis-document JSON. It is
// the single chokepoint for genesis-document parsing, used by both the loader and
// the devnet bundle validator (which must fail-closed on fetched bytes).
func ValidateGenesisFileBytes(data []byte, gf *GenesisStateFile) error {
	if len(data) == 0 {
		return fmt.Errorf("empty genesis file")
	}
	if gf == nil {
		return fmt.Errorf("nil destination")
	}
	if err := json.Unmarshal(data, gf); err != nil {
		return fmt.Errorf("not a genesis file: %w", err)
	}
	return gf.Validate()
}

// Validate enforces the genesis sanity rules for the consolidated document:
//   - the schema version is the one this build understands (no compatibility
//     fallback, so an older layout is refused rather than half-read);
//   - a document that names a validator set must list at least
//     consensus.MinValidators of them (a GENESIS rule, not a runtime wait
//     condition). A document with NO validator section is a valid block-0 audit
//     record for a network that was not provisioned with `genesis create`;
//   - node IDs and reward addresses are well-formed, unique, and one reward
//     address per node ID;
//   - stakes and balances are positive decimal nSPX;
//   - chain parameters are present and positive whenever a validator set is;
//   - the multisig policy and witness book, when present, are self-consistent.
//
// It deliberately does not care whether any validator is online.
func (gf *GenesisStateFile) Validate() error {
	if gf == nil {
		return fmt.Errorf("genesis file is nil")
	}
	if gf.Version != genesisStateFileVersion {
		return fmt.Errorf("unsupported version %d (want %d)", gf.Version, genesisStateFileVersion)
	}

	// A validator set and its chain parameters travel together: chain params with
	// no set (or a set with no params) is a half-written `genesis create`
	// document, and accepting it would let a node run with membership but the
	// default EpochBlocks.
	hasSet := len(gf.Validators) > 0
	hasChain := gf.Chain.EpochBlocks != 0 || gf.Chain.ChainID != 0 || gf.Chain.Network != ""
	if hasSet != hasChain {
		return fmt.Errorf("genesis file must carry both the chain parameters and the validator set (chain present=%t, validators present=%t)", hasChain, hasSet)
	}

	if hasSet {
		if len(gf.Validators) < consensus.MinValidators {
			return fmt.Errorf("genesis file must list at least %d validators, got %d",
				consensus.MinValidators, len(gf.Validators))
		}
		if gf.Chain.EpochBlocks == 0 {
			return fmt.Errorf("chain parameter epoch_blocks must be positive")
		}
		if gf.Chain.ChainID == 0 {
			return fmt.Errorf("chain parameter chain_id must be positive")
		}

		seenIDs := make(map[string]bool, len(gf.Validators))
		seenReward := make(map[string]bool, len(gf.Validators))
		for i, v := range gf.Validators {
			if strings.TrimSpace(v.NodeID) == "" {
				return fmt.Errorf("validator[%d]: node_id is empty", i)
			}
			if seenIDs[v.NodeID] {
				return fmt.Errorf("validator[%d]: duplicate node_id %s", i, v.NodeID)
			}
			seenIDs[v.NodeID] = true

			if _, err := parseDecimalNSPX(v.StakeNSPX); err != nil {
				return fmt.Errorf("validator[%d] (%s): stake_nspx %q: %w", i, v.NodeID, v.StakeNSPX, err)
			}
			if v.PublicKey != "" {
				pk, err := hex.DecodeString(stripHexPrefix(v.PublicKey))
				if err != nil || len(pk) != 32 {
					return fmt.Errorf("validator[%d] (%s): public_key must be 32 bytes of hex", i, v.NodeID)
				}
			}
			if v.RewardAddress != "" {
				addr := common.CanonicalSPIFAddress(v.RewardAddress)
				if !common.ValidateSPIFAddress(addr) {
					return fmt.Errorf("validator[%d] (%s): reward_address %q is not a valid address", i, v.NodeID, v.RewardAddress)
				}
				if seenReward[addr] {
					return fmt.Errorf("validator[%d]: reward address %s is bound to more than one validator", i, addr)
				}
				seenReward[addr] = true
			}
		}
	}

	for i, a := range gf.FundedAccounts {
		addr := common.CanonicalSPIFAddress(a.Address)
		if !common.ValidateSPIFAddress(addr) {
			return fmt.Errorf("funded_accounts[%d]: address %q is not a valid address", i, a.Address)
		}
		if _, err := parseDecimalNSPX(a.BalanceNSPX); err != nil {
			return fmt.Errorf("funded_accounts[%d] (%s): balance_nspx %q: %w", i, addr, a.BalanceNSPX, err)
		}
	}

	if gf.Multisig != nil {
		if err := gf.Multisig.Validate(); err != nil {
			return fmt.Errorf("multisig section: %w", err)
		}
	}
	if gf.Witnesses != nil {
		if err := gf.Witnesses.validateSelf(); err != nil {
			return fmt.Errorf("witnesses section: %w", err)
		}
	}
	return nil
}

// StakeNSPX returns the parsed initial stake of nodeID, or nil when the document
// does not list that node.
func (gf *GenesisStateFile) StakeNSPX(nodeID string) *big.Int {
	if gf == nil {
		return nil
	}
	for _, v := range gf.Validators {
		if v.NodeID == nodeID {
			stake, err := parseDecimalNSPX(v.StakeNSPX)
			if err != nil {
				return nil
			}
			return stake
		}
	}
	return nil
}

// WriteGenesisFile persists gf atomically to <datadir>/config/genesis_state.json
// (mode 0644, public data — it is also served over the devnet bundle endpoint so
// late joiners read the identical validator set, custody policy and witness book).
func WriteGenesisFile(datadir string, gf *GenesisStateFile) error {
	if gf == nil {
		return fmt.Errorf("genesis file is nil")
	}
	if err := gf.Validate(); err != nil {
		return fmt.Errorf("refusing to write an invalid genesis file: %w", err)
	}
	genesisFileMu.Lock()
	defer genesisFileMu.Unlock()
	return writeGenesisFileUnlocked(datadir, gf)
}

// MutateGenesisFile performs a load → mutate → atomic write cycle on the one
// genesis document, which is how the four writers share it without clobbering
// each other's sections. mutate receives the current document (an empty one at the
// current schema version when the file does not exist yet) and may change any
// field; everything it leaves alone is preserved.
//
// The result is validated before it is written, so an invalid document is never
// persisted. An error from the mutator aborts without writing.
func MutateGenesisFile(datadir string, mutate func(*GenesisStateFile)) error {
	if mutate == nil {
		return fmt.Errorf("genesis file: nil mutator")
	}
	genesisFileMu.Lock()
	defer genesisFileMu.Unlock()

	gf, err := LoadGenesisFile(datadir)
	if err != nil {
		return err
	}
	if gf == nil {
		gf = &GenesisStateFile{Version: genesisStateFileVersion}
	}
	mutate(gf)
	if gf.Version == 0 {
		gf.Version = genesisStateFileVersion
	}
	if err := gf.Validate(); err != nil {
		return fmt.Errorf("genesis file: refusing to write an invalid document: %w", err)
	}
	return writeGenesisFileUnlocked(datadir, gf)
}

// writeGenesisFileUnlocked marshals and atomically persists gf. Callers must hold
// genesisFileMu.
func writeGenesisFileUnlocked(datadir string, gf *GenesisStateFile) error {
	data, err := json.MarshalIndent(gf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal genesis file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(GenesisStateFilePathForDataDir(datadir)), 0o755); err != nil {
		return err
	}
	return writeBundleFile(datadir, GenesisStateFileSubdir, append(data, '\n'))
}

// parseDecimalNSPX parses a decimal nSPX string into a big.Int.
func parseDecimalNSPX(s string) (*big.Int, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return nil, fmt.Errorf("empty amount")
	}
	v, ok := new(big.Int).SetString(t, 10)
	if !ok {
		return nil, fmt.Errorf("not a decimal integer: %q", s)
	}
	return v, nil
}

// stripHexPrefix removes a leading 0x/0X if present.
func stripHexPrefix(s string) string {
	if len(s) >= 2 && (s[:2] == "0x" || s[:2] == "0X") {
		return s[2:]
	}
	return s
}
