// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/cons.go

package core

const (
	// NodeStarting - Node is initializing
	NodeStarting NodeState = iota

	// NodeDiscoveringPeers - Looking for peers via DHT/bootstrap
	NodeDiscoveringPeers

	// NodeConnecting - Attempting TCP/WebSocket connections
	NodeConnecting

	// NodeHandshaking - Exchanging version/chain info with peers
	NodeHandshaking

	// NodeSyncingHeaders - Downloading and verifying block headers
	NodeSyncingHeaders

	// NodeSyncingBlocks - Downloading full blocks
	NodeSyncingBlocks

	// NodeVerifying - Validating chain integrity
	NodeVerifying

	// NodeSynchronized - Chain is up to date
	NodeSynchronized

	// NodeConsensusReady - Ready to participate in consensus
	NodeConsensusReady

	// NodeValidatorActive - Actively participating in PBFT
	NodeValidatorActive
)

// Constants for blockchain status, sync modes, etc.
const (
	StatusInitializing BlockchainStatus = iota
	StatusSyncing
	StatusRunning
	StatusStopped
	StatusForked
)

const (
	SyncModeFull SyncMode = iota
	SyncModeFast
	SyncModeLight
)

const (
	ImportedBest BlockImportResult = iota
	ImportedSide
	ImportedExisting
	ImportInvalid
	ImportError
)

const (
	CacheTypeBlock CacheType = iota
	CacheTypeTransaction
	CacheTypeReceipt
	CacheTypeState
)

const (
	// PhaseDevnet is the bootstrap phase: the vault is being drained via
	// distribution blocks.  The chain must NOT be promoted until
	// IsDistributionComplete() returns true.
	PhaseDevnet ChainPhase = "devnet"

	// PhaseTestnet is the public test phase.  It continues the devnet chain
	// from wherever devnet stopped — same genesis, same block history, higher
	// ChainID, different ports.
	PhaseTestnet ChainPhase = "testnet"

	// PhaseMainnet is production.  Same ancestry as devnet and testnet.
	PhaseMainnet ChainPhase = "mainnet"
)

// Add constants for new keys
const (
	accountPrefix    = "acct:"
	totalSupplyKey   = "supply:total"
	genesisSupplyKey = "supply:genesis"
	rewardsMintedKey = "supply:rewards"
)
