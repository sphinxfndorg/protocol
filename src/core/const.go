// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/cons.go

package core

// NodeState represents the operational state of a node in the synchronization lifecycle.
// The node progresses strictly forward through these states:
//
//	Bootstrapping        → Node is initializing, loading chain params
//	DiscoveringPeers     → Looking for peers via DHT/bootstrap/seeds
//	Connecting           → Establishing TCP/WebSocket connections
//	Handshaking          → Exchanging version/chain info with peers
//	SyncingHeaders       → Downloading and verifying block headers
//	SyncingBlocks        → Downloading full block bodies
//	Verifying            → Validating chain integrity & attestation quorum
//	CatchingUp           → Near tip, full verification on every block
//	Ready                → Synchronized with canonical chain; may observe but NOT produce blocks
//	ValidatorActive      → Synchronized AND eligible to propose/validate blocks
//
// Only Ready and ValidatorActive nodes may participate in PBFT consensus.
// All other states are pre-consensus synchronization states.
const (
	NodeBootstrapping    NodeState = iota // 0: Initial startup, genesis loading
	NodeDiscoveringPeers                  // 1: Looking for peers
	NodeConnecting                        // 2: Establishing connections
	NodeHandshaking                       // 3: Exchanging chain metadata
	NodeSyncingHeaders                    // 4: Downloading header chain
	NodeSyncingBlocks                     // 5: Downloading full blocks
	NodeVerifying                         // 6: Validating chain integrity
	NodeCatchingUp                        // 7: Near tip, full per-block verification
	NodeReady                             // 8: Fully synchronized, can participate in consensus
	NodeValidatorActive                   // 9: Synchronized and acting as PBFT validator
)

// IsConsensusEligible returns true when the node is sufficiently synchronized
// to participate in PBFT consensus (proposing blocks and voting).
func (s NodeState) IsConsensusEligible() bool {
	return s == NodeReady || s == NodeValidatorActive
}

// IsSynchronizing returns true when the node is still downloading/catching up.
func (s NodeState) IsSynchronizing() bool {
	return s < NodeReady
}

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

// String returns the human-readable name of a NodeState.
func (s NodeState) String() string {
	switch s {
	case NodeBootstrapping:
		return "Bootstrapping"
	case NodeDiscoveringPeers:
		return "DiscoveringPeers"
	case NodeConnecting:
		return "Connecting"
	case NodeHandshaking:
		return "Handshaking"
	case NodeSyncingHeaders:
		return "SyncingHeaders"
	case NodeSyncingBlocks:
		return "SyncingBlocks"
	case NodeVerifying:
		return "Verifying"
	case NodeCatchingUp:
		return "CatchingUp"
	case NodeReady:
		return "Ready"
	case NodeValidatorActive:
		return "ValidatorActive"
	default:
		return "Unknown"
	}
}
