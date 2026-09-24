// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/types.go
package bind

import (
	"sync"

	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	config "github.com/sphinxfndorg/protocol/src/core/sthincs/config" // Add this import
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/http"
	"github.com/sphinxfndorg/protocol/src/network"
	"github.com/sphinxfndorg/protocol/src/p2p"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/transport"
)

// NodeConfig defines the configuration for a node's TCP server.
type NodeConfig struct {
	Address   string
	Name      string
	MessageCh chan *security.Message
	RPCServer *rpc.Server
	ReadyCh   chan struct{}
}

// NodeSetupConfig defines the configuration for setting up a node's servers.
type NodeSetupConfig struct {
	Address       string
	Name          string
	Role          network.NodeRole
	HTTPPort      string
	WSPort        string
	UDPPort       string
	SeedNodes     []string
	KeyManager    *key.KeyManager
	SphincsParams *config.STHINCSParameters // Now config is defined
}

// NodeResources holds the initialized resources for a node.
type NodeResources struct {
	Blockchain           *core.Blockchain
	NodeManager          *network.NodeManager
	ConsensusNodeManager consensus.NodeManager // Add this if needed
	MessageCh            chan *security.Message
	RPCServer            *rpc.Server
	P2PServer            *p2p.Server
	PublicKey            string
	TCPServer            *transport.TCPServer
	WebSocketServer      *transport.WebSocketServer
	HTTPServer           *http.Server
}

// SyncState represents the current block synchronization status of a node.
type SyncState int

const (
	// SyncStateSyncing means the node is still downloading/catching up on blocks
	// and must NOT participate in PBFT voting or propose blocks.
	SyncStateSyncing SyncState = iota

	// SyncStateCaughtUp means the node's local height is within 1 block of the
	// network tip. It can now transition to full consensus participation.
	SyncStateCaughtUp

	// SyncStateConsensusParticipant means the node is fully synced and actively
	// participating in PBFT rounds (sending PREPARE/COMMIT votes, proposing).
	SyncStateConsensusParticipant
)

// String returns a human-readable name for the SyncState.
func (s SyncState) String() string {
	switch s {
	case SyncStateSyncing:
		return "SYNCING"
	case SyncStateCaughtUp:
		return "CAUGHT_UP"
	case SyncStateConsensusParticipant:
		return "CONSENSUS_PARTICIPANT"
	default:
		return "UNKNOWN"
	}
}

// GetBlocksRequest is the P2P message a syncing node sends to request a range
// of blocks from a peer. Max 500 blocks per request to limit payload size.
type GetBlocksRequest struct {
	FromHeight uint64 `json:"from_height"`
	ToHeight   uint64 `json:"to_height"`
	MaxResults uint64 `json:"max_results,omitempty"` // optional, default 500
}

// GetBlocksResponse is the P2P reply containing the requested block data.
type GetBlocksResponse struct {
	Blocks     []*types.Block `json:"blocks"`
	TipHeight  uint64         `json:"tip_height"`  // the peer's current chain tip
	ChainReady bool           `json:"chain_ready"` // false while genesis/tip is not installed
	Error      string         `json:"error,omitempty"`
}

// knownPeerInfo describes a single peer entry as gossiped during a
// peer-exchange (PEX) round.
type knownPeerInfo struct {
	NodeID  string `json:"node_id"`
	Address string `json:"address"`
}

// peerKeyExchangeMsg is the payload sent over the wire during the
// post-connect public-key handshake.
//
// Admission is challenge-response gated: the receiver first issues an
// auth_challenge nonce, the sender signs challengePayload(nonce, NodeID,
// GenesisHash, RewardAddress), and only a verified proof leads to
// RegisterPublicKey or any admission side effect (see challenge.go).
//
// Address is the sender's ADVERTISED LISTENING address (host:port). Only its
// port is trusted on receipt: the receiver combines it with the connection's
// source IP (derivePeerListenAddr), so a remote peer can never redirect the
// dial to an arbitrary host, and the ephemeral source port of the inbound
// connection is never recorded as the peer's address.
//
// RewardAddress is the SPIF wallet address the peer claims stake against.
// It is covered by the challenge signature above — the same proof that
// authenticates the node identity also commits to this claim — and the
// recipient additionally looks up the address's real on-chain balance via
// SetStakeFromBalance before granting any validator weight. One funded
// reward address admits at most one node ID (rewardClaimLedger). Sending a
// bogus or empty address just means the peer registers as a known network
// peer with zero stake; it does not grant validator status. This is what
// makes peer admission permissionless-safe: showing up on the wire is enough
// to be gossiped to, but never enough to vote.
//
// GenesisHash is the peer's claimed genesis block hash. It is verified
// against the local genesis hash during key exchange. If the hashes differ,
// the connection is rejected — this prevents accidental network splits when
// nodes bootstrap from different genesis configurations. A peer with a
// different genesis is on a fundamentally incompatible chain and must never
// be admitted to the gossip graph or validator set.
//
// Signature is the peer's proof of key possession: the reply side's
// response to the receiver-chosen challenge nonce (same payload rules as
// above). It must verify under PublicKey before that key is registered.
type peerKeyExchangeMsg struct {
	NodeID        string `json:"node_id"`
	PublicKey     []byte `json:"public_key"`
	RewardAddress string `json:"reward_address,omitempty"`
	GenesisHash   string `json:"genesis_hash,omitempty"`
	Address       string `json:"address,omitempty"`
	Signature     []byte `json:"signature,omitempty"`
}

// peerExchangeMsg is the payload sent over the wire when a node asks a peer
// "who else do you know about?".
//
// The requester's half (NodeID, Address, PublicKey, GenesisHash) is
// challenge-response authenticated exactly like key_exchange: the responder
// only serves Peers after the requester's auth_proof verifies. Peers is
// therefore only populated in replies.
type peerExchangeMsg struct {
	NodeID      string          `json:"node_id"`
	Address     string          `json:"address"`
	PublicKey   []byte          `json:"public_key,omitempty"`
	GenesisHash string          `json:"genesis_hash,omitempty"`
	Peers       []knownPeerInfo `json:"peers,omitempty"`
}

// authChallengeMsg is the receiver-chosen challenge sent before any
// admission: the sender must sign challengePayload over this nonce.
type authChallengeMsg struct {
	Nonce []byte `json:"nonce"`
}

// authProofMsg carries the sender's response to an auth_challenge.
type authProofMsg struct {
	Signature []byte `json:"signature"`
}

// phase2InitState tracks Phase 2 initialization state.
type phase2InitState struct {
	mu          sync.Mutex
	running     bool
	initialized bool
}
