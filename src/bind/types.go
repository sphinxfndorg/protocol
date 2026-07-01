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
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/http"
	"github.com/sphinxfndorg/protocol/src/network"
	"github.com/sphinxfndorg/protocol/src/p2p"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/transport"
)

// NodeConfig defines the configuration for a node’s TCP server.
// NodeConfig defines the configuration for a TCP server.
type NodeConfig struct {
	Address   string
	Name      string
	MessageCh chan *security.Message
	RPCServer *rpc.Server
	ReadyCh   chan struct{}
}

// NodeSetupConfig defines the configuration for setting up a node’s servers.
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

// knownPeerInfo describes a single peer entry as gossiped during a
// peer-exchange (PEX) round.
type knownPeerInfo struct {
	NodeID  string `json:"node_id"`
	Address string `json:"address"`
}

// peerKeyExchangeMsg is the payload sent over the wire during the
// post-connect public-key handshake.
//
// RewardAddress is the SPIF wallet address the peer claims stake against.
// It is NOT trusted on its own — the recipient looks up the address's real
// on-chain balance via SetStakeFromBalance before granting any validator
// weight. Sending a bogus or empty address just means the peer registers
// as a known network peer with zero stake; it does not grant validator
// status. This is what makes peer admission permissionless-safe: showing
// up on the wire is enough to be gossiped to, but never enough to vote.
type peerKeyExchangeMsg struct {
	NodeID        string `json:"node_id"`
	PublicKey     []byte `json:"public_key"`
	RewardAddress string `json:"reward_address,omitempty"`
}

// peerExchangeMsg is the payload sent over the wire when a node asks a peer
// "who else do you know about?"
type peerExchangeMsg struct {
	NodeID  string          `json:"node_id"`
	Address string          `json:"address"`
	Peers   []knownPeerInfo `json:"peers"`
}

// phase2InitState tracks Phase 2 initialization state.
type phase2InitState struct {
	mu          sync.Mutex
	running     bool
	initialized bool
}
