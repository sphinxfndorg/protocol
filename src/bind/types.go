// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/types.go
package bind

import (
	"github.com/sphinxorg/protocol/src/consensus"
	"github.com/sphinxorg/protocol/src/core"
	config "github.com/sphinxorg/protocol/src/core/sthincs/config" // Add this import
	key "github.com/sphinxorg/protocol/src/core/sthincs/key/backend"
	security "github.com/sphinxorg/protocol/src/handshake"
	"github.com/sphinxorg/protocol/src/http"
	"github.com/sphinxorg/protocol/src/network"
	"github.com/sphinxorg/protocol/src/p2p"
	"github.com/sphinxorg/protocol/src/rpc"
	"github.com/sphinxorg/protocol/src/transport"
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
