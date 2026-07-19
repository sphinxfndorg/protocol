// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/p2p/types.go
package p2p

import (
	"net"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/network"
	"github.com/sphinxfndorg/protocol/src/transport"
	"github.com/syndtr/goleveldb/leveldb"
)

type Server struct {
	localNode   *network.Node
	nodeManager *network.NodeManager
	seedNodes   []string
	udpConn     *net.UDPConn
	messageCh   chan *security.Message
	blockchain  *core.Blockchain
	peerManager *PeerManager
	tcpServer   *transport.TCPServer
	mu          sync.RWMutex
	db          *leveldb.DB
	sphincsMgr  *sign.STHINCSManager // Field uses STHINCSManager
	stopCh      chan struct{}        // Channel to signal stop
	udpReadyCh  chan struct{}        // Channel to signal UDP readiness
	dht         network.DHT          // Add DHT field
	consensus   *consensus.Consensus

	neighborsCache     map[network.NodeID][]network.PeerInfo
	neighborsCacheTime time.Time
	cacheMutex         sync.RWMutex
}

func (s *Server) LocalNode() *network.Node {
	return s.localNode
}

func (s *Server) NodeManager() *network.NodeManager {
	return s.nodeManager
}

func (s *Server) PeerManager() *PeerManager {
	return s.peerManager
}

// FIXED: Changed parameter type from *sign.SphincsManager to *sign.STHINCSManager
func (s *Server) SetSphincsMgr(mgr *sign.STHINCSManager) {
	s.sphincsMgr = mgr
}

type Peer = network.Peer

type PeerManager struct {
	server      *Server
	peers       map[string]*network.Peer
	scores      map[string]int
	bans        map[string]time.Time
	maxPeers    int
	maxInbound  int
	maxOutbound int
	mu          sync.RWMutex
}
