// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/bind.go
package bind

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	logger "github.com/sphinxfndorg/protocol/src/log"
	"github.com/sphinxfndorg/protocol/src/network"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/transport"
)

// BindTCPServers binds TCP servers for the given node configurations.
func BindTCPServers(configs []NodeConfig, wg *sync.WaitGroup) error {
	for _, config := range configs {
		if config.Address == "" || config.Name == "" || config.MessageCh == nil || config.RPCServer == nil || config.ReadyCh == nil {
			logger.Errorf("Invalid configuration for %s: missing required fields", config.Name)
			return fmt.Errorf("invalid configuration for %s: missing required fields", config.Name)
		}

		// Create and start TCP server
		tcpServer := transport.NewTCPServer(config.Address, config.MessageCh, config.RPCServer, config.ReadyCh)
		wg.Add(1)
		go func(name, addr string, server *transport.TCPServer) {
			defer wg.Done()
			logger.Infof("Starting TCP server for %s on %s", name, addr)
			if err := server.Start(); err != nil {
				logger.Errorf("TCP server failed for %s: %v", name, err)
			} else {
				logger.Infof("TCP server for %s successfully started", name)
			}
		}(config.Name, config.Address, tcpServer)
	}
	return nil
}

// ============================================================================
// TCP handler
// ============================================================================

// handleIncomingConn processes a single accepted TCP connection.
func handleIncomingConn(
	conn net.Conn,
	selfID string,
	selfAddr string,
	ownRewardAddress string,
	signingService *consensus.SigningService,
	sthincsParams *parameters.Parameters,
	cons *consensus.Consensus,
	p2pMgr *network.P2PConsensusNodeManager,
	rpcServer *rpc.Server,
	bc *core.Blockchain,
	getKnownPeers func() []knownPeerInfo,
	onPeerDiscovered func(nodeID, address string),
	onPeerStakeClaim func(nodeID, rewardAddress string),
) {
	// Read length-prefixed message from client
	msgData, err := readFramedMessage(conn)
	if err != nil {
		log.Printf("[%s] Failed to read message: %v", selfID, err)
		return
	}

	var msg security.Message
	if err := json.Unmarshal(msgData, &msg); err != nil {
		log.Printf("[%s] Failed to decode message: %v", selfID, err)
		return
	}

	log.Printf("[%s] Received message type: %s", selfID, msg.Type)

	switch msg.Type {
	case "key_exchange":
		var kx peerKeyExchangeMsg
		if err := json.Unmarshal(msg.Data, &kx); err != nil {
			log.Printf("[%s] Failed to unmarshal key exchange: %v", selfID, err)
			return
		}

		pk, err := sthincs.DeserializePK(sthincsParams, kx.PublicKey)
		if err != nil {
			log.Printf("[%s] Failed to deserialize public key: %v", selfID, err)
			return
		}
		signingService.RegisterPublicKey(kx.NodeID, pk)
		logger.Info("✅ [%s] Registered public key from %s", selfID, kx.NodeID)

		if onPeerDiscovered != nil && kx.NodeID != "" {
			var peerAddr string
			if strings.HasPrefix(kx.NodeID, "Node-") {
				peerAddr = strings.TrimPrefix(kx.NodeID, "Node-")
			} else {
				peerAddr = kx.NodeID
			}
			onPeerDiscovered(kx.NodeID, peerAddr)
		}

		// A reward address only ever results in a *verified* stake check
		// downstream (see stakeValidatorFromRewardAddress) — receiving one
		// here never grants validator status by itself.
		if onPeerStakeClaim != nil && kx.RewardAddress != "" {
			onPeerStakeClaim(kx.NodeID, kx.RewardAddress)
		}

		ownPKBytes, err := signingService.GetPublicKey()
		if err != nil {
			log.Printf("[%s] Failed to get own public key: %v", selfID, err)
			return
		}
		reply := peerKeyExchangeMsg{NodeID: selfID, PublicKey: ownPKBytes, RewardAddress: ownRewardAddress}
		replyBytes, _ := json.Marshal(reply)
		replyMsg := security.Message{Type: "key_exchange", Data: replyBytes}
		encodedReply, _ := replyMsg.Encode()
		if err := writeFramedMessage(conn, encodedReply); err != nil {
			log.Printf("[%s] Failed to send key exchange reply: %v", selfID, err)
		}

	case "peer_exchange":
		var req peerExchangeMsg
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			log.Printf("[%s] Failed to unmarshal peer exchange request: %v", selfID, err)
			return
		}

		if onPeerDiscovered != nil && req.NodeID != "" && req.Address != "" {
			onPeerDiscovered(req.NodeID, req.Address)
		}

		var knownPeers []knownPeerInfo
		if getKnownPeers != nil {
			knownPeers = getKnownPeers()
		}

		logger.Info("[%s] 🔍 Peer exchange request from %s (%s) — sharing %d known peer(s)",
			selfID, req.NodeID, req.Address, len(knownPeers))

		reply := peerExchangeMsg{NodeID: selfID, Address: selfAddr, Peers: knownPeers}
		replyBytes, err := json.Marshal(reply)
		if err != nil {
			log.Printf("[%s] Failed to marshal peer exchange reply: %v", selfID, err)
			return
		}
		replyMsg := security.Message{Type: "peer_exchange", Data: replyBytes}
		encodedReply, err := replyMsg.Encode()
		if err != nil {
			log.Printf("[%s] Failed to encode peer exchange reply: %v", selfID, err)
			return
		}
		if err := writeFramedMessage(conn, encodedReply); err != nil {
			log.Printf("[%s] Failed to send peer exchange reply: %v", selfID, err)
		}

	case "checkpoint":
		var cp consensus.CheckpointMessage
		if err := json.Unmarshal(msg.Data, &cp); err != nil {
			log.Printf("[%s] Failed to unmarshal checkpoint: %v", selfID, err)
			return
		}

		logger.Info("[%s] Received checkpoint from peer: height=%d, phase=%s, supply=%s SPX",
			selfID, cp.TipHeight, cp.Phase, cp.MintedSPX)

		if cons != nil {
			if err := cons.HandleCheckpointMessage(msg.Data, ""); err != nil {
				log.Printf("[%s] Failed to handle checkpoint: %v", selfID, err)
			}
		}

	case "get_blocks":
		var req GetBlocksRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			log.Printf("[%s] Failed to unmarshal get_blocks request: %v", selfID, err)
			return
		}

		// Validate request bounds
		if req.FromHeight > req.ToHeight || req.ToHeight-req.FromHeight > 500 {
			log.Printf("[%s] Invalid get_blocks range: %d -> %d", selfID, req.FromHeight, req.ToHeight)
			return
		}
		if req.MaxResults == 0 || req.MaxResults > 500 {
			req.MaxResults = 500
		}
		if req.ToHeight-req.FromHeight+1 > req.MaxResults {
			req.ToHeight = req.FromHeight + req.MaxResults - 1
		}

		// Gather blocks from local storage
		var blocks []*types.Block
		for h := req.FromHeight; h <= req.ToHeight; h++ {
			blk := bc.GetBlockByNumber(h)
			if blk == nil {
				break // gap in chain, serve what we have
			}
			blocks = append(blocks, blk)
		}

		// Get our tip height so the requester knows how far ahead we are
		tipHeight := uint64(0)
		if latest := bc.GetLatestBlock(); latest != nil {
			tipHeight = latest.GetHeight()
		}

		resp := GetBlocksResponse{
			Blocks:    blocks,
			TipHeight: tipHeight,
		}
		respBytes, _ := json.Marshal(resp)
		respMsg := security.Message{Type: "get_blocks", Data: respBytes}
		encodedResp, _ := respMsg.Encode()
		if err := writeFramedMessage(conn, encodedResp); err != nil {
			log.Printf("[%s] Failed to send get_blocks response: %v", selfID, err)
		}
		logger.Info("[%s] 📦 Served %d blocks (heights %d-%d) to peer", selfID, len(blocks), req.FromHeight, req.ToHeight)

	case "proposal", "prepare", "vote", "timeout", "randao_sync":
		if p2pMgr == nil {
			log.Printf("[%s] P2P manager is nil, cannot handle consensus message", selfID)
			return
		}

		log.Printf("[%s] 📨 Processing consensus message type=%s", selfID, msg.Type)

		if err := p2pMgr.HandleIncomingMessage(msg.Type, msg.Data, ""); err != nil {
			log.Printf("[%s] consensus handling error: %v", selfID, err)
		} else {
			log.Printf("[%s] ✅ Successfully handled %s message", selfID, msg.Type)
		}

	case "rpc":
		var rpcData []byte
		if err := json.Unmarshal(msg.Data, &rpcData); err != nil {
			log.Printf("[%s] Failed to unmarshal RPC data: %v", selfID, err)
			return
		}
		respData, err := rpcServer.HandleRequest(rpcData)
		if err != nil {
			log.Printf("[%s] RPC handler error: %v", selfID, err)
		}
		respPayload, err := json.Marshal(respData)
		if err != nil {
			log.Printf("[%s] Failed to marshal RPC response: %v", selfID, err)
			return
		}
		respMsg := security.Message{Type: "rpc", Data: respPayload}
		encodedResp, err := respMsg.Encode()
		if err != nil {
			log.Printf("[%s] Failed to encode RPC response: %v", selfID, err)
			return
		}
		if err := writeFramedMessage(conn, encodedResp); err != nil {
			log.Printf("[%s] Failed to send RPC response: %v", selfID, err)
		}
		return

	default:
		log.Printf("[%s] Unknown message type: %s", selfID, msg.Type)
	}
}
