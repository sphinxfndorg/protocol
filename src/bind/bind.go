// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/bind.go
package bind

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/core"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	"github.com/sphinxfndorg/protocol/src/network"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/transport"
)

// BindTCPServers binds TCP servers for the given node configurations.
func BindTCPServers(configs []NodeConfig, wg *sync.WaitGroup) error {
	for _, config := range configs {
		if config.Address == "" || config.Name == "" || config.MessageCh == nil || config.RPCServer == nil || config.ReadyCh == nil {
			logger.Error("Invalid configuration for %s: missing required fields", config.Name)
			return fmt.Errorf("invalid configuration for %s: missing required fields", config.Name)
		}

		// Create and start TCP server
		tcpServer := transport.NewTCPServer(config.Address, config.MessageCh, config.RPCServer, config.ReadyCh)
		wg.Add(1)
		go func(name, addr string, server *transport.TCPServer) {
			defer wg.Done()
			logger.Info("Starting TCP server for %s on %s", name, addr)
			if err := server.Start(); err != nil {
				logger.Error("TCP server failed for %s: %v", name, err)
			} else {
				logger.Info("TCP server for %s successfully started", name)
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
		logger.Warn("[%s] Failed to read message: %v", selfID, err)
		return
	}

	var msg security.Message
	if err := json.Unmarshal(msgData, &msg); err != nil {
		logger.Warn("[%s] Failed to decode message: %v", selfID, err)
		return
	}

	logger.Debug("[%s] Received message type: %s", selfID, msg.Type)

	switch msg.Type {
	case "key_exchange":
		var kx peerKeyExchangeMsg
		if err := json.Unmarshal(msg.Data, &kx); err != nil {
			logger.Warn("[%s] Failed to unmarshal key exchange: %v", selfID, err)
			return
		}

		pk, err := sthincs.DeserializePK(sthincsParams, kx.PublicKey)
		if err != nil {
			logger.Warn("[%s] Failed to deserialize public key: %v", selfID, err)
			return
		}
		signingService.RegisterPublicKey(kx.NodeID, pk)
		logger.Info("[%s] Registered public key from %s", selfID, kx.NodeID)

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
			logger.Error("[%s] Failed to get own public key: %v", selfID, err)
			return
		}
		reply := peerKeyExchangeMsg{NodeID: selfID, PublicKey: ownPKBytes, RewardAddress: ownRewardAddress}
		replyBytes, _ := json.Marshal(reply)
		replyMsg := security.Message{Type: "key_exchange", Data: replyBytes}
		encodedReply, _ := replyMsg.Encode()
		if err := writeFramedMessage(conn, encodedReply); err != nil {
			logger.Warn("[%s] Failed to send key exchange reply: %v", selfID, err)
		}

	case "peer_exchange":
		var req peerExchangeMsg
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			logger.Warn("[%s] Failed to unmarshal peer exchange request: %v", selfID, err)
			return
		}

		if onPeerDiscovered != nil && req.NodeID != "" && req.Address != "" {
			onPeerDiscovered(req.NodeID, req.Address)
		}

		var knownPeers []knownPeerInfo
		if getKnownPeers != nil {
			knownPeers = getKnownPeers()
		}

		logger.Info("[%s] Peer exchange request from %s (%s) — sharing %d known peer(s)",
			selfID, req.NodeID, req.Address, len(knownPeers))

		reply := peerExchangeMsg{NodeID: selfID, Address: selfAddr, Peers: knownPeers}
		replyBytes, err := json.Marshal(reply)
		if err != nil {
			logger.Warn("[%s] Failed to marshal peer exchange reply: %v", selfID, err)
			return
		}
		replyMsg := security.Message{Type: "peer_exchange", Data: replyBytes}
		encodedReply, err := replyMsg.Encode()
		if err != nil {
			logger.Warn("[%s] Failed to encode peer exchange reply: %v", selfID, err)
			return
		}
		if err := writeFramedMessage(conn, encodedReply); err != nil {
			logger.Warn("[%s] Failed to send peer exchange reply: %v", selfID, err)
		}

	case "checkpoint":
		var cp consensus.CheckpointMessage
		if err := json.Unmarshal(msg.Data, &cp); err != nil {
			logger.Warn("[%s] Failed to unmarshal checkpoint: %v", selfID, err)
			return
		}

		logger.Info("[%s] Received checkpoint from peer: height=%d, phase=%s, supply=%s SPX",
			selfID, cp.TipHeight, cp.Phase, cp.MintedSPX)

		if cons != nil {
			if err := cons.HandleCheckpointMessage(msg.Data, ""); err != nil {
				logger.Warn("[%s] Failed to handle checkpoint: %v", selfID, err)
			}
		}

	case "get_blocks":
		var req GetBlocksRequest
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			logger.Warn("[%s] Failed to unmarshal get_blocks request: %v", selfID, err)
			return
		}

		// Validate request bounds
		if req.FromHeight > req.ToHeight || req.ToHeight-req.FromHeight > 500 {
			logger.Warn("[%s] Invalid get_blocks range: %d -> %d", selfID, req.FromHeight, req.ToHeight)
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
		chainReady := false
		if latest := bc.GetLatestBlock(); latest != nil {
			tipHeight = latest.GetHeight()
			chainReady = true
		}

		resp := GetBlocksResponse{
			Blocks:     blocks,
			TipHeight:  tipHeight,
			ChainReady: chainReady,
		}
		respBytes, _ := json.Marshal(resp)
		respMsg := security.Message{Type: "get_blocks", Data: respBytes}
		encodedResp, _ := respMsg.Encode()
		if err := writeFramedMessage(conn, encodedResp); err != nil {
			logger.Warn("[%s] Failed to send get_blocks response: %v", selfID, err)
		}
		logger.Debug("[%s] Served %d blocks (heights %d-%d) to peer", selfID, len(blocks), req.FromHeight, req.ToHeight)

	case "proposal", "prepare", "vote", "timeout", "randao_sync", "sync_request", "sync_response":
		if p2pMgr == nil {
			logger.Warn("[%s] P2P manager is nil, cannot handle consensus message", selfID)
			return
		}

		logger.Debug("[%s] Processing consensus message type=%s", selfID, msg.Type)

		if err := p2pMgr.HandleIncomingMessage(msg.Type, msg.Data, ""); err != nil {
			logger.Warn("[%s] consensus handling error: %v", selfID, err)
		} else {
			logger.Debug("[%s] Successfully handled %s message", selfID, msg.Type)
		}

	case "rpc":
		var rpcData []byte
		if err := json.Unmarshal(msg.Data, &rpcData); err != nil {
			logger.Warn("[%s] Failed to unmarshal RPC data: %v", selfID, err)
			return
		}
		respData, err := rpcServer.HandleRequest(rpcData)
		if err != nil {
			logger.Warn("[%s] RPC handler error: %v", selfID, err)
		}
		respPayload, err := json.Marshal(respData)
		if err != nil {
			logger.Warn("[%s] Failed to marshal RPC response: %v", selfID, err)
			return
		}
		respMsg := security.Message{Type: "rpc", Data: respPayload}
		encodedResp, err := respMsg.Encode()
		if err != nil {
			logger.Warn("[%s] Failed to encode RPC response: %v", selfID, err)
			return
		}
		if err := writeFramedMessage(conn, encodedResp); err != nil {
			logger.Warn("[%s] Failed to send RPC response: %v", selfID, err)
		}
		return

	default:
		logger.Warn("[%s] Unknown message type: %s", selfID, msg.Type)
	}
}
