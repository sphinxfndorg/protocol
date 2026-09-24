// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/bind.go
package bind

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
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
		if err := validatePeerGenesisHash(kx.GenesisHash, core.GetGenesisHash()); err != nil {
			logger.Warn("[%s] Rejecting key exchange from %s: %v", selfID, kx.NodeID, err)
			return
		}
		if kx.NodeID == "" {
			logger.Warn("[%s] Rejecting key exchange with empty node ID", selfID)
			return
		}

		pk, err := sthincs.DeserializePK(sthincsParams, kx.PublicKey)
		if err != nil {
			logger.Warn("[%s] Failed to deserialize public key: %v", selfID, err)
			return
		}

		// PROOF OF KEY POSSESSION: issue a receiver-chosen nonce and verify
		// the sender's signature over (nonce || node_id || genesis_hash ||
		// reward_address) BEFORE RegisterPublicKey or any admission side
		// effect. verifyAndRegisterPeerKey also enforces node_id <-> key
		// binding (first verified handshake pins the identity).
		nonce, err := newChallengeNonce()
		if err != nil {
			logger.Warn("[%s] Failed to create admission challenge: %v", selfID, err)
			return
		}
		if err := sendAuthChallenge(conn, nonce); err != nil {
			logger.Warn("[%s] Failed to send admission challenge to %s: %v", selfID, kx.NodeID, err)
			return
		}
		proofSig, err := readAuthProof(conn)
		if err != nil {
			logger.Warn("[%s] Rejecting key exchange from %s: no valid challenge proof: %v", selfID, kx.NodeID, err)
			return
		}
		if err := verifyAndRegisterPeerKey(sthincsParams, signingService, pk, nonce,
			kx.NodeID, kx.GenesisHash, kx.RewardAddress, proofSig); err != nil {
			logger.Warn("[%s] Rejecting key exchange from %s: %v", selfID, kx.NodeID, err)
			return
		}
		logger.Info("[%s] Verified key possession for %s", selfID, kx.NodeID)

		// Dialable address = connection IP + the peer's CLAIMED listening
		// port (never the ephemeral source port of this connection). The
		// address goes into the address book only; p2pMgr admission happens
		// later, after OUR dial-back handshake to this address succeeds
		// (see ensureDialbackAdmitted in nodes.go).
		peerAddr, deriveErr := derivePeerListenAddr(conn.RemoteAddr(), kx.Address)
		if deriveErr != nil {
			logger.Warn("[%s] %s proved its key but has no dialable address (%v) — recording key only", selfID, kx.NodeID, deriveErr)
		} else if onPeerDiscovered != nil {
			onPeerDiscovered(kx.NodeID, peerAddr)
		}

		// A reward address only ever results in a *verified* stake check
		// downstream (see stakeValidatorFromRewardAddress) — and here it is
		// additionally covered by the challenge signature just verified, so
		// the claim is bound to the authenticated node identity. Receiving
		// one never grants validator status by itself.
		if onPeerStakeClaim != nil && kx.RewardAddress != "" && deriveErr == nil {
			onPeerStakeClaim(kx.NodeID, kx.RewardAddress)
		}

		ownPKBytes, err := signingService.GetPublicKey()
		if err != nil {
			logger.Error("[%s] Failed to get own public key: %v", selfID, err)
			return
		}
		// The reply must itself prove OUR key possession, otherwise the
		// dialing side would be registering an unauthenticated key.
		replySig, err := signChallenge(signingService, nonce, selfID, core.GetGenesisHash(), ownRewardAddress)
		if err != nil {
			logger.Error("[%s] Failed to sign key exchange reply: %v", selfID, err)
			return
		}
		reply := peerKeyExchangeMsg{
			NodeID:        selfID,
			PublicKey:     ownPKBytes,
			RewardAddress: ownRewardAddress,
			GenesisHash:   core.GetGenesisHash(),
			Address:       selfAddr,
			Signature:     replySig,
		}
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

		// The peer list is served ONLY after the requester passes the same
		// challenge-response used by key exchange. Nothing — not even the
		// requester's address book entry — happens before the proof
		// verifies.
		if req.NodeID == "" {
			logger.Warn("[%s] Peer exchange request with empty node ID — peer list withheld", selfID)
			return
		}
		if len(req.PublicKey) == 0 {
			logger.Warn("[%s] Peer exchange request from %s carries no public key — peer list withheld", selfID, req.NodeID)
			return
		}
		if err := validatePeerGenesisHash(req.GenesisHash, core.GetGenesisHash()); err != nil {
			logger.Warn("[%s] Rejecting peer exchange from %s: %v", selfID, req.NodeID, err)
			return
		}

		nonce, err := newChallengeNonce()
		if err != nil {
			logger.Warn("[%s] Failed to create PEX challenge: %v", selfID, err)
			return
		}
		if err := sendAuthChallenge(conn, nonce); err != nil {
			logger.Warn("[%s] Failed to send PEX challenge to %s: %v", selfID, req.NodeID, err)
			return
		}
		proofSig, err := readAuthProof(conn)
		if err != nil {
			logger.Warn("[%s] Peer exchange from %s failed challenge — peer list withheld: %v", selfID, req.NodeID, err)
			return
		}
		reqPK, err := sthincs.DeserializePK(sthincsParams, req.PublicKey)
		if err != nil {
			logger.Warn("[%s] Peer exchange from %s has an unusable public key — peer list withheld: %v", selfID, req.NodeID, err)
			return
		}
		// PEX requests carry no reward address, so the signed payload uses
		// the empty reward field (see challengePayload).
		if err := verifyAndRegisterPeerKey(sthincsParams, signingService, reqPK, nonce,
			req.NodeID, req.GenesisHash, "", proofSig); err != nil {
			logger.Warn("[%s] Peer exchange from %s failed challenge — peer list withheld: %v", selfID, req.NodeID, err)
			return
		}

		// Requester authenticated: record its dialable address (connection
		// IP + claimed listening port; address book only — p2pMgr admission
		// still requires OUR dial-back, see ensureDialbackAdmitted).
		if onPeerDiscovered != nil {
			if peerAddr, dErr := derivePeerListenAddr(conn.RemoteAddr(), req.Address); dErr == nil {
				onPeerDiscovered(req.NodeID, peerAddr)
			} else {
				logger.Warn("[%s] Peer %s passed the challenge but has no dialable address: %v", selfID, req.NodeID, dErr)
			}
		}

		var knownPeers []knownPeerInfo
		if getKnownPeers != nil {
			knownPeers = getKnownPeers()
		}
		// Deterministic order and a bounded list size.
		sort.Slice(knownPeers, func(i, j int) bool { return knownPeers[i].NodeID < knownPeers[j].NodeID })
		const maxPeerExchangePeers = 64
		if len(knownPeers) > maxPeerExchangePeers {
			knownPeers = knownPeers[:maxPeerExchangePeers]
		}

		logger.Info("[%s] Peer exchange request from %s passed the challenge — sharing %d known peer(s)",
			selfID, req.NodeID, len(knownPeers))

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

	case "transaction":
		// Gossiped transaction — relayed by sendrawtransaction through the
		// rpc.Server txRelay hook (StartNode's SetTxRelay wiring in
		// nodes.go) and delivered here by p2pMgr.BroadcastMessage. Every
		// validator must add it to its own mempool, or a wallet-submitted
		// tx exists only on the node the wallet connected to and can sit
		// uncommitted forever (the USI "Confirmed: pending" bug).
		var gossipedTx types.Transaction
		if err := json.Unmarshal(msg.Data, &gossipedTx); err != nil {
			logger.Warn("[%s] Failed to unmarshal gossiped transaction: %v", selfID, err)
			return
		}
		if !gossipedTx.IsSystemTransaction() && !gossipedTx.HasFullAuthBundle() {
			logger.Warn("[%s] Gossiped transaction rejected: missing full SPHINCS auth bundle", selfID)
			return
		}
		if err := bc.AddTransaction(&gossipedTx); err != nil {
			logger.Warn("[%s] Failed to add gossiped transaction %s: %v", selfID, gossipedTx.ID, err)
			return
		}
		logger.Info("[%s] Accepted gossiped transaction %s into mempool", selfID, gossipedTx.ID)

	case "proposal", "prepare", "vote", "timeout", "randao_sync", "sync_request", "sync_response",
		"prepare_certificate", "commit_certificate":
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
