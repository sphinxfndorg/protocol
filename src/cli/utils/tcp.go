// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/tcp.go
package utils

import (
	"encoding/json"
	"log"
	"net"

	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	logger "github.com/sphinxfndorg/protocol/src/log"
	"github.com/sphinxfndorg/protocol/src/network"
	rpc "github.com/sphinxfndorg/protocol/src/rpc" // custom RPC package
)

// handleIncomingConn processes a single accepted TCP connection.
func handleIncomingConn(
	conn net.Conn,
	selfID string,
	signingService *consensus.SigningService,
	sthincsParams *parameters.Parameters,
	cons *consensus.Consensus,
	p2pMgr *network.P2PConsensusNodeManager,
	rpcServer *rpc.Server, // use custom type
) {
	var msg security.Message
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&msg); err != nil {
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

		ownPKBytes, err := signingService.GetPublicKey()
		if err != nil {
			log.Printf("[%s] Failed to get own public key: %v", selfID, err)
			return
		}
		reply := peerKeyExchangeMsg{NodeID: selfID, PublicKey: ownPKBytes}
		replyBytes, _ := json.Marshal(reply)
		replyMsg := security.Message{Type: "key_exchange", Data: replyBytes}
		json.NewEncoder(conn).Encode(&replyMsg)

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
		// Unwrap the RPC payload (the client sends it as a JSON-encoded byte string)
		var rpcData []byte
		if err := json.Unmarshal(msg.Data, &rpcData); err != nil {
			log.Printf("[%s] Failed to unmarshal RPC data: %v", selfID, err)
			return
		}
		// Process the RPC request using the custom server's handler
		respData, err := rpcServer.HandleRequest(rpcData)
		if err != nil {
			log.Printf("[%s] RPC handler error: %v", selfID, err)
		}
		// Wrap the response in a security.Message of type "rpc"
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
		// Send response back on the same TCP connection
		if _, err := conn.Write(encodedResp); err != nil {
			log.Printf("[%s] Failed to send RPC response: %v", selfID, err)
		}
		return

	default:
		log.Printf("[%s] Unknown message type: %s", selfID, msg.Type)
	}
}
