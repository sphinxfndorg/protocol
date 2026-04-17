// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/cli/utils/tcp.go
package utils

import (
	"encoding/json"
	"log"
	"net"

	"github.com/sphinxorg/protocol/src/consensus"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/sthincs"
	security "github.com/sphinxorg/protocol/src/handshake"
	logger "github.com/sphinxorg/protocol/src/log"
	"github.com/sphinxorg/protocol/src/network"
)

// handleIncomingConn processes a single accepted TCP connection.
func handleIncomingConn(
	conn net.Conn,
	selfID string,
	signingService *consensus.SigningService,
	sthincsParams *parameters.Parameters,
	_ *consensus.Consensus,
	p2pMgr *network.P2PConsensusNodeManager,
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

	case "proposal", "prepare", "vote", "timeout", "randao_sync":
		// Handle consensus messages directly
		if p2pMgr == nil {
			log.Printf("[%s] P2P manager is nil, cannot handle consensus message", selfID)
			return
		}

		log.Printf("[%s] 📨 Processing consensus message type=%s", selfID, msg.Type)

		// Pass the message directly to the consensus manager
		if err := p2pMgr.HandleIncomingMessage(msg.Type, msg.Data, ""); err != nil {
			log.Printf("[%s] consensus handling error: %v", selfID, err)
		} else {
			log.Printf("[%s] ✅ Successfully handled %s message", selfID, msg.Type)
		}

	default:
		log.Printf("[%s] Unknown message type: %s", selfID, msg.Type)
	}
}
