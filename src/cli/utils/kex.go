// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/kex.go
package utils

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	logger "github.com/sphinxfndorg/protocol/src/log"
)

// exchangeKeyWithPeerSync performs synchronous key exchange with a single peer
func exchangeKeyWithPeerSync(peerAddr string, nodeID string, signingService *consensus.SigningService, sthincsParams *parameters.Parameters) error {
	ownPKBytes, err := signingService.GetPublicKey()
	if err != nil {
		return fmt.Errorf("failed to get own public key: %v", err)
	}

	payload := peerKeyExchangeMsg{NodeID: nodeID, PublicKey: ownPKBytes}
	payloadBytes, _ := json.Marshal(payload)

	conn, err := net.DialTimeout("tcp", peerAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	msg := security.Message{Type: "key_exchange", Data: payloadBytes}
	if err := json.NewEncoder(conn).Encode(&msg); err != nil {
		return fmt.Errorf("send failed: %v", err)
	}

	var reply security.Message
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&reply); err != nil {
		return fmt.Errorf("receive failed: %v", err)
	}

	if reply.Type != "key_exchange" {
		return fmt.Errorf("unexpected reply type: %s", reply.Type)
	}

	var kx peerKeyExchangeMsg
	if err := json.Unmarshal(reply.Data, &kx); err != nil {
		return fmt.Errorf("unmarshal failed: %v", err)
	}

	pk, err := sthincs.DeserializePK(sthincsParams, kx.PublicKey)
	if err != nil {
		return fmt.Errorf("deserialize failed: %v", err)
	}

	signingService.RegisterPublicKey(kx.NodeID, pk)
	logger.Info("✅ Key exchange complete with %s", kx.NodeID)
	return nil
}
