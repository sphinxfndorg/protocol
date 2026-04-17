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

// go/src/cli/utils/kex.go
package utils

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/sphinxorg/protocol/src/consensus"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/sthincs"
	security "github.com/sphinxorg/protocol/src/handshake"
	logger "github.com/sphinxorg/protocol/src/log"
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
