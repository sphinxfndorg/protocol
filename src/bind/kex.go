package bind

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	security "github.com/sphinxfndorg/protocol/src/handshake"
)

// ============================================================================
// Key exchange
// ============================================================================

// exchangeKeyWithPeerSync performs synchronous key exchange with a single peer.
// It returns the peer's full handshake payload (including their claimed
// RewardAddress) so the caller can decide separately whether to admit them
// as a validator — key exchange itself never grants stake.
//
// Genesis hash verification: If the peer's genesis hash differs from ours,
// the connection is rejected with an error. This prevents accidental network
// splits when nodes bootstrap from different genesis configurations.
func exchangeKeyWithPeerSync(peerAddr string, nodeID string, ownRewardAddress string, ownGenesisHash string, signingService *consensus.SigningService, sthincsParams *parameters.Parameters) (*peerKeyExchangeMsg, error) {
	ownPKBytes, err := signingService.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get own public key: %v", err)
	}

	payload := peerKeyExchangeMsg{
		NodeID:        nodeID,
		PublicKey:     ownPKBytes,
		RewardAddress: ownRewardAddress,
		GenesisHash:   ownGenesisHash,
	}
	payloadBytes, _ := json.Marshal(payload)

	conn, err := net.DialTimeout("tcp", peerAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	msg := security.Message{Type: "key_exchange", Data: payloadBytes}
	encodedMsg, err := msg.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode failed: %v", err)
	}
	if err := writeFramedMessage(conn, encodedMsg); err != nil {
		return nil, fmt.Errorf("send failed: %v", err)
	}

	replyData, err := readFramedMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("receive failed: %v", err)
	}
	var reply security.Message
	if err := json.Unmarshal(replyData, &reply); err != nil {
		return nil, fmt.Errorf("decode failed: %v", err)
	}

	if reply.Type != "key_exchange" {
		return nil, fmt.Errorf("unexpected reply type: %s", reply.Type)
	}

	var kx peerKeyExchangeMsg
	if err := json.Unmarshal(reply.Data, &kx); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %v", err)
	}

	// ════════════════════════════════════════════════════════════════════
	// GENESIS HASH VERIFICATION
	// ════════════════════════════════════════════════════════════════════
	// If the peer advertises a genesis hash and it differs from ours, the
	// peer is on a fundamentally incompatible chain. Reject the connection
	// immediately — a peer with a different genesis must never be admitted
	// to the gossip graph or validator set.
	if kx.GenesisHash != "" && ownGenesisHash != "" && kx.GenesisHash != ownGenesisHash {
		return nil, fmt.Errorf(
			"genesis hash mismatch with peer %s at %s: peer=%s, local=%s — "+
				"peer is on a different chain, connection rejected",
			kx.NodeID, peerAddr, kx.GenesisHash, ownGenesisHash,
		)
	}
	// ════════════════════════════════════════════════════════════════════

	pk, err := sthincs.DeserializePK(sthincsParams, kx.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("deserialize failed: %v", err)
	}

	signingService.RegisterPublicKey(kx.NodeID, pk)
	logger.Info("Key exchange complete with %s (genesis=%s)", kx.NodeID, kx.GenesisHash)
	return &kx, nil
}
