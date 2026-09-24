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
// RewardAddress and listening Address) so the caller can decide separately
// whether to admit them as a validator — key exchange itself never grants
// stake.
//
// Authentication: the exchange is challenge-response gated in both
// directions. The peer MUST issue an auth_challenge nonce; we sign
// challengePayload(nonce, nodeID, genesisHash, ownRewardAddress) and send an
// auth_proof before the peer will reply, and the peer's own reply carries
// its signature over the same nonce — verified here against its public key
// BEFORE we register that key. A peer that answers with a plain,
// unchallenged key_exchange reply is refused (it cannot prove possession).
//
// Genesis hash verification: If the peer's genesis hash differs from ours,
// the connection is rejected with an error. This prevents accidental network
// splits when nodes bootstrap from different genesis configurations.
//
// selfAddr is our advertised LISTENING address (sent as Address so the peer
// can derive a dialable address for us); it is never taken from the wire.
func exchangeKeyWithPeerSync(peerAddr string, selfAddr string, nodeID string, ownRewardAddress string, ownGenesisHash string, signingService *consensus.SigningService, sthincsParams *parameters.Parameters) (*peerKeyExchangeMsg, error) {
	ownPKBytes, err := signingService.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get own public key: %v", err)
	}

	payload := peerKeyExchangeMsg{
		NodeID:        nodeID,
		PublicKey:     ownPKBytes,
		RewardAddress: ownRewardAddress,
		GenesisHash:   ownGenesisHash,
		Address:       selfAddr,
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

	// Step 1: the receiver MUST challenge us before it will reply.
	replyData, err := readFramedMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("receive failed: %v", err)
	}
	var challenge security.Message
	if err := json.Unmarshal(replyData, &challenge); err != nil {
		return nil, fmt.Errorf("decode failed: %v", err)
	}
	if challenge.Type != "auth_challenge" {
		return nil, fmt.Errorf("peer %s did not issue an authentication challenge (got %q) — refusing unauthenticated key exchange", peerAddr, challenge.Type)
	}
	var ch authChallengeMsg
	if err := json.Unmarshal(challenge.Data, &ch); err != nil {
		return nil, fmt.Errorf("decode challenge failed: %v", err)
	}
	if len(ch.Nonce) != challengeNonceLen {
		return nil, fmt.Errorf("peer %s sent an invalid challenge nonce (len=%d)", peerAddr, len(ch.Nonce))
	}

	// Step 2: prove possession of our key over (nonce || node_id ||
	// genesis_hash || reward_address) — the reward-address claim included.
	proof, err := signChallenge(signingService, ch.Nonce, nodeID, ownGenesisHash, ownRewardAddress)
	if err != nil {
		return nil, err
	}
	proofBytes, _ := json.Marshal(authProofMsg{Signature: proof})
	proofMsg := security.Message{Type: "auth_proof", Data: proofBytes}
	encodedProof, err := proofMsg.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode proof failed: %v", err)
	}
	if err := writeFramedMessage(conn, encodedProof); err != nil {
		return nil, fmt.Errorf("send proof failed: %v", err)
	}

	// Step 3: read the peer's final reply.
	replyData, err = readFramedMessage(conn)
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
	if err := validatePeerGenesisHash(kx.GenesisHash, ownGenesisHash); err != nil {
		return nil, fmt.Errorf("genesis validation failed for peer %s at %s: %w", kx.NodeID, peerAddr, err)
	}
	// ════════════════════════════════════════════════════════════════════

	if kx.NodeID == "" {
		return nil, fmt.Errorf("peer at %s replied with an empty node ID", peerAddr)
	}

	pk, err := sthincs.DeserializePK(sthincsParams, kx.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("deserialize failed: %v", err)
	}

	// Step 4: verify the peer's proof of key possession (mutual auth) —
	// this registers the peer's key ONLY on success and enforces
	// node_id <-> key binding in both directions.
	if err := verifyAndRegisterPeerKey(sthincsParams, signingService, pk, ch.Nonce,
		kx.NodeID, kx.GenesisHash, kx.RewardAddress, kx.Signature); err != nil {
		return nil, fmt.Errorf("peer %s at %s failed the challenge: %w", kx.NodeID, peerAddr, err)
	}

	logger.Info("Key exchange complete with %s (genesis=%s)", kx.NodeID, kx.GenesisHash)
	return &kx, nil
}

func validatePeerGenesisHash(peerGenesisHash, localGenesisHash string) error {
	if peerGenesisHash == "" {
		return fmt.Errorf("peer did not provide a genesis hash")
	}
	if localGenesisHash == "" {
		return fmt.Errorf("local genesis hash is unavailable")
	}
	if peerGenesisHash != localGenesisHash {
		return fmt.Errorf("genesis hash mismatch: peer=%s, local=%s", peerGenesisHash, localGenesisHash)
	}
	return nil
}
