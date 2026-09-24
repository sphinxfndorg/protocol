// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/challenge.go
//
// Challenge-response peer admission for the P2P TCP protocol.
//
// The wire format already allows this entirely inside src/bind: every frame
// is a length-prefixed security.Message {type, data} JSON envelope over a
// plain TCP connection, and BOTH endpoints of the key_exchange /
// peer_exchange dialogues live in this package (handleIncomingConn in
// bind.go as receiver, exchangeKeyWithPeerSync in kex.go and
// requestPeerListSync in p2p.go as sender). Adding two message types
// ("auth_challenge", "auth_proof") and two JSON fields (Address, Signature)
// is additive — no changes to src/handshake or src/network are needed, and
// every other message type (get_blocks, consensus broadcasts, ...) keeps its
// read-request-then-reply shape because challenges are only issued inside
// the key_exchange and peer_exchange cases.
//
// Protocol:
//
//	sender   -> receiver : key_exchange / peer_exchange request
//	receiver -> sender   : auth_challenge { nonce }   (receiver-chosen)
//	sender   -> receiver : auth_proof { signature }   over challengePayload
//	receiver             : verify signature under the claimed public key,
//	                       enforce node_id <-> key binding, THEN
//	                       RegisterPublicKey and any admission side effect,
//	                       THEN reply.
package bind

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	security "github.com/sphinxfndorg/protocol/src/handshake"
)

// challengeNonceLen is the size in bytes of the receiver-chosen nonce.
const challengeNonceLen = 32

// newChallengeNonce returns a fresh cryptographically random nonce for an
// admission challenge.
func newChallengeNonce() ([]byte, error) {
	nonce := make([]byte, challengeNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate challenge nonce: %w", err)
	}
	return nonce, nil
}

// challengePayload builds the exact bytes an admission sender must sign:
//
//	nonce || node_id || genesis_hash || reward_address
//
// each component length-prefixed with a 4-byte big-endian length so the
// fields cannot be confused with one another (a bare concatenation would let
// an attacker move bytes between fields). The reward address is always
// included — even when empty — so the payload is fully determined by values
// the verifier already knows, and a claim of a reward address is therefore
// always covered by the same signature that authenticates the node identity.
func challengePayload(nonce []byte, nodeID, genesisHash, rewardAddress string) []byte {
	appendLP := func(dst []byte, b []byte) []byte {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(b)))
		dst = append(dst, l[:]...)
		return append(dst, b...)
	}
	payload := make([]byte, 0, len(nonce)+len(nodeID)+len(genesisHash)+len(rewardAddress)+16)
	payload = appendLP(payload, nonce)
	payload = appendLP(payload, []byte(nodeID))
	payload = appendLP(payload, []byte(genesisHash))
	payload = appendLP(payload, []byte(rewardAddress))
	return payload
}

// sendAuthChallenge sends an auth_challenge frame with the given nonce.
func sendAuthChallenge(conn net.Conn, nonce []byte) error {
	data, err := json.Marshal(authChallengeMsg{Nonce: nonce})
	if err != nil {
		return fmt.Errorf("marshal challenge: %w", err)
	}
	msg := security.Message{Type: "auth_challenge", Data: data}
	encoded, err := msg.Encode()
	if err != nil {
		return fmt.Errorf("encode challenge: %w", err)
	}
	if err := writeFramedMessage(conn, encoded); err != nil {
		return fmt.Errorf("send challenge: %w", err)
	}
	return nil
}


// readAuthProof reads the auth_proof frame that must answer a challenge and
// returns the carried signature.
func readAuthProof(conn net.Conn) ([]byte, error) {
	proofData, err := readFramedMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("read proof: %w", err)
	}
	var msg security.Message
	if err := json.Unmarshal(proofData, &msg); err != nil {
		return nil, fmt.Errorf("decode proof envelope: %w", err)
	}
	if msg.Type != "auth_proof" {
		return nil, fmt.Errorf("expected auth_proof, got %q", msg.Type)
	}
	var proof authProofMsg
	if err := json.Unmarshal(msg.Data, &proof); err != nil {
		return nil, fmt.Errorf("decode proof: %w", err)
	}
	if len(proof.Signature) == 0 {
		return nil, fmt.Errorf("empty challenge signature")
	}
	return proof.Signature, nil
}

// signChallenge produces the auth_proof signature for the local node:
// SignMessage(challengePayload(nonce, nodeID, genesisHash, rewardAddress)).
func signChallenge(signingService *consensus.SigningService, nonce []byte, nodeID, genesisHash, rewardAddress string) ([]byte, error) {
	if signingService == nil {
		return nil, fmt.Errorf("signing service unavailable")
	}
	payload := challengePayload(nonce, nodeID, genesisHash, rewardAddress)
	sig, err := signingService.SignMessage(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign challenge: %w", err)
	}
	if len(sig) == 0 {
		return nil, fmt.Errorf("empty challenge signature")
	}
	return sig, nil
}

// verifyAndRegisterPeerKey verifies a challenge proof and, only on success,
// enforces node_id <-> key binding and registers the key. It is the single
// gate in front of RegisterPublicKey for remote peers:
//
//  1. The signed payload must be exactly challengePayload(nonce, nodeID,
//     genesisHash, rewardAddress) — so the signature covers the claimed
//     identity, the chain, and any claimed reward address, and the nonce
//     makes it fresh for this connection.
//  2. The SPHINCS+ signature must verify under pk (proof of key possession).
//  3. node_id <-> key binding: if nodeID is already bound to a different key
//     (first-verified binding, pinned in the SigningService registry — our
//     own node's key is pinned at startup), the claim is rejected. For a new
//     identity the signed payload itself commits the key to the node_id,
//     and this call pins it for every later handshake.
func verifyAndRegisterPeerKey(
	sthincsParams *parameters.Parameters,
	signingService *consensus.SigningService,
	pk *sthincs.SPHINCS_PK,
	nonce []byte,
	nodeID string,
	genesisHash string,
	rewardAddress string,
	signedData []byte,
) error {
	if sthincsParams == nil {
		return fmt.Errorf("STHINCS parameters unavailable")
	}
	if signingService == nil {
		return fmt.Errorf("signing service unavailable")
	}
	if pk == nil {
		return fmt.Errorf("missing public key")
	}
	if nodeID == "" {
		return fmt.Errorf("missing node ID")
	}
	if len(nonce) != challengeNonceLen {
		return fmt.Errorf("invalid challenge nonce length %d", len(nonce))
	}
	if len(signedData) == 0 {
		return fmt.Errorf("missing challenge signature from %s", nodeID)
	}

	signedMsg, err := consensus.DeserializeSignedMessage(signedData)
	if err != nil {
		return fmt.Errorf("malformed challenge signature from %s: %w", nodeID, err)
	}

	payload := challengePayload(nonce, nodeID, genesisHash, rewardAddress)
	if !bytes.Equal(signedMsg.Data, payload) {
		return fmt.Errorf("challenge proof from %s does not cover the claimed node_id/genesis/reward address", nodeID)
	}

	// Mirror SigningService.VerifySignature: the SPHINCS+ signature is over
	// timestamp || nonce || payload (see sthincs SignMessage).
	fullMsg := make([]byte, 0, len(signedMsg.Timestamp)+len(signedMsg.Nonce)+len(signedMsg.Data))
	fullMsg = append(fullMsg, signedMsg.Timestamp...)
	fullMsg = append(fullMsg, signedMsg.Nonce...)
	fullMsg = append(fullMsg, signedMsg.Data...)

	sig, err := sthincs.DeserializeSignature(sthincsParams, signedMsg.Signature)
	if err != nil {
		return fmt.Errorf("cannot deserialize challenge signature from %s: %w", nodeID, err)
	}
	if !sthincs.Spx_verify(sthincsParams, fullMsg, sig, pk) {
		return fmt.Errorf("SPHINCS+ challenge verification failed for %s — no proof of key possession", nodeID)
	}

	// node_id <-> key binding: first verified handshake pins the identity.
	if bound, ok := signingService.GetRegisteredPublicKey(nodeID); ok {
		same, err := samePublicKey(bound, pk)
		if err != nil {
			return fmt.Errorf("cannot compare bound key for %s: %w", nodeID, err)
		}
		if !same {
			return fmt.Errorf("node %s is already bound to a different public key — identity mismatch", nodeID)
		}
	}

	signingService.RegisterPublicKey(nodeID, pk)
	return nil
}

// samePublicKey reports whether two SPHINCS+ public keys are identical.
func samePublicKey(a, b *sthincs.SPHINCS_PK) (bool, error) {
	if a == nil || b == nil {
		return false, fmt.Errorf("nil public key")
	}
	ab, err := a.SerializePK()
	if err != nil {
		return false, err
	}
	bb, err := b.SerializePK()
	if err != nil {
		return false, err
	}
	return bytes.Equal(ab, bb), nil
}

// derivePeerListenAddr computes the dialable address of an inbound peer:
//
//	IP   = source IP of the accepted TCP connection (never attacker-chosen)
//	port = port of the listening address the peer claims in its message
//
// The connection's SOURCE port is ephemeral and is deliberately NOT used —
// recording it would make the peer undialable and, on a same-box devnet
// where every node is 127.0.0.1, would produce self-dial entries. The
// claimed HOST part is ignored entirely, so the only thing a remote peer can
// influence is the port on its own IP.
func derivePeerListenAddr(remote net.Addr, claimedListenAddr string) (string, error) {
	if remote == nil {
		return "", fmt.Errorf("missing connection remote address")
	}
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil || host == "" {
		return "", fmt.Errorf("cannot derive peer IP from connection endpoint %q: %v", remote.String(), err)
	}
	_, portStr, err := net.SplitHostPort(claimedListenAddr)
	if err != nil || portStr == "" {
		return "", fmt.Errorf("peer did not claim a usable listening address (got %q)", claimedListenAddr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("peer claimed an invalid listening port %q", portStr)
	}
	return net.JoinHostPort(host, portStr), nil
}
