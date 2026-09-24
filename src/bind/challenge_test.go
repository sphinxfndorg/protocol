// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/challenge_test.go
//
// Tests for challenge-response peer admission: address derivation, proof
// verification + node_id<->key binding, and the key_exchange/peer_exchange
// handler flows (no proof -> no admission, no peer list).
package bind

import (
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	config "github.com/sphinxfndorg/protocol/src/core/sthincs/config"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	security "github.com/sphinxfndorg/protocol/src/handshake"
)

// testSTHINCSParams returns the production SPHINCS+ parameter set for tests.
func testSTHINCSParams(t *testing.T) *parameters.Parameters {
	t.Helper()
	cfg, err := config.NewSTHINCSParameters()
	if err != nil {
		t.Fatalf("NewSTHINCSParameters: %v", err)
	}
	return cfg.Params
}

// newTestSigningService builds a fully functional SigningService (real key
// generation, no evidence DB) for challenge sign/verify tests.
func newTestSigningService(t *testing.T, nodeID string) (*consensus.SigningService, *parameters.Parameters) {
	t.Helper()
	cfg, err := config.NewSTHINCSParameters()
	if err != nil {
		t.Fatalf("NewSTHINCSParameters: %v", err)
	}
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	mgr := sign.NewSTHINCSManager(nil, km, cfg)
	ss := consensus.NewSigningService(mgr, km, nodeID)
	if _, err := ss.GetPublicKey(); err != nil {
		t.Fatalf("test signing service has no public key: %v", err)
	}
	return ss, cfg.Params
}

// rawChallengeSignature builds a SignedMessage exactly the way
// SigningService.SignMessage does (SPHINCS+ over timestamp||nonce||payload)
// but with a raw key pair, so proof verification can be tested without a
// full SigningService.
func rawChallengeSignature(t *testing.T, params *parameters.Parameters, sk *sthincs.SPHINCS_SK, nonce []byte, nodeID, genesis, reward string) []byte {
	t.Helper()
	payload := challengePayload(nonce, nodeID, genesis, reward)
	timestamp := []byte{0, 0, 0, 0, 0, 0, 0, 1}
	sigNonce := make([]byte, 16)
	fullMsg := make([]byte, 0, len(timestamp)+len(sigNonce)+len(payload))
	fullMsg = append(fullMsg, timestamp...)
	fullMsg = append(fullMsg, sigNonce...)
	fullMsg = append(fullMsg, payload...)

	sig, err := sthincs.Spx_sign(params, fullMsg, sk)
	if err != nil {
		t.Fatalf("Spx_sign: %v", err)
	}
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		t.Fatalf("SerializeSignature: %v", err)
	}
	sm := &consensus.SignedMessage{Signature: sigBytes, Timestamp: timestamp, Nonce: sigNonce, Data: payload}
	signed, err := sm.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return signed
}


// TestDerivePeerListenAddr pins the address-derivation rule: the dialable
// address is connection IP + CLAIMED listening port — never the ephemeral
// source port of the inbound connection, and never a host chosen by the peer.
func TestDerivePeerListenAddr(t *testing.T) {
	remote, err := net.ResolveTCPAddr("tcp", "203.0.113.7:54321") // ephemeral source port
	if err != nil {
		t.Fatal(err)
	}

	got, err := derivePeerListenAddr(remote, "203.0.113.7:32307")
	if err != nil {
		t.Fatalf("derivePeerListenAddr: %v", err)
	}
	if got != "203.0.113.7:32307" {
		t.Fatalf("got %q, want 203.0.113.7:32307 (claimed listen port, not source port 54321)", got)
	}

	// The claimed HOST is ignored — only the port is taken from the claim.
	got, err = derivePeerListenAddr(remote, "10.0.0.99:32308")
	if err != nil {
		t.Fatalf("derivePeerListenAddr (spoofed host): %v", err)
	}
	if got != "203.0.113.7:32308" {
		t.Fatalf("claimed host must be ignored, got %q", got)
	}

	if _, err := derivePeerListenAddr(remote, "no-port"); err == nil {
		t.Fatal("expected error for a claim without a port")
	}
	if _, err := derivePeerListenAddr(remote, "x:99999"); err == nil {
		t.Fatal("expected error for an out-of-range claimed port")
	}
	if _, err := derivePeerListenAddr(nil, "x:1"); err == nil {
		t.Fatal("expected error for a nil remote address")
	}
}

// TestChallengeProofRoundTripAndBinding exercises verifyAndRegisterPeerKey
// with real SPHINCS+ signatures: accept a valid proof, register the key,
// then reject tampered/replayed/mismatched claims and enforce node_id<->key
// binding.
func TestChallengeProofRoundTripAndBinding(t *testing.T) {
	params := testSTHINCSParams(t)
	skA, pkA, err := sthincs.Spx_keygen(params)
	if err != nil {
		t.Fatalf("Spx_keygen: %v", err)
	}
	skB, pkB, err := sthincs.Spx_keygen(params)
	if err != nil {
		t.Fatalf("Spx_keygen: %v", err)
	}
	nonce, err := newChallengeNonce()
	if err != nil {
		t.Fatal(err)
	}
	ss := &consensus.SigningService{}

	// 1. Valid proof verifies and registers the key.
	signed := rawChallengeSignature(t, params, skA, nonce, "Node-A", "genesis-1", "SPIF-reward")
	if err := verifyAndRegisterPeerKey(params, ss, pkA, nonce, "Node-A", "genesis-1", "SPIF-reward", signed); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	if _, ok := ss.GetRegisteredPublicKey("Node-A"); !ok {
		t.Fatal("key not registered after valid proof")
	}

	// 2. The same signature presented under a different node ID fails
	// (the payload is bound to the claimed identity).
	if err := verifyAndRegisterPeerKey(params, ss, pkA, nonce, "Node-B", "genesis-1", "SPIF-reward", signed); err == nil {
		t.Fatal("proof accepted for a different node ID")
	}

	// 3. A signature under a different key fails verification.
	signedB := rawChallengeSignature(t, params, skB, nonce, "Node-C", "genesis-1", "")
	if err := verifyAndRegisterPeerKey(params, ss, pkA, nonce, "Node-C", "genesis-1", "", signedB); err == nil {
		t.Fatal("proof verified under the wrong public key")
	}

	// 4. A different reward-address claim fails (claim covered by signature).
	if err := verifyAndRegisterPeerKey(params, ss, pkA, nonce, "Node-A", "genesis-1", "SPIF-other", signed); err == nil {
		t.Fatal("proof accepted for a different reward-address claim")
	}

	// 5. node_id <-> key binding: once Node-A is pinned to pkA, a valid
	// proof from a DIFFERENT key claiming Node-A must be rejected.
	skBProof := rawChallengeSignature(t, params, skB, nonce, "Node-A", "genesis-1", "SPIF-reward")
	err = verifyAndRegisterPeerKey(params, ss, pkB, nonce, "Node-A", "genesis-1", "SPIF-reward", skBProof)
	if err == nil || !strings.Contains(err.Error(), "already bound to a different public key") {
		t.Fatalf("expected key-binding rejection, got %v", err)
	}

	// 6. Garbage signature bytes are rejected.
	if err := verifyAndRegisterPeerKey(params, ss, pkA, nonce, "Node-D", "genesis-1", "", []byte("garbage")); err == nil {
		t.Fatal("garbage signature accepted")
	}
}

// sendTestFrame marshals payload into a security.Message envelope of the
// given type and writes it as one length-prefixed frame.
func sendTestFrame(t *testing.T, conn net.Conn, msgType string, payload any) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s payload: %v", msgType, err)
	}
	env := security.Message{Type: msgType, Data: data}
	encoded, err := env.Encode()
	if err != nil {
		t.Fatalf("encode %s envelope: %v", msgType, err)
	}
	if err := writeFramedMessage(conn, encoded); err != nil {
		t.Fatalf("send %s frame: %v", msgType, err)
	}
}

// readTestFrame reads one length-prefixed frame and decodes its
// security.Message envelope.
func readTestFrame(t *testing.T, conn net.Conn) security.Message {
	t.Helper()
	return readTestFrameWithin(t, conn, frameReadTimeout)
}

// readTestFrameWithin is readTestFrame with an explicit read deadline. Reads
// that must wait for the handler to COMPUTE a signature — the key_exchange
// reply is signed, so it costs a full Spx_sign (~11s with the production
// parameter set) — need handshakeSignTimeout rather than frameReadTimeout.
func readTestFrameWithin(t *testing.T, conn net.Conn, timeout time.Duration) security.Message {
	t.Helper()
	raw, err := readFramedMessageWithTimeout(conn, timeout)
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	var msg security.Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("decode frame envelope: %v", err)
	}
	return msg
}

// requireChallenge reads the next frame, asserts it is the receiver-chosen
// auth_challenge and returns its nonce.
func requireChallenge(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	msg := readTestFrame(t, conn)
	if msg.Type != "auth_challenge" {
		t.Fatalf("expected auth_challenge before admission, got %q", msg.Type)
	}
	var ch authChallengeMsg
	if err := json.Unmarshal(msg.Data, &ch); err != nil {
		t.Fatalf("decode auth_challenge: %v", err)
	}
	if len(ch.Nonce) != challengeNonceLen {
		t.Fatalf("challenge nonce len = %d, want %d", len(ch.Nonce), challengeNonceLen)
	}
	return ch.Nonce
}

// expectNoFrame asserts the handler writes nothing within d: no reply (the
// key_exchange result or the peer list) may be sent before the proof arrives.
// net.Pipe is synchronous, so a premature reply is observed here rather than
// silently buffered.
func expectNoFrame(t *testing.T, conn net.Conn, d time.Duration) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	var lenBuf [4]byte
	if _, err := conn.Read(lenBuf[:]); err == nil {
		t.Fatal("handler sent a reply before receiving a challenge proof")
	}
}

// TestChallengeHandlerFlowsGateAdmission drives the real key_exchange /
// peer_exchange handler (handleIncomingConn) over an in-memory pipe. The
// handler MUST issue an auth_challenge first, and until a valid auth_proof
// answers it, no admission side effect fires and no reply — neither the
// key_exchange result nor the peer list — is written. A valid proof
// (control) completes the handshake and registers the peer key.
func TestChallengeHandlerFlowsGateAdmission(t *testing.T) {
	params := testSTHINCSParams(t)
	genesis := core.GetGenesisHash()
	sk, pk, err := sthincs.Spx_keygen(params)
	if err != nil {
		t.Fatalf("Spx_keygen: %v", err)
	}
	pkBytes, err := pk.SerializePK()
	if err != nil {
		t.Fatalf("SerializePK: %v", err)
	}

	t.Run("key_exchange without proof grants nothing", func(t *testing.T) {
		server, client := net.Pipe()
		defer client.Close()

		var mu sync.Mutex
		discovered, stakeClaim := false, false
		ss := &consensus.SigningService{}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			handleIncomingConn(
				server, "self", "127.0.0.1:1", "", ss, params,
				nil, nil, nil, nil, nil,
				func(string, string) { mu.Lock(); discovered = true; mu.Unlock() },
				func(string, string) { mu.Lock(); stakeClaim = true; mu.Unlock() },
			)
		}()

		sendTestFrame(t, client, "key_exchange", peerKeyExchangeMsg{
			NodeID:        "attacker",
			PublicKey:     pkBytes,
			RewardAddress: "SPIF-reward",
			GenesisHash:   genesis,
			Address:       "203.0.113.9:32307",
		})
		requireChallenge(t, client)

		// No proof is ever sent: the handler must not reply at all.
		expectNoFrame(t, client, 500*time.Millisecond)

		_ = client.Close() // unblock the handler's proof read
		<-done

		if _, ok := ss.GetRegisteredPublicKey("attacker"); ok {
			t.Fatal("public key registered despite missing challenge proof")
		}
		mu.Lock()
		d, s := discovered, stakeClaim
		mu.Unlock()
		if d || s {
			t.Fatalf("admission side effects fired without a proof: discovered=%v stakeClaim=%v", d, s)
		}
	})

	t.Run("peer_exchange without proof withholds peer list", func(t *testing.T) {
		server, client := net.Pipe()
		defer client.Close()

		var mu sync.Mutex
		discovered := false
		peerListCalls := 0
		ss := &consensus.SigningService{}
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			handleIncomingConn(
				server, "self", "127.0.0.1:1", "", ss, params,
				nil, nil, nil, nil,
				func() []knownPeerInfo {
					mu.Lock()
					defer mu.Unlock()
					peerListCalls++
					return []knownPeerInfo{{NodeID: "known", Address: "198.51.100.4:32307"}}
				},
				func(string, string) { mu.Lock(); discovered = true; mu.Unlock() },
				nil,
			)
		}()

		sendTestFrame(t, client, "peer_exchange", peerExchangeMsg{
			NodeID:      "attacker",
			Address:     "203.0.113.9:32307",
			PublicKey:   pkBytes,
			GenesisHash: genesis,
		})
		requireChallenge(t, client)

		// Without a proof the peer list must be withheld entirely.
		expectNoFrame(t, client, 500*time.Millisecond)

		_ = client.Close() // unblock the handler's proof read
		<-done

		mu.Lock()
		calls, d := peerListCalls, discovered
		mu.Unlock()
		if calls != 0 {
			t.Fatalf("getKnownPeers called %d time(s) before proof verification", calls)
		}
		if d {
			t.Fatal("peer discovered before proof verification")
		}
		if _, ok := ss.GetRegisteredPublicKey("attacker"); ok {
			t.Fatal("public key registered despite missing challenge proof")
		}
	})

	t.Run("key_exchange with valid proof is admitted", func(t *testing.T) {
		server, client := net.Pipe()
		defer client.Close()

		ss, _ := newTestSigningService(t, "self")
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer server.Close()
			handleIncomingConn(
				server, "self", "127.0.0.1:1", "SPIF-self", ss, params,
				nil, nil, nil, nil, nil, nil, nil,
			)
		}()

		sendTestFrame(t, client, "key_exchange", peerKeyExchangeMsg{
			NodeID:        "attacker",
			PublicKey:     pkBytes,
			RewardAddress: "SPIF-reward",
			GenesisHash:   genesis,
			Address:       "203.0.113.9:32307",
		})
		nonce := requireChallenge(t, client)

		proof := rawChallengeSignature(t, params, sk, nonce, "attacker", genesis, "SPIF-reward")
		sendTestFrame(t, client, "auth_proof", authProofMsg{Signature: proof})

		// The reply write blocks on the pipe until we read it, so read
		// before waiting for the handler to finish. The handler signs this
		// reply (signChallenge), so allow for its signature computation time.
		reply := readTestFrameWithin(t, client, handshakeSignTimeout)
		if reply.Type != "key_exchange" {
			t.Fatalf("expected key_exchange reply after valid proof, got %q", reply.Type)
		}
		var kx peerKeyExchangeMsg
		if err := json.Unmarshal(reply.Data, &kx); err != nil {
			t.Fatalf("decode key_exchange reply: %v", err)
		}
		if kx.NodeID != "self" {
			t.Fatalf("reply node_id = %q, want %q", kx.NodeID, "self")
		}
		<-done

		if _, ok := ss.GetRegisteredPublicKey("attacker"); !ok {
			t.Fatal("valid proof did not register the peer key")
		}
	})
}

