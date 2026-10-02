// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/p2p.go
//
// ★ REMOVED (Phase 1, step 5): startP2PServer(name, *p2p.Server, ...) used
// to spin up one p2p.Server per node for the legacy same-box harness. It
// went with bind/legacy.go: production StartNode binds its own listeners in
// SECTION 11 (net.Listen for P2P gossip, transport.NewTCPServer for
// wallet/JSON-RPC) and releases them through nodeShutdown, so nothing
// called it any more.
package bind

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/sphinxfndorg/protocol/src/consensus"
	logger "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/core"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	security "github.com/sphinxfndorg/protocol/src/handshake"
)

// requestPeerListSync asks a single peer "who else do you know about?".
//
// The request is challenge-response authenticated: the responder only
// returns its peer list after our signature over the responder-chosen nonce
// (covering our node ID, genesis hash and empty reward field) verifies
// under the public key we present. A responder that will not challenge us
// is treated as unauthenticated and its reply is refused.
func requestPeerListSync(peerAddr string, selfNodeID string, selfAddr string, ownGenesisHash string, signingService *consensus.SigningService) (*peerExchangeMsg, error) {
	ownPK, err := signingService.GetPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get own public key: %v", err)
	}
	request := peerExchangeMsg{
		NodeID:      selfNodeID,
		Address:     selfAddr,
		PublicKey:   ownPK,
		GenesisHash: ownGenesisHash,
	}
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal peer exchange request: %v", err)
	}

	conn, err := net.DialTimeout("tcp", peerAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %v", err)
	}
	defer conn.Close()

	msg := security.Message{Type: "peer_exchange", Data: requestBytes}
	encodedMsg, err := msg.Encode()
	if err != nil {
		return nil, fmt.Errorf("encode failed: %v", err)
	}
	if err := writeFramedMessage(conn, encodedMsg); err != nil {
		return nil, fmt.Errorf("send failed: %v", err)
	}

	// Step 1: expect the responder's challenge before any peer list.
	replyData, err := readFramedMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("receive failed: %v", err)
	}
	var challenge security.Message
	if err := json.Unmarshal(replyData, &challenge); err != nil {
		return nil, fmt.Errorf("decode failed: %v", err)
	}
	if challenge.Type != "auth_challenge" {
		return nil, fmt.Errorf("peer %s did not challenge the peer exchange request (got %q)", peerAddr, challenge.Type)
	}
	var ch authChallengeMsg
	if err := json.Unmarshal(challenge.Data, &ch); err != nil {
		return nil, fmt.Errorf("decode challenge failed: %v", err)
	}
	if len(ch.Nonce) != challengeNonceLen {
		return nil, fmt.Errorf("peer %s sent an invalid challenge nonce (len=%d)", peerAddr, len(ch.Nonce))
	}

	// Step 2: prove key possession over the challenge.
	proof, err := signChallenge(signingService, ch.Nonce, selfNodeID, ownGenesisHash, "")
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

	// Step 3: read the peer list reply. The responder only had to VERIFY our
	// proof (milliseconds) before replying — unlike key_exchange, the peer
	// list is not signed — so the ordinary frame deadline is enough here.
	replyData, err = readFramedMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("receive failed: %v", err)
	}
	var reply security.Message
	if err := json.Unmarshal(replyData, &reply); err != nil {
		return nil, fmt.Errorf("decode failed: %v", err)
	}
	if reply.Type != "peer_exchange" {
		return nil, fmt.Errorf("unexpected reply type: %s", reply.Type)
	}

	var pex peerExchangeMsg
	if err := json.Unmarshal(reply.Data, &pex); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %v", err)
	}
	return &pex, nil
}

// discoverAndRegisterPeers bootstraps this node into the network starting
// from a small list of seed addresses.
//
// onPeerDiscovered registers a peer for gossip/relay purposes only — it
// never grants validator status. onPeerStakeClaim handles authenticated
// reward-address metadata only; stake transactions and genesis chain state
// are the sole sources of validator membership.
//
// progress: dashboard to update peer discovery progress.
func discoverAndRegisterPeers(
	seedAddrs []string,
	selfNodeID string,
	selfAddr string,
	ownRewardAddress string,
	signingService *consensus.SigningService,
	sthincsParams *parameters.Parameters,
	maxHops int,
	onPeerDiscovered func(nodeID, address string),
	onPeerStakeClaim func(nodeID, rewardAddress string),
	progress *logger.BlockchainProgress, // NEW
) {
	if len(seedAddrs) == 0 {
		logger.Info("discoverAndRegisterPeers: no seeds configured, skipping discovery")
		return
	}
	if maxHops <= 0 {
		maxHops = 2
	}

	// Start the peer discovery spinner
	progress.StartPeerDiscovery()

	visited := map[string]bool{selfAddr: true}
	frontier := make([]string, 0, len(seedAddrs))
	for _, addr := range seedAddrs {
		if addr != "" && !visited[addr] {
			frontier = append(frontier, addr)
		}
	}

	totalFound := 0
	totalConnected := 0

	for hop := 0; hop < maxHops && len(frontier) > 0; hop++ {
		logger.Info("discoverAndRegisterPeers: hop %d/%d, dialing %d address(es)", hop+1, maxHops, len(frontier))
		next := make([]string, 0)

		for _, addr := range frontier {
			if visited[addr] {
				continue
			}
			visited[addr] = true

			kx, err := exchangeKeyWithPeerSync(addr, selfAddr, selfNodeID, ownRewardAddress, core.GetGenesisHash(), signingService, sthincsParams)
			if err != nil {
				logger.Warn("discoverAndRegisterPeers: key exchange with %s failed: %v", addr, err)
				continue
			}
			// The key exchange is challenge-response authenticated, so the
			// identity that answered at addr is proven — register it in the
			// address book now (p2p dial-back admission is scheduled there).
			onPeerDiscovered(kx.NodeID, addr)
			if kx.RewardAddress != "" && onPeerStakeClaim != nil {
				onPeerStakeClaim(kx.NodeID, kx.RewardAddress)
			}

			pex, err := requestPeerListSync(addr, selfNodeID, selfAddr, core.GetGenesisHash(), signingService)
			if err != nil {
				logger.Warn("discoverAndRegisterPeers: peer exchange with %s failed: %v", addr, err)
				totalFound++
				totalConnected++
				progress.UpdatePeerDiscovery(totalFound, totalConnected)
				continue
			}

			if pex.NodeID != "" {
				if pex.NodeID != kx.NodeID {
					logger.Warn("discoverAndRegisterPeers: peer at %s claimed %s in PEX but %s in key exchange — PEX identity ignored", addr, pex.NodeID, kx.NodeID)
				}
				totalFound++
				totalConnected++
				progress.UpdatePeerDiscovery(totalFound, totalConnected)
			}

			for _, p := range pex.Peers {
				if p.Address == "" || visited[p.Address] {
					continue
				}
				next = append(next, p.Address)
				// We don't count these as connected yet, just discovered
				// But we increment totalFound for discovered peers
				totalFound++
				progress.UpdatePeerDiscovery(totalFound, totalConnected)
			}
		}

		frontier = next
	}

	progress.CompletePeerDiscovery(totalConnected)
	logger.Info("discoverAndRegisterPeers: discovery complete, contacted %d address(es) total", len(visited)-1)
}
