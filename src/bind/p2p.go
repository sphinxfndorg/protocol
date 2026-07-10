// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/p2p.go
package bind

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	security "github.com/sphinxfndorg/protocol/src/handshake"
	logger "github.com/sphinxfndorg/protocol/src/log"
	"github.com/sphinxfndorg/protocol/src/p2p"
)

// startP2PServer starts a P2P server for the given node.
func startP2PServer(name string, server *p2p.Server, readyCh chan<- struct{}, errorCh chan<- error, udpReadyCh chan<- struct{}, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("Starting P2P server for %s on %s", name, server.LocalNode().Address)
		startCh := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("Panic in P2P server startup for %s: %v", name, r)
					startCh <- fmt.Errorf("panic: %v", r)
				}
			}()
			logger.Infof("Calling server.Start() for %s", name)
			err := server.Start()
			logger.Infof("server.Start() for %s returned with error: %v", name, err)
			startCh <- err
		}()
		select {
		case err := <-startCh:
			if err != nil {
				logger.Errorf("P2P server failed for %s: %v", name, err)
				// Attempt to close the server on failure
				if closeErr := server.Close(); closeErr != nil {
					logger.Errorf("Failed to close P2P server for %s: %v", name, closeErr)
				}
				if closeErr := server.CloseDB(); closeErr != nil {
					logger.Errorf("Failed to close DB for %s: %v", name, closeErr)
				}
				errorCh <- err
				return
			}
			logger.Infof("P2P server for %s started successfully", name)
			logger.Infof("Sending UDP ready signal for %s", name)
			udpReadyCh <- struct{}{} // Signal UDP listener is ready
			logger.Infof("Sending ready signal for P2P server %s", name)
			readyCh <- struct{}{}
		case <-time.After(10 * time.Second):
			logger.Warnf("P2P server for %s took too long to start, assuming ready", name)
			logger.Infof("Sending UDP ready signal for %s", name)
			udpReadyCh <- struct{}{}
			logger.Infof("Sending ready signal for P2P server %s", name)
			readyCh <- struct{}{}
		}
	}()
}

// requestPeerListSync asks a single peer "who else do you know about?".
func requestPeerListSync(peerAddr string, selfNodeID string, selfAddr string) (*peerExchangeMsg, error) {
	request := peerExchangeMsg{NodeID: selfNodeID, Address: selfAddr}
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

	replyData, err := readFramedMessage(conn)
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
// never grants validator status. onPeerStakeClaim is called separately,
// only when a peer's key-exchange reply includes a non-empty reward
// address; the caller is expected to verify that address's on-chain
// balance before admitting the peer as a validator (see
// stakeValidatorFromRewardAddress). Discovery and validator admission are
// intentionally decoupled: showing up on the wire earns you a spot in the
// gossip graph, never a vote.
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
) {
	if len(seedAddrs) == 0 {
		logger.Info("discoverAndRegisterPeers: no seeds configured, skipping discovery")
		return
	}
	if maxHops <= 0 {
		maxHops = 2
	}

	visited := map[string]bool{selfAddr: true}
	frontier := make([]string, 0, len(seedAddrs))
	for _, addr := range seedAddrs {
		if addr != "" && !visited[addr] {
			frontier = append(frontier, addr)
		}
	}

	for hop := 0; hop < maxHops && len(frontier) > 0; hop++ {
		logger.Info("discoverAndRegisterPeers: hop %d/%d, dialing %d address(es)", hop+1, maxHops, len(frontier))
		next := make([]string, 0)

		for _, addr := range frontier {
			if visited[addr] {
				continue
			}
			visited[addr] = true

			kx, err := exchangeKeyWithPeerSync(addr, selfNodeID, ownRewardAddress, core.GetGenesisHash(), signingService, sthincsParams)
			if err != nil {
				logger.Warn("discoverAndRegisterPeers: key exchange with %s failed: %v", addr, err)
				continue
			}
			if kx.RewardAddress != "" && onPeerStakeClaim != nil {
				onPeerStakeClaim(kx.NodeID, kx.RewardAddress)
			}

			pex, err := requestPeerListSync(addr, selfNodeID, selfAddr)
			if err != nil {
				logger.Warn("discoverAndRegisterPeers: peer exchange with %s failed: %v", addr, err)
				onPeerDiscovered(addrToNodeIDFallback(addr), addr)
				continue
			}

			if pex.NodeID != "" {
				onPeerDiscovered(pex.NodeID, addr)
			}

			for _, p := range pex.Peers {
				if p.Address == "" || visited[p.Address] {
					continue
				}
				next = append(next, p.Address)
			}
		}

		frontier = next
	}

	logger.Info("discoverAndRegisterPeers: discovery complete, contacted %d address(es) total", len(visited)-1)
}

func addrToNodeIDFallback(addr string) string {
	return fmt.Sprintf("Node-%s", addr)
}
