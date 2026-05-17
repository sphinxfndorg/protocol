// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/consensus/global.go
package consensus

import "time"

// Configuration
const (
	BATCH_SIZE     = 10000
	BASE_TIMEOUT   = 150 * time.Millisecond
	FAST_TIMEOUT   = 80 * time.Millisecond
	PIPELINE_DEPTH = 3
)

// Node role constants defining different types of nodes in the network
const (
	RoleValidator NodeRole = iota // Validator nodes participate in consensus voting
	RoleObserver                  // Observer nodes can read but not participate in consensus
	RoleBootnode                  // Bootnodes help other nodes discover the network
)

// Node status constants representing the current state of a node
const (
	NodeStatusActive   NodeStatus = iota // Node is active and participating
	NodeStatusInactive                   // Node is inactive or disconnected
	NodeStatusSyncing                    // Node is synchronizing with the network
)

// Consensus phase constants representing the current state of PBFT consensus
const (
	PhaseIdle         ConsensusPhase = iota // No active consensus round
	PhasePrePrepared                        // Received proposal but not yet prepared
	PhasePrepared                           // Received enough prepare votes to proceed
	PhaseCommitted                          // Received enough commit votes to finalize
	PhaseViewChanging                       // In the process of changing consensus view
)
