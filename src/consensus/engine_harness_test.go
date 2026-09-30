// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/consensus/engine_harness_test.go
//
// Checkpoint 1b item 2: ENGINE-LEVEL harness.
//
// These live in package consensus because they exercise UNEXPORTED engine
// internals — receivedVotes, validatorSet, calculateQuorumSize — on the
// PRODUCTION *Consensus type. Every method below is the real engine method.
// Only the struct construction is hand-rolled, because NewConsensus derives the
// VDF/RANDAO seed from a genesis block and supplying one drags in the entire
// storage stack; the quorum path under test reads none of that.
//
// Signatures are REAL SPHINCS+, generated per validator, so "N validators" means
// N independent keypairs rather than N labels.
package consensus

import (
	"math/big"
	"strconv"
	"testing"

	config "github.com/sphinxfndorg/protocol/src/core/sthincs/config"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
)

// engineNode is one in-process consensus engine with its own real keypair.
type engineNode struct {
	id  string
	c   *Consensus
	vs  *ValidatorSet
	att *Attestation
	vot *Vote
}

func harnessParamsConsensus(t *testing.T) *parameters.Parameters {
	t.Helper()
	cfg, err := config.NewSTHINCSParameters()
	if err != nil {
		t.Fatalf("NewSTHINCSParameters: %v", err)
	}
	return cfg.Params
}

func harnessKeyPairConsensus(t *testing.T) (*sthincs.SPHINCS_SK, *sthincs.SPHINCS_PK) {
	t.Helper()
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	sk, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return &sthincs.SPHINCS_SK{SKseed: sk.SKseed, SKprf: sk.SKprf, PKseed: sk.PKseed, PKroot: sk.PKroot},
		&sthincs.SPHINCS_PK{PKseed: pk.PKseed, PKroot: pk.PKroot}
}

func newEngineNode(t *testing.T, id string, allIDs []string, unit *big.Int) *engineNode {
	t.Helper()
	vs := NewValidatorSet(unit)
	if err := vs.AddGenesisValidator(id, unit); err != nil {
		t.Fatalf("AddGenesisValidator: %v", err)
	}
	// ★ The FULL membership, as a real node derives it from the same chain.
	// If each engine held only ITSELF, getTotalNodes() would return 1 and a
	// 2-validator set would present to the engine as a 1-validator one.
	for _, other := range allIDs {
		if other == id {
			continue
		}
		if err := vs.AddGenesisValidator(other, unit); err != nil {
			t.Fatalf("AddGenesisValidator(%s): %v", other, err)
		}
	}
	vs.ProcessEpochTransition(0)
	vs.SealGenesis()

	// A REAL signature over a REAL message, so the vote is not a stub.
	params := harnessParamsConsensus(t)
	sk, pk := harnessKeyPairConsensus(t)
	msg := []byte("engine-harness-vote:" + id)
	s, err := sthincs.Spx_sign(params, msg, sk)
	if err != nil {
		t.Fatalf("Spx_sign: %v", err)
	}
	sig, err := s.SerializeSignature()
	if err != nil {
		t.Fatalf("SerializeSignature: %v", err)
	}
	if !sthincs.Spx_verify(params, msg, s, pk) {
		t.Fatalf("[%s] the freshly made signature does not verify", id)
	}

	return &engineNode{
		id:  id,
		vs:  vs,
		att: &Attestation{ValidatorID: id, Signature: sig},
		vot: &Vote{VoterID: id, Signature: sig},
		c: &Consensus{

			nodeID:              id,
			validatorSet:        vs,
			selector:            NewStakeWeightedSelector(vs),
			receivedVotes:       make(map[string]map[string]*Vote),
			weightedCommitVotes: make(map[string]*big.Int),
		},
	}
}

// fileVote records `voter`'s vote into THIS node's vote table for blockHash, as
// HandleVote would after verifying the signature.
//
// The voter is a PARAMETER on purpose: a node collects OTHER nodes' votes, so
// calling this on the receiving node would file one validator's vote N times —
// which looks exactly like full quorum and would make every assertion here
// vacuous.
func (n *engineNode) fileVote(blockHash string, voter *engineNode) {
	n.c.mu.Lock()
	defer n.c.mu.Unlock()
	if n.c.receivedVotes[blockHash] == nil {
		n.c.receivedVotes[blockHash] = make(map[string]*Vote)
	}
	n.c.receivedVotes[blockHash][voter.id] = voter.vot
}

func engineUnit() *big.Int {
	return new(big.Int).Mul(big.NewInt(32), new(big.Int).SetUint64(denom.SPX))
}

// TestEngine_QuorumForN drives the REAL Consensus.hasQuorum for N = 2, 3, 4 and
// asserts the stop-one behaviour:
//
//	N=2: stop one -> 1 of 2 -> HALTS
//	N=3: stop one -> 2 of 3 -> HALTS
//	N=4: stop one -> 3 of 4 -> CONTINUES
//
// It also asserts the stake rule and the vote-count floor AGREE. Their
// disagreement is what this item found: the floor was int(N*0.67), which
// returns 2 for N=3 — permitting the very 2-of-3 that the SAFETY FLOOR comment
// beside it says it exists to prevent.
func TestEngine_QuorumForN(t *testing.T) {
	prev := epochBlocksOverride
	SetEpochBlocks(4)
	defer func() { epochBlocksOverride = prev }()
	ResetSnapshots()
	defer ResetSnapshots()

	for _, n := range []int{2, 3, 4} {
		n := n
		t.Run("N"+strconv.Itoa(n), func(t *testing.T) {
			ResetSnapshots()
			defer ResetSnapshots()

			unit := engineUnit()
			ids := make([]string, 0, n)
			for i := 0; i < n; i++ {
				ids = append(ids, "Node-"+string(rune('a'+i)))
			}
			nodes := make([]*engineNode, 0, n)
			snap := &ValidatorSnapshot{
				Epoch:      0,
				TotalStake: new(big.Int).Mul(unit, big.NewInt(int64(n))),
				Validators: make(map[string]*StakedValidator, n),
			}
			for i := 0; i < n; i++ {
				nd := newEngineNode(t, "Node-"+string(rune('a'+i)), ids, unit)
				nodes = append(nodes, nd)
				snap.Validators[nd.id] = &StakedValidator{ID: nd.id, StakeAmount: new(big.Int).Set(unit)}
			}
			StoreSnapshotForTest(*snap)

			lead := nodes[0]
			const blockHash = "block-under-test"

			// All N running: every validator votes, and the chain must commit.
			for _, nd := range nodes {
				lead.fileVote(blockHash, nd)
			}
			if !lead.c.hasQuorum(blockHash) {
				t.Fatalf("N=%d: with all %d validators voting the chain did NOT commit", n, n)
			}

			// Stop one.
			lead.c.mu.Lock()
			delete(lead.c.receivedVotes[blockHash], nodes[n-1].id)
			lead.c.mu.Unlock()

			running := n - 1
			committed := lead.c.hasQuorum(blockHash)
			need := StrictTwoThirdsCount(n)
			floor := lead.c.calculateQuorumSize(n)
			voted := new(big.Int).Mul(unit, big.NewInt(int64(running)))
			stakeOK := MeetsStakeQuorum(voted, snap.TotalStake)

			if floor != need {
				t.Errorf("N=%d: calculateQuorumSize = %d, want StrictTwoThirdsCount = %d "+
					"(the vote floor and the stake rule must agree)", n, floor, need)
			}
			if (floor <= running) != stakeOK {
				t.Errorf("N=%d: the vote floor (%d, %d running) and the stake rule (%v) DISAGREE",
					n, floor, running, stakeOK)
			}
			t.Logf("N=%d: need %d of %d; %d running -> floor=%d stakeOK=%v committed=%v",
				n, need, n, running, floor, stakeOK, committed)

			switch n {
			case 2, 3:
				if committed {
					t.Errorf("N=%d: with only %d of %d running the chain COMMITTED; "+
						"strict >2/3 requires a halt here", n, running, n)
				}
			case 4:
				if !committed {
					t.Errorf("N=%d: with %d of %d running the chain HALTED; 4 is the "+
						"smallest set that tolerates one offline validator", n, running, n)
				}
			}
		})
	}
}
