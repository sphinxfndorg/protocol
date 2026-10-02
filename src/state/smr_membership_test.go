package state

import (
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/consensus"
)

func TestStateMachineMembershipComesFromHeightSnapshot(t *testing.T) {
	consensus.ResetSnapshots()
	t.Cleanup(consensus.ResetSnapshots)
	consensus.StoreSnapshotForTest(consensus.ValidatorSnapshot{
		Epoch:      0,
		TotalStake: big.NewInt(10),
		Validators: map[string]*consensus.StakedValidator{
			"validator": {ID: "validator", StakeAmount: big.NewInt(10)},
		},
	})

	sm := &StateMachine{nodeID: "peer"}
	if sm.isValidatorAt(1, "validator") != true {
		t.Fatal("chain-snapshot validator was not recognized")
	}
	if sm.isValidatorAt(1, "peer") {
		t.Fatal("unstaked peer was recognized as a validator")
	}
	if sm.isValidatorAt(1, "missing") {
		t.Fatal("missing snapshot authorized a validator")
	}

	if err := sm.validateOperation(&Operation{Type: OpStateTransition, Proposer: "validator", Sequence: 1}); err != nil {
		t.Fatalf("chain-state validator rejected: %v", err)
	}
	if err := sm.validateOperation(&Operation{Type: OpStateTransition, Proposer: "peer", Sequence: 1}); err == nil {
		t.Fatal("constructor/local peer data authorized a non-validator")
	}
}
