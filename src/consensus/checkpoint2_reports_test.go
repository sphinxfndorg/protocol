package consensus

import (
	"math/big"
	"testing"
)

func TestUnequalStakeSnapshotQuorumReport(t *testing.T) {
	snapshot := &ValidatorSnapshot{
		Epoch:      0,
		TotalStake: big.NewInt(100),
		Validators: map[string]*StakedValidator{
			"whale":   {ID: "whale", StakeAmount: big.NewInt(70)},
			"small-a": {ID: "small-a", StakeAmount: big.NewInt(10)},
			"small-b": {ID: "small-b", StakeAmount: big.NewInt(10)},
			"small-c": {ID: "small-c", StakeAmount: big.NewInt(10)},
		},
	}
	tests := []struct {
		name   string
		stake  int64
		voters int
		quorum bool
	}{
		{name: "whale alone exceeds stake threshold but not distinct-voter floor", stake: 70, voters: 1},
		{name: "three small validators do not reach stake threshold", stake: 30, voters: 3},
		{name: "whale and two small validators clear both thresholds", stake: 90, voters: 3, quorum: true},
		{name: "all validators clear both thresholds", stake: 100, voters: 4, quorum: true},
	}

	t.Log("unequal-stake quorum: strict >2/3 stake AND floor(2N/3)+1 distinct voters")
	for _, test := range tests {
		got := quorumFromSnapshot(snapshot, big.NewInt(test.stake), test.voters)
		t.Logf("%s: voters=%d stake=%d/100 quorum=%v", test.name, test.voters, test.stake, got)
		if got != test.quorum {
			t.Errorf("%s: quorum=%v, want %v", test.name, got, test.quorum)
		}
	}
}

func TestViewChangeTimeoutRequiresSnapshotQuorum(t *testing.T) {
	snapshot := &ValidatorSnapshot{
		Epoch:      2,
		TotalStake: big.NewInt(100),
		Validators: map[string]*StakedValidator{
			"whale":   {ID: "whale", StakeAmount: big.NewInt(70)},
			"small-a": {ID: "small-a", StakeAmount: big.NewInt(10)},
			"small-b": {ID: "small-b", StakeAmount: big.NewInt(10)},
			"small-c": {ID: "small-c", StakeAmount: big.NewInt(10)},
		},
	}
	tests := []struct {
		name       string
		snapshot   *ValidatorSnapshot
		voters     []string
		wantQuorum bool
	}{
		{name: "whale alone is below distinct-voter floor", snapshot: snapshot, voters: []string{"whale"}},
		{name: "unstaked peer contributes neither stake nor distinct vote", snapshot: snapshot, voters: []string{"whale", "small-a", "peer"}},
		{name: "three small validators are below stake quorum", snapshot: snapshot, voters: []string{"small-a", "small-b", "small-c"}},
		{name: "whale and two small validators meet quorum", snapshot: snapshot, voters: []string{"whale", "small-a", "small-b"}, wantQuorum: true},
		{name: "missing snapshot", voters: []string{"whale"}},
	}

	t.Log("view-change timeout: positive-stake snapshot members must aggregate strict stake and distinct-voter quorum")
	for _, test := range tests {
		votes := make(map[string]*TimeoutMsg)
		for _, voter := range test.voters {
			votes[voter] = &TimeoutMsg{VoterID: voter}
		}
		stake, distinct := timeoutVotesQuorum(test.snapshot, votes)
		got := quorumFromSnapshot(test.snapshot, stake, distinct)
		t.Logf("%s: voters=%d stake=%s quorum=%v", test.name, distinct, stake, got)
		if got != test.wantQuorum {
			t.Errorf("%s: quorum=%v, want %v", test.name, got, test.wantQuorum)
		}
	}
}
