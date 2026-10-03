// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package consensus

import (
	"context"
	"errors"
	"testing"
)

// TestParticipationAllowed_GateSemantics reproduces the localnet stall without
// spawning any process.
//
// The chain-state gate (core.Blockchain.IsValidatorPausedForHeight) answers
// "is this validator PAUSED". The localnet stall happened because the consensus
// side read that boolean as "is participation allowed", so a healthy, unpaused
// validator (gate=false) was rejected as a "paused validator" and every
// proposal was dropped before any vote could be cast.
//
// In production the gate always returns false, because the policy that would
// write a pause record is disabled and no code writes
// "protocol:validator_pause_epoch:*" — so this case alone is what produced
// zero votes across a 4-validator localnet.
func TestParticipationAllowed_GateSemantics(t *testing.T) {
	cases := []struct {
		name       string
		gate       func(string, uint64) (bool, error)
		wantAllow  bool
		wantReason string
	}{
		{
			name:       "no gate installed preserves participation",
			gate:       nil,
			wantAllow:  true,
			wantReason: "isolated harnesses install no gate and must still participate",
		},
		{
			name:       "unpaused validator may participate",
			gate:       func(string, uint64) (bool, error) { return false, nil },
			wantAllow:  true,
			wantReason: "gate=false means NOT paused, so the validator must be allowed",
		},
		{
			name:       "paused validator may not participate",
			gate:       func(string, uint64) (bool, error) { return true, nil },
			wantAllow:  false,
			wantReason: "gate=true means paused, so the validator must be blocked",
		},
		{
			name:       "gate error fails closed",
			gate:       func(string, uint64) (bool, error) { return false, errors.New("state DB unavailable") },
			wantAllow:  false,
			wantReason: "an unreadable pause record must not be read as permission",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newGateTestConsensus()
			if tc.gate != nil {
				c.SetParticipationGate(tc.gate)
			}
			got := c.participationAllowed("Node-127.0.0.1:30303", 1)
			if got != tc.wantAllow {
				t.Fatalf("participationAllowed = %v, want %v — %s", got, tc.wantAllow, tc.wantReason)
			}
		})
	}
}

// TestParticipationAllowed_RealGateShape pins the exact contract of the
// production gate: a validator with no pause record must be allowed. It uses the
// same signature and semantics as core.Blockchain.IsValidatorPausedForHeight
// without needing a Blockchain, so the inversion cannot come back unnoticed.
func TestParticipationAllowed_RealGateShape(t *testing.T) {
	// IsValidatorPausedForHeight returns (false, nil) when the pause key is
	// absent — which is always, since nothing writes it.
	notPaused := func(string, uint64) (bool, error) { return false, nil }
	c := newGateTestConsensus()
	c.SetParticipationGate(notPaused)
	if !c.participationAllowed("Node-127.0.0.1:30303", 1) {
		t.Fatal("a validator with no pause record must be allowed to participate; " +
			"returning false here is the localnet zero-vote stall")
	}
}

// newGateTestConsensus builds a Consensus with only the fields participationAllowed
// touches, so the gate test needs no blockchain, key manager or network.
func newGateTestConsensus() *Consensus {
	return &Consensus{
		ctx:    context.Background(),
		cancel: func() {},
	}
}
