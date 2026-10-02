package types

import (
	"math/big"
	"testing"
)

func TestStakeActionRequiresIdentityProof(t *testing.T) {
	if _, err := BuildStakeActionData("stake", "Node-a", "", nil); err == nil {
		t.Fatal("stake payload was built without validator proof")
	}
	data, err := BuildStakeActionData("stake", "Node-a", "abcd", []byte("proof"))
	if err != nil {
		t.Fatal(err)
	}
	action, ok, err := ParseStakeAction(data)
	if err != nil || !ok || action.ValidatorPublicKey != "abcd" || string(action.ValidatorProof) != "proof" {
		t.Fatalf("ParseStakeAction() = (%+v, %v, %v)", action, ok, err)
	}
	if _, err := BuildStakeActionData("unstake", "Node-a", "abcd", []byte("proof")); err == nil {
		t.Fatal("unstake payload unexpectedly accepted a validator identity proof")
	}
}

func TestDoubleSignEvidenceRequiresSameHeightAndView(t *testing.T) {
	first := SignedVoteEvidence{
		ChainID: 73310, Height: 5, Phase: "prepare", View: 2,
		ValidatorID: "Node-a", BlockHash: "block-a", Signature: []byte("sig-a"),
	}
	second := SignedVoteEvidence{
		ChainID: 73310, Height: 5, Phase: "commit", View: 2,
		ValidatorID: "Node-a", BlockHash: "block-b", Signature: []byte("sig-b"),
	}
	data, err := BuildDoubleSignEvidenceData(first, second)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ParseDoubleSignEvidence(data); err != nil || !ok {
		t.Fatalf("valid evidence rejected: recognized=%v err=%v", ok, err)
	}
	second.Height++
	if _, err := BuildDoubleSignEvidenceData(first, second); err == nil {
		t.Fatal("evidence from different heights was accepted")
	}
	second.Height--
	second.View++
	if _, err := BuildDoubleSignEvidenceData(first, second); err == nil {
		t.Fatal("evidence from different views was accepted")
	}
	if _, err := StakeIdentityProofMessage(7331, "stake", "Node-a", "owner", big.NewInt(-1)); err == nil {
		t.Fatal("negative stake amount was accepted in identity proof")
	}
}
