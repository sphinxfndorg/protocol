package consensus

import (
	"testing"

	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
)

func newProofTestSigner(t *testing.T) (*SigningService, []byte) {
	t.Helper()
	keyManager, err := key.NewKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	privateKey, publicKey, err := keyManager.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, publicBytes, err := keyManager.SerializeKeyPair(privateKey, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	manager := sign.NewSTHINCSManager(nil, keyManager, keyManager.GetSPHINCSParameters())
	service, err := NewSigningService(manager, keyManager, "Node-proof-test", privateBytes, publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	return service, publicBytes
}

func TestVerifyStakeIdentityProofBindsExactMessage(t *testing.T) {
	service, publicKey := newProofTestSigner(t)
	message := []byte(`{"domain":"SPHINX_STAKE_IDENTITY_V1","validator_id":"Node-proof-test"}`)
	proof, err := service.SignMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyStakeIdentityProof(publicKey, proof, message); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	if err := VerifyStakeIdentityProof(publicKey, proof, []byte("different stake")); err == nil {
		t.Fatal("proof accepted for a different stake message")
	}
}

func TestVerifyDoubleSignEvidenceRequiresConflictingVotesAtSameHeightAndView(t *testing.T) {
	service, publicKey := newProofTestSigner(t)
	first := &Vote{ChainID: 73310, Height: 12, Phase: VotePhasePrepare, View: 3, VoterID: "Node-proof-test", BlockHash: "block-a"}
	second := &Vote{ChainID: 73310, Height: 12, Phase: VotePhaseCommit, View: 3, VoterID: "Node-proof-test", BlockHash: "block-b"}
	if err := service.SignVote(first); err != nil {
		t.Fatal(err)
	}
	if err := service.SignVote(second); err != nil {
		t.Fatal(err)
	}
	if err := VerifyDoubleSignEvidence(first, second, publicKey); err != nil {
		t.Fatalf("valid double-sign evidence rejected: %v", err)
	}

	phaseRelabeled := *first
	phaseRelabeled.Phase = VotePhaseCommit
	if valid, err := service.VerifyVote(&phaseRelabeled); err == nil && valid {
		t.Fatal("signature was reusable under a different consensus phase")
	}
	chainRelabeled := *first
	chainRelabeled.ChainID++
	if valid, err := service.VerifyVote(&chainRelabeled); err == nil && valid {
		t.Fatal("signature was reusable on a different chain ID")
	}

	second.Height++
	if err := VerifyDoubleSignEvidence(first, second, publicKey); err == nil {
		t.Fatal("evidence for different heights was accepted")
	}
	second.Height--
	second.View++
	if err := VerifyDoubleSignEvidence(first, second, publicKey); err == nil {
		t.Fatal("evidence for different views was accepted")
	}
}
