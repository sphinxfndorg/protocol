package types

import (
	"encoding/json"
	"fmt"
)

const SlashEvidenceType = "sphinx_double_sign"

type SignedVoteEvidence struct {
	ChainID     uint64 `json:"chain_id"`
	Height      uint64 `json:"height"`
	Phase       string `json:"phase"`
	View        uint64 `json:"view"`
	ValidatorID string `json:"validator_id"`
	BlockHash   string `json:"block_hash"`
	Signature   []byte `json:"signature"`
}

type DoubleSignEvidence struct {
	Type   string             `json:"type"`
	First  SignedVoteEvidence `json:"first"`
	Second SignedVoteEvidence `json:"second"`
}

func BuildDoubleSignEvidenceData(first, second SignedVoteEvidence) ([]byte, error) {
	evidence := DoubleSignEvidence{Type: SlashEvidenceType, First: first, Second: second}
	if err := evidence.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(evidence)
	if err != nil {
		return nil, fmt.Errorf("encode double-sign evidence: %w", err)
	}
	return data, nil
}

func ParseDoubleSignEvidence(data []byte) (*DoubleSignEvidence, bool, error) {
	if len(data) == 0 {
		return nil, false, nil
	}
	var marker struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &marker); err != nil || marker.Type != SlashEvidenceType {
		return nil, false, nil
	}
	var evidence DoubleSignEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return nil, true, fmt.Errorf("decode double-sign evidence: %w", err)
	}
	if err := evidence.Validate(); err != nil {
		return nil, true, err
	}
	return &evidence, true, nil
}

func (e *DoubleSignEvidence) Validate() error {
	if e == nil || e.Type != SlashEvidenceType {
		return fmt.Errorf("invalid double-sign evidence type")
	}
	a, b := e.First, e.Second
	if a.ChainID == 0 || a.ChainID != b.ChainID || a.Height == 0 || a.Height != b.Height ||
		!validConsensusPhase(a.Phase) || !validConsensusPhase(b.Phase) || a.View != b.View ||
		a.ValidatorID == "" || a.ValidatorID != b.ValidatorID ||
		a.BlockHash == "" || b.BlockHash == "" || a.BlockHash == b.BlockHash ||
		len(a.Signature) == 0 || len(b.Signature) == 0 {
		return fmt.Errorf("double-sign evidence must contain distinct signed blocks from one validator at the same height and view")
	}

	return nil
}

func validConsensusPhase(phase string) bool {
	switch phase {
	case "prepare", "commit", "timeout":
		return true
	default:
		return false
	}
}
