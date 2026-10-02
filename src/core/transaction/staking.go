package types

import (
	"encoding/json"
	"fmt"
	"math/big"
)

const (
	StakeActionType      = "sphinx_stake"
	StakingEscrowAddress = "0000000000000000000000000000000000000002"
)

type StakeAction struct {
	Type               string `json:"type"`
	Action             string `json:"action"`
	ValidatorID        string `json:"validator_id"`
	ValidatorPublicKey string `json:"validator_public_key,omitempty"`
	ValidatorProof     []byte `json:"validator_proof,omitempty"`
}

func BuildStakeActionData(action, validatorID, publicKey string, proof []byte) ([]byte, error) {
	if action != "stake" && action != "unstake" {
		return nil, fmt.Errorf("unsupported stake action %q", action)
	}
	if validatorID == "" {
		return nil, fmt.Errorf("validator ID is required")
	}
	if action == "stake" && (publicKey == "" || len(proof) == 0) {
		return nil, fmt.Errorf("stake action requires validator public key and proof of possession")
	}
	if action == "unstake" && (publicKey != "" || len(proof) != 0) {
		return nil, fmt.Errorf("unstake action cannot include validator identity proof")
	}
	data, err := json.Marshal(StakeAction{
		Type:               StakeActionType,
		Action:             action,
		ValidatorID:        validatorID,
		ValidatorPublicKey: publicKey,
		ValidatorProof:     proof,
	})
	if err != nil {
		return nil, fmt.Errorf("encode stake action: %w", err)
	}
	return data, nil
}

// StakeIdentityProofMessage binds validator key possession to the chain,
// action, identity, staking owner, and exact stake amount.
func StakeIdentityProofMessage(chainID uint64, action, validatorID, owner string, amount *big.Int) ([]byte, error) {
	if amount == nil || amount.Sign() < 0 {
		return nil, fmt.Errorf("stake proof amount must be non-negative")
	}
	message, err := json.Marshal(struct {
		Domain      string `json:"domain"`
		ChainID     uint64 `json:"chain_id"`
		Action      string `json:"action"`
		ValidatorID string `json:"validator_id"`
		Owner       string `json:"owner"`
		AmountNSPX  string `json:"amount_nspx"`
	}{
		Domain:      "SPHINX_STAKE_IDENTITY_V1",
		ChainID:     chainID,
		Action:      action,
		ValidatorID: validatorID,
		Owner:       owner,
		AmountNSPX:  amount.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("encode stake identity proof message: %w", err)
	}
	return message, nil
}

// ParseStakeAction recognizes the signed transaction payload reserved for
// staking. Ordinary OP_RETURN data is reported as not-staking.
func ParseStakeAction(data []byte) (*StakeAction, bool, error) {
	if len(data) == 0 {
		return nil, false, nil
	}
	var marker struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &marker); err != nil || marker.Type != StakeActionType {
		return nil, false, nil
	}
	var action StakeAction
	if err := json.Unmarshal(data, &action); err != nil {
		return nil, true, fmt.Errorf("decode stake action: %w", err)
	}
	if action.Type != StakeActionType || action.ValidatorID == "" ||
		(action.Action != "stake" && action.Action != "unstake") {
		return nil, true, fmt.Errorf("invalid stake action payload")
	}
	if action.Action == "stake" && (action.ValidatorPublicKey == "" || len(action.ValidatorProof) == 0) {
		return nil, true, fmt.Errorf("stake action is missing validator key proof")
	}
	if action.Action == "unstake" && (action.ValidatorPublicKey != "" || len(action.ValidatorProof) != 0) {
		return nil, true, fmt.Errorf("unstake action must not contain validator key proof")
	}
	return &action, true, nil
}
