// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"encoding/json"
	"fmt"

	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	"github.com/sphinxfndorg/protocol/src/policy"
)

func init() {
	policy.SetEscrowWitnessVerifier(func(msg []byte, witness []byte, height uint64, headerTS uint64) bool {
		var w multisig.MultiSigWitness
		if err := json.Unmarshal(witness, &w); err != nil {
			return false
		}
		if err := multisig.ValidateWitnessExpiry(w.Expiry, headerTS); err != nil {
			return false
		}
		return multisig.VerifyThreshold(msg, w, headerTS)
	})
}

func marshalWitness(w multisig.MultiSigWitness) []byte {
	data, err := json.Marshal(w)
	if err != nil {
		return nil
	}
	return data
}

func ReleaseDevModuleWithWitness(bc *Blockchain, stateDB *StateDB, recipient string, moduleID uint64, w multisig.MultiSigWitness, height uint64, headerTS uint64) error {
	if stateDB == nil {
		return fmt.Errorf("nil state")
	}
	if !escrowEnforced() {
		return policy.ReleaseDevelopmentModule(stateDB, recipient, moduleID)
	}
	msg := devModuleReleaseMessage(bc, recipient, moduleID, w.Expiry)
	if err := policy.ReleaseDevelopmentModuleWithWitness(stateDB, recipient, moduleID, marshalWitness(w), height, headerTS, msg); err != nil {
		return err
	}
	return nil
}
