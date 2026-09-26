// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package policy

import (
	"fmt"
)

type WitnessVerifier func(msg []byte, witness []byte, height uint64, headerTS uint64) bool

var escrowWitnessVerifier WitnessVerifier

func SetEscrowWitnessVerifier(v WitnessVerifier) {
	escrowWitnessVerifier = v
}

func ReleaseDevelopmentModuleWithWitness(state CGEState, recipient string, moduleID uint64, witness []byte, height uint64, headerTS uint64, msg []byte) error {
	if escrowWitnessVerifier != nil {
		if len(witness) == 0 {
			return fmt.Errorf("ReleaseDevelopmentModule: missing multisig witness for module %d", moduleID)
		}
		if !escrowWitnessVerifier(msg, witness, height, headerTS) {
			return fmt.Errorf("ReleaseDevelopmentModule: invalid multisig witness for module %d", moduleID)
		}
	}
	return ReleaseDevelopmentModule(state, recipient, moduleID)
}

func VerifyEscrowWitness(msg []byte, witness []byte, height uint64, headerTS uint64) error {
	if escrowWitnessVerifier == nil {
		return nil
	}
	if len(witness) == 0 {
		return fmt.Errorf("escrow release: missing multisig witness")
	}
	if !escrowWitnessVerifier(msg, witness, height, headerTS) {
		return fmt.Errorf("escrow release: invalid multisig witness")
	}
	return nil
}
