package consensus

import (
	"fmt"
	"math/big"
	"testing"
)

func TestValidatorSetRejectsAdmissionAboveCap(t *testing.T) {
	minimumStake := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
	validatorSet := NewValidatorSet(minimumStake)
	for i := 0; i < MaxValidatorSetSize; i++ {
		if err := validatorSet.AddGenesisValidator(fmt.Sprintf("Node-%03d", i), minimumStake); err != nil {
			t.Fatalf("AddGenesisValidator(%d): %v", i, err)
		}
	}
	if err := validatorSet.AddGenesisValidator("Node-over-cap", minimumStake); err == nil {
		t.Fatal("genesis admission above the validator cap succeeded")
	}
	if err := validatorSet.QueueValidator("Node-over-cap", minimumStake, 1); err == nil {
		t.Fatal("queued admission above the validator cap succeeded")
	}
}
