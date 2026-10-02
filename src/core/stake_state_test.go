package core

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/consensus"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

func TestQueuedStakeActivationAndUnstakeRefund(t *testing.T) {
	db, err := database.NewLevelDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	stateDB := NewStateDB(db)
	amount := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))
	activationEpoch := uint64(2)
	if err := stateDB.queueStakeChange(queuedStakeChange{
		Action:          "stake",
		ValidatorID:     "Node-127.0.0.1:30304",
		Owner:           "owner",
		PublicKey:       strings.Repeat("ab", 32),
		AmountNSPX:      amount.String(),
		ActivationEpoch: activationEpoch,
	}); err != nil {
		t.Fatal(err)
	}
	stateDB.SetBalance(types.StakingEscrowAddress, amount)
	if _, err := stateDB.Commit(); err != nil {
		t.Fatal(err)
	}
	stateDB = NewStateDB(db)

	boundaryHeight := activationEpoch * consensus.EpochBlocks()
	beforeActivation := &types.Block{Header: &types.BlockHeader{Height: boundaryHeight - 1}}
	if err := (&Blockchain{}).applyQueuedStakeChanges(beforeActivation, stateDB); err != nil {
		t.Fatal(err)
	}
	if stake, err := stateDB.GetValidatorStake("Node-127.0.0.1:30304"); err == nil && stake.Sign() != 0 {
		t.Fatalf("stake activated before epoch %d: %s", activationEpoch, stake)
	}
	if queue, err := stateDB.readStakeQueue(); err != nil || len(queue) != 1 {
		t.Fatalf("pending stake queue = %v, err=%v; want one entry", queue, err)
	}

	activationBlock := &types.Block{Header: &types.BlockHeader{Height: boundaryHeight}}
	if err := (&Blockchain{}).applyQueuedStakeChanges(activationBlock, stateDB); err != nil {
		t.Fatal(err)
	}
	if _, err := stateDB.Commit(); err != nil {
		t.Fatal(err)
	}
	stateDB = NewStateDB(db)
	if stake, err := stateDB.GetValidatorStake("Node-127.0.0.1:30304"); err != nil || stake.Cmp(amount) != 0 {
		t.Fatalf("activated stake = %v, err=%v; want %s", stake, err, amount)
	}
	owner, err := stateDB.GetContractValue(stakeOwnerKeyPrefix + "Node-127.0.0.1:30304")
	if err != nil || string(owner) != "owner" {
		t.Fatalf("activated stake owner = %q, err=%v; want owner", owner, err)
	}
	publicKey, err := stateDB.GetContractValue(stakePublicKeyPrefix + "Node-127.0.0.1:30304")
	if err != nil || len(publicKey) != 32 || publicKey[0] != 0xab {
		t.Fatalf("activated validator key = %x, err=%v; want 32 bytes", publicKey, err)
	}

	if err := stateDB.queueStakeChange(queuedStakeChange{
		Action:          "unstake",
		ValidatorID:     "Node-127.0.0.1:30304",
		Owner:           "owner",
		ActivationEpoch: activationEpoch + 2,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := stateDB.Commit(); err != nil {
		t.Fatal(err)
	}
	stateDB = NewStateDB(db)
	exitEpoch := activationEpoch + 2
	unstakeBlock := &types.Block{Header: &types.BlockHeader{Height: exitEpoch * consensus.EpochBlocks()}}
	if err := (&Blockchain{}).applyQueuedStakeChanges(unstakeBlock, stateDB); err != nil {
		t.Fatal(err)
	}
	if _, err := stateDB.Commit(); err != nil {
		t.Fatal(err)
	}
	stateDB = NewStateDB(db)
	balance, err := stateDB.GetBalance("owner")
	if err != nil || balance.Sign() != 0 {
		t.Fatalf("unstake refunded before evidence window closed: balance=%v, err=%v", balance, err)
	}
	if stake, err := stateDB.GetValidatorStake("Node-127.0.0.1:30304"); err != nil || stake.Sign() != 0 {
		t.Fatalf("stake after unstake = %v, err=%v; want zero", stake, err)
	}
	withdrawal, err := (&Blockchain{}).getPendingWithdrawal(stateDB, "Node-127.0.0.1:30304")
	if err != nil || withdrawal.ReleaseEpoch != exitEpoch+UnbondingEpochs {
		t.Fatalf("pending withdrawal = %+v, err=%v; release epoch want %d",
			withdrawal, err, exitEpoch+UnbondingEpochs)
	}
	if err := (&Blockchain{}).applyDoubleSignPenalty(stateDB, "Node-127.0.0.1:30304"); err != nil {
		t.Fatalf("slash pending withdrawal: %v", err)
	}
	if _, err := stateDB.Commit(); err != nil {
		t.Fatal(err)
	}
	stateDB = NewStateDB(db)
	withdrawal, err = (&Blockchain{}).getPendingWithdrawal(stateDB, "Node-127.0.0.1:30304")
	if err != nil {
		t.Fatalf("read slashed pending withdrawal: %v", err)
	}
	remaining, ok := new(big.Int).SetString(withdrawal.AmountNSPX, 10)
	wantRemaining := new(big.Int).Div(new(big.Int).Mul(amount, big.NewInt(95)), big.NewInt(100))
	if !ok || remaining.Cmp(wantRemaining) != 0 {
		t.Fatalf("pending withdrawal after 5%% slash = %s; want %s",
			withdrawal.AmountNSPX, wantRemaining)
	}
	maturityBlock := &types.Block{Header: &types.BlockHeader{
		Height: (exitEpoch + UnbondingEpochs) * consensus.EpochBlocks(),
	}}
	if err := (&Blockchain{}).applyQueuedStakeChanges(maturityBlock, stateDB); err != nil {
		t.Fatalf("release matured withdrawal: %v", err)
	}
	if _, err := stateDB.Commit(); err != nil {
		t.Fatal(err)
	}
	stateDB = NewStateDB(db)
	balance, err = stateDB.GetBalance("owner")
	if err != nil || balance.Cmp(remaining) != 0 {
		t.Fatalf("matured withdrawal = %v, err=%v; want slashed amount %s", balance, err, remaining)
	}
	if queue, err := stateDB.readStakeQueue(); err != nil || len(queue) != 0 {
		t.Fatalf("queue after activation = %v, err=%v; want empty", queue, err)
	}
}

func TestEvidenceAndUnbondingWindowsAreOrdered(t *testing.T) {
	if UnbondingEpochs <= MaxEvidenceAgeEpochs {
		t.Fatalf("unbonding period %d must exceed evidence age %d", UnbondingEpochs, MaxEvidenceAgeEpochs)
	}
}

func TestStakeAdmissionEnforcesValidatorCapAndPendingWithdrawal(t *testing.T) {
	db, err := database.NewLevelDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()

	stateDB := NewStateDB(db)
	stake := big.NewInt(1)
	for i := 0; i < consensus.MaxValidatorSetSize; i++ {
		stateDB.SetValidatorStake(fmt.Sprintf("Node-%03d", i), stake)
	}
	bc := &Blockchain{}
	if err := bc.validateStakeAdmission(stateDB, "Node-over-cap"); err == nil {
		t.Fatal("stake admission above validator cap succeeded")
	}

	stateDB = NewStateDB(db)
	if err := bc.validateStakeAdmission(stateDB, "Node-first"); err != nil {
		t.Fatalf("admission below validator cap: %v", err)
	}
	withdrawal, err := json.Marshal(pendingWithdrawal{
		ValidatorID: "Node-exiting", Owner: "owner", AmountNSPX: "1", ReleaseEpoch: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	stateDB.SetContractValue(pendingWithdrawalPrefix+"Node-exiting", withdrawal)
	if err := bc.validateStakeAdmission(stateDB, "Node-exiting"); err == nil {
		t.Fatal("stake admission while prior stake is pending withdrawal succeeded")
	}
}

func TestDoubleSignEvidenceSlashesExitedPendingWithdrawal(t *testing.T) {
	const validatorID = "Node-evidence-test"
	consensus.ResetSnapshots()
	defer consensus.ResetSnapshots()

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
	signer, err := consensus.NewSigningService(
		sign.NewSTHINCSManager(nil, keyManager, keyManager.GetSPHINCSParameters()),
		keyManager, validatorID, privateBytes, publicBytes,
	)
	if err != nil {
		t.Fatal(err)
	}
	first := &consensus.Vote{
		ChainID: DevnetChainID, Height: 1, Phase: consensus.VotePhasePrepare,
		View: 2, VoterID: validatorID, BlockHash: "conflicting-block-a",
	}
	second := &consensus.Vote{
		ChainID: DevnetChainID, Height: 1, Phase: consensus.VotePhaseCommit,
		View: 2, VoterID: validatorID, BlockHash: "conflicting-block-b",
	}
	if err := signer.SignVote(first); err != nil {
		t.Fatal(err)
	}
	if err := signer.SignVote(second); err != nil {
		t.Fatal(err)
	}
	evidenceData, err := types.BuildDoubleSignEvidenceData(
		types.SignedVoteEvidence{
			ChainID: first.ChainID, Height: first.Height, Phase: first.Phase,
			View: first.View, ValidatorID: first.VoterID, BlockHash: first.BlockHash,
			Signature: first.Signature,
		},
		types.SignedVoteEvidence{
			ChainID: second.ChainID, Height: second.Height, Phase: second.Phase,
			View: second.View, ValidatorID: second.VoterID, BlockHash: second.BlockHash,
			Signature: second.Signature,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	amount := new(big.Int).Mul(big.NewInt(50), big.NewInt(1e18))
	consensus.StoreSnapshotForTest(consensus.ValidatorSnapshot{
		Epoch: 0, TotalStake: new(big.Int).Set(amount),
		Validators: map[string]*consensus.StakedValidator{
			validatorID: {ID: validatorID, StakeAmount: new(big.Int).Set(amount)},
		},
	})
	db, err := database.NewLevelDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stateDB := NewStateDB(db)
	stateDB.SetBalance(types.StakingEscrowAddress, amount)
	stateDB.SetBalance("fee-payer", big.NewInt(1))
	withdrawalBytes, err := json.Marshal(pendingWithdrawal{
		ValidatorID: validatorID, Owner: "owner", AmountNSPX: amount.String(), ReleaseEpoch: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	stateDB.SetContractValue(pendingWithdrawalPrefix+validatorID, withdrawalBytes)
	stateDB.SetContractValue(stakePublicKeyPrefix+validatorID, publicBytes)

	gas := policy.GetDefaultPolicyParams().QuoteTransactionGas(uint64(len(evidenceData)))
	tx := &types.Transaction{
		ID: "double-sign-evidence", ChainID: DevnetChainID,
		Sender: "fee-payer", Receiver: "fee-payer", Amount: big.NewInt(0),
		GasLimit: gas.GasLimit, GasPrice: big.NewInt(0), ReturnData: evidenceData,
	}
	block := &types.Block{
		Header: &types.BlockHeader{Block: 3, Height: 3},
		Body:   types.BlockBody{TxsList: []*types.Transaction{tx}},
	}
	bc := &Blockchain{chainParams: GetDevnetChainParams()}
	if err := bc.applyTransactions(block, stateDB); err != nil {
		t.Fatalf("include valid double-sign evidence: %v", err)
	}
	withdrawal, err := bc.getPendingWithdrawal(stateDB, validatorID)
	if err != nil {
		t.Fatal(err)
	}
	slashed, _ := new(big.Int).SetString(withdrawal.AmountNSPX, 10)
	want := new(big.Int).Div(new(big.Int).Mul(amount, big.NewInt(95)), big.NewInt(100))
	if slashed.Cmp(want) != 0 {
		t.Fatalf("evidence left pending withdrawal at %s; want %s", slashed, want)
	}
	if err := bc.applyTransactions(block, stateDB); err == nil {
		t.Fatal("replayed double-sign evidence was accepted")
	}
}

func TestGenesisStakeIsEscrowedOnce(t *testing.T) {
	db, err := database.NewLevelDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	stateDB := NewStateDB(db)
	amount := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18))
	const validatorID = "Node-127.0.0.1:30303"
	const owner = "genesis-owner"
	stateDB.SetValidatorStake(validatorID, amount)
	stateDB.SetContractValue(stakeOwnerKeyPrefix+validatorID, []byte(owner))
	stateDB.SetBalance(owner, amount)

	if err := (&Blockchain{}).escrowGenesisStakes(stateDB); err != nil {
		t.Fatalf("escrowGenesisStakes: %v", err)
	}
	if _, err := stateDB.Commit(); err != nil {
		t.Fatalf("commit escrow state: %v", err)
	}

	stateDB = NewStateDB(db)
	ownerBalance, err := stateDB.GetBalance(owner)
	if err != nil || ownerBalance.Sign() != 0 {
		t.Fatalf("owner balance = %v, err=%v; want zero", ownerBalance, err)
	}
	escrowBalance, err := stateDB.GetBalance(types.StakingEscrowAddress)
	if err != nil || escrowBalance.Cmp(amount) != 0 {
		t.Fatalf("escrow balance = %v, err=%v; want %s", escrowBalance, err, amount)
	}

	if err := (&Blockchain{}).escrowGenesisStakes(stateDB); err != nil {
		t.Fatalf("repeat escrowGenesisStakes: %v", err)
	}
	if _, err := stateDB.Commit(); err != nil {
		t.Fatalf("commit repeated escrow state: %v", err)
	}
	stateDB = NewStateDB(db)
	escrowBalance, err = stateDB.GetBalance(types.StakingEscrowAddress)
	if err != nil || escrowBalance.Cmp(amount) != 0 {
		t.Fatalf("escrow balance after repeat = %v, err=%v; want unchanged %s", escrowBalance, err, amount)
	}
}

func TestQueuedStakeChangeRejectsDuplicateValidator(t *testing.T) {
	db, err := database.NewLevelDB(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	stateDB := NewStateDB(db)
	change := queuedStakeChange{
		Action:          "stake",
		ValidatorID:     "Node-127.0.0.1:30304",
		Owner:           "owner",
		AmountNSPX:      "32000000000000000000",
		ActivationEpoch: 2,
	}
	if err := stateDB.queueStakeChange(change); err != nil {
		t.Fatal(err)
	}
	change.Action = "unstake"
	if err := stateDB.queueStakeChange(change); err == nil {
		t.Fatal("expected duplicate validator queue entry to be rejected")
	}
}
