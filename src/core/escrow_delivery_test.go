// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	txtypes "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// buildEscrowNode builds one independent node: its own storage, its own
// LevelDB and its own committed parent state (escrow funded + the CGE clock
// origin recorded the way block 0 records it).
func buildEscrowNode(t *testing.T, genesisTS int64) (*Blockchain, *database.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.NewLevelDB(dir + "/state")
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	bc := mkIB(t, dir, db)
	bc.chainParams = GetDevnetChainParams()

	s := NewStateDB(db)
	s.SetBalance(GetCGEEscrowAddress(), nspx(425_000_000))
	s.IncrementTotalSupply(nspx(425_000_000))
	s.SetCGEGenesisTimestamp(genesisTS)
	if _, err := s.Commit(); err != nil {
		t.Fatalf("seed commit: %v", err)
	}
	return bc, db
}

// escrowDeliveryBlock builds the block as a proposer would seal it: the sealed
// timestamp and the witness set are the only CGE inputs, and both travel in
// the block itself.
func escrowDeliveryBlock(t *testing.T, height uint64, ts int64, ws []*txtypes.CGEReleaseWitness) *txtypes.Block {
	t.Helper()
	body := txtypes.NewBlockBody(nil, nil, height)
	body.CGEWitnesses = ws
	gasLimit := GetDevnetChainParams().BlockGasLimit
	return txtypes.NewBlock(&txtypes.BlockHeader{
		Version:    1,
		Block:      height,
		Height:     height,
		Timestamp:  ts,
		Difficulty: big.NewInt(1),
		Nonce:      common.FormatNonce(2),
		GasLimit:   new(big.Int).Set(gasLimit),
		GasUsed:    big.NewInt(0),
		ParentHash: make([]byte, 32),
		Miner:      make([]byte, 20),
	}, body)
}

// TestEscrowWitnessDeliveryTwoNodesFromBlockData is the end-to-end delivery
// test: the proposer stages a witness, previews the state root and seals a
// block. A second, fully independent node then receives ONLY the serialized
// block and must reach the identical state root and identical balances.
func TestEscrowWitnessDeliveryTwoNodesFromBlockData(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	p := setupEscrowPolicy(t, pks, 2)

	const height = uint64(2)
	genesisTS := int64(CanonicalGenesisTimestamp)
	headerTS := genesisTS + 12*policy.CGEMonthSeconds
	expiry := uint64(headerTS) + uint64(12*policy.CGEMonthSeconds)

	founder := allocByLabel(t, "Founder")
	delta := policy.CGEScheduleForLabel(founder.Label).UnlockedAt(headerTS-genesisTS, founder.BalanceNSPX)
	if delta.Sign() <= 0 {
		t.Fatalf("month-12 tranche must be positive, got %s", delta)
	}

	proposer, _ := buildEscrowNode(t, genesisTS)
	verifier, verifierDB := buildEscrowNode(t, genesisTS)

	msg := cgeReleaseMessage(proposer, founder.Address, delta, height, expiry)
	w := signWitness(t, proposer, p, sks, pks, []int{0, 1}, msg, expiry)

	// Proposer intake: goes through the expiry-horizon sanity check.
	if err := proposer.SubmitCGEWitness(founder.Address, height, w, uint64(headerTS)); err != nil {
		t.Fatalf("SubmitCGEWitness: %v", err)
	}
	staged := proposer.pendingBlockWitnesses(height)
	if len(staged) != 1 || staged[0].Recipient != founder.Address {
		t.Fatalf("staged witnesses = %+v, want one for %s", staged, founder.Address)
	}

	// The proposer's preview must already include the gated release.
	previewRoot := proposer.previewStateRoot(height, nil, "", headerTS, staged)
	if len(previewRoot) == 0 {
		t.Fatal("proposer preview produced an empty state root")
	}

	// Seal the block; the verifier gets nothing but its bytes.
	wire, err := json.Marshal(escrowDeliveryBlock(t, height, headerTS, staged))
	if err != nil {
		t.Fatalf("marshal block: %v", err)
	}
	var received txtypes.Block
	if err := json.Unmarshal(wire, &received); err != nil {
		t.Fatalf("unmarshal block: %v", err)
	}
	if got := BlockWitnesses(&received); len(got) != 1 {
		t.Fatalf("witness did not survive block transport: %d carried", len(got))
	}

	root, err := verifier.ExecuteBlock(&received)
	if err != nil {
		t.Fatalf("verifier ExecuteBlock: %v", err)
	}
	if !bytes.Equal(previewRoot, root) {
		t.Fatalf("proposer preview root != verifier root:\npreview=%x\nverify =%x", previewRoot, root)
	}

	vs := NewStateDB(verifierDB)
	bal, err := vs.GetBalance(founder.Address)
	if err != nil {
		t.Fatalf("read founder balance: %v", err)
	}
	if bal.Cmp(delta) != 0 {
		t.Fatalf("verifier founder balance = %s, want the released tranche %s", bal.String(), delta.String())
	}
	wantEscrow := new(big.Int).Sub(nspx(425_000_000), delta)
	escrowBal, err := vs.GetBalance(GetCGEEscrowAddress())
	if err != nil {
		t.Fatalf("read escrow balance: %v", err)
	}
	if escrowBal.Cmp(wantEscrow) != 0 {
		t.Fatalf("verifier escrow balance = %s, want %s", escrowBal.String(), wantEscrow.String())
	}

	// The proposer, executing the very same block bytes, must agree.
	proposerRoot, err := proposer.ExecuteBlock(&received)
	if err != nil {
		t.Fatalf("proposer ExecuteBlock: %v", err)
	}
	if !bytes.Equal(proposerRoot, root) {
		t.Fatalf("two independent nodes diverged on identical block bytes:\nA=%x\nB=%x", proposerRoot, root)
	}
}

func TestEscrowWitnessDeliveryRejectsBadWitnesses(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	p := setupEscrowPolicy(t, pks, 2)

	const height = uint64(2)
	genesisTS := int64(CanonicalGenesisTimestamp)
	headerTS := genesisTS + 12*policy.CGEMonthSeconds
	expiry := uint64(headerTS) + uint64(12*policy.CGEMonthSeconds)
	founder := allocByLabel(t, "Founder")
	delta := policy.CGEScheduleForLabel(founder.Label).UnlockedAt(headerTS-genesisTS, founder.BalanceNSPX)

	// Release messages are chain-scoped (domain || chainID || escrow || …), so
	// they must be signed against a real chain-params context — the same one
	// the executing node recomputes from.
	msgBC, _ := buildEscrowNode(t, genesisTS)
	msg := cgeReleaseMessage(msgBC, founder.Address, delta, height, expiry)
	expiredMsg := cgeReleaseMessage(msgBC, founder.Address, delta, height, uint64(headerTS)-1)
	soonMsg := cgeReleaseMessage(msgBC, founder.Address, delta, height, uint64(headerTS)+1)

	// Each case runs on a fresh node, so a rejected release is visible as an
	// untouched founder balance.
	run := func(t *testing.T, w multisig.MultiSigWitness) *big.Int {
		t.Helper()
		bc, db := buildEscrowNode(t, genesisTS)
		block := escrowDeliveryBlock(t, height, headerTS, []*txtypes.CGEReleaseWitness{
			{Recipient: founder.Address, Witness: w},
		})
		if _, err := bc.ExecuteBlock(block); err != nil {
			t.Fatalf("ExecuteBlock: %v", err)
		}
		bal, err := NewStateDB(db).GetBalance(founder.Address)
		if err != nil {
			t.Fatalf("read founder balance: %v", err)
		}
		return bal
	}

	// Below threshold: one valid signature is not enough for a 2-of-3 policy.
	below := signWitness(t, nil, p, sks, pks, []int{0}, msg, expiry)
	if bal := run(t, below); bal.Sign() != 0 {
		t.Fatalf("below-threshold witness must not mutate state, got %s", bal.String())
	}

	// Expired: the sealed header timestamp is already past the witness expiry.
	expired := signWitness(t, nil, p, sks, pks, []int{0, 1}, expiredMsg, uint64(headerTS)-1)
	if bal := run(t, expired); bal.Sign() != 0 {
		t.Fatalf("expired witness must not mutate state, got %s", bal.String())
	}

	// Signature is valid but the expiry sits inside the minimum horizon: the
	// witness would die the moment a release landed one slot late.
	soon := signWitness(t, nil, p, sks, pks, []int{0, 1}, soonMsg, uint64(headerTS)+1)
	if bal := run(t, soon); bal.Sign() != 0 {
		t.Fatalf("witness inside the minimum expiry horizon must not mutate state, got %s", bal.String())
	}

	// No witness carried at all.
	if bal := run(t, multisig.MultiSigWitness{}); bal.Sign() != 0 {
		t.Fatalf("absent witness must not mutate state, got %s", bal.String())
	}

	// Sanity: the good witness does release, so the rejections above are not
	// the result of the schedule never firing.
	good := signWitness(t, nil, p, sks, pks, []int{0, 1}, msg, expiry)
	if bal := run(t, good); bal.Cmp(delta) != 0 {
		t.Fatalf("valid witness must release %s, got %s", delta.String(), bal.String())
	}
}

// TestEscrowWitnessIntakeHorizon guards the proposer-side construction check:
// an operator cannot stage a witness that is already dead or that stays valid
// for an absurdly long window.
func TestEscrowWitnessIntakeHorizon(t *testing.T) {
	_, pks := escrowTestKeys(t, 3)
	p := setupEscrowPolicy(t, pks, 2)

	bc, _ := buildEscrowNode(t, int64(CanonicalGenesisTimestamp))
	ref := uint64(CanonicalGenesisTimestamp)

	if err := bc.SubmitCGEWitness("recipient", 1, multisig.MultiSigWitness{Policy: p, Expiry: 0}, ref); err == nil {
		t.Fatal("unset expiry must be rejected at intake")
	}
	if err := bc.SubmitCGEWitness("recipient", 1, multisig.MultiSigWitness{Policy: p, Expiry: ref + 60}, ref); err == nil {
		t.Fatal("expiry inside the minimum horizon must be rejected at intake")
	}
	ok := multisig.MultiSigWitness{Policy: p, Sigs: map[int][]byte{0: {0x01}}, Expiry: ref + 30*24*3600}
	if err := bc.SubmitCGEWitness("recipient", 1, ok, ref); err != nil {
		t.Fatalf("one-month horizon witness must be accepted at intake: %v", err)
	}
	if got := bc.pendingBlockWitnesses(1); len(got) != 1 {
		t.Fatalf("staged witnesses = %d, want 1", len(got))
	}
	bc.dropPendingBlockWitnesses(1)
	if got := bc.pendingBlockWitnesses(1); len(got) != 0 {
		t.Fatalf("staged witnesses must be cleared after sealing, got %d", len(got))
	}
}
