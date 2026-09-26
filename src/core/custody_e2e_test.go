// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package core

import (
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/sphinxfndorg/protocol/src/common"
	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	txtypes "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/pool"
	storage "github.com/sphinxfndorg/protocol/src/state"
)

// buildCustodyNode is one independent node for the custody-spend E2E test: its
// own storage and LevelDB, a genesis block already stored and funded from the
// custodial vault address, a running status, a TPS monitor and a live mempool.
func buildCustodyNode(t *testing.T, genesisTS int64, vault string) (*Blockchain, *database.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := database.NewLevelDB(dir + "/state")
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := storage.NewStorage(dir)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	bc := &Blockchain{storage: store}
	bc.SetStorageDB(db)
	bc.SetStateDB(db)
	bc.chainParams = GetDevnetChainParams()

	s := NewStateDB(db)
	s.SetBalance(vault, nspx(1_000_000))
	s.SetNonce(vault, 0)
	s.SetCGEGenesisTimestamp(genesisTS)
	s.IncrementTotalSupply(nspx(1_000_000))
	stateRoot, err := s.Commit()
	if err != nil {
		t.Fatalf("genesis commit: %v", err)
	}

	genesis := txtypes.NewBlock(&txtypes.BlockHeader{
		Version:    1,
		Block:      0,
		Height:     0,
		Timestamp:  genesisTS,
		Difficulty: big.NewInt(1),
		Nonce:      common.FormatNonce(1),
		TxsRoot:    txtypes.EmptyMerkleRoot,
		StateRoot:  stateRoot,
		GasLimit:   new(big.Int).Set(bc.chainParams.BlockGasLimit),
		GasUsed:    big.NewInt(0),
		ExtraData:  []byte("custody-e2e-genesis"),
		Miner:      make([]byte, 20),
		ParentHash: make([]byte, 32),
	}, txtypes.NewBlockBody(nil, nil, 0))
	genesis.PopulateLogsBloom()
	genesis.FinalizeHash()

	if err := store.StoreBlock(genesis); err != nil {
		t.Fatalf("store genesis: %v", err)
	}
	bc.chain = []*txtypes.Block{genesis}
	bc.tpsMonitor = txtypes.NewTPSMonitor(5 * time.Second)
	bc.SetStatus(StatusRunning)

	bc.mempool = pool.NewMempool(GetDefaultMempoolConfig(), bc)
	t.Cleanup(func() { bc.mempool.Stop() })
	return bc, db
}

func readCustodyBalance(t *testing.T, db *database.DB, addr string) *big.Int {
	t.Helper()
	v, err := NewStateDB(db).GetBalance(addr)
	if err != nil {
		t.Fatalf("read %s: %v", addr, err)
	}
	return v
}

func readCustodyNonce(t *testing.T, db *database.DB, addr string) uint64 {
	t.Helper()
	n, err := NewStateDB(db).GetNonce(addr)
	if err != nil {
		t.Fatalf("read nonce %s: %v", addr, err)
	}
	return n
}

func waitCustodyPending(t *testing.T, bc *Blockchain, txID string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		_, status := bc.mempool.GetTransaction(txID)
		if status == pool.StatusPending {
			return
		}
		if status == pool.StatusInvalid {
			msg, _ := bc.mempool.GetTransactionError(txID)
			t.Fatalf("tx %s rejected by mempool validation: %s", txID, msg)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("tx %s never reached the pending pool", txID)
}

// TestCustodySpendFullPath is the first test that exercises the complete
// spender-initiated custody path: a CLI-style spend message, mempool admission
// on the proposer, JSON gossip transport into a second node's mempool, block
// proposal through CreateBlock, CommitBlock execution, a disk round-trip of
// the sealed block, and a fresh third node that commits ONLY those bytes to
// reach identical state on all three nodes.
func TestCustodySpendFullPath(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	p := setupVaultCustodyPolicy(t, pks, 2, "sphinx-vault-v1")
	vault, err := p.Address()
	if err != nil {
		t.Fatal(err)
	}

	genesisTS := int64(CanonicalGenesisTimestamp)
	chainID := GetDevnetChainParams().ChainID
	proposer, proposerDB := buildCustodyNode(t, genesisTS, vault)
	syncPeer, _ := buildCustodyNode(t, genesisTS, vault)
	fresh, freshDB := buildCustodyNode(t, genesisTS, vault)

	headerTS := genesisTS + 1
	expiry := uint64(headerTS) + uint64(30*24*3600)
	receiver := "00000000000000000000000000000000000000AA"
	amount := nspx(25_000)

	spend := &txtypes.Transaction{
		ID:        "custody-e2e-spend-0",
		ChainID:   chainID,
		Sender:    vault,
		Receiver:  receiver,
		Amount:    amount,
		Nonce:     0,
		Timestamp: headerTS,
	}
	msg := multisig.SpendMessage(&p, chainID, vault, receiver, amount, spend.Nonce, expiry)
	sigs := map[int][]byte{}
	for _, i := range []int{0, 2} {
		sig, err := multisig.SignCustodyMessage(msg, sks[i], pks[i])
		if err != nil {
			t.Fatal(err)
		}
		sigs[i] = sig
	}
	spend.MultiSigWitness = &multisig.MultiSigWitness{Policy: p, Sigs: sigs, Expiry: expiry}
	priceIB(t, proposer, spend)

	startVault := readCustodyBalance(t, proposerDB, vault)
	fee := new(big.Int).Mul(spend.GasLimit, spend.GasPrice)

	// Mempool admission on the proposer through the real AddTransaction entry
	// (policy gate, then the mempool's synchronous witness cryptography).
	if err := proposer.AddTransaction(spend); err != nil {
		t.Fatalf("AddTransaction: %v", err)
	}
	waitCustodyPending(t, proposer, spend.ID)

	// Gossip-equivalent hop: exactly the transform p2p and bind perform —
	// serialize, reject anything that is neither a bundle nor a custody
	// witness shape, deserialize into the peer's own admission path.
	gossip, err := json.Marshal(spend)
	if err != nil {
		t.Fatal(err)
	}
	var wire txtypes.Transaction
	if err := json.Unmarshal(gossip, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.HasFullAuthBundle() {
		t.Fatal("a custody spend must not carry a single-key bundle")
	}
	if !multisig.HasSpendWitnessShape(wire.Sender, wire.MultiSigWitness) {
		t.Fatal("the gossiped custody spend fails the witness-shape screen")
	}
	if err := syncPeer.AddTransaction(&wire); err != nil {
		t.Fatalf("peer AddTransaction: %v", err)
	}
	waitCustodyPending(t, syncPeer, spend.ID)

	// Block proposal pulls the admitted spend from the mempool.
	block, err := proposer.CreateBlock()
	if err != nil {
		t.Fatalf("CreateBlock: %v", err)
	}
	if len(block.Body.TxsList) != 1 {
		t.Fatalf("proposed block has %d txs, want exactly the custody spend", len(block.Body.TxsList))
	}
	got := block.Body.TxsList[0]
	if got.MultiSigWitness == nil || len(got.MultiSigWitness.Sigs) != 2 {
		n := 0
		if got.MultiSigWitness != nil {
			n = len(got.MultiSigWitness.Sigs)
		}
		t.Fatalf("the 2-of-3 witness did not survive proposal, sigs=%d", n)
	}
	if got.ID != spend.ID || got.Sender != vault {
		t.Fatalf("proposal carried the wrong transaction: id=%s sender=%s", got.ID, got.Sender)
	}

	// Commit executes the spend.
	if err := proposer.CommitBlock(block); err != nil {
		t.Fatalf("CommitBlock: %v", err)
	}
	wantVault := new(big.Int).Sub(new(big.Int).Sub(startVault, amount), fee)
	vaultAfter := readCustodyBalance(t, proposerDB, vault)
	if vaultAfter.Cmp(wantVault) != 0 {
		t.Fatalf("vault after commit = %s, want %s (amount + gas fee)", vaultAfter, wantVault)
	}
	if got := readCustodyBalance(t, proposerDB, receiver); got.Cmp(amount) != 0 {
		t.Fatalf("receiver after commit = %s, want %s", got, amount)
	}
	if n := readCustodyNonce(t, proposerDB, vault); n != 1 {
		t.Fatalf("vault nonce after commit = %d, want 1", n)
	}

	// The sealed block survives a disk round-trip, and a fresh node that was
	// never part of the ceremony reaches identical state committing only it.
	stored, err := proposer.storage.GetLatestBlock()
	if err != nil {
		t.Fatalf("read sealed block from disk: %v", err)
	}
	diskBytes, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("marshal disk block: %v", err)
	}
	var synced txtypes.Block
	if err := json.Unmarshal(diskBytes, &synced); err != nil {
		t.Fatalf("unmarshal disk block: %v", err)
	}
	syncedTx := synced.Body.TxsList[0]
	if syncedTx.MultiSigWitness == nil || len(syncedTx.MultiSigWitness.Sigs) != 2 {
		t.Fatal("the witness must survive the disk round-trip")
	}
	if err := fresh.CommitBlock(&synced); err != nil {
		t.Fatalf("fresh node CommitBlock: %v", err)
	}
	if got := readCustodyBalance(t, freshDB, vault); got.Cmp(vaultAfter) != 0 {
		t.Fatalf("fresh node vault = %s, proposer vault = %s", got, vaultAfter)
	}
	if got := readCustodyBalance(t, freshDB, receiver); got.Cmp(amount) != 0 {
		t.Fatalf("fresh node receiver = %s, want %s", got, amount)
	}
	if n := readCustodyNonce(t, freshDB, vault); n != 1 {
		t.Fatalf("fresh node vault nonce = %d, want 1", n)
	}
	if proposerRoot, freshRoot := block.Header.StateRoot, synced.Header.StateRoot; !equalCustodyBytes(proposerRoot, freshRoot) {
		t.Fatalf("state roots diverge: proposer=%x fresh=%x", proposerRoot, freshRoot)
	}
}

// TestCustodySpendBelowThresholdNeverCommits submits the same spend with only
// one of two required signatures and confirms it cannot reach a block: the
// mempool rejects it, and the commit path rejects it too.
func TestCustodySpendBelowThresholdNeverCommits(t *testing.T) {
	sks, pks := escrowTestKeys(t, 3)
	p := setupVaultCustodyPolicy(t, pks, 2, "sphinx-vault-v1")
	vault, err := p.Address()
	if err != nil {
		t.Fatal(err)
	}

	genesisTS := int64(CanonicalGenesisTimestamp)
	chainID := GetDevnetChainParams().ChainID
	proposer, proposerDB := buildCustodyNode(t, genesisTS, vault)

	headerTS := genesisTS + 1
	expiry := uint64(headerTS) + uint64(30*24*3600)
	receiver := "00000000000000000000000000000000000000AA"
	amount := nspx(25_000)

	spend := &txtypes.Transaction{
		ID:        "custody-e2e-spend-thin",
		ChainID:   chainID,
		Sender:    vault,
		Receiver:  receiver,
		Amount:    amount,
		Nonce:     0,
		Timestamp: headerTS,
	}
	msg := multisig.SpendMessage(&p, chainID, vault, receiver, amount, spend.Nonce, expiry)
	sig, err := multisig.SignCustodyMessage(msg, sks[0], pks[0])
	if err != nil {
		t.Fatal(err)
	}
	spend.MultiSigWitness = &multisig.MultiSigWitness{Policy: p, Sigs: map[int][]byte{0: sig}, Expiry: expiry}
	priceIB(t, proposer, spend)

	if err := proposer.AddTransaction(spend); err == nil {
		t.Fatal("a below-threshold witness must be rejected at mempool admission")
	}

	if err := proposer.CommitBlock(custodyBlock(1, headerTS, spend)); err == nil {
		t.Fatal("a below-threshold witness must be rejected at commit")
	}
	if got := readCustodyBalance(t, proposerDB, vault); got.Cmp(nspx(1_000_000)) != 0 {
		t.Fatalf("failed commit must not move funds, vault = %s", got)
	}
}

func equalCustodyBytes(a, b []byte) bool {
	for i := range b {
		if i >= len(a) || a[i] != b[i] {
			return false
		}
	}
	return len(a) == len(b)
}
