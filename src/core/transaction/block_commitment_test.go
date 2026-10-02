package types

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
)

func TestBlockCommitmentsAffectHashAndSurviveJSON(t *testing.T) {
	header := &BlockHeader{
		Version:               1,
		Block:                 1,
		Height:                1,
		Timestamp:             1,
		ParentHash:            make([]byte, 32),
		Difficulty:            big.NewInt(1),
		Nonce:                 common.FormatNonce(1),
		TxsRoot:               EmptyMerkleRoot,
		StateRoot:             common.SpxHash([]byte("state")),
		GasLimit:              big.NewInt(1_000_000),
		GasUsed:               big.NewInt(0),
		UnclesHash:            CalculateUnclesHash(nil, 1),
		Miner:                 make([]byte, 20),
		ActiveSnapshotHash:    "snapshot-a",
		GenesisDocumentDigest: "genesis-a",
	}
	block := NewBlock(header, &BlockBody{})
	block.FinalizeHash()
	firstHash := block.GetHash()
	if generated := string(block.GenerateBlockHash()); generated != firstHash {
		t.Fatalf("GenerateBlockHash() = %q, finalized hash = %q", generated, firstHash)
	}

	encoded, err := json.Marshal(block)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Block
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Header.ActiveSnapshotHash != header.ActiveSnapshotHash ||
		decoded.Header.GenesisDocumentDigest != header.GenesisDocumentDigest {
		t.Fatalf("commitments were not preserved by JSON round trip: %#v", decoded.Header)
	}
	if !bytes.Equal(decoded.GenerateBlockHash(), block.Header.Hash) {
		t.Fatal("JSON round trip changed the committed block hash")
	}

	header.ActiveSnapshotHash = "snapshot-b"
	block.FinalizeHash()
	if block.GetHash() == firstHash {
		t.Fatal("changing the active snapshot commitment did not change the block hash")
	}
	header.GenesisDocumentDigest = "genesis-b"
	previousHash := block.GetHash()
	block.FinalizeHash()
	if block.GetHash() == previousHash {
		t.Fatal("changing the genesis-document commitment did not change the block hash")
	}
}
