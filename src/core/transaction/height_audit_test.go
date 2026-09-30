// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/transaction/height_audit_test.go
//
// Checkpoint 1b item 6: header height audit.
//
// The hazard is that BlockHeader carries TWO height fields — Block (JSON
// "nblock") and Height (JSON "height") — and GetHeight() reads only Block. A
// header literal that sets Height and omits Block therefore compiles, looks
// correct, and reads as height 0: the GENESIS EXEMPTION. VerifyBlockAttestations
// returns nil for height 0 without checking anything, and EpochForHeight(0) is
// epoch 0, so such a block would skip both quorum verification and epoch
// resolution.
package types

import "testing"

// TestGetHeight_DoesNotMasqueradeAsGenesis is the core assertion: a header
// carrying ONLY Height must not read as height 0.
func TestGetHeight_DoesNotMasqueradeAsGenesis(t *testing.T) {
	b := &Block{Header: &BlockHeader{Height: 7}}
	if got := b.GetHeight(); got != 7 {
		t.Fatalf("a block with only Header.Height=7 reads as height %d; it would be "+
			"treated as GENESIS and skip attestation verification entirely", got)
	}
}

// TestGetHeight_BlockIsAuthoritative pins the precedence when both are set: the
// field GetHeight documents as authoritative wins.
func TestGetHeight_BlockIsAuthoritative(t *testing.T) {
	b := &Block{Header: &BlockHeader{Block: 5, Height: 5}}
	if got := b.GetHeight(); got != 5 {
		t.Errorf("GetHeight = %d, want 5", got)
	}
	// Genesis is genuinely 0 in both fields.
	g := &Block{Header: &BlockHeader{Block: 0, Height: 0}}
	if got := g.GetHeight(); got != 0 {
		t.Errorf("genesis GetHeight = %d, want 0", got)
	}
}

// TestValidateHeightFields_RejectsDisagreement is the malformed-header detector.
// It must report, not repair: a block whose two committed height fields disagree
// is one peers will hash differently.
func TestValidateHeightFields_RejectsDisagreement(t *testing.T) {
	ok := &Block{Header: &BlockHeader{Block: 9, Height: 9}}
	if err := ok.ValidateHeightFields(); err != nil {
		t.Errorf("a consistent header was rejected: %v", err)
	}
	bad := &Block{Header: &BlockHeader{Block: 9, Height: 10}}
	if err := bad.ValidateHeightFields(); err == nil {
		t.Error("a header with Block=9, Height=10 was accepted; peers would disagree on its hash")
	}
	if err := (&Block{}).ValidateHeightFields(); err == nil {
		t.Error("a block with no header was accepted")
	}
}

// TestNormalizeHeights_RepairsTheDecodePath covers the one place repair IS
// allowed: a producer's JSON that emitted only one of the two fields.
func TestNormalizeHeights_RepairsTheDecodePath(t *testing.T) {
	// Only Height present -> Block filled in from it.
	a := &Block{Header: &BlockHeader{Height: 12}}
	a.NormalizeHeights()
	if a.Header.Block != 12 || a.Header.Height != 12 {
		t.Errorf("after NormalizeHeights: Block=%d Height=%d, want 12/12", a.Header.Block, a.Header.Height)
	}
	// Only Block present -> Height filled in from it.
	b := &Block{Header: &BlockHeader{Block: 13}}
	b.NormalizeHeights()
	if b.Header.Block != 13 || b.Header.Height != 13 {
		t.Errorf("after NormalizeHeights: Block=%d Height=%d, want 13/13", b.Header.Block, b.Header.Height)
	}
	// Genesis is left alone: 0/0 is legitimate, not a defect.
	g := &Block{Header: &BlockHeader{}}
	g.NormalizeHeights()
	if g.Header.Block != 0 || g.Header.Height != 0 {
		t.Errorf("NormalizeHeights changed genesis to Block=%d Height=%d", g.Header.Block, g.Header.Height)
	}
	// A genuine disagreement is NOT silently resolved away.
	d := &Block{Header: &BlockHeader{Block: 3, Height: 4}}
	d.NormalizeHeights()
	if d.Header.Block != 3 || d.Header.Height != 4 {
		t.Errorf("NormalizeHeights overwrote a real disagreement: Block=%d Height=%d", d.Header.Block, d.Header.Height)
	}
}

// TestNewBlockHeader_SetsBothHeightFields audits the CONSTRUCTOR, the one place
// a well-formed header is minted. If it set only one field, every block in the
// chain would be malformed.
func TestNewBlockHeader_SetsBothHeightFields(t *testing.T) {
	for _, h := range []uint64{0, 1, 2, 1000} {
		hdr := NewBlockHeader(h, nil, nil, nil, nil, nil, nil, nil, nil, 1700000000, nil)
		if hdr.Block != h || hdr.Height != h {
			t.Errorf("NewBlockHeader(%d) set Block=%d Height=%d; both must be %d",
				h, hdr.Block, hdr.Height, h)
		}
		if err := (&Block{Header: hdr}).ValidateHeightFields(); err != nil {
			t.Errorf("NewBlockHeader(%d) produced a malformed header: %v", h, err)
		}
	}
}
