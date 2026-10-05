// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/pinned_genesis_test.go
package core

import (
	"strings"
	"testing"
)

// pinnedMainnetGenesis builds the smallest document ValidatePinnedGenesisDocument
// accepts: a non-bootstrap mainnet document naming one founder validator with a
// committed public key and positive stake, on the real mainnet chain IDs.
func pinnedMainnetGenesis(t *testing.T) *GenesisStateFile {
	t.Helper()
	mainnet := GetSphinxChainParams()
	return &GenesisStateFile{
		Version: genesisStateFileVersion,
		ChainID: mainnet.ChainID,
		Chain: GenesisChainParams{
			ChainID:      mainnet.ChainID,
			Network:      string(PhaseMainnet),
			EpochBlocks:  DevnetEpochBlocks,
			MinStakeNSPX: "32",
		},
		Validators: []GenesisStakedValidator{
			{
				NodeID:        "Node-203.0.113.10:30303",
				PublicKey:     strings.Repeat("ab", 32),
				StakeNSPX:     "32000000000000000000",
				RewardAddress: "SPIF0000000000000000000000000000000000000000",
			},
		},
	}
}

// The pin is the root of trust: a document whose ConsensusDigest matches the
// out-of-band pin must be accepted, and every way of getting that pin wrong
// must fail closed before the document is trusted.
func TestValidatePinnedGenesisDocument_DigestPinContract(t *testing.T) {
	good := pinnedMainnetGenesis(t)
	correctPin, err := good.ConsensusDigest()
	if err != nil {
		t.Fatalf("ConsensusDigest: %v", err)
	}

	t.Run("matching pin accepted", func(t *testing.T) {
		if err := ValidatePinnedGenesisDocument(pinnedMainnetGenesis(t), "mainnet", correctPin); err != nil {
			t.Fatalf("a document matching its pinned digest must be accepted: %v", err)
		}
		// The comparison is case-insensitive: operators may publish upper case.
		if err := ValidatePinnedGenesisDocument(pinnedMainnetGenesis(t), "mainnet", strings.ToUpper(correctPin)); err != nil {
			t.Fatalf("an upper-case form of the same pin must be accepted: %v", err)
		}
	})

	t.Run("digest mismatch refused", func(t *testing.T) {
		wrong := strings.Repeat("0", 64)
		if wrong == correctPin {
			t.Skip("document digest unexpectedly all zeros")
		}
		err := ValidatePinnedGenesisDocument(pinnedMainnetGenesis(t), "mainnet", wrong)
		if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
			t.Fatalf("a wrong pin must be refused with a digest mismatch, got: %v", err)
		}
	})

	t.Run("short pin refused", func(t *testing.T) {
		err := ValidatePinnedGenesisDocument(pinnedMainnetGenesis(t), "mainnet", correctPin[:32])
		if err == nil || !strings.Contains(err.Error(), "64-character hex") {
			t.Fatalf("a short pin must be refused, got: %v", err)
		}
	})

	t.Run("non-hex pin refused", func(t *testing.T) {
		err := ValidatePinnedGenesisDocument(pinnedMainnetGenesis(t), "mainnet", strings.Repeat("z", 64))
		if err == nil || !strings.Contains(err.Error(), "not valid hex") {
			t.Fatalf("a non-hex pin must be refused, got: %v", err)
		}
	})

	t.Run("devnet refused", func(t *testing.T) {
		err := ValidatePinnedGenesisDocument(pinnedMainnetGenesis(t), "devnet", correctPin)
		if err == nil || !strings.Contains(err.Error(), "only for mainnet or testnet") {
			t.Fatalf("pinned validation must not run for devnet, got: %v", err)
		}
	})

	t.Run("nil document refused", func(t *testing.T) {
		if err := ValidatePinnedGenesisDocument(nil, "mainnet", correctPin); err == nil {
			t.Fatal("a missing document must be refused")
		}
	})
}

// The structural preconditions: a self-authored bootstrap document, a document
// with no founder validator set, or one stamped for the wrong chain must never
// reach the digest comparison — they are refused first, whatever the pin says.
func TestValidatePinnedGenesisDocument_StructuralRefusals(t *testing.T) {
	good := pinnedMainnetGenesis(t)
	correctPin, err := good.ConsensusDigest()
	if err != nil {
		t.Fatalf("ConsensusDigest: %v", err)
	}

	t.Run("bootstrap document refused", func(t *testing.T) {
		gf := pinnedMainnetGenesis(t)
		gf.Bootstrap = true
		err := ValidatePinnedGenesisDocument(gf, "mainnet", correctPin)
		if err == nil || !strings.Contains(err.Error(), "bootstrap") {
			t.Fatalf("a self-authored bootstrap document must be refused, got: %v", err)
		}
	})

	t.Run("missing validator set refused", func(t *testing.T) {
		gf := pinnedMainnetGenesis(t)
		gf.Validators = nil
		err := ValidatePinnedGenesisDocument(gf, "mainnet", correctPin)
		if err == nil || !strings.Contains(err.Error(), "validator set") {
			t.Fatalf("a document with no founder validator set must be refused, got: %v", err)
		}
	})

	t.Run("wrong chain ID refused", func(t *testing.T) {
		gf := pinnedMainnetGenesis(t)
		gf.ChainID++
		gf.Chain.ChainID++
		err := ValidatePinnedGenesisDocument(gf, "mainnet", correctPin)
		if err == nil || !strings.Contains(err.Error(), "chain ID mismatch") {
			t.Fatalf("a document for another chain must be refused, got: %v", err)
		}
	})

	t.Run("validator without public key refused", func(t *testing.T) {
		gf := pinnedMainnetGenesis(t)
		gf.Validators[0].PublicKey = ""
		err := ValidatePinnedGenesisDocument(gf, "mainnet", correctPin)
		if err == nil || !strings.Contains(err.Error(), "public key") {
			t.Fatalf("a founder validator without a public key must be refused, got: %v", err)
		}
	})

	t.Run("validator with zero stake refused", func(t *testing.T) {
		gf := pinnedMainnetGenesis(t)
		gf.Validators[0].StakeNSPX = "0"
		err := ValidatePinnedGenesisDocument(gf, "mainnet", correctPin)
		if err == nil || !strings.Contains(err.Error(), "stake") {
			t.Fatalf("a founder validator with zero stake must be refused, got: %v", err)
		}
	})
}
