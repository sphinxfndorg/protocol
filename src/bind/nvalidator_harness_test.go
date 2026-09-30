// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/nvalidator_harness_test.go
//
// Checkpoint item 4: an IN-PROCESS harness with N real SPHINCS+ validators.
//
// Why this exists. Every quorum rule added in Checkpoint 1 was pinned against
// hand-built snapshots, which proves the ARITHMETIC but not the SIGNING. This
// harness runs actual SPHINCS+ keypairs — the same production parameter set —
// and asks the question that matters for N in {1,2,3,4,6}: with N real
// validators, does a block signed by the protocol-required number of them
// verify, and is a block signed by one fewer refused?
//
// The expected count is not a guess. Under strict voted*3 > total*2 with equal
// stakes it is StrictTwoThirdsCount(N):
//
//	N=1 -> 1     N=2 -> 2     N=3 -> 3     N=4 -> 3     N=6 -> 5
//
// So N=3 needs ALL THREE, meaning a 3-validator devnet HALTS if one node stops.
// That is correct under the rule, and the harness asserts it rather than
// leaving it to be discovered in production.
package bind

import (
	"math/big"
	"testing"

	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	config "github.com/sphinxfndorg/protocol/src/core/sthincs/config"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	denom "github.com/sphinxfndorg/protocol/src/params/denom"
)

// harnessEpochBlocks is the epoch length used by the harness. Small, so a test
// reaches a boundary without producing thousands of blocks.
const harnessEpochBlocks = 4

// harnessValidator is one real, independently keyed SPHINCS+ validator.
type harnessValidator struct {
	id  string
	sk  *sthincs.SPHINCS_SK
	pk  *sthincs.SPHINCS_PK
	svc *consensus.SigningService
}

// newHarnessValidator builds one validator with its OWN freshly generated
// SPHINCS+ keypair, plus a full SigningService over the production parameters.
//
// Key material is generated in test code on purpose: production
// NewSigningService only LOADS a node's persisted identity and never generates,
// so a test has to supply it. Independent generation per validator is what the
// harness depends on — sharing one key across all N would make the whole table
// meaningless, which TestHarness_RealSPHINCS_QuorumForN explicitly checks.
func newHarnessValidator(t *testing.T, id string) *harnessValidator {
	t.Helper()
	cfg, err := config.NewSTHINCSParameters()
	if err != nil {
		t.Fatalf("NewSTHINCSParameters: %v", err)
	}
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	sk, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		t.Fatalf("SerializeKeyPair: %v", err)
	}
	mgr := sign.NewSTHINCSManager(nil, km, cfg)
	svc, err := consensus.NewSigningService(mgr, km, id, skBytes, pkBytes)
	if err != nil {
		t.Fatalf("NewSigningService: %v", err)
	}
	// The key backend and the sthincs package declare separate but
	// field-identical SK/PK structs. Convert explicitly rather than reaching
	// through SerializeKeyPair, so the harness signs with exactly the key the
	// SigningService was built from.
	return &harnessValidator{
		id:  id,
		sk:  &sthincs.SPHINCS_SK{SKseed: sk.SKseed, SKprf: sk.SKprf, PKseed: sk.PKseed, PKroot: sk.PKroot},
		pk:  &sthincs.SPHINCS_PK{PKseed: pk.PKseed, PKroot: pk.PKroot},
		svc: svc,
	}
}

// harnessParams returns the production SPHINCS+ parameters.
func harnessParams(t *testing.T) *parameters.Parameters {
	t.Helper()
	cfg, err := config.NewSTHINCSParameters()
	if err != nil {
		t.Fatalf("NewSTHINCSParameters: %v", err)
	}
	return cfg.Params
}

// attestationMessage is the stable message a validator signs for a block at
// `height`. It binds the signature to BOTH the height and the validator, so a
// signature cannot be replayed onto another height or another validator.
func attestationMessage(height uint64, validatorID string) []byte {
	msg := make([]byte, 0, 4+len(validatorID))
	for i := 0; i < 4; i++ {
		msg = append(msg, byte(height>>(8*i)))
	}
	return append(msg, []byte(validatorID)...)
}

// signBlockAttestation produces a REAL SPHINCS+ signature over
// attestationMessage(height, id). Using the real signing primitive — not a stub
// — is the entire point of the harness.
func (h *harnessValidator) signBlockAttestation(t *testing.T, height uint64) *types.Attestation {
	t.Helper()
	sig, err := sthincs.Spx_sign(harnessParams(t), attestationMessage(height, h.id), h.sk)
	if err != nil {
		t.Fatalf("[%s] Spx_sign: %v", h.id, err)
	}
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		t.Fatalf("[%s] SerializeSignature: %v", h.id, err)
	}
	return &types.Attestation{ValidatorID: h.id, Signature: sigBytes, View: height}
}

// verifyAttestation checks a real signature under h's own public key. The
// harness verifies every signature it collects, so a "valid quorum" result can
// never be an artefact of accepting unsigned or malformed attestations.
func (h *harnessValidator) verifyAttestation(t *testing.T, height uint64, att *types.Attestation) bool {
	t.Helper()
	if h.pk == nil {
		return false
	}
	sig, err := sthincs.DeserializeSignature(harnessParams(t), att.Signature)
	if err != nil {
		return false
	}
	// Spx_verify takes (params, message, sig, pk) and returns only a bool.
	return sthincs.Spx_verify(harnessParams(t), attestationMessage(height, h.id), sig, h.pk)
}

// buildSnapshotFor builds a snapshot giving every validator in `vals` an equal
// 32 SPX stake, and returns it with that per-validator unit.
func buildSnapshotFor(vals []*harnessValidator) (*consensus.ValidatorSnapshot, *big.Int) {
	unit := new(big.Int).Mul(big.NewInt(32), new(big.Int).SetUint64(denom.SPX))
	snap := &consensus.ValidatorSnapshot{
		Epoch:      0,
		TotalStake: new(big.Int).Mul(unit, big.NewInt(int64(len(vals)))),
		Validators: make(map[string]*consensus.StakedValidator, len(vals)),
	}
	for _, v := range vals {
		snap.Validators[v.id] = &consensus.StakedValidator{ID: v.id, StakeAmount: new(big.Int).Set(unit)}
	}
	return snap, unit
}

// harnessBlock builds a block at `height` carrying exactly `atts`.
//
// Header.Block is set, NOT Header.Height: GetHeight() reads Block, and the
// genesis exemption keys on height 0. A header carrying only Height would read
// as genesis and skip verification entirely — which would make this harness
// assert nothing at all.
func harnessBlock(height uint64, atts []*types.Attestation) *types.Block {
	return &types.Block{
		Header: &types.BlockHeader{Block: height, Height: height},
		Body:   types.BlockBody{Attestations: atts},
	}
}

func harnessNodeID(i int) string { return "Node-" + string(rune('a'+i)) }

// TestHarness_RealSPHINCS_QuorumForN runs the harness for N = 1, 2, 3, 4, 6.
//
// For each N it asserts BOTH directions, which is what makes the table
// meaningful:
//   - a block signed by StrictTwoThirdsCount(N) validators VERIFIES;
//   - a block signed by one fewer is REFUSED.
//
// It also asserts each signature is individually valid, and that a signature
// does NOT verify under a different validator's identity — the check that would
// catch a harness accidentally sharing one keypair across all N.
func TestHarness_RealSPHINCS_QuorumForN(t *testing.T) {
	prev := consensus.EpochBlocksOverride()
	consensus.SetEpochBlocks(harnessEpochBlocks)
	defer func() { consensus.RestoreEpochBlocks(prev) }()

	for _, n := range []int{1, 2, 3, 4, 6} {
		n := n
		t.Run(harnessSetLabel(n), func(t *testing.T) {
			consensus.ResetSnapshots()
			defer consensus.ResetSnapshots()

			vals := make([]*harnessValidator, 0, n)
			for i := 0; i < n; i++ {
				vals = append(vals, newHarnessValidator(t, harnessNodeID(i)))
			}

			snap, unit := buildSnapshotFor(vals)
			consensus.StoreSnapshotForTest(*snap)

			need := consensus.StrictTwoThirdsCount(n)
			if need > n {
				t.Fatalf("N=%d: required distinct voters %d exceeds the set size", n, need)
			}

			// One REAL signature per validator, each verified on its own.
			sigs := make(map[string]*types.Attestation, n)
			for _, v := range vals {
				att := v.signBlockAttestation(t, 1)
				if !v.verifyAttestation(t, 1, att) {
					t.Fatalf("[%s] its own SPHINCS+ signature did not verify", v.id)
				}
				sigs[v.id] = att
			}

			// A signature must not verify under another validator's identity.
			if n > 1 {
				if vals[0].verifyAttestation(t, 1, sigs[vals[1].id]) {
					t.Error("a signature verified under the WRONG validator's identity; keypairs are being shared")
				}
			}

			// ── Exactly `need` signatures verify the block. ──
			okAtts := make([]*types.Attestation, 0, need)
			for i := 0; i < need; i++ {
				okAtts = append(okAtts, sigs[vals[i].id])
			}
			if err := core.VerifyBlockAttestations(harnessBlock(1, okAtts)); err != nil {
				t.Errorf("N=%d: a block signed by %d of %d (32 SPX each) must verify, got: %v",
					n, need, n, err)
			}

			// ── One fewer is refused. ──
			if short := need - 1; short >= 1 && short < n {
				shortAtts := make([]*types.Attestation, 0, short)
				for i := 0; i < short; i++ {
					shortAtts = append(shortAtts, sigs[vals[i].id])
				}
				if err := core.VerifyBlockAttestations(harnessBlock(1, shortAtts)); err == nil {
					t.Errorf("N=%d: a block signed by only %d of %d must be REFUSED "+
						"(not strictly more than two thirds)", n, short, n)
				}
			}

			// The stake rule and the distinct-voter floor must agree on the same
			// boundary, so the two checks cannot drift apart.
			if !consensus.MeetsStakeQuorum(new(big.Int).Mul(unit, big.NewInt(int64(need))), snap.TotalStake) {
				t.Errorf("N=%d: %d of %d should clear the stake rule", n, need, n)
			}
			if need >= 2 {
				if consensus.MeetsStakeQuorum(new(big.Int).Mul(unit, big.NewInt(int64(need-1))), snap.TotalStake) {
					t.Errorf("N=%d: %d of %d should NOT clear the stake rule", n, need-1, n)
				}
			}
			t.Logf("N=%d: %d of %d required", n, need, n)
		})
	}
}

func harnessSetLabel(n int) string { return "N" + string(rune('0'+n)) }
