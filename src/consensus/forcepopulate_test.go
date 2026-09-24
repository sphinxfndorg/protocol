// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/consensus/forcepopulate_test.go
package consensus

import (
	"bytes"
	"math/big"
	"strings"
	"testing"
	"time"

	logger "github.com/sphinxfndorg/protocol/src/console"
)

// stubChain is a BlockChain whose lookups always miss. That is exactly the
// state of a node during startup/sync: consensus signatures exist for blocks
// that have not reached this node's storage yet. It is also the minimal
// implementation needed to drive ForcePopulateAllSignatures' populated path
// without standing up a full storage stack.
type stubChain struct{}

func (stubChain) GetLatestBlock() Block                               { return nil }
func (stubChain) ValidateBlock(block Block) error                     { return nil }
func (stubChain) CommitBlock(block Block) error                       { return nil }
func (stubChain) GetBlockByHash(hash string) Block                    { return nil }
func (stubChain) GetValidatorStake(validatorID string) *big.Int       { return big.NewInt(0) }
func (stubChain) GetTotalStaked() *big.Int                            { return big.NewInt(0) }
func (stubChain) UpdateValidatorStake(id string, d *big.Int) error    { return nil }
func (stubChain) GetGenesisTime() time.Time                           { return time.Unix(0, 0) }
func (stubChain) GetCheckpointMessage() (*CheckpointMessage, error)   { return nil, nil }
func (stubChain) ApplyCheckpointFromPeer(cp *CheckpointMessage) error { return nil }

// captureNodeLogs redirects the process-wide logger (the one the node writes
// through) into a buffer for one call and returns everything emitted at or
// above level. SetLevel/SetDefaultWriter are global seams, so every test using
// this helper restores them and must not use t.Parallel.
func captureNodeLogs(t *testing.T, level logger.Level, fn func()) string {
	t.Helper()

	buf := &bytes.Buffer{}
	logger.SetDefaultWriter(buf)
	logger.SetLevel(level)
	defer func() {
		logger.SetLevel(logger.INFO) // the node's default (see console.init)
		logger.SetDefaultWriter(nil) // nil restores os.Stdout
	}()

	fn()
	return buf.String()
}

// TestForcePopulateAllSignaturesSilentWhenEmpty pins the fix for the log flood
// seen in a 3-node run, once per 2-second state-machine tick:
//
//	10:58:35.028 INFO Force populating all consensus signatures
//	10:58:35.028 INFO Force population completed for 0 signatures
//	10:58:37.027 INFO Force populating all consensus signatures
//	10:58:37.028 INFO Force population completed for 0 signatures
//
// ForcePopulateAllSignatures is called by StateMachine.syncFinalStates on the
// 2-second replication tick for the entire life of the node (see state/smr.go),
// and on an idle or still-syncing node the signature set is empty. Those two
// INFO lines therefore replayed ~60 times a minute forever, burying the
// actionable startup diagnostics around them. With nothing to populate there is
// nothing an operator needs to be told, so an empty set must log nothing at all
// — at INFO and at DEBUG alike, because the early return is unconditional
// rather than a level change (the remaining lines are per-signature, per-tick).
func TestForcePopulateAllSignaturesSilentWhenEmpty(t *testing.T) {
	// Zero value is sufficient: with an empty set the method returns before it
	// reaches blockChain, so no stub is needed on this path.
	c := &Consensus{}

	for _, level := range []logger.Level{logger.INFO, logger.DEBUG} {
		out := captureNodeLogs(t, level, func() { c.ForcePopulateAllSignatures() })
		if out != "" {
			t.Fatalf("ForcePopulateAllSignatures with an empty signature set logged %d bytes at %v, want silence:\n%s",
				len(out), level, out)
		}
	}
}

// TestForcePopulateAllSignaturesPopulatedStaysOutOfInfo is the other half of the
// fix: the early return must not swallow the real path, and a populated pass
// must stay out of INFO. It runs every 2s, so its progress lines ("Force
// populating %d consensus signatures", one per signature, and the completion
// line) were moved to DEBUG. This asserts both directions: at INFO — the level a
// running node logs at — a populated pass prints nothing, while at DEBUG it
// still reports its work, and the signature is still populated.
func TestForcePopulateAllSignaturesPopulatedStaysOutOfInfo(t *testing.T) {
	newPopulated := func() *Consensus {
		c := &Consensus{blockChain: stubChain{}}
		c.consensusSignatures = []*ConsensusSignature{{
			BlockHash:   "abcdef0123456789",
			MessageType: "prepare",
			// MerkleRoot and Status are deliberately unset: populating them is
			// exactly what this method exists to do.
		}}
		return c
	}

	// 1. At INFO — the level a running node logs at — a populated pass is silent.
	if out := captureNodeLogs(t, logger.INFO, func() { newPopulated().ForcePopulateAllSignatures() }); out != "" {
		t.Fatalf("a populated ForcePopulateAllSignatures pass logged %d bytes at INFO, want silence (this runs every 2s):\n%s",
			len(out), out)
	}

	// 2. At DEBUG the same pass still reports what it did.
	c := newPopulated()
	out := captureNodeLogs(t, logger.DEBUG, func() { c.ForcePopulateAllSignatures() })
	for _, want := range []string{
		"Force populating 1 consensus signatures",
		"Force population completed for 1 signatures",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("DEBUG output missing %q; got:\n%s", want, out)
		}
	}

	// 3. And the work itself still happened: the block is not in storage, so the
	//    merkle root gets the block_not_found_ placeholder and the status is
	//    derived from the message type.
	sig := c.consensusSignatures[0]
	if !strings.HasPrefix(sig.MerkleRoot, "block_not_found_") {
		t.Errorf("MerkleRoot = %q, want block_not_found_<hash prefix> placeholder", sig.MerkleRoot)
	}
	if sig.Status != "prepared" {
		t.Errorf("Status = %q, want \"prepared\" (derived from MessageType \"prepare\")", sig.Status)
	}
}
