// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/multisig_coverage.go
//
// `multisig coverage` — the pre-flight check that gates step 3 (flipping
// escrowEnforced). It answers the operational question an operator cannot
// answer by reading the config: for every time-based CGE recipient, is there
// a staged witness that is actually usable, far enough into the future?
//
// ★ WHY THIS EXISTS: this is the third instance of the same failure shape
// (a policy present / a mechanism built, but coverage incomplete and nothing
// forcing you to notice). Flipping enforcement with an uncovered recipient
// does not secure that recipient's vesting — it silently skips every one of
// their releases. The check exits non-zero when coverage is incomplete, so a
// rollout gate can be `multisig coverage && flip` instead of a promise.
package utils

import (
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/sphinxfndorg/protocol/src/core"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/rpc"
)

// defaultCoverageHorizon is how far past the current sealed timestamp the
// pre-flight demands coverage for when --horizon is not given: one CGE month,
// matching the schedule's own granularity (every schedule is a whole number
// of 30-day months), so "covered" means "can never be surprised by the next
// cliff".
var defaultCoverageHorizon = time.Duration(policy.CGEMonthSeconds) * time.Second

// runMultisigCoverage reports staged-witness coverage for every time-based CGE
// recipient and fails loudly when any of them is uncovered.
//
//	multisig coverage --policy config/escrow_multisig.json \
//	    --dir config/cge_witnesses --rpc 127.0.0.1:8700 [--horizon <unix>]
//
// The reference timestamps are CHAIN-derived (the sealed tip header), never a
// wall clock: a witness that looks fine on the operator's laptop but expires
// before the chain reaches the cliff is exactly the mistake this catches.
// --now exists for offline planning against a known chain state, not as the
// normal path.
func runMultisigCoverage(args []string) error {
	fs := flag.NewFlagSet("multisig coverage", flag.ContinueOnError)
	policyPath := fs.String("policy", custodyRoles["escrow"].OutPath, "escrow custody policy JSON the node auto-loads (required)")
	dir := fs.String("dir", core.DefaultCGEWitnessDir, "directory of pre-signed CGE witness files to audit")
	rpcAddr := fs.String("rpc", "127.0.0.1:8700", "node JSON-RPC host:port used to read the sealed tip timestamp")
	nowFlag := fs.Uint64("now", 0, "chain timestamp to evaluate against (0 = read the sealed tip from --rpc)")
	horizonFlag := fs.Uint64("horizon", 0, "require coverage through this unix timestamp (0 = --now + one CGE month)")
	asJSON := fs.Bool("json", false, "print the coverage rows as JSON (for a rollout gate)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Loading the policy publishes the address the staged witnesses must be
	// signed under. Enforcement is deliberately NOT touched here: the whole
	// point is to decide whether it is safe to enable.
	if *policyPath == "" {
		return fmt.Errorf("--policy is required (the escrow policy the node auto-loads)")
	}
	addr, err := core.LoadEscrowPolicy(*policyPath)
	if err != nil {
		return fmt.Errorf("escrow custody policy %s: %w", *policyPath, err)
	}

	nowTS := *nowFlag
	if nowTS == 0 {
		nowTS, err = chainTipTimestamp(*rpcAddr)
		if err != nil {
			return fmt.Errorf("read the sealed tip timestamp from %s: %w (pass --now for offline planning)", *rpcAddr, err)
		}
	}
	horizonTS := *horizonFlag
	if horizonTS == 0 {
		horizonTS = nowTS + uint64(defaultCoverageHorizon.Seconds())
	}
	if horizonTS < nowTS {
		return fmt.Errorf("--horizon %d is before --now %d", horizonTS, nowTS)
	}

	coverage, err := core.CheckCGEWitnessCoverage(*dir, nowTS, horizonTS)
	if err != nil {
		return err
	}
	if len(coverage) == 0 {
		return fmt.Errorf("no time-based CGE recipients found — refusing to report READY")
	}

	if *asJSON {
		data, err := json.MarshalIndent(coverage, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	} else {
		fmt.Printf("escrow=%s policy=%s dir=%s\n", addr, *policyPath, *dir)
		fmt.Print(core.FormatCGEWitnessCoverage(coverage, horizonTS))
	}

	// The verdict IS the exit code: a rollout gate can depend on it.
	if !core.CGEWitnessCoverageReady(coverage) {
		return fmt.Errorf("CGE witness coverage is incomplete — do NOT enable enforcement (escrowEnforced) until every recipient above is COVERED")
	}
	return nil
}

// chainTipTimestamp reads the sealed tip header timestamp over JSON-RPC. It is
// the only clock this command trusts: the header was agreed by consensus, so
// every node sees the same value, unlike time.Now().
func chainTipTimestamp(rpcAddr string) (uint64, error) {
	raw, err := rpc.CallRPC(rpcAddr, "getblockheader", []interface{}{"latest"}, 30)
	if err != nil {
		return 0, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return 0, fmt.Errorf("node returned no tip header")
	}
	var hdr types.BlockHeader
	if err := json.Unmarshal(raw, &hdr); err != nil {
		return 0, fmt.Errorf("parse getblockheader response: %w", err)
	}
	if hdr.Timestamp <= 0 {
		return 0, fmt.Errorf("tip header has a non-positive timestamp (%d)", hdr.Timestamp)
	}
	return uint64(hdr.Timestamp), nil
}
