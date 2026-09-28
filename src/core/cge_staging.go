// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/cge_staging.go
//
// CGE witness staging workflow (step 2 of 3): the production caller for
// SubmitCGEWitness.
//
// Custodians pre-sign the exact release authorization OFF-CHAIN, well before
// the release height/schedule threshold is reached, and the signed artifact
// is dropped into a proposal directory (default config/cge_witnesses/).
// Each *.json file carries one (recipient, target_height, witness) triple.
// At block-production time CreateBlock stages whatever is on disk for
// nextHeight into the in-memory pool; the witness rides in the block body so
// verifiers need no pool and no side channel.
//
// Scope: staging only. This file never flips escrowEnforced, never touches
// the genesis path, and never changes the CGEReleasesAuthorised() /
// per-release audit logging.
package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	logger "github.com/sphinxfndorg/protocol/src/console"
	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
)

// DefaultCGEWitnessDir is where the proposing node looks for custodian
// pre-signed CGE release authorizations. Each *.json file is one artifact
// as written by the offline ceremony (recipient + target_height + witness),
// so no node is ever told a release amount: the amount stays bound inside
// the signed witness and is verified from the block at execution time.
//
// TRUST BOUNDARY, same as config/spend_proposals: anything that can write
// here can stage a witness ATTEMPT for a release the quorum already signed.
// A malformed or invalid file is logged and skipped, never fatal, so one bad
// drop cannot stop the others from staging.
const DefaultCGEWitnessDir = "config/cge_witnesses"

// cgeWitnessFile is the on-disk form of one pre-signed release
// authorization: which recipient's release, at which block height, under
// which M-of-N witness.
type cgeWitnessFile struct {
	Recipient    string                   `json:"recipient"`
	TargetHeight uint64                   `json:"target_height"`
	Witness      multisig.MultiSigWitness `json:"witness"`
}

// SetCGEWitnessDir overrides the proposal directory CreateBlock stages CGE
// witnesses from (tests). Empty restores the default.
func (bc *Blockchain) SetCGEWitnessDir(dir string) {
	if bc == nil {
		return
	}
	bc.cgeWitnessDir = dir
}

// cgeWitnessStagingDir resolves the directory CreateBlock stages from.
func (bc *Blockchain) cgeWitnessStagingDir() string {
	if bc != nil && bc.cgeWitnessDir != "" {
		return bc.cgeWitnessDir
	}
	return DefaultCGEWitnessDir
}

// StageCGEWitnessesFromDir is the production caller for SubmitCGEWitness:
// it scans dir for *.json witness files and stages each valid one into the
// in-memory pool via SubmitCGEWitness. refTime is the chain-derived expiry
// reference (the last sealed block's timestamp / the timestamp about to be
// sealed), never a wall clock. A missing directory stages nothing and is not
// an error (quiet devnet / pre-ceremony node). A malformed file, a file with
// an empty recipient or zero height, or a witness that fails the intake
// horizon check is logged and skipped — never fatal to the rest.
//
// It returns the number of witnesses staged.
func (bc *Blockchain) StageCGEWitnessesFromDir(dir string, refTime uint64) (int, error) {
	if bc == nil {
		return 0, nil
	}
	if dir == "" {
		dir = DefaultCGEWitnessDir
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || len(e.Name()) == 0 || e.Name()[0] == '.' {
			continue
		}
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	staged := 0
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			logger.Warn("CGE witness staging: skipping %s: %v", path, err)
			continue
		}
		var f cgeWitnessFile
		if err := json.Unmarshal(data, &f); err != nil {
			logger.Warn("CGE witness staging: skipping %s: not a witness file: %v", path, err)
			continue
		}
		if f.Recipient == "" || f.TargetHeight == 0 {
			logger.Warn("CGE witness staging: skipping %s: need a recipient and a positive target_height", path)
			continue
		}
		if err := bc.SubmitCGEWitness(f.Recipient, f.TargetHeight, f.Witness, refTime); err != nil {
			logger.Warn("CGE witness staging: skipping %s: %v", path, err)
			continue
		}
		staged++
	}
	return staged, nil
}
