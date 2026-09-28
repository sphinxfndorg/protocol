// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/cge_preflight.go
//
// Pre-flight coverage check for step 3 (enforcement). Given the current CGE
// schedule state, it reports — per time-based recipient — whether a valid
// staged witness reaches far enough into the future, and which recipients
// do NOT. Run this against every recipient, for real, before enabling
// enforcement anywhere it matters: flipping escrowEnforced with incomplete
// coverage silently skips every uncovered recipient (the exact failure shape
// step 2 closed for staging, re-appearing as an operational gap).
//
// Scope: read-only. Never stages, never flips escrowEnforced, never touches
// the genesis path or the audit logging.
package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	multisig "github.com/sphinxfndorg/protocol/src/core/musig"
	"github.com/sphinxfndorg/protocol/src/policy"
)

// CGEWitnessCoverage is the pre-flight verdict for one time-based recipient:
// which staged witness (if any) covers it, through which release timestamp,
// and — when uncovered — why.
type CGEWitnessCoverage struct {
	Label        string `json:"label"`
	Recipient    string `json:"recipient"`
	Covered      bool   `json:"covered"`
	CoverThrough uint64 `json:"cover_through_ts,omitempty"`
	Expiry       uint64 `json:"expiry,omitempty"`
	TargetHeight uint64 `json:"target_height,omitempty"`
	// FilesPresent counts staged files that name this recipient, including
	// ones that turned out unusable. The distinction matters operationally:
	// "0 files" means the ceremony has not run for this recipient, "N files
	// but unusable" means someone thinks they staged it and is wrong.
	FilesPresent int `json:"files_present"`
	// Unusable is true when the recipient has staged file(s) that exist but
	// cannot authorize anything (bad expiry, below threshold, unreadable).
	// The caller-facing difference from a plain MISSING is deliberate.
	Unusable bool `json:"unusable,omitempty"`
	// Advisory marks a row that is reported for the operator to see but does
	// NOT gate readiness (e.g. files naming no time-based recipient).
	Advisory bool   `json:"advisory,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// CheckCGEWitnessCoverage scans dir for staged witness files and reports, for
// every time-based CGE recipient, whether a threshold-valid witness with an
// expiry horizon reaching horizonTS exists. nowTS is the chain-derived
// reference (current sealed timestamp), never a wall clock: a witness counts
// as covering only when (a) it carries threshold signature slots under the
// live escrow policy, and (b) its expiry satisfies ValidateWitnessExpiry at
// horizonTS — i.e. it stays usable (including the 24h verify-side retry
// floor, deliberately kept) through the whole horizon being checked.
//
// horizonTS is the "far enough into the future" bound the operator chooses
// (e.g. next cliff + slack). Full release-binding (escrow, recipient,
// amount, height) is verified at execution time by verifyCGEWitness; the
// pre-flight answers the operational question — which recipients have usable
// staged coverage — not the cryptographic one.
func CheckCGEWitnessCoverage(dir string, nowTS, horizonTS uint64) ([]CGEWitnessCoverage, error) {
	if dir == "" {
		dir = DefaultCGEWitnessDir
	}
	files, unusable, err := scanCGEWitnessDir(dir)
	if err != nil {
		return nil, err
	}
	byRecipient := map[string][]cgeWitnessFile{}
	for _, f := range files {
		byRecipient[strings.ToUpper(f.Recipient)] = append(byRecipient[strings.ToUpper(f.Recipient)], f)
	}
	var out []CGEWitnessCoverage
	for _, alloc := range DefaultGenesisAllocations() {
		if alloc == nil {
			continue
		}
		if !policy.CGEScheduleForLabel(alloc.Label).IsTimeBased() {
			continue // liquid (already paid) or module-gated (never by time)
		}
		key := strings.ToUpper(alloc.Address)
		c := CGEWitnessCoverage{Label: alloc.Label, Recipient: alloc.Address}
		cands := byRecipient[key]
		broken := unusable[key]
		c.FilesPresent = len(cands) + len(broken)
		if len(cands) == 0 {
			if len(broken) > 0 {
				// A file exists but could not be used. Saying "no staged
				// witness" here would send the operator hunting for a file
				// that is sitting right there — name the real problem.
				c.Reason = fmt.Sprintf("staged file(s) present but unusable: %s", strings.Join(broken, "; "))
			} else {
				c.Reason = "no staged witness file for this recipient"
			}
			out = append(out, c)
			continue
		}
		sort.Slice(cands, func(i, j int) bool { return cands[i].Witness.Expiry > cands[j].Witness.Expiry })
		for _, cand := range cands {
			if reason := cgeCoverageFailure(cand.Witness, nowTS, horizonTS); reason != "" {
				if c.Reason == "" {
					c.Reason = reason
					c.Expiry = cand.Witness.Expiry
					c.TargetHeight = cand.TargetHeight
				}
				continue
			}
			c.Covered = true
			c.CoverThrough = horizonTS
			c.Expiry = cand.Witness.Expiry
			c.TargetHeight = cand.TargetHeight
			c.Reason = ""
			break
		}
		if !c.Covered && c.Reason == "" {
			c.Reason = "no staged witness reaches the horizon with threshold signatures"
		}
		if !c.Covered {
			// The file(s) are there; they just cannot authorize anything.
			// Say that, instead of letting it read as "ceremony not run".
			c.Unusable = true
			c.Reason = "staged file present but unusable: " + c.Reason
		}
		out = append(out, c)
	}
	// Files whose recipient could not be attributed to any time-based
	// allocation (typo'd address, or a witness for a liquid/module-gated
	// label). Reported, but never gating: they cannot make a covered
	// recipient uncovered.
	if stray := unusable[""]; len(stray) > 0 {
		sort.Strings(stray)
		out = append(out, CGEWitnessCoverage{
			Label:    "(unmatched files)",
			Advisory: true,
			Reason:   strings.Join(stray, "; "),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out, nil
}

// CGEWitnessCoverageReady reports whether every time-based recipient is
// covered through horizonTS. Step 3 must not proceed while this is false.
// Advisory rows (unmatched files) are reported but do not affect readiness.
func CGEWitnessCoverageReady(coverage []CGEWitnessCoverage) bool {
	rows := 0
	for _, c := range coverage {
		if c.Advisory {
			continue
		}
		rows++
		if !c.Covered {
			return false
		}
	}
	return rows > 0
}

// FormatCGEWitnessCoverage renders the operational checklist: one line per
// recipient plus a READY / NOT READY verdict for the enforcement flip.
//
// Statuses are deliberately distinct, because they call for different
// operator action: COVERED (nothing to do), MISSING (the ceremony has not
// run for this recipient), UNUSABLE (a file exists but cannot authorize —
// the operator THINKS this recipient is staged, which is the worse state),
// and an ADVISORY row for files naming no time-based recipient.
func FormatCGEWitnessCoverage(coverage []CGEWitnessCoverage, horizonTS uint64) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CGE witness coverage through %d:\n", horizonTS)
	anyCovered := false
	unusable := 0
	for _, c := range coverage {
		status := "COVERED"
		detail := fmt.Sprintf("expiry=%d height=%d", c.Expiry, c.TargetHeight)
		switch {
		case c.Advisory:
			status = "ADVISORY"
			detail = c.Reason
		case !c.Covered && c.Unusable:
			status = "UNUSABLE"
			detail = c.Reason
			unusable++
		case !c.Covered:
			status = "MISSING"
			detail = c.Reason
		default:
			anyCovered = true
		}
		fmt.Fprintf(&b, "  %-16s %-42s %s (%s)\n", c.Label, c.Recipient, status, detail)
	}
	if unusable > 0 {
		b.WriteString("  ^ UNUSABLE means a file exists but cannot authorize anything: the operator THINKS\n")
		b.WriteString("    this recipient is staged. Fix these before reading MISSING as 'ceremony not run'.\n")
	}
	if anyCovered {
		b.WriteString("  NOTE: a covered row means a usable witness is staged for this recipient's NEXT\n")
		b.WriteString("        pending milestone. It is bound to the milestone (cumulative target), not to a\n")
		b.WriteString("        block height, so whichever block lands the release can carry it. The staged\n")
		b.WriteString("        target_height is a not-before hint; re-stage after a milestone lands.\n")
	}
	if CGEWitnessCoverageReady(coverage) {
		b.WriteString("READY: all time-based recipients covered — safe to consider enforcement\n")
	} else {
		b.WriteString("NOT READY: do NOT enable enforcement — uncovered recipients would skip\n")
	}
	return b.String()
}

// scanCGEWitnessDir loads every witness file in dir (same selection rules as
// staging: *.json, no dotfiles, no subdirs).
//
// It returns the files that are fully usable for coverage evaluation AND, for
// every file whose recipient could be identified but whose witness could not
// be parsed, a reason keyed by recipient. That split is the whole point:
// silently dropping an unusable file (the way staging must, so one bad drop
// cannot block the others) would make this pre-flight report "no staged
// witness" for a recipient whose file is sitting right there — sending the
// operator after the wrong problem. A file whose recipient cannot even be
// read is reported under an empty-recipient key so it is still surfaced.
func scanCGEWitnessDir(dir string) ([]cgeWitnessFile, map[string][]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
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
	var out []cgeWitnessFile
	unusable := map[string][]string{}
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			unusable[""] = append(unusable[""], fmt.Sprintf("%s: %v", name, err))
			continue
		}
		// Lenient metadata pass first, so a witness that fails to parse can
		// still be attributed to a recipient.
		var meta struct {
			Recipient    string `json:"recipient"`
			TargetHeight uint64 `json:"target_height"`
		}
		_ = json.Unmarshal(data, &meta)
		key := strings.ToUpper(meta.Recipient)

		var f cgeWitnessFile
		if err := json.Unmarshal(data, &f); err != nil {
			unusable[key] = append(unusable[key], fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if f.Recipient == "" || f.TargetHeight == 0 {
			unusable[key] = append(unusable[key], fmt.Sprintf("%s: needs a recipient and a positive target_height", name))
			continue
		}
		out = append(out, f)
	}
	return out, unusable, nil
}

// cgeCoverageFailure returns "" when w is usable through horizonTS, else the
// reason it does not count. The horizon check keeps the 24h verify-side floor
// (deliberate: a witness dying inside the horizon leaves no retry room), so a
// witness expiring before horizonTS + 24h never covers. Signature slots are
// counted against the live escrow policy — a below-threshold file never
// covers, even with a generous expiry.
func cgeCoverageFailure(w multisig.MultiSigWitness, nowTS, horizonTS uint64) string {
	p := activeEscrowPolicy()
	if p == nil {
		return "no escrow custody policy loaded"
	}
	if err := multisig.ValidateWitnessExpiry(w.Expiry, nowTS); err != nil {
		return fmt.Sprintf("invalid at intake: %v", err)
	}
	if err := multisig.ValidateWitnessExpiry(w.Expiry, horizonTS); err != nil {
		return fmt.Sprintf("expiry %d does not reach horizon %d (24h retry floor kept): %v", w.Expiry, horizonTS, err)
	}
	if len(w.Sigs) == 0 {
		return "witness carries no signatures"
	}
	valid := 0
	seen := map[int]bool{}
	for idx := range w.Sigs {
		if seen[idx] || idx < 0 || idx >= len(p.PubKeys) {
			continue
		}
		seen[idx] = true
		valid++
	}
	if valid < int(p.Threshold) {
		return fmt.Sprintf("only %d signature slots for threshold %d", valid, p.Threshold)
	}
	return ""
}
