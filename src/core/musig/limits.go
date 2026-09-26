// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package multisig

import "fmt"

// Witness expiry is a unix timestamp, measured against the sealed block header
// timestamp (never a wall clock). The window has a floor so a release that
// lands a few slots late still has a live authorization, and a ceiling so a
// leaked custodian key cannot authorize releases indefinitely.
const (
	MinWitnessValiditySeconds uint64 = 24 * 3600
	MaxWitnessValiditySeconds uint64 = 5 * 365 * 24 * 3600
)

// ValidateWitnessExpiry rejects witnesses that are unspendable-too-soon or
// that stay valid for an unreasonably wide window. refTime == 0 means the
// reference time is not known yet (offline signing); only the zero check runs.
func ValidateWitnessExpiry(expiry, refTime uint64) error {
	if expiry == 0 {
		return fmt.Errorf("witness expiry is unset: this witness can never authorize a release")
	}
	if refTime == 0 {
		return nil
	}
	if expiry < refTime+MinWitnessValiditySeconds {
		return fmt.Errorf("witness expiry %d is under the %d second minimum horizon from %d: unspendable too soon",
			expiry, MinWitnessValiditySeconds, refTime)
	}
	if expiry > refTime+MaxWitnessValiditySeconds {
		return fmt.Errorf("witness expiry %d is beyond the %d second maximum horizon from %d: replay window too wide",
			expiry, MaxWitnessValiditySeconds, refTime)
	}
	return nil
}
