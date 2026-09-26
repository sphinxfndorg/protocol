// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package multisig

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type witnessJSON struct {
	Policy MultiPartyPolicy  `json:"policy"`
	Sigs   map[string]string `json:"sigs"`
	Expiry uint64            `json:"expiry"`
}

func (w MultiSigWitness) MarshalJSON() ([]byte, error) {
	jw := witnessJSON{Policy: w.Policy, Expiry: w.Expiry, Sigs: map[string]string{}}
	for idx, sig := range w.Sigs {
		jw.Sigs[fmt.Sprintf("%d", idx)] = hex.EncodeToString(sig)
	}
	return json.Marshal(jw)
}

func (w *MultiSigWitness) UnmarshalJSON(data []byte) error {
	var jw witnessJSON
	if err := json.Unmarshal(data, &jw); err != nil {
		return err
	}
	w.Policy = jw.Policy
	w.Expiry = jw.Expiry
	w.Sigs = make(map[int][]byte, len(jw.Sigs))
	for ks, vs := range jw.Sigs {
		var idx int
		if _, err := fmt.Sscanf(ks, "%d", &idx); err != nil {
			return fmt.Errorf("bad sig index %q: %w", ks, err)
		}
		b, err := hex.DecodeString(vs)
		if err != nil {
			return fmt.Errorf("sig[%d]: %w", idx, err)
		}
		w.Sigs[idx] = b
	}
	return nil
}

func (w *MultiSigWitness) ValidCount() int {
	return len(w.Sigs)
}

func (w *MultiSigWitness) MeetsThreshold() bool {
	return len(w.Sigs) >= int(w.Policy.Threshold)
}
