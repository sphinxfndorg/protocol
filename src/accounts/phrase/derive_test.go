// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package seed

import (
	"bytes"
	"testing"
)

// The phrase alone must reproduce every derived value.
func TestGenerateKeysReproducibleFromPhrase(t *testing.T) {
	phrase, b32, hp, mk, cc, fp, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	b32b, hp2, mk2, cc2, fp2, err := DeriveKeys(phrase)
	if err != nil {
		t.Fatal(err)
	}
	if b32 != b32b || !bytes.Equal(hp, hp2) || !bytes.Equal(mk, mk2) || !bytes.Equal(cc, cc2) || !bytes.Equal(fp, fp2) {
		t.Fatal("DeriveKeys(phrase) did not reproduce GenerateKeys output")
	}
	if len(bytes.Fields([]byte(phrase))) != 12 {
		t.Fatalf("expected 12 words for 128-bit entropy, got %q", phrase)
	}
}
