package sips3

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/spxhash/v2"
	"golang.org/x/crypto/argon2"
)

// TestStretchPassphraseMatchesPreChangeBehaviour pins the extendedSalt and the
// derived verifier to the values produced BEFORE stretchPassphrase switched
// from common.SpxHash to common.SpxHashUncached. Both paths share one instance
// and one protocol key, so the digest must be byte-identical; this test is what
// proves it rather than assuming it.
//
// The expected values were captured by running the original inline code:
//
//	saltBytes    := []byte("mnemonic" + passphrase)
//	hash         := common.SpxHash([]byte(passphrase))
//	extendedSalt := append(saltBytes, hash...)
//	stretched    := argon2.IDKey([]byte(passphrase), extendedSalt, iterations, memory, parallelism, tagSize)
func TestStretchPassphraseMatchesPreChangeBehaviour(t *testing.T) {
	cases := []struct {
		name         string
		passphrase   string
		wantSpxHash  string // hex digest of the passphrase
		wantExtSalt  string // hex extendedSalt
		wantVerifier string // hex Argon2id verifier, i.e. the returned string
	}{
		{
			name:         "three words",
			passphrase:   "abandon ability able",
			wantSpxHash:  "f773fb53a00571186f44c9f586a8a0e5e849af3b12767b058a3f4c622b20b71e",
			wantExtSalt:  "6d6e656d6f6e69636162616e646f6e206162696c6974792061626c65f773fb53a00571186f44c9f586a8a0e5e849af3b12767b058a3f4c622b20b71e",
			wantVerifier: "f7163f142816f03aadc9377b8c56fd38084dc9e570a52c9ee594884e73b1fafd",
		},
		{
			name:         "twelve words",
			passphrase:   "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
			wantSpxHash:  "3a58f58f1b4c73e1c96d3156b7828b428be997b12812e37ad70d0c75938bab22",
			wantExtSalt:  "6d6e656d6f6e69637a6f6f207a6f6f207a6f6f207a6f6f207a6f6f207a6f6f207a6f6f207a6f6f207a6f6f207a6f6f207a6f6f2077726f6e673a58f58f1b4c73e1c96d3156b7828b428be997b12812e37ad70d0c75938bab22",
			wantVerifier: "ffbbf90f51557a3cd2b2d9d96e2a8fa4c646b872d6bd855b71eea88fcc5fa4d1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Asserted through both APIs so the cached/uncached equality is
			// pinned rather than presumed.
			cached := common.SpxHash([]byte(tc.passphrase))
			uncached := common.SpxHashUncached([]byte(tc.passphrase))
			if got := hex.EncodeToString(cached); got != tc.wantSpxHash {
				t.Fatalf("SpxHash digest differs from the pinned pre-change value:\n got:  %s\n want: %s", got, tc.wantSpxHash)
			}
			if hex.EncodeToString(uncached) != hex.EncodeToString(cached) {
				t.Fatalf("SpxHashUncached differs from SpxHash:\n cached:   %x\n uncached: %x", cached, uncached)
			}

			// Re-derive the extendedSalt from the pinned digest and confirm the
			// Argon2id step is unchanged, mirroring the pre-change inline code.
			saltBytes := []byte("mnemonic" + tc.passphrase)
			extendedSalt := append(saltBytes, uncached...)
			if got := hex.EncodeToString(extendedSalt); got != tc.wantExtSalt {
				t.Fatalf("extendedSalt changed:\n got:  %s\n want: %s", got, tc.wantExtSalt)
			}

			stretched := argon2.IDKey([]byte(tc.passphrase), extendedSalt, iterations, memory, parallelism, tagSize)
			if got := hex.EncodeToString(stretched); got != tc.wantVerifier {
				t.Fatalf("stretched verifier changed:\n got:  %s\n want: %s", got, tc.wantVerifier)
			}

			// And the value the function actually returns must match the
			// pre-change return value, byte for byte.
			got, err := stretchPassphrase(tc.passphrase)
			if err != nil {
				t.Fatalf("stretchPassphrase: %v", err)
			}
			if got != tc.wantVerifier {
				t.Fatalf("stretchPassphrase returned a different verifier:\n got:  %s\n want: %s", got, tc.wantVerifier)
			}
		})
	}
}

// TestStretchPassphraseRejectsInvalidUTF8 covers the validation the extracted
// helper now owns, which GeneratePassphrase previously performed inline.
func TestStretchPassphraseRejectsInvalidUTF8(t *testing.T) {
	if _, err := stretchPassphrase(string([]byte{0xff, 0xfe})); err == nil {
		t.Fatal("stretchPassphrase accepted an invalid UTF-8 passphrase, want error")
	}
}

// TestStretchPassphraseUsesTheUncacheablePath documents the behavioural point of
// the switch: the passphrase is secret material, so it must take a path that
// stores nothing in the process-wide LRU.
//
// common's shared instance is package-level and unexported, so the cache cannot
// be inspected from here. What is asserted instead is that the input really is
// in the cacheable size range (so the cached path would have retained it), and
// that a repeated passphrase still yields an identical verifier, i.e. skipping
// the cache changed nothing observable about the result.
func TestStretchPassphraseUsesTheUncacheablePath(t *testing.T) {
	const passphrase = "abandon ability able about above absent absorb abstract absurd abuse access accident"

	// If this ever exceeded MaxCachedInputSize the cached path would have
	// bypassed the cache anyway and this test would stop proving anything.
	if len(passphrase) > spxhash.MaxCachedInputSize {
		t.Fatalf("passphrase is %d bytes, above the %d-byte cache window; "+
			"this test no longer exercises the cached-vs-uncached distinction",
			len(passphrase), spxhash.MaxCachedInputSize)
	}

	first, err := stretchPassphrase(passphrase)
	if err != nil {
		t.Fatalf("first stretchPassphrase: %v", err)
	}
	// A second call would be a cache hit had the first populated the LRU.
	// The verifier must be identical either way.
	second, err := stretchPassphrase(passphrase)
	if err != nil {
		t.Fatalf("second stretchPassphrase: %v", err)
	}
	if first != second {
		t.Fatalf("verifier changed across repeat calls:\n first:  %s\n second: %s", first, second)
	}
}

// TestStretchPassphraseAcceptsWordListPassphrases guards that ordinary
// passphrases of the lengths this package generates still derive cleanly.
func TestStretchPassphraseAcceptsWordListPassphrases(t *testing.T) {
	for _, tc := range []struct {
		name  string
		words int
	}{
		{"12 words", 12},
		{"24 words", 24},
	} {
		t.Run(tc.name, func(t *testing.T) {
			passphrase := strings.TrimSpace(strings.Repeat("abandon ", tc.words))
			got, err := stretchPassphrase(passphrase)
			if err != nil {
				t.Fatalf("stretchPassphrase: %v", err)
			}
			if len(got) != tagSize*2 {
				t.Fatalf("verifier is %d hex chars, want %d (tagSize*2)", len(got), tagSize*2)
			}
		})
	}
}
