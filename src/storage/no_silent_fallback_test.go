// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package storage

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoProductionCallerOfSilentFallback turns the "no production path uses the
// silent fallback" claim into an ENFORCED invariant rather than a one-off grep.
//
// AddBytesToIPFSWithFallback is deprecated precisely because it returns a
// plausible-looking spxhash- CID when nothing was uploaded, which is how mints
// came to anchor content that no IPFS node could serve. Keeping it callable is a
// deliberate compatibility decision, but "deprecated" quietly rotting back into
// "silently reintroduced by a future refactor" is exactly how the original bug
// would return. This test fails the moment any non-test file calls it again.
//
// Scope note: a static check cannot rule out reflection or a dynamically
// dispatched call in general. It is conclusive HERE because the method is never
// taken as a value, never assigned to a func variable, and never registered by
// name anywhere in the module — so every possible call site is the literal
// method-call form this test searches for.
func TestNoProductionCallerOfSilentFallback(t *testing.T) {
	// The method call form, including the receiver dot so that prose mentions
	// in comments (which have no parenthesis) are not flagged.
	const callForm = ".AddBytesToIPFSWithFallback("

	// Its own definition file is the only permitted occurrence.
	const definitionFile = "ipfs.go"

	repoRoot := filepath.Join("..", "..")
	skipDirs := map[string]bool{
		".git": true, "node_modules": true, "dist": true, "vendor": true,
	}

	var violations []string
	walkErr := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// A missing/unreadable subtree must not masquerade as a pass.
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		if d.Name() == definitionFile {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for i, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, callForm) {
				violations = append(violations,
					filepath.ToSlash(path)+":"+itoa(i+1)+": "+strings.TrimSpace(line))
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking the source tree: %v", walkErr)
	}

	if len(violations) > 0 {
		t.Fatalf("production code must not call the silent-fallback pin — it invents a CID for a failed upload, which is the bug this work fixed. Use PinPayload instead.\nOffending call site(s):\n  %s",
			strings.Join(violations, "\n  "))
	}
}

// itoa avoids importing strconv just for an error message.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
