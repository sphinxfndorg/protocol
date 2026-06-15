// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/key/org.go
// usi/core/key/org.go
package keys

import (
	"fmt"
	"log"
	"strings"
)

// OrgCode represents a valid organization identifier (4-byte prefix).
type OrgCode string

const (
	OrgSPIF OrgCode = "SPIF" // SPIF - Sphinx Fingerprint (Identity Defense System)
)

// orgMeta holds display metadata for an organisation.
type orgMeta struct {
	Code        OrgCode
	DisplayCode string // how it appears in a formatted address (may differ from raw Code)
	Name        string // full name
	Description string // short description
}

// orgRegistry is the authoritative list of supported organisations.
var orgRegistry = []orgMeta{
	{OrgSPIF, "SPIF", "Sphinx Fingerprint", "Identity Defense System"},
}

// orgByCode provides O(1) lookup.
var orgByCode map[string]orgMeta

func init() {
	log.Printf("[INFO] org.go init: registering %d organizations", len(orgRegistry))
	orgByCode = make(map[string]orgMeta, len(orgRegistry))
	for _, m := range orgRegistry {
		orgByCode[strings.TrimSpace(string(m.Code))] = m
		log.Printf("[DEBUG] org.go init: registered org code: %q", strings.TrimSpace(string(m.Code)))
	}
	log.Printf("[SUCCESS] org.go init: organization registry initialized")
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

// OrgPrefix returns the raw 4-byte prefix slice for use in binary address fields.
func OrgPrefix(code OrgCode) []byte {
	raw := string(code)
	log.Printf("[DEBUG] OrgPrefix: converting org code %q to prefix", raw)
	// Ensure exactly 4 bytes
	for len(raw) < 4 {
		raw += " "
	}
	result := []byte(raw[:4])
	log.Printf("[DEBUG] OrgPrefix: prefix bytes: %v", result)
	return result
}

// IsValidOrgCode reports whether code is a registered organisation.
func IsValidOrgCode(code string) bool {
	trimmed := strings.TrimSpace(strings.ToUpper(code))
	_, ok := orgByCode[trimmed]
	log.Printf("[DEBUG] IsValidOrgCode: checking code %q -> %v", code, ok)
	return ok
}

// OrgDisplayName returns the full name for an org code.
func OrgDisplayName(code string) (string, error) {
	log.Printf("[INFO] OrgDisplayName: looking up display name for code: %q", code)
	trimmed := strings.TrimSpace(strings.ToUpper(code))
	m, ok := orgByCode[trimmed]
	if !ok {
		log.Printf("[ERROR] OrgDisplayName: unknown organisation code: %q", code)
		return "", fmt.Errorf("unknown organisation code: %q", code)
	}
	log.Printf("[SUCCESS] OrgDisplayName: found name: %q", m.Name)
	return m.Name, nil
}

// OrgDescription returns the short description for an org code.
func OrgDescription(code string) (string, error) {
	log.Printf("[INFO] OrgDescription: looking up description for code: %q", code)
	trimmed := strings.TrimSpace(strings.ToUpper(code))
	m, ok := orgByCode[trimmed]
	if !ok {
		log.Printf("[ERROR] OrgDescription: unknown organisation code: %q", code)
		return "", fmt.Errorf("unknown organisation code: %q", code)
	}
	log.Printf("[SUCCESS] OrgDescription: found description: %q", m.Description)
	return m.Description, nil
}

// AllOrgs returns a slice of all registered organisations for UI population.
func AllOrgs() []orgMeta {
	log.Printf("[INFO] AllOrgs: returning %d registered organizations", len(orgRegistry))
	result := make([]orgMeta, len(orgRegistry))
	copy(result, orgRegistry)
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// Address formatting
// ─────────────────────────────────────────────────────────────────────────────

// FormatOrgAddress formats a raw SHAKE-256 fingerprint byte slice (including
// the org prefix and checksum appended by SHAKE256HashWithOrg) into the
// canonical address string:
//
//	<ORG> XXXX XXXX … (32 hex bytes of hash, 4-char groups, checksum hidden)
func FormatOrgAddress(data []byte, code OrgCode) string {
	displayCode := strings.TrimSpace(string(code))
	log.Printf("[INFO] FormatOrgAddress: formatting address with org prefix %q", displayCode)
	log.Printf("[DEBUG] FormatOrgAddress: input data size: %d bytes", len(data))

	prefix := OrgPrefix(code)
	hasPrefix := len(data) >= 4 && string(data[:4]) == string(prefix)
	log.Printf("[DEBUG] FormatOrgAddress: has org prefix in data: %v", hasPrefix)

	var hashData []byte
	if hasPrefix {
		body := data[4:] // strip org prefix
		log.Printf("[DEBUG] FormatOrgAddress: stripped prefix, body size: %d bytes", len(body))
		// Remove trailing checksum (last 4 bytes) from display
		if len(body) > ChecksumLength {
			hashData = body[:len(body)-ChecksumLength]
			log.Printf("[DEBUG] FormatOrgAddress: removed checksum, hash data size: %d bytes", len(hashData))
		} else {
			hashData = body
		}
	} else {
		hashData = data
		log.Printf("[DEBUG] FormatOrgAddress: no prefix found, using raw data")
	}

	hexStr := fmt.Sprintf("%X", hashData)
	log.Printf("[DEBUG] FormatOrgAddress: hex string length: %d chars", len(hexStr))

	var groups []string
	for i := 0; i < len(hexStr); i += 4 {
		end := i + 4
		if end > len(hexStr) {
			end = len(hexStr)
		}
		groups = append(groups, hexStr[i:end])
	}

	result := displayCode + " " + strings.Join(groups, " ")
	log.Printf("[SUCCESS] FormatOrgAddress: formatted address: %s", result[:min(50, len(result))]+"...")
	return result
}

// FormatOrgAddressForDisplay normalises an already-formatted address string
// (strips org prefix, rebuilds canonical spacing).
func FormatOrgAddressForDisplay(addr string) string {
	log.Printf("[INFO] FormatOrgAddressForDisplay: normalizing address: %s", addr[:min(40, len(addr))]+"...")

	clean := strings.ReplaceAll(addr, " ", "")
	clean = strings.ReplaceAll(clean, "-", "")
	log.Printf("[DEBUG] FormatOrgAddressForDisplay: cleaned string length: %d", len(clean))

	// Detect and strip known org prefix (SPIF)
	code, rest := extractOrgCode(clean)
	if code == "" {
		// Fall back: treat the whole string as hex
		rest = clean
		code = "SPIF"
		log.Printf("[WARN] FormatOrgAddressForDisplay: no org prefix found, using 'SPIF'")
	} else {
		log.Printf("[DEBUG] FormatOrgAddressForDisplay: detected org code: %q", code)
	}

	// Show first 64 hex characters of the hash
	var result strings.Builder
	result.WriteString(code)
	result.WriteByte(' ')

	displayCount := 0
	for i := 0; i < len(rest) && i < 64; i += 4 {
		end := i + 4
		if end > len(rest) {
			end = len(rest)
		}
		if i > 0 {
			result.WriteByte(' ')
		}
		result.WriteString(strings.ToUpper(rest[i:end]))
		displayCount++
	}

	log.Printf("[SUCCESS] FormatOrgAddressForDisplay: formatted with %d groups", displayCount)
	return result.String()
}

// SHAKE256HashWithOrg produces:
//
//	[4-byte org prefix][32-byte SHAKE-256 hash][4-byte checksum]  — total 40 bytes
func SHAKE256HashWithOrg(data []byte, code OrgCode) []byte {
	log.Printf("[INFO] SHAKE256HashWithOrg: computing hash with org prefix %q", strings.TrimSpace(string(code)))
	log.Printf("[DEBUG] SHAKE256HashWithOrg: input data size: %d bytes", len(data))

	raw := shake256Raw(data) // 32-byte hash
	log.Printf("[DEBUG] SHAKE256HashWithOrg: raw SHAKE256 hash (first 8 bytes): %x", raw[:8])

	withPrefix := append(OrgPrefix(code), raw...) // 36 bytes
	log.Printf("[DEBUG] SHAKE256HashWithOrg: with prefix, size: %d bytes", len(withPrefix))

	result := addChecksum(withPrefix) // 40 bytes
	log.Printf("[DEBUG] SHAKE256HashWithOrg: final result size: %d bytes", len(result))
	log.Printf("[DEBUG] SHAKE256HashWithOrg: checksum (first 2 bytes): %x", result[:2])

	log.Printf("[SUCCESS] SHAKE256HashWithOrg: hash with org prefix %q generated, total %d bytes", strings.TrimSpace(string(code)), len(result))
	return result
}

// NormalizeOrgAddress converts a user-supplied address string (any format) to
// the canonical 64-char hex hash used for comparisons.
func NormalizeOrgAddress(addr string) (string, error) {
	log.Printf("[INFO] NormalizeOrgAddress: normalizing address: %s", addr[:min(40, len(addr))]+"...")

	clean := strings.ReplaceAll(addr, " ", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ToUpper(clean)
	log.Printf("[DEBUG] NormalizeOrgAddress: cleaned string length: %d", len(clean))

	_, rest := extractOrgCode(clean)
	if rest == "" {
		rest = clean // no recognised prefix — try as raw hex
		log.Printf("[DEBUG] NormalizeOrgAddress: no org prefix found, treating as raw hex")
	} else {
		log.Printf("[DEBUG] NormalizeOrgAddress: extracted rest length: %d", len(rest))
	}

	if len(rest) < 64 {
		log.Printf("[ERROR] NormalizeOrgAddress: address too short: expected at least 64 hex characters, got %d", len(rest))
		return "", fmt.Errorf("address too short: expected at least 64 hex characters after prefix, got %d", len(rest))
	}
	hash64 := rest[:64]

	for i, c := range hash64 {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			log.Printf("[ERROR] NormalizeOrgAddress: invalid hex character at position %d: %c", i, c)
			return "", fmt.Errorf("invalid hex character in address: %c", c)
		}
	}

	log.Printf("[SUCCESS] NormalizeOrgAddress: normalized hash: %.16s...", hash64)
	return hash64, nil
}

// IsValidOrgAddressFormat validates the full address string (prefix + hash + optional checksum).
func IsValidOrgAddressFormat(addr string) bool {
	log.Printf("[DEBUG] IsValidOrgAddressFormat: validating address: %s", addr[:min(40, len(addr))]+"...")

	clean := strings.ReplaceAll(addr, " ", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ToUpper(clean)

	code, rest := extractOrgCode(clean)
	if code == "" {
		log.Printf("[WARN] IsValidOrgAddressFormat: no recognised org prefix found")
		return false
	}
	log.Printf("[DEBUG] IsValidOrgAddressFormat: found org code: %q", code)

	if len(rest) < 64 || len(rest) > 72 {
		log.Printf("[WARN] IsValidOrgAddressFormat: invalid rest length: %d (expected 64-72)", len(rest))
		return false
	}

	for i, c := range rest {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
			log.Printf("[WARN] IsValidOrgAddressFormat: invalid hex character at position %d: %c", i, c)
			return false
		}
	}

	log.Printf("[SUCCESS] IsValidOrgAddressFormat: address is valid")
	return true
}

// VerifyOrgAddressChecksum verifies the checksum embedded in an address.
func VerifyOrgAddressChecksum(addr string) bool {
	log.Printf("[INFO] VerifyOrgAddressChecksum: verifying checksum for address: %s", addr[:min(40, len(addr))]+"...")

	clean := strings.ReplaceAll(addr, " ", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ToUpper(clean)

	_, rest := extractOrgCode(clean)
	if rest == "" {
		log.Printf("[WARN] VerifyOrgAddressChecksum: no org prefix found")
		return false
	}

	b, err := hexDecodeUpper(rest)
	if err != nil {
		log.Printf("[WARN] VerifyOrgAddressChecksum: failed to decode hex: %v", err)
		return false
	}

	result := false
	if len(b) == 36 {
		result = verifyChecksum(b)
		log.Printf("[DEBUG] VerifyOrgAddressChecksum: 36-byte data, checksum verified: %v", result)
	} else {
		result = len(b) == 32
		log.Printf("[DEBUG] VerifyOrgAddressChecksum: %d-byte data, assuming valid (no checksum)", len(b))
	}

	if result {
		log.Printf("[SUCCESS] VerifyOrgAddressChecksum: checksum verification passed")
	} else {
		log.Printf("[WARN] VerifyOrgAddressChecksum: checksum verification failed")
	}
	return result
}

// ExtractOrgCodeFromAddress parses the org code out of a formatted address.
func ExtractOrgCodeFromAddress(addr string) (OrgCode, error) {
	log.Printf("[INFO] ExtractOrgCodeFromAddress: extracting org code from: %s", addr[:min(40, len(addr))]+"...")

	clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(addr, " ", ""), "-", ""))
	code, _ := extractOrgCode(clean)
	if code == "" {
		log.Printf("[ERROR] ExtractOrgCodeFromAddress: no recognised organisation prefix in address")
		return "", fmt.Errorf("no recognised organisation prefix in address: %q", addr)
	}
	log.Printf("[SUCCESS] ExtractOrgCodeFromAddress: extracted org code: %q", code)
	return OrgCode(code), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Backward-compat shims — keep old callers working during migration
// ─────────────────────────────────────────────────────────────────────────────

// NormalizeFingerprint is kept for callers that have not been migrated yet.
// It accepts both old addresses and new org-prefixed addresses.
func NormalizeFingerprint(fp string) (string, error) {
	log.Printf("[INFO] NormalizeFingerprint: normalizing fingerprint: %s", fp[:min(40, len(fp))]+"...")

	clean := strings.ReplaceAll(fp, " ", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ToUpper(clean)

	// Strip SPIF prefix
	originalLen := len(clean)
	clean = strings.TrimPrefix(clean, "SPIF")
	_, rest := extractOrgCode(clean)
	if rest != "" {
		clean = rest
	}

	if originalLen != len(clean) {
		log.Printf("[DEBUG] NormalizeFingerprint: stripped prefix, new length: %d", len(clean))
	}

	if len(clean) < 64 {
		log.Printf("[ERROR] NormalizeFingerprint: fingerprint too short: expected at least 64 hex characters, got %d", len(clean))
		return "", fmt.Errorf("fingerprint too short: expected at least 64 hex characters, got %d", len(clean))
	}
	fpResult := clean[:64]

	for i, c := range fpResult {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			log.Printf("[ERROR] NormalizeFingerprint: invalid hex character at position %d: %c", i, c)
			return "", fmt.Errorf("invalid hex character in fingerprint: %c", c)
		}
	}

	log.Printf("[SUCCESS] NormalizeFingerprint: normalized fingerprint: %.16s...", fpResult)
	return fpResult, nil
}

// NormalizeFingerprints normalises multiple fingerprints/addresses.
func NormalizeFingerprints(fps []string) ([]string, error) {
	log.Printf("[INFO] NormalizeFingerprints: normalizing %d fingerprints", len(fps))
	out := make([]string, 0, len(fps))
	for i, fp := range fps {
		log.Printf("[DEBUG] NormalizeFingerprints: processing fingerprint %d: %s", i+1, fp[:min(30, len(fp))]+"...")
		norm, err := NormalizeFingerprint(fp)
		if err != nil {
			log.Printf("[ERROR] NormalizeFingerprints: fingerprint %d invalid: %v", i+1, err)
			return nil, fmt.Errorf("fingerprint %d: %w", i+1, err)
		}
		out = append(out, norm)
	}
	log.Printf("[SUCCESS] NormalizeFingerprints: normalized %d fingerprints", len(out))
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

// extractOrgCode tries to peel the SPIF prefix off s
// (which must already be uppercased with spaces removed).
// Returns ("", "") if none is found.
func extractOrgCode(s string) (code, rest string) {
	if len(s) >= 4 && s[:4] == "SPIF" {
		log.Printf("[DEBUG] extractOrgCode: found org code SPIF")
		return "SPIF", s[4:]
	}
	log.Printf("[DEBUG] extractOrgCode: no valid org code found in string")
	return "", ""
}

// hexDecodeUpper decodes an uppercase hex string; returns error on bad input.
func hexDecodeUpper(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex string")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := hexVal(s[i])
		lo := hexVal(s[i+1])
		if hi == 255 || lo == 255 {
			return nil, fmt.Errorf("invalid hex char at position %d", i)
		}
		b[i/2] = (hi << 4) | lo
	}
	return b, nil
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return 255
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
