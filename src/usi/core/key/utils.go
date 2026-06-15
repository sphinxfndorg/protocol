// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/key/utils.go
package keys

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ─────────────────────────────────────────────────────────────────────────────
// Legacy constants — kept for backward compatibility
// ─────────────────────────────────────────────────────────────────────────────

// SPIFPrefix is the 4-byte prefix used by addresses.
// New code should use OrgPrefix(code) instead.
var SPIFPrefix = []byte("SPIF")

// ChecksumLength in bytes.
const ChecksumLength = 4

// ─────────────────────────────────────────────────────────────────────────────
// Key derivation
// ─────────────────────────────────────────────────────────────────────────────

// DeriveKeyFromPassphrase uses Argon2id with SHA3-512 stretching.
func DeriveKeyFromPassphrase(passphrase string, salt []byte) []byte {
	log.Printf("[INFO] DeriveKeyFromPassphrase: deriving key from passphrase using Argon2id with SHA3-512")
	log.Printf("[DEBUG] DeriveKeyFromPassphrase: passphrase length: %d chars, salt size: %d bytes", len(passphrase), len(salt))

	argon2Key := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
	log.Printf("[INFO] DeriveKeyFromPassphrase: Argon2id key derivation completed: %d bytes", len(argon2Key))

	sha3Hash := sha3.New512()
	if _, err := sha3Hash.Write(argon2Key); err != nil {
		log.Printf("[ERROR] DeriveKeyFromPassphrase: error during SHA3-512 hashing: %v", err)
		for i := range argon2Key {
			argon2Key[i] = 0
		}
		return make([]byte, 32)
	}

	finalKey := sha3Hash.Sum(nil)[:32]
	log.Printf("[DEBUG] DeriveKeyFromPassphrase: final key (first 8 bytes): %x", finalKey[:8])

	for i := range argon2Key {
		argon2Key[i] = 0
	}
	log.Printf("[DEBUG] DeriveKeyFromPassphrase: intermediate buffer cleared")

	log.Printf("[SUCCESS] DeriveKeyFromPassphrase: key derived successfully with SHA3-512 stretching")
	return finalKey
}

// ─────────────────────────────────────────────────────────────────────────────
// Salt generation
// ─────────────────────────────────────────────────────────────────────────────

// GeneratePureSalt generates n random bytes with no prefix.
func GeneratePureSalt(n int) ([]byte, error) {
	log.Printf("[INFO] GeneratePureSalt: generating pure salt, size: %d bytes", n)
	salt := make([]byte, n)
	_, err := rand.Read(salt)
	if err != nil {
		log.Printf("[ERROR] GeneratePureSalt: error generating salt: %v", err)
		return nil, err
	}
	log.Printf("[SUCCESS] GeneratePureSalt: salt generated successfully (size: %d bytes)", n)
	log.Printf("[DEBUG] GeneratePureSalt: salt (first 8 bytes): %x", salt[:min(8, len(salt))])
	return salt, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Checksum helpers (SHA-256 based, for fingerprint/address integrity)
// ─────────────────────────────────────────────────────────────────────────────

// computeChecksum calculates a 4-byte checksum (first 4 bytes of SHA-256).
func computeChecksum(data []byte) []byte {
	log.Printf("[DEBUG] computeChecksum: computing checksum for %d bytes", len(data))
	hash := sha256.Sum256(data)
	log.Printf("[DEBUG] computeChecksum: computed checksum: %x", hash[:ChecksumLength])
	return hash[:ChecksumLength]
}

func addChecksum(data []byte) []byte {
	if len(data) < 4 {
		log.Printf("[DEBUG] addChecksum: data too short for checksum, returning as-is")
		return data
	}
	checksum := computeChecksum(data)
	result := append(data, checksum...)
	log.Printf("[DEBUG] addChecksum: added checksum, result size: %d bytes", len(result))
	return result
}

func verifyChecksum(data []byte) bool {
	if len(data) < ChecksumLength {
		log.Printf("[DEBUG] verifyChecksum: data too short (%d bytes, need %d)", len(data), ChecksumLength)
		return false
	}
	contentLen := len(data) - ChecksumLength
	content := data[:contentLen]
	expected := data[contentLen:]
	actual := computeChecksum(content)
	result := string(actual) == string(expected)
	log.Printf("[DEBUG] verifyChecksum: checksum verification result: %v", result)
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// SHAKE-256 raw helper (used by both SHAKE256Hash and new org functions)
// ─────────────────────────────────────────────────────────────────────────────

// shake256Raw returns a 32-byte SHAKE-256 hash of data with no prefix or checksum.
func shake256Raw(data []byte) []byte {
	log.Printf("[DEBUG] shake256Raw: computing raw SHAKE256 hash of %d bytes", len(data))
	h := sha3.NewSHAKE256()
	h.Write(data)
	out := make([]byte, 32)
	h.Read(out)
	log.Printf("[DEBUG] shake256Raw: raw hash (first 8 bytes): %x", out[:8])
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// SHAKE256Hash — generates a 32-byte SHAKE256 hash with the SPIF prefix
// and a 4-byte checksum.
func SHAKE256Hash(data []byte) []byte {
	log.Printf("[INFO] SHAKE256Hash: computing SHAKE256 hash (SPIF format)")
	log.Printf("[DEBUG] SHAKE256Hash: input data size: %d bytes", len(data))

	out := shake256Raw(data)
	withPrefix := append(SPIFPrefix, out...)
	result := addChecksum(withPrefix)

	log.Printf("[SUCCESS] SHAKE256Hash: SPIF fingerprint generated, size: %d bytes", len(result))
	log.Printf("[DEBUG] SHAKE256Hash: result (first 8 bytes): %x", result[:8])
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// FormatFingerprint — formats a byte slice (with SPIF prefix + checksum) into
// the human-readable "SPIF XXXX XXXX …" form.
func FormatFingerprint(data []byte) string {
	log.Printf("[INFO] FormatFingerprint: formatting fingerprint (SPIF format)")
	log.Printf("[DEBUG] FormatFingerprint: input data size: %d bytes", len(data))

	hasPrefix := len(data) >= 4 && string(data[:4]) == "SPIF"
	log.Printf("[DEBUG] FormatFingerprint: has SPIF prefix: %v", hasPrefix)

	if hasPrefix {
		body := data[4:]
		var hashData []byte
		if len(body) > ChecksumLength {
			hashData = body[:len(body)-ChecksumLength]
			log.Printf("[DEBUG] FormatFingerprint: stripped prefix and checksum, hash size: %d bytes", len(hashData))
		} else {
			hashData = body
		}

		hexHash := fmt.Sprintf("%X", hashData)
		var groups []string
		for i := 0; i < len(hexHash); i += 4 {
			end := i + 4
			if end > len(hexHash) {
				end = len(hexHash)
			}
			groups = append(groups, hexHash[i:end])
		}
		result := "SPIF " + strings.Join(groups, " ")
		log.Printf("[SUCCESS] FormatFingerprint: formatted: %s", result[:min(50, len(result))]+"...")
		return result
	}

	hexStr := fmt.Sprintf("%X", data)
	var groups []string
	for i := 0; i < len(hexStr); i += 4 {
		end := i + 4
		if end > len(hexStr) {
			end = len(hexStr)
		}
		groups = append(groups, hexStr[i:end])
	}
	result := strings.Join(groups, " ")
	log.Printf("[SUCCESS] FormatFingerprint: formatted (no prefix): %s", result[:min(50, len(result))]+"...")
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// File I/O helpers
// ─────────────────────────────────────────────────────────────────────────────

// WriteFile writes data to a file with secure permissions (0600).
func WriteFile(path string, data []byte) error {
	log.Printf("[INFO] WriteFile: writing data to file: %s", path)
	log.Printf("[DEBUG] WriteFile: data size: %d bytes", len(data))

	err := os.WriteFile(path, data, 0600)
	if err != nil {
		log.Printf("[ERROR] WriteFile: error writing to file %s: %v", path, err)
		return err
	}
	log.Printf("[SUCCESS] WriteFile: data written to file successfully: %s", path)
	return nil
}

// ReadFile reads data from a file and logs whether it carries a recognised prefix.
func ReadFile(path string) ([]byte, error) {
	log.Printf("[INFO] ReadFile: reading data from file: %s", path)

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[ERROR] ReadFile: error reading file %s: %v", path, err)
		return nil, err
	}
	log.Printf("[DEBUG] ReadFile: read %d bytes", len(data))

	if len(data) >= 4 {
		prefix := string(data[:4])
		if prefix == "SPIF" {
			log.Printf("[INFO] ReadFile: file contains SPIF prefix")
		} else if IsValidOrgCode(strings.TrimSpace(prefix)) {
			log.Printf("[INFO] ReadFile: file contains org prefix: %q", strings.TrimSpace(prefix))
		} else {
			log.Printf("[WARN] ReadFile: file does not contain a recognised prefix")
		}
	}

	log.Printf("[SUCCESS] ReadFile: file read successfully: %s", path)
	log.Printf("[DEBUG] ReadFile: data (first 8 bytes): %x", data[:min(8, len(data))])
	return data, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// RandomBytes
// ─────────────────────────────────────────────────────────────────────────────

// RandomBytes generates n random bytes with the SPIF prefix.
func RandomBytes(n int) ([]byte, error) {
	log.Printf("[INFO] RandomBytes: generating random bytes, size: %d bytes", n)

	randomData := make([]byte, n)
	_, err := rand.Read(randomData)
	if err != nil {
		log.Printf("[ERROR] RandomBytes: error generating random bytes: %v", err)
		return nil, err
	}
	result := append(SPIFPrefix, randomData...)
	log.Printf("[SUCCESS] RandomBytes: random bytes generated with SPIF prefix, total size: %d bytes", len(result))
	log.Printf("[DEBUG] RandomBytes: result (first 8 bytes): %x", result[:min(8, len(result))])
	return result, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Fingerprint / address parsing helpers (shared by legacy + new code)
// ─────────────────────────────────────────────────────────────────────────────

// ParseFingerprints parses comma-separated fingerprints/addresses.
func ParseFingerprints(input string) []string {
	log.Printf("[DEBUG] ParseFingerprints: parsing input: %q", input[:min(50, len(input))])
	parts := strings.Split(input, ",")
	var result []string
	for i, fp := range parts {
		trimmed := strings.TrimSpace(fp)
		if trimmed != "" {
			result = append(result, trimmed)
			log.Printf("[DEBUG] ParseFingerprints: part %d: %s", i+1, trimmed[:min(30, len(trimmed))])
		}
	}
	log.Printf("[INFO] ParseFingerprints: parsed %d fingerprints", len(result))
	return result
}

// IsValidFingerprintFormat validates either SPIF or org-prefix addresses.
func IsValidFingerprintFormat(fp string) bool {
	log.Printf("[DEBUG] IsValidFingerprintFormat: validating: %s", fp[:min(40, len(fp))])

	clean := strings.ReplaceAll(fp, " ", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ToUpper(clean)

	// Try org-prefix format first.
	if IsValidOrgAddressFormat(fp) {
		log.Printf("[SUCCESS] IsValidFingerprintFormat: valid org-prefix address")
		return true
	}

	// Fall back to SPIF.
	clean = strings.TrimPrefix(clean, "SPIF")
	if len(clean) < 64 || len(clean) > 72 {
		log.Printf("[WARN] IsValidFingerprintFormat: invalid length: %d (expected 64-72)", len(clean))
		return false
	}
	for i, c := range clean {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
			log.Printf("[WARN] IsValidFingerprintFormat: invalid hex character at position %d: %c", i, c)
			return false
		}
	}
	b, err := hex.DecodeString(strings.ToUpper(clean))
	if err != nil {
		log.Printf("[WARN] IsValidFingerprintFormat: hex decode failed: %v", err)
		return false
	}
	if len(b) == 36 {
		result := verifyChecksum(b)
		log.Printf("[DEBUG] IsValidFingerprintFormat: SPIF with checksum, valid: %v", result)
		return result
	}
	log.Printf("[SUCCESS] IsValidFingerprintFormat: valid SPIF fingerprint")
	return len(b) == 32
}

// FormatFingerprintForDisplay formats any address (org-based) nicely.
func FormatFingerprintForDisplay(fp string) string {
	log.Printf("[INFO] FormatFingerprintForDisplay: formatting: %s", fp[:min(40, len(fp))])

	clean := strings.ReplaceAll(fp, " ", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ToUpper(clean)

	// Detect org prefix.
	code, rest := extractOrgCodePublic(clean)
	if code != "" && rest != "" {
		log.Printf("[DEBUG] FormatFingerprintForDisplay: detected org code: %q", code)
		var sb strings.Builder
		for i := 0; i < len(rest) && i < 64; i += 4 {
			end := i + 4
			if end > len(rest) {
				end = len(rest)
			}
			if i > 0 {
				sb.WriteByte(' ')
			}
			sb.WriteString(rest[i:end])
		}
		result := code + " " + sb.String()
		log.Printf("[SUCCESS] FormatFingerprintForDisplay: formatted with org prefix: %s", result[:min(50, len(result))])
		return result
	}

	// SPIF fallback.
	clean = strings.TrimPrefix(clean, "SPIF")
	var result strings.Builder
	for i := 0; i < len(clean) && i < 64; i += 4 {
		end := i + 4
		if end > len(clean) {
			end = len(clean)
		}
		if i > 0 {
			result.WriteByte(' ')
		}
		result.WriteString(clean[i:end])
	}
	finalResult := "SPIF " + result.String()
	log.Printf("[SUCCESS] FormatFingerprintForDisplay: formatted SPIF: %s", finalResult[:min(50, len(finalResult))])
	return finalResult
}

// extractOrgCodePublic is the exported-facing thin wrapper around the internal
// extractOrgCode defined in org.go (same package, so directly callable).
func extractOrgCodePublic(s string) (code, rest string) {
	return extractOrgCode(s)
}

// VerifyFingerprintChecksum verifies the checksum of a fingerprint or address.
func VerifyFingerprintChecksum(addr string) bool {
	log.Printf("[INFO] VerifyFingerprintChecksum: verifying checksum for: %s", addr[:min(40, len(addr))])

	// Try org format first.
	if VerifyOrgAddressChecksum(addr) {
		log.Printf("[SUCCESS] VerifyFingerprintChecksum: org-prefix checksum verified")
		return true
	}

	// SPIF format.
	clean := strings.ReplaceAll(addr, " ", "")
	clean = strings.ReplaceAll(clean, "-", "")
	clean = strings.ToUpper(clean)
	clean = strings.TrimPrefix(clean, "SPIF")

	b, err := hex.DecodeString(clean)
	if err != nil {
		log.Printf("[WARN] VerifyFingerprintChecksum: hex decode failed: %v", err)
		return false
	}
	if len(b) == 36 {
		result := verifyChecksum(b)
		log.Printf("[DEBUG] VerifyFingerprintChecksum: SPIF checksum verified: %v", result)
		return result
	}
	log.Printf("[SUCCESS] VerifyFingerprintChecksum: valid without checksum (32 bytes)")
	return len(b) == 32
}

// ─────────────────────────────────────────────────────────────────────────────
// SPIF prefix helpers
// ─────────────────────────────────────────────────────────────────────────────

// ExtractDataWithoutPrefix removes the SPIF prefix.
func ExtractDataWithoutPrefix(data []byte) ([]byte, error) {
	log.Printf("[DEBUG] ExtractDataWithoutPrefix: checking for SPIF prefix in %d bytes", len(data))
	if len(data) < 4 || string(data[:4]) != "SPIF" {
		log.Printf("[ERROR] ExtractDataWithoutPrefix: data does not contain valid SPIF prefix")
		return nil, fmt.Errorf("data does not contain valid SPIF prefix")
	}
	result := data[4:]
	log.Printf("[SUCCESS] ExtractDataWithoutPrefix: removed prefix, remaining size: %d bytes", len(result))
	return result, nil
}

// AddSPIFPrefix adds the SPIF prefix if not already present.
func AddSPIFPrefix(data []byte) []byte {
	if len(data) >= 4 && string(data[:4]) == "SPIF" {
		log.Printf("[DEBUG] AddSPIFPrefix: SPIF prefix already present")
		return data
	}
	result := append(SPIFPrefix, data...)
	log.Printf("[DEBUG] AddSPIFPrefix: added SPIF prefix, new size: %d bytes", len(result))
	return result
}

// HasSPIFPrefix reports whether data starts with "SPIF".
func HasSPIFPrefix(data []byte) bool {
	has := len(data) >= 4 && string(data[:4]) == "SPIF"
	log.Printf("[DEBUG] HasSPIFPrefix: %v", has)
	return has
}

// ComputeFingerprint returns hex(SHA3-256(pubKeyBytes)).
// This is the canonical fingerprint used by the key server — distinct from
// the SHAKE256/org-address fingerprint used for human-readable addresses.
// The key server needs a plain SHA3-256 hash, not the org-prefixed SHAKE256 format.
func ComputeFingerprint(pubKeyBytes []byte) (string, error) {
	log.Printf("[INFO] ComputeFingerprint: computing fingerprint from %d bytes", len(pubKeyBytes))

	if len(pubKeyBytes) == 0 {
		log.Printf("[ERROR] ComputeFingerprint: empty public key")
		return "", fmt.Errorf("ComputeFingerprint: empty public key")
	}
	h := sha3.New256()
	h.Write(pubKeyBytes)
	result := hex.EncodeToString(h.Sum(nil))
	log.Printf("[SUCCESS] ComputeFingerprint: computed fingerprint: %.16s...", result)
	return result, nil
}

// GetPublicKeyFingerprintFromBytes generates the formatted address fingerprint
// using the specified organization code. This is needed for bundle lookups
// where we need to derive the address format that users would copy from the GUI.
func GetPublicKeyFingerprintFromBytes(pubKeyBytes []byte, orgCode OrgCode) string {
	log.Printf("[INFO] GetPublicKeyFingerprintFromBytes: generating fingerprint for org code %q", strings.TrimSpace(string(orgCode)))
	log.Printf("[DEBUG] GetPublicKeyFingerprintFromBytes: public key size: %d bytes", len(pubKeyBytes))

	// Generate using the org-specific format
	raw := SHAKE256HashWithOrg(pubKeyBytes, orgCode)
	result := FormatOrgAddress(raw, orgCode)

	log.Printf("[SUCCESS] GetPublicKeyFingerprintFromBytes: generated fingerprint: %s", result[:min(50, len(result))])
	return result
}

// GetPublicKeyFingerprintFromBytesLegacy is for backward compatibility
// when org code is unknown (falls back to SPIF format)
func GetPublicKeyFingerprintFromBytesLegacy(pubKeyBytes []byte) string {
	log.Printf("[INFO] GetPublicKeyFingerprintFromBytesLegacy: generating SPIF fingerprint")
	log.Printf("[DEBUG] GetPublicKeyFingerprintFromBytesLegacy: public key size: %d bytes", len(pubKeyBytes))

	// SPIF format
	fingerprint := SHAKE256Hash(pubKeyBytes)
	result := FormatFingerprint(fingerprint)

	log.Printf("[SUCCESS] GetPublicKeyFingerprintFromBytesLegacy: generated SPIF fingerprint: %s", result[:min(50, len(result))])
	return result
}
