// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/common/hexutil.go
package common

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// SPIF Address Utilities (post-quantum SPHINCS+ addresses)
// ─────────────────────────────────────────────────────────────────────────────

// SPIFPrefix is the canonical address prefix used by every SPIF address
// on the protocol. All packages building, parsing, or displaying SPIF
// addresses should reference this constant instead of hardcoding "SPIF".
const SPIFPrefix = "SPIF"

// DEADPrefix is the canonical prefix for provably-unspendable burn addresses
// ("DEAD XXXX XXXX ..."). A DEAD address is derived from a real SPHINCS+
// public key exactly like a SPIF address (same SHAKE256+checksum pipeline,
// different 4-byte org prefix), but its private key material is destroyed in
// a burn ceremony (random passphrase wiped, encrypted blob never persisted),
// so no one — including the ceremony operator — can ever spend from it.
// Consensus treats DEAD addresses as receive-only: funds sent there are
// permanently removed from circulation.
const DEADPrefix = "DEAD"

// DefaultBurnAddress is the protocol's default, canonical burn address.
//
// It was produced by a one-time burn ceremony: a real SPHINCS+ key pair was
// generated under the DEAD org code with a 32-byte crypto-random passphrase
// that was wiped from memory immediately after derivation, and the encrypted
// private key was never written to disk. Only the address (display form) and
// the public key (hex) were retained. The passphrase is unrecoverable by
// design — brute-forcing 256 bits of entropy is infeasible — so this address
// is provably unspendable.
//
// Display form (canonical, grouped):
const DefaultBurnAddress = "DEAD F470 9938 90D8 C4B4 70C4 025D 7693 272F 6562 DA6C F438 CE16 7595 780E 190E 894F"

// DefaultBurnPublicKeyHex is the SPHINCS+ public key the default burn address
// was derived from (hex-encoded, retained for auditability — it cannot spend).
const DefaultBurnPublicKeyHex = "902c07557a9ea822b38bfea5b8ad1d69fab170e1a407c475c57633b5506850c6"

// IsBurnAddress reports whether addr is a burn (DEAD-prefixed) address.
// It accepts the grouped display form ("DEAD XXXX ..."), raw hex with a
// literal DEAD prefix, and the canonical raw hex of the default burn address.
func IsBurnAddress(addr string) bool {
	prefix, _, err := SplitAddressPrefix(addr)
	if err != nil {
		return false
	}
	return prefix == DEADPrefix
}

// SplitAddressPrefix strips a known org prefix (SPIF or DEAD,
// case-insensitive), all spaces, tabs, newlines and hyphens, and returns the
// detected prefix ("" for raw hex with no prefix) plus the canonical cleaned
// hex string (uppercase, without prefix). It validates the remainder is valid
// hex of length 40 or 64.
func SplitAddressPrefix(addr string) (prefix string, raw string, err error) {
	cleaned := strings.TrimSpace(addr)
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	cleaned = strings.ReplaceAll(cleaned, "\t", "")
	cleaned = strings.ReplaceAll(cleaned, "\n", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	if len(cleaned) >= len(SPIFPrefix) && strings.EqualFold(cleaned[:len(SPIFPrefix)], SPIFPrefix) {
		raw = cleaned[len(SPIFPrefix):]
		prefix = SPIFPrefix
	} else if len(cleaned) >= len(DEADPrefix) && strings.EqualFold(cleaned[:len(DEADPrefix)], DEADPrefix) {
		raw = cleaned[len(DEADPrefix):]
		prefix = DEADPrefix
	} else {
		raw = cleaned
		prefix = ""
	}
	if len(raw) != 40 && len(raw) != 64 {
		return "", "", fmt.Errorf("address must be 40 or 64 hex characters, got %d", len(raw))
	}
	if _, err := hex.DecodeString(raw); err != nil {
		return "", "", fmt.Errorf("address is not valid hex: %w", err)
	}
	return prefix, strings.ToUpper(raw), nil
}

// NormalizeAddress strips any known prefix (SPIF or DEAD, case-insensitive),
// all spaces, tabs, and hyphens, then validates the remainder is valid hex of
// length 40 or 64. Returns the canonical cleaned hex string (uppercase,
// without prefix) or an error. System addresses ("genesis", "") fail here —
// use CanonicalAddress when pass-through is wanted.
func NormalizeAddress(addr string) (string, error) {
	_, raw, err := SplitAddressPrefix(addr)
	return raw, err
}

// NormalizeSPIFAddress strips the SPIF prefix (case-insensitive), all spaces,
// tabs, and hyphens, then validates that the remaining string is valid hex of
// length 40 or 64. Returns the canonical cleaned hex string (uppercase, without
// SPIFPrefix) or an error.
//
// Canonical form is UPPERCASE so that LevelDB state keys, mempool nonce keys,
// and equality checks are stable regardless of whether the caller passed
// "SPIF f6f6 ...", "f6f6...", or "F6F6...".
//
// NOTE: kept for backward compatibility. New code that must also accept DEAD
// burn addresses should use NormalizeAddress / ValidateAddress instead.
func NormalizeSPIFAddress(addr string) (string, error) {
	_, raw, err := SplitAddressPrefix(addr)
	return raw, err
}

// CanonicalSPIFAddress returns the canonical (uppercase raw hex) form of addr.
// If addr is not a valid SPIF/hex address (e.g. "genesis" or ""), it returns
// the input unchanged so system addresses and empties pass through.
func CanonicalSPIFAddress(addr string) string {
	if raw, err := NormalizeSPIFAddress(addr); err == nil {
		return raw
	}
	return addr
}

// ValidateSPIFAddress returns true if the given string is a valid SPIF address.
// It accepts formats with or without "SPIF" prefix and with spaces/hyphens.
// NOTE: kept for backward compatibility — DEAD burn addresses also pass here
// (same hex body, different prefix). Use ValidateAddress for new code.
func ValidateSPIFAddress(addr string) bool {
	_, err := NormalizeSPIFAddress(addr)
	return err == nil
}

// ValidateAddress returns true if the given string is a valid protocol
// address: SPIF wallet/contract address OR DEAD burn address, with or without
// prefix, with spaces/hyphens tolerated.
func ValidateAddress(addr string) bool {
	_, err := NormalizeAddress(addr)
	return err == nil
}

// CanonicalAddress returns the canonical (uppercase raw hex) form of addr.
// If addr is not a valid SPIF/DEAD hex address (e.g. "genesis" or ""), it
// returns the input unchanged so system addresses and empties pass through.
func CanonicalAddress(addr string) string {
	if raw, err := NormalizeAddress(addr); err == nil {
		return raw
	}
	return addr
}

// FormatSPIFAddress takes a raw hex string (40 or 64 chars) and formats it as:
//
//	"SPIF XXXX XXXX XXXX ..." (groups of 4 hex characters).
//
// If the input already has a SPIF prefix or spaces, it normalises first.
// Returns the formatted string or an error if invalid.
func FormatSPIFAddress(addr string) (string, error) {
	raw, err := NormalizeSPIFAddress(addr)
	if err != nil {
		return "", err
	}

	var groups []string
	for i := 0; i < len(raw); i += 4 {
		end := i + 4
		if end > len(raw) {
			end = len(raw)
		}
		groups = append(groups, raw[i:end])
	}
	return SPIFPrefix + " " + strings.Join(groups, " "), nil
}

// MustFormatSPIFAddress is like FormatSPIFAddress but panics on error.
// Useful for tests or where the input is known to be valid.
func MustFormatSPIFAddress(addr string) string {
	s, err := FormatSPIFAddress(addr)
	if err != nil {
		panic(err)
	}
	return s
}

// MustFormatDEADAddress is like FormatDEADAddress but panics on error.
func MustFormatDEADAddress(addr string) string {
	s, err := FormatDEADAddress(addr)
	if err != nil {
		panic(err)
	}
	return s
}

// FormatDEADAddress takes a raw hex string (40 or 64 chars) and formats it as:
//
//	"DEAD XXXX XXXX XXXX ..." (groups of 4 hex characters).
//
// If the input already has a DEAD/SPIF prefix or spaces, it normalises first
// (the hex body is prefix-independent) and re-renders with the DEAD prefix.
// Returns the formatted string or an error if invalid.
func FormatDEADAddress(addr string) (string, error) {
	_, raw, err := SplitAddressPrefix(addr)
	if err != nil {
		return "", err
	}

	var groups []string
	for i := 0; i < len(raw); i += 4 {
		end := i + 4
		if end > len(raw) {
			end = len(raw)
		}
		groups = append(groups, raw[i:end])
	}
	return DEADPrefix + " " + strings.Join(groups, " "), nil
}

// FormatAddressWithPrefix formats raw hex with the given prefix ("SPIF" or
// "DEAD"). Unknown prefixes fall back to SPIF.
func FormatAddressWithPrefix(addr, prefix string) (string, error) {
	p := strings.ToUpper(strings.TrimSpace(prefix))
	if p != SPIFPrefix && p != DEADPrefix {
		p = SPIFPrefix
	}
	_, raw, err := SplitAddressPrefix(addr)
	if err != nil {
		return "", err
	}
	var groups []string
	for i := 0; i < len(raw); i += 4 {
		end := i + 4
		if end > len(raw) {
			end = len(raw)
		}
		groups = append(groups, raw[i:end])
	}
	return p + " " + strings.Join(groups, " "), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Cryptographic-address rejection defense
//
// The validators above are SYNTACTIC on purpose: they answer "is this string
// shaped like an address", which is what state keys and canonicalization need.
// They cannot answer "did a key pair produce this", because no public key is in
// scope there and src/common cannot import src/usi/core/key (that package
// imports src/common, so the dependency is one-way by design).
//
// These helpers add the two halves of a real rejection gate that the callers
// with a public key can then enforce:
//
//   - a STRICT shape check, so a body that no SPHINCS+ key could ever have
//     produced is refused outright; and
//   - a canonical comparison primitive, so a caller holding the public key can
//     require that the address is exactly what that key derives to.
//
// A caller that has only an address string still cannot prove provenance — see
// IsKeyDerivedAddress for the honest statement of that limit.
// ─────────────────────────────────────────────────────────────────────────────

// SPHINCSAddressHexLen is the canonical body length of an address derived from a
// 32-byte SPHINCS+ public key under this protocol's construction
// (usi/core/key.GetPublicKeyFingerprintFromBytes).
//
// 64 hex chars is not arbitrary: SplitAddressPrefix also admits a 40-hex form,
// which is legacy 20-byte material and is used for system-style escrow entries
// ("0000...0002"). No SPHINCS+ key produces a 40-hex body, so a caller that must
// only accept key-derived addresses can reject that length without ambiguity.
const SPHINCSAddressHexLen = 64

// IsSPHINCSAddressShape reports whether addr has the exact shape of a
// SPHINCS+-derived address: a 64-hex body, with or without a SPIF/DEAD prefix.
//
// This is a NECESSARY but NOT SUFFICIENT gate. It rejects fabricated values
// whose length or alphabet could never come from the key derivation — including
// the 40-hex legacy form — but it cannot by itself tell a fabricated 64-hex
// body from a real one. Callers that hold the public key must additionally use
// ValidateKeyDerivedAddress.
func IsSPHINCSAddressShape(addr string) bool {
	_, raw, err := SplitAddressPrefix(addr)
	return err == nil && len(raw) == SPHINCSAddressHexLen
}

// ValidateSPHINCSAddressShape is IsSPHINCSAddressShape with a rejection reason.
func ValidateSPHINCSAddressShape(addr string) error {
	if _, _, err := SplitAddressPrefix(addr); err != nil {
		return fmt.Errorf("address %q is malformed: %w", addr, err)
	}
	if !IsSPHINCSAddressShape(addr) {
		return fmt.Errorf("address %q is not a cryptographic-standard address: "+
			"a SPHINCS+-derived body is %d hex characters", addr, SPHINCSAddressHexLen)
	}
	return nil
}

// IsKeyDerivedAddress reports whether addr is exactly the address that derived
// derives to (typically derived := the value computed from a public key).
//
// Comparison is on the CANONICAL form, so "SPIF ab cd …", "ab cd …" and
// lowercase all compare equal to the same derived value, and it is
// constant-time so a mismatched address does not leak its prefix position.
//
// LIMITATION — read before relying on this: this compares two strings. It
// proves provenance ONLY when the caller supplies derived from a real public key
// they hold. Handed a self-consistent pair chosen by an attacker it proves
// nothing, which is exactly why every call site must compute `derived` itself
// and never accept it from the same untrusted input as `addr`.
func IsKeyDerivedAddress(addr, derived string) bool {
	a, err := NormalizeAddress(addr)
	if err != nil {
		return false
	}
	d, err := NormalizeAddress(derived)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(d)) == 1
}

// ValidateKeyDerivedAddress is the rejection primitive for callers that hold a
// public key: it rejects anything that is not well-shaped AND not the value that
// key derives to.
//
// derived MUST be computed by the caller from its own public key (for this
// protocol, keys.GetPublicKeyFingerprintFromBytes(pubKey, keys.OrgSPIF)). Passing
// an attacker-supplied `derived` alongside an attacker-supplied `addr` turns
// this into a tautology, so the derivation must never come from the same
// untrusted source as the address being checked.
func ValidateKeyDerivedAddress(addr, derived string) error {
	if err := ValidateSPHINCSAddressShape(addr); err != nil {
		return err
	}
	if !IsKeyDerivedAddress(addr, derived) {
		return fmt.Errorf("address %q is not derived from the supplied public key; "+
			"expected %s", addr, derived)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Generic Hex Utilities (non-EVM specific)
// ─────────────────────────────────────────────────────────────────────────────

// Bytes2Hex converts bytes to hexadecimal string.
func Bytes2Hex(b []byte) string {
	return hex.EncodeToString(b)
}

// Hex2Bytes converts hexadecimal string to bytes.
func Hex2Bytes(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// IsValidHexString checks if a string is valid hexadecimal.
func IsValidHexString(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// FormatHash formats a byte slice as a 64-character hex hash string.
func FormatHash(hash []byte) string {
	return fmt.Sprintf("%064x", hash)
}

// FormatAddress formats a byte slice as a 40-character hex address string.
// This is generic and can be used for any 20-byte address representation.
func FormatAddress(address []byte) string {
	return fmt.Sprintf("%040x", address)
}

// FormatBigInt formats a big.Int as a hex string with optional padding.
func FormatBigInt(value *big.Int, padToLength int) string {
	hexStr := fmt.Sprintf("%x", value)
	if padToLength > 0 && len(hexStr) < padToLength {
		return strings.Repeat("0", padToLength-len(hexStr)) + hexStr
	}
	return hexStr
}

// ParseBigInt parses a hex string into a big.Int.
func ParseBigInt(hexStr string) (*big.Int, error) {
	value := new(big.Int)
	_, success := value.SetString(hexStr, 16)
	if !success {
		return nil, fmt.Errorf("invalid hex string: %s", hexStr)
	}
	return value, nil
}

// BytesToHexWithPrefix converts bytes to hex with "0x" prefix.
// This is kept for compatibility with EVM-style RPC calls if needed.
func BytesToHexWithPrefix(b []byte) string {
	return "0x" + hex.EncodeToString(b)
}

// HexToBytesWithoutPrefix converts hex string (with or without prefix) to bytes.
func HexToBytesWithoutPrefix(hexStr string) ([]byte, error) {
	cleanHex := strings.TrimPrefix(hexStr, "0x")
	return hex.DecodeString(cleanHex)
}

// ─────────────────────────────────────────────────────────────────────────────
// Nonce Utilities (used for block headers and transactions)
// ─────────────────────────────────────────────────────────────────────────────

// FormatNonce formats a uint64 nonce as a 16-character hex string.
func FormatNonce(nonce uint64) string {
	return fmt.Sprintf("%016x", nonce)
}

// FormatNonce32 formats a nonce as a 32-character hex string.
func FormatNonce32(nonce uint64) string {
	return fmt.Sprintf("%032x", nonce)
}

// ParseNonce converts a hex nonce string back to uint64.
func ParseNonce(nonceStr string) (uint64, error) {
	return strconv.ParseUint(nonceStr, 16, 64)
}

// GenerateRandomNonce generates a cryptographically secure random nonce.
func GenerateRandomNonce() string {
	randomBytes := make([]byte, 8)
	_, err := rand.Read(randomBytes)
	if err != nil {
		// Fallback to timestamp-based randomness if crypto rand fails.
		fallbackNonce := GetCurrentTimestamp()
		randomBytes = make([]byte, 8)
		binary.BigEndian.PutUint64(randomBytes, uint64(fallbackNonce))
	}
	return FormatNonce(binary.BigEndian.Uint64(randomBytes))
}

// GenerateRandomNonceUint64 generates a random uint64 nonce.
func GenerateRandomNonceUint64() uint64 {
	var nonce uint64
	binary.Read(rand.Reader, binary.BigEndian, &nonce)
	return nonce
}

// ValidateNonceFormat validates if a nonce string is properly formatted.
func ValidateNonceFormat(nonce string) error {
	if len(nonce) != 16 {
		return fmt.Errorf("nonce must be 16 characters long, got %d", len(nonce))
	}
	_, err := hex.DecodeString(nonce)
	if err != nil {
		return fmt.Errorf("nonce must be valid hex: %w", err)
	}
	return nil
}

// ZeroNonce returns the zero nonce (all zeros).
func ZeroNonce() string {
	return "0000000000000000"
}

// MaxNonce returns the maximum possible nonce value.
func MaxNonce() string {
	return "ffffffffffffffff"
}

// NonceToBytes converts a nonce string to bytes.
func NonceToBytes(nonce string) ([]byte, error) {
	if err := ValidateNonceFormat(nonce); err != nil {
		return nil, err
	}
	return hex.DecodeString(nonce)
}

// BytesToNonce converts bytes to a nonce string.
func BytesToNonce(b []byte) (string, error) {
	if len(b) != 8 {
		return "", fmt.Errorf("nonce bytes must be 8 bytes long, got %d", len(b))
	}
	nonceUint := binary.BigEndian.Uint64(b)
	return FormatNonce(nonceUint), nil
}
