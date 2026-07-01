// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/common/hexutil.go
package common

import (
	"crypto/rand"
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

// NormalizeSPIFAddress strips the "SPIF" prefix, all spaces, and hyphens,
// then validates that the remaining string is valid hex of length 40 or 64.
// Returns the cleaned hex string (without "SPIF") or an error.
func NormalizeSPIFAddress(addr string) (string, error) {
	raw := strings.TrimSpace(addr)
	if strings.HasPrefix(raw, "SPIF") {
		raw = strings.TrimPrefix(raw, "SPIF")
		raw = strings.ReplaceAll(raw, " ", "")
		raw = strings.ReplaceAll(raw, "-", "")
	}
	if len(raw) != 40 && len(raw) != 64 {
		return "", fmt.Errorf("address must be 40 or 64 hex characters, got %d", len(raw))
	}
	if _, err := hex.DecodeString(raw); err != nil {
		return "", fmt.Errorf("address is not valid hex: %w", err)
	}
	return raw, nil
}

// ValidateSPIFAddress returns true if the given string is a valid SPIF address.
// It accepts formats with or without "SPIF" prefix and with spaces/hyphens.
func ValidateSPIFAddress(addr string) bool {
	_, err := NormalizeSPIFAddress(addr)
	return err == nil
}

// FormatSPIFAddress takes a raw hex string (40 or 64 chars) and formats it as:
//
//	"SPIF XXXX XXXX XXXX ..." (groups of 4 hex characters).
//
// If the input already has a "SPIF" prefix or spaces, it normalises first.
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
	return "SPIF " + strings.Join(groups, " "), nil
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
