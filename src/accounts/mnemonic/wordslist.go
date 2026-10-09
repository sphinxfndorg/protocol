// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package sips3

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/sphinxfndorg/protocol/src/common"
	"golang.org/x/crypto/argon2"
)

// Argon2 parameters. argon2.IDKey memory is in KiB, so 64*1024 = 64 MiB.
// OWASP minimum: m=37 MiB,t=1,p=1 or m=15 MiB,t=2,p=1.
const (
	memory      = 64 * 1024
	iterations  = 2
	parallelism = 1
	tagSize     = 32
)

// WordListSize is the exact size of EACH language list (11 bits per word).
const WordListSize = 2048

// Language identifies which embedded list a mnemonic was built from.
type Language string

const (
	English Language = "english"
	Bahasa  Language = "bahasa"
)

// SECURITY: word lists are embedded and SHA-256 pinned instead of being
// downloaded from a mutable GitHub branch at runtime (a tampered or tiny list
// would collapse entropy; a random list per phrase made recovery impossible).
//
// SETUP (one time), place both files in this directory, one word per line:
//
//	wordlists/english.txt   (2048 unique words)
//	wordlists/bahasa.txt    (2048 unique words)
//
// Then run `sha256sum` on each (or call LoadWordList once: the error prints the
// hash) and paste the hashes below. Empty pin = fail closed.
//
//go:embed wordlists/english.txt
var englishRaw []byte

//go:embed wordlists/bahasa.txt
var bahasaRaw []byte

const (
	EnglishWordListSHA256 = "187db04a869dd9bc7be80d21a86497d692c0db6abd3aa8cb6be5d618ff757fae"
	BahasaWordListSHA256  = "cbb777280ebae586926679c6d96c6b8b6515e8db2c3480b6cd48ec5ac7d80fc2"
)

// ErrAmbiguousLanguage means every word of the phrase exists in both lists
// and the checksum passes for both. Astronomically unlikely, but reported
// instead of guessed.
var ErrAmbiguousLanguage = errors.New("sips3: mnemonic is valid in more than one language")

// LoadWordList returns the verified list for lang.
func LoadWordList(lang Language) ([]string, error) {
	var raw []byte
	var pin string
	switch lang {
	case English:
		raw, pin = englishRaw, EnglishWordListSHA256
	case Bahasa:
		raw, pin = bahasaRaw, BahasaWordListSHA256
	default:
		return nil, fmt.Errorf("sips3: unsupported language %q", lang)
	}
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	if pin == "" {
		return nil, fmt.Errorf("sips3: %s word list is not pinned; embedded list hashes to %s", lang, got)
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(strings.ToLower(pin))) != 1 {
		return nil, fmt.Errorf("sips3: %s word list does not match pinned SHA-256", lang)
	}
	words := parseWordList(raw)
	if err := validateWordList(words); err != nil {
		return nil, fmt.Errorf("%s list: %w", lang, err)
	}
	return words, nil
}

func parseWordList(raw []byte) []string {
	var words []string
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if w := strings.TrimSpace(line); w != "" {
			words = append(words, w)
		}
	}
	return words
}

// validateWordList enforces size, UTF-8, no inner whitespace, uniqueness.
func validateWordList(words []string) error {
	if len(words) != WordListSize {
		return fmt.Errorf("sips3: word list must contain exactly %d words, got %d", WordListSize, len(words))
	}
	seen := make(map[string]struct{}, len(words))
	for _, w := range words {
		if !utf8.ValidString(w) {
			return errors.New("sips3: word list contains invalid UTF-8")
		}
		for _, r := range w {
			if unicode.IsSpace(r) {
				return fmt.Errorf("sips3: word %q contains whitespace", w)
			}
		}
		if _, dup := seen[w]; dup {
			return fmt.Errorf("sips3: duplicate word %q in list", w)
		}
		seen[w] = struct{}{}
	}
	return nil
}

// randomLanguage picks English or Bahasa with crypto/rand (50/50).
func randomLanguage() (Language, error) {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("sips3: failed to pick language: %w", err)
	}
	if b[0]&1 == 0 {
		return English, nil
	}
	return Bahasa, nil
}

func entropyBitsForWordCount(wordCount int) (int, error) {
	switch wordCount {
	case 12:
		return 128, nil
	case 15:
		return 160, nil
	case 18:
		return 192, nil
	case 21:
		return 224, nil
	case 24:
		return 256, nil
	}
	return 0, errors.New("sips3: word count must be 12, 15, 18, 21, or 24")
}

// mnemonicFromEntropy encodes entropy || SHA-256 checksum bits into 11-bit
// indices of ONE list (BIP-39 construction).
func mnemonicFromEntropy(words []string, entropy []byte) (string, error) {
	bits := len(entropy) * 8
	if bits < 128 || bits > 256 || bits%32 != 0 {
		return "", errors.New("sips3: entropy must be 16, 20, 24, 28 or 32 bytes")
	}
	cs := bits / 32
	h := sha256.Sum256(entropy)

	n := new(big.Int).SetBytes(entropy)
	n.Lsh(n, uint(cs))
	n.Or(n, big.NewInt(int64(h[0]>>(8-uint(cs)))))

	total := bits + cs
	count := total / 11
	mask := big.NewInt(0x7ff)
	out := make([]string, count)
	for i := 0; i < count; i++ {
		idx := new(big.Int).Rsh(n, uint(total-11*(i+1)))
		idx.And(idx, mask)
		out[i] = words[idx.Int64()]
	}
	return strings.Join(out, " "), nil
}

// NewMnemonicFromEntropyLang builds a checksummed mnemonic in a given language.
func NewMnemonicFromEntropyLang(entropy []byte, lang Language) (string, error) {
	words, err := LoadWordList(lang)
	if err != nil {
		return "", fmt.Errorf("failed to load words: %w", err)
	}
	return mnemonicFromEntropy(words, entropy)
}

// NewMnemonicFromEntropy builds a checksummed mnemonic in a randomly chosen
// language (English or Bahasa). All words come from that one list.
func NewMnemonicFromEntropy(entropy []byte) (string, error) {
	lang, err := randomLanguage()
	if err != nil {
		return "", err
	}
	return NewMnemonicFromEntropyLang(entropy, lang)
}

// checkMnemonic verifies membership + checksum against a single list.
func checkMnemonic(words, fields []string) error {
	bits, err := entropyBitsForWordCount(len(fields))
	if err != nil {
		return err
	}
	index := make(map[string]int, len(words))
	for i, w := range words {
		index[w] = i
	}
	cs := bits / 32
	n := new(big.Int)
	for _, f := range fields {
		i, ok := index[f]
		if !ok {
			return fmt.Errorf("sips3: word %q is not in the word list", f)
		}
		n.Lsh(n, 11)
		n.Or(n, big.NewInt(int64(i)))
	}
	gotCS := new(big.Int).And(n, big.NewInt(int64(1<<uint(cs)-1))).Int64()
	n.Rsh(n, uint(cs))
	entropy := make([]byte, bits/8)
	n.FillBytes(entropy)
	h := sha256.Sum256(entropy)
	if int64(h[0]>>(8-uint(cs))) != gotCS {
		return errors.New("sips3: mnemonic checksum mismatch")
	}
	return nil
}

// matchingLanguages returns every language for which the phrase is valid.
func matchingLanguages(mnemonic string) ([]Language, error) {
	fields := strings.Fields(mnemonic)
	var matched []Language
	var firstErr error
	for _, lang := range []Language{English, Bahasa} {
		words, err := LoadWordList(lang)
		if err != nil {
			return nil, err
		}
		if err := checkMnemonic(words, fields); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		matched = append(matched, lang)
	}
	if len(matched) == 0 {
		return nil, fmt.Errorf("sips3: mnemonic is not valid in any supported language: %w", firstErr)
	}
	return matched, nil
}

// DetectLanguage returns the single language a valid phrase belongs to.
func DetectLanguage(mnemonic string) (Language, error) {
	m, err := matchingLanguages(mnemonic)
	if err != nil {
		return "", err
	}
	if len(m) > 1 {
		return "", ErrAmbiguousLanguage
	}
	return m[0], nil
}

// ValidateMnemonic checks membership, word count and checksum in whichever
// supported language the phrase uses. Mixed-language phrases are rejected.
func ValidateMnemonic(mnemonic string) error {
	_, err := matchingLanguages(mnemonic)
	return err
}

// GeneratePassphrase creates a checksummed passphrase of wordCount words from
// the given list (one language) using crypto/rand entropy. Returns the
// passphrase and its Argon2id verifier.
func GeneratePassphrase(words []string, wordCount int) (string, string, error) {
	if err := validateWordList(words); err != nil {
		return "", "", err
	}
	bits, err := entropyBitsForWordCount(wordCount)
	if err != nil {
		return "", "", err
	}
	entropy := make([]byte, bits/8)
	if _, err := rand.Read(entropy); err != nil {
		return "", "", fmt.Errorf("failed to generate entropy: %w", err)
	}
	defer func() {
		for i := range entropy {
			entropy[i] = 0
		}
	}()

	passphraseStr, err := mnemonicFromEntropy(words, entropy)
	if err != nil {
		return "", "", err
	}
	// Do NOT swap the primitive in stretchPassphrase: Argon2id is the KDF and
	// changing it would alter SIPS-0001 and the pinned test vectors.
	stretchedHashStr, err := stretchPassphrase(passphraseStr)
	if err != nil {
		return "", "", err
	}
	return passphraseStr, stretchedHashStr, nil
}

// stretchPassphrase derives the hex-encoded Argon2id verifier (UNCHANGED,
// pinned by TestStretchPassphraseMatchesPreChangeBehaviour):
//
//	extendedSalt = []byte("mnemonic"+passphrase) || SpxHash(passphrase)
//	verifier     = hex(argon2.IDKey(passphrase, extendedSalt, iterations, memory, parallelism, tagSize))
func stretchPassphrase(passphraseStr string) (string, error) {
	if !utf8.ValidString(passphraseStr) {
		return "", errors.New("invalid UTF-8 encoding in passphrase")
	}
	saltBytes := []byte("mnemonic" + passphraseStr)
	hash := common.SpxHashUncached([]byte(passphraseStr)) // secret input: uncached
	extendedSalt := append(saltBytes, hash...)
	stretchedHash := argon2.IDKey([]byte(passphraseStr), extendedSalt, iterations, memory, parallelism, tagSize)
	return fmt.Sprintf("%x", stretchedHash), nil
}

func isValidEntropy(entropy int) bool {
	switch entropy {
	case 128, 160, 192, 224, 256:
		return true
	}
	return false
}

// NewMnemonicLang generates a mnemonic in the given language.
func NewMnemonicLang(entropy int, lang Language) (string, string, error) {
	if !isValidEntropy(entropy) {
		return "", "", errors.New("invalid entropy: must be one of 128, 160, 192, 224, or 256")
	}
	wordCount := (entropy + entropy/32) / 11 // 128->12 ... 256->24
	words, err := LoadWordList(lang)
	if err != nil {
		return "", "", fmt.Errorf("failed to load words: %w", err)
	}
	passphrase, verifier, err := GeneratePassphrase(words, wordCount)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate passphrase: %w", err)
	}
	return passphrase, verifier, nil
}

// NewMnemonic generates a mnemonic in a randomly chosen language
// (English or Bahasa). Returns the mnemonic and its Argon2id verifier.
func NewMnemonic(entropy int) (string, string, error) {
	lang, err := randomLanguage()
	if err != nil {
		return "", "", err
	}
	return NewMnemonicLang(entropy, lang)
}
