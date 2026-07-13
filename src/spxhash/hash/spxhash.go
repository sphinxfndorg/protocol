// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/spxhash.go
package spxhash

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// SIPS-0001 https://github.com/sphinx-core/sips/wiki/SIPS-0001

// Generate salt using Argon2
//
// FIX #2 (Deterministic self-derived salt):
// The original code called argon2.IDKey(data, data, ...) — using the input as
// both the password and the salt argument. A salt's purpose is to make every
// hash instance unique even when the input is identical, preventing
// pre-computation (rainbow-table) attacks. Using the input itself as the salt
// entirely defeats this: two callers with the same input always produce the
// same salt and therefore the same final hash, making pre-computation trivial.
//
// Fix: 16 bytes of cryptographically random entropy are generated with
// crypto/rand and mixed with the input data to form the Argon2 salt argument.
// The random entropy is also returned so it can be stored in the SphinxHash
// instance and included during hashing to keep results reproducible within a
// single instance's lifetime.
//
// FIX A: The original used append(data, entropy...) which writes into data's
// underlying array when it has spare capacity, silently corrupting the caller's
// buffer. A fresh allocation is used instead so generateSalt never mutates its
// input.
//
// FIX SALT: If entropy is provided (non-nil), use it directly instead of
// generating random entropy. This allows deterministic testing with fixed salts.
//
// FIX DET (determinism/one-way contradiction):
// generateSalt itself is unchanged — it still supports both "use the entropy
// I was given" and "generate fresh random entropy" modes. What changed is
// that callers can no longer reach the random-entropy branch by accident.
// NewSphinxHash (the deterministic, consensus-safe constructor) now requires
// a non-empty salt and always takes the providedEntropy branch below. Only
// NewSphinxHashKeyed is allowed to request the random branch, and it does so
// explicitly and by name.
func generateSalt(data []byte, saltSz int, providedEntropy []byte) (salt []byte, entropy []byte, err error) {
	// If entropy is provided, use it directly (deterministic mode)
	if providedEntropy != nil {
		entropy = make([]byte, len(providedEntropy))
		copy(entropy, providedEntropy)
	} else {
		// Otherwise generate random entropy
		entropy = make([]byte, saltSz)
		if _, err = rand.Read(entropy); err != nil {
			return nil, nil, errors.New("spxhash: failed to read random entropy for salt: " + err.Error())
		}
	}

	// Use the constants for Argon2 parameters
	timeCost := uint32(iterations) // Use the number of iterations from the constant
	memoryCost := uint32(memory)   // Use memory cost from the constant
	threads := uint8(parallelism)  // Use parallelism from the constant

	// FIX A: allocate a new backing array instead of append(data, entropy...)
	// to avoid mutating the caller's slice.
	const maxCombinedSize = 1 << 20 // 1 MB maximum combined size
	totalCombinedSize := len(data) + len(entropy)
	if totalCombinedSize > maxCombinedSize {
		return nil, nil, fmt.Errorf("spxhash: combined input size %d exceeds maximum %d", totalCombinedSize, maxCombinedSize)
	}
	combined := make([]byte, totalCombinedSize)
	copy(combined, data)
	copy(combined[len(data):], entropy)

	// Argon2id (a combination of Argon2d and Argon2i) for secure hash-based salt generation
	salt = argon2.IDKey(
		combined, // password: data + random entropy
		entropy,  // salt:     the random entropy alone (truly random)
		timeCost,
		memoryCost,
		threads,
		uint32(saltSz),
	)
	return salt, entropy, nil
}

// NewSphinxHash creates a new, DETERMINISTIC SphinxHash with a specific bit
// size for the hash.
//
// This is the constructor to use anywhere the output must be independently
// reproducible by another process, another node, or another call — for
// example transaction hashes, block hashes, Merkle leaves/roots, or address
// derivation from a public key. Given the same bitSize and the same salt,
// GetHash(data) always returns the same bytes, no matter which instance or
// process computed it.
//
// FIX #2: salt generation now incorporates the caller-supplied entropy (see
// generateSalt). Returns an error if the OS random source is unavailable
// during that derivation.
//
// FIX J: bitSize is now validated; values other than 256, 384, or 512 are
// rejected with an explicit error instead of silently falling through to the
// default 32-byte output in Size(), which would produce wrong-length hashes
// with no indication to the caller.
//
// FIX SALT: salt is used as the entropy for deterministic hashing.
//
// FIX DET (determinism/one-way contradiction):
// Previously this same function accepted a nil entropy argument and silently
// fell back to crypto/rand, meaning two calls with entropy == nil produced
// two different, non-comparable hashers even though they shared a name and
// a bitSize. That made "SphinxHash" behave like a keyed/salted construction
// (Argon2id, HMAC) rather than a classical hash function, and there was
// nothing in the API surface warning a caller which behavior they'd get.
// salt is now required and validated up front: a nil or empty salt is
// rejected with an error rather than silently substituted with randomness.
// Callers that actually want per-instance randomness must say so explicitly
// by calling NewSphinxHashKeyed instead.
func NewSphinxHash(bitSize int, salt []byte) (*SphinxHash, error) {
	// FIX J: validate bitSize before doing any work.
	if bitSize != 256 && bitSize != 384 && bitSize != 512 {
		return nil, fmt.Errorf("spxhash: unsupported bitSize %d (must be 256, 384, or 512)", bitSize)
	}

	// FIX DET: a deterministic hasher is meaningless without a fixed salt.
	// Reject nil/empty here instead of quietly generating random entropy, so
	// a caller that forgets to pass a salt gets a loud error instead of a
	// silently non-reproducible hash.
	if len(salt) == 0 {
		return nil, errors.New("spxhash: NewSphinxHash requires a non-empty salt for deterministic hashing; use NewSphinxHashKeyed for randomized, per-instance hashing")
	}

	var data []byte // Empty data for salt generation
	derivedSalt, saltEntropy, err := generateSalt(data, saltSize, salt)
	if err != nil {
		return nil, err
	}

	return &SphinxHash{
		bitSize:     bitSize,
		salt:        derivedSalt,
		saltEntropy: saltEntropy,
		cache:       NewLRUCache(DefaultCacheSize),
	}, nil
}

// NewSphinxHashKeyed creates a new, RANDOMIZED SphinxHash with a specific bit
// size for the hash.
//
// Each call produces an instance with its own fresh, cryptographically
// random salt, so two instances created by NewSphinxHashKeyed will (with
// overwhelming probability) produce different output for the same input.
// This is the intended behavior for password-storage / MAC-like use cases,
// where non-determinism across instances defeats pre-computation attacks —
// it mirrors how Argon2id or HMAC-with-a-fresh-key is normally used.
//
// FIX DET (determinism/one-way contradiction):
// This constructor did not exist before; its behavior is what NewSphinxHash
// used to do whenever it was called with a nil entropy argument. Splitting
// it out means the random-salt behavior now has to be requested by name —
// it can no longer be reached by accident (e.g. forgetting to pass a salt)
// at a call site that actually needed a reproducible hash.
//
// Do not use this constructor anywhere the resulting hash must be
// independently reproduced by another process or node.
func NewSphinxHashKeyed(bitSize int) (*SphinxHash, error) {
	// FIX J: validate bitSize before doing any work.
	if bitSize != 256 && bitSize != 384 && bitSize != 512 {
		return nil, fmt.Errorf("spxhash: unsupported bitSize %d (must be 256, 384, or 512)", bitSize)
	}

	var data []byte // Empty data for salt generation
	// Passing nil here deliberately takes the random-entropy branch inside
	// generateSalt — this is the one and only constructor allowed to do so.
	salt, saltEntropy, err := generateSalt(data, saltSize, nil)
	if err != nil {
		return nil, err
	}

	return &SphinxHash{
		bitSize:     bitSize,
		salt:        salt,
		saltEntropy: saltEntropy,
		cache:       NewLRUCache(DefaultCacheSize),
	}, nil
}

// Size returns the output length in bytes for this instance's configured
// bitSize: 256 -> 32, 384 -> 48, 512 -> 64.
//
// FIX SIZE (missing method / compile error "s.Size undefined"):
// hashData and sphinxHash both call s.Size() to determine the dynamic
// output length (shakeLength), but no Size method was ever defined on
// SphinxHash, so the package failed to compile. bitSize is already
// validated to be one of 256, 384, or 512 in NewSphinxHash and
// NewSphinxHashKeyed (FIX J), so a plain division by 8 is safe here and
// needs no extra validation.
func (s *SphinxHash) Size() int {
	return s.bitSize / 8
}

// EncodedSalt returns the random entropy bytes that were used to derive this
// instance's salt.
//
// FIX E: Without a way to persist the salt, hashes computed by one SphinxHash
// instance cannot be verified by another (e.g. after a process restart or
// across a network). Callers should store the value returned here alongside the
// hash output and pass it to DecodeSalt when reconstructing the instance for
// verification.
//
// Note: for instances created with NewSphinxHash, this returns the caller's
// own fixed salt (echoed back), which is already known and shared. For
// instances created with NewSphinxHashKeyed, this is the only way to recover
// the random entropy that made the instance unique, and it must be persisted
// if the hash needs to be reproduced later.
func (s *SphinxHash) EncodedSalt() []byte {
	out := make([]byte, len(s.saltEntropy))
	copy(out, s.saltEntropy)
	return out
}

// Clone returns a deep copy of s with the same salt and bitSize but an empty
// accumulated data buffer and a fresh cache.
//
// FIX M: hash.Hash callers often need to snapshot state mid-stream (e.g. hash
// a shared prefix then branch in two directions). Without Clone the only option
// is to re-hash from scratch.
func (s *SphinxHash) Clone() *SphinxHash {
	saltCopy := make([]byte, len(s.salt))
	copy(saltCopy, s.salt)
	entropyCopy := make([]byte, len(s.saltEntropy))
	copy(entropyCopy, s.saltEntropy)
	return &SphinxHash{
		bitSize:     s.bitSize,
		salt:        saltCopy,
		saltEntropy: entropyCopy,
		cache:       NewLRUCache(DefaultCacheSize),
	}
}

// cacheKey builds a collision-resistant cache key that is bound to both the
// full input content and the instance's salt.
//
// FIX #1 (Cache key collision):
// The original code used binary.LittleEndian.Uint64(data[:8]) as the cache
// key, meaning any two inputs that share the same first 8 bytes — regardless
// of what follows — mapped to the same key. A cache hit on such a collision
// returned the wrong hash silently, breaking correctness and making it
// exploitable in integrity-checking contexts.
//
// FIX F (Cross-instance cache poisoning):
// The key previously depended only on input data, not on the instance's salt.
// If a cache were ever shared between two SphinxHash instances (e.g. via a
// package-level singleton), a hit from instance A would return the wrong hash
// for instance B, because the two instances produce different hashes for the
// same input. The salt is mixed into the key (as the HMAC key, below) so each
// instance's entries are distinct.
//
// FIX W (Weak cache key hashing) / FIX WIDE (supersedes FIX W):
// FIX W originally swapped the fast SHA-512/256 keying for Argon2id, reasoning
// that a fast hash made collision search on the key space "feasible." That
// diagnosis was half right: an unkeyed, 64-bit-truncated key does have a weak
// ~2^32 birthday bound. But the fix it applied — a memory-hard KDF — treated
// the symptom (fast per-guess cost) rather than the cause (too-small key
// space), and it paid that cost (~1ms) on every single call, hit or miss,
// since cacheKey must run before the cache can even be checked.
//
// Fix: derive the key with HMAC-SHA-512/256, keyed on the instance's salt
// (preserving FIX F's salt-binding), and keep the full 32-byte output as
// CacheKey instead of truncating to 64 bits (preserving and strengthening
// FIX #1's collision resistance: ~2^128 birthday bound instead of ~2^32).
// HMAC is a fast pseudorandom function — microseconds, not milliseconds —
// and widening the key space is what actually closes the collision-search
// gap FIX W was reaching for, independent of how expensive a single guess is.
func (s *SphinxHash) cacheKey(data []byte) CacheKey {
	mac := hmac.New(sha512.New512_256, s.salt)
	mac.Write(data)
	var key CacheKey
	copy(key[:], mac.Sum(nil))
	return key
}

// GetHash retrieves or calculates the hash of the given data.
//
// FIX #7 (Double Argon2 KDF on every miss):
// The original code constructed a brand-new SphinxHash (and therefore ran a
// full Argon2 key derivation) on every cache miss, and then called hashData
// which ran Argon2 a second time. This made cache misses extremely expensive
// for no benefit.
//
// Fix: hashData is now called directly on the receiver, reusing the
// already-derived salt stored in the current instance. Only one Argon2 call
// is made per unique input.
//
// FIX C (Short-input path ignores bitSize):
// The original short-input fast path always used sha512.New512_256(), producing
// a fixed 32-byte output regardless of the configured bitSize. For bitSize 384
// or 512 this silently returns the wrong length. The fast path now routes
// through hashData like everything else so the output length always matches
// s.Size().
func (s *SphinxHash) GetHash(data []byte) []byte {
	hashKey := s.cacheKey(data) // FIX #1 + F: full-content, salt-bound key
	if cachedValue, found := s.cache.Get(hashKey); found {
		return cachedValue // Return cached value if found (Get already returns a copy — FIX G)
	}

	// FIX C: removed the len(data) < 8 short-circuit that bypassed hashData and
	// always produced 32-byte output. All inputs now go through hashData so the
	// output length always matches the configured bitSize.
	// FIX #7: compute the hash on the receiver directly — no extra NewSphinxHash.
	hash := s.hashData(data)   // Calculate the hash using the instance salt
	s.cache.Put(hashKey, hash) // Store the calculated hash in the cache (Put stores a copy — FIX G)

	return hash // Return the calculated hash
}

// Read reads from the hash data into p.
//
// FIX #8: if no Write has preceded Read the hash covers an empty byte slice;
// callers that need data in the hash must Write it first. io.ErrShortBuffer is
// returned when p is smaller than the full hash so callers are not silently
// truncated.
func (s *SphinxHash) Read(p []byte) (n int, err error) {
	// Calculate the hash for the data stored in the SphinxHash instance
	hash := s.GetHash(s.data)

	// Copy the hash into the provided buffer p
	n = copy(p, hash)
	if n < len(hash) {
		return n, io.ErrShortBuffer // Return ErrShortBuffer if the buffer is smaller than the hash
	}
	return n, nil
}

// Write adds data to the hash.
func (s *SphinxHash) Write(p []byte) (n int, err error) {
	s.data = append(s.data, p...) // Append new data to the existing data
	return len(p), nil            // Return the number of bytes written
}

// Sum appends the current hash to b and returns the resulting slice.
func (s *SphinxHash) Sum(b []byte) []byte {
	hash := s.GetHash(s.data) // Compute the hash of the current data
	return append(b, hash...) // Append the hash to the provided byte slice
}

// Reset clears the accumulated data so the instance can be reused.
func (s *SphinxHash) Reset() {
	s.data = s.data[:0]
}

// hashData calculates the combined hash of data using multiple hash functions based on the bit size.
//
// FIX B: The original used append(data, s.salt...) which writes into data's
// underlying array when it has spare capacity, silently corrupting the caller's
// buffer. A fresh allocation is used instead.
//
// FIX D: saltEntropy is now mixed into the stretched key input so the stored
// entropy field is actually used in the hash derivation, fulfilling the
// cross-instance rainbow-table protection described in the type comment.
func (s *SphinxHash) hashData(data []byte) []byte {
	var sha2Hash []byte

	// FIX B: allocate a new backing array instead of append(data, s.salt...)
	// to avoid mutating the caller's data slice.
	//
	// FIX D: include saltEntropy alongside the salt so the random entropy
	// generated at construction time actively influences the hash output.
	const maxHashInputSize = 1 << 20 // 1 MB maximum hash input size
	totalSize := len(data) + len(s.salt) + len(s.saltEntropy)
	if totalSize > maxHashInputSize {
		panic(fmt.Sprintf("spxhash: hash input size %d exceeds maximum %d", totalSize, maxHashInputSize))
	}
	combined := make([]byte, totalSize)
	copy(combined, data)
	copy(combined[len(data):], s.salt)
	copy(combined[len(data)+len(s.salt):], s.saltEntropy)

	// Key stretching using Argon2id, which is a memory-hard function to improve resistance against brute-force attacks.
	stretchedKey := argon2.IDKey(combined, s.salt, iterations, memory, parallelism, 64) // Generate a 64-byte key.

	// Step 1: Compute SHA-512/256 on the stretched key.
	hash := sha512.New512_256() // Create a new SHA-512/256 hash instance.
	hash.Write(stretchedKey)    // Hash the stretched key using SHA-512/256.
	sha2Hash = hash.Sum(nil)    // Get the resulting hash.

	// Step 2: Compute SHAKE256 (a variable-length cryptographic hash function).
	shake := sha3.NewShake256()
	shake.Write(stretchedKey) // Use the stretched key for SHAKE256.

	// Dynamically determine the length of the shake output based on the size.
	shakeLength := s.Size()                // Use the Size function to dynamically set the output length for SHAKE256.
	shakeHash := make([]byte, shakeLength) // Create a slice for the dynamically determined length.
	if _, err := shake.Read(shakeHash); err != nil {
		panic(fmt.Sprintf("spxhash: failed to read SHAKE256 hash: %v", err))
	} // Read the resulting hash into shakeHash.

	// FIX #3 (Runtime panic for bitSize 384/512):
	// sphinxHash panicked when len(hash1) != len(hash2). sha2Hash is always
	// 32 bytes (SHA-512/256 fixed output) but shakeHash was sized by s.Size(),
	// giving 48 or 64 bytes for bitSize 384/512. The mismatch triggered the
	// panic unconditionally for those bit sizes.
	//
	// Fix: SHA-2 hash is extended to match shakeLength by feeding it through
	// SHAKE256 as well, so both inputs to sphinxHash are always shakeLength
	// bytes regardless of the configured bit size.
	var sha2Extended []byte
	if len(sha2Hash) != shakeLength {
		extShake := sha3.NewShake256()
		extShake.Write(sha2Hash)
		sha2Extended = make([]byte, shakeLength)
		if _, err := extShake.Read(sha2Extended); err != nil {
			panic(fmt.Sprintf("spxhash: failed to read extended SHAKE256 hash: %v", err))
		}
	} else {
		sha2Extended = sha2Hash
	}

	// Step 3: Combine both the hashes (SHA-256 and SHAKE256) using SphinxHash.
	return s.sphinxHash(sha2Extended, shakeHash, prime64) // Pass the hashes and prime constant to SphinxHash for combination.
}

// sphinxHash combines two byte slices (hash1 and hash2) using a prime constant and applies structured combinations.
// It utilizes chaining (H∘(x) = H0(H1(x))) and concatenation (H|(x) = H0(x)|H1(x)) of hash functions to enhance pre-image and collision resistance.
//
// FIX #3: The length-mismatch guard now returns a zero-value slice instead of
// calling panic, preventing a denial-of-service if the lengths somehow still
// diverge (belt-and-suspenders after the fix in hashData).
//
// FIX #5 (chainHash state accumulation across rounds):
// The original code reused a single sha512.New512_256() instance across all
// 1000 rounds. Because hash.Write accumulates state, round N was hashing the
// concatenation of ALL prior sphinxHash values rather than just the current
// one, making the construction hard to reason about and impossible to specify
// formally. Fix: a fresh hash instance is created inside the loop so each
// round hashes only the current sphinxHash value.
//
// FIX #9 (prime32 passed where uint64 expected):
// The call site now passes prime64 (a full 64-bit constant) so the XOR and
// addition steps use the full constant rather than a 32-bit value
// zero-extended to 64 bits.
//
// FIX H (Concatenation collapsed — collision-resistance guarantee lost):
// The original re-hashed the H|(x) concatenation back to 32 bytes immediately,
// discarding the width benefit that makes concatenation collision-resistant.
// The mixing rounds now operate on the full-width concatenated value
// (chainHash1Result + chainHash2Result), and the final output length is
// shakeLength (the configured output size) rather than a fixed 32 bytes.
//
// FIX I (XOR schedule repeats every 64 rounds):
// The original used (round % 64) as the shift amount, causing the XOR mask to
// repeat identically every 64 rounds across all 1000 iterations. A per-round
// hash-derived mask is used instead so no two rounds apply the same transform.
func (s *SphinxHash) sphinxHash(hash1, hash2 []byte, primeConstant uint64) []byte {

	// Ensure both input hashes have the same length for consistent processing.
	// This check ensures that both input hashes are compatible for further processing in the algorithm.
	if len(hash1) != len(hash2) {
		// FIX #3: return a zero-value slice instead of panicking.
		return make([]byte, s.Size())
	}

	// Step 1: Hash both input hashes to protect against pre-images.
	// This applies a chaining operation: H∘(x) = H0(H1(x)).
	// We first hash hash1 using SHA-512/256 to apply standard cryptographic resistance.
	chainHash1 := sha512.New512_256()
	chainHash1.Write(hash1)                 // Hash the first input hash using SHA-512/256.
	chainHash1Result := chainHash1.Sum(nil) // Get the result of the hash as a slice.

	// Step 2: Apply a second hash function (H0) to the result of the first hash (H1).
	// This ensures the chaining mechanism H∘(x) = H0(H1(x)), where the second hash function is applied to the result of the first.
	shakeLength := s.Size()                       // Dynamically set the length of the output hash.
	shake := sha3.NewShake256()                   // Create a SHAKE256 instance for further processing.
	shake.Write(chainHash1Result)                 // Apply SHAKE256 to the result of the first hash (chainHash1Result).
	chainHash2Result := make([]byte, shakeLength) // Dynamically allocate space for the result based on shakeLength.
	shake.Read(chainHash2Result)                  // Read the result into the allocated slice.

	// Step 3: Combine the two hashed results into one hash.
	// This concatenates (H|(x) = H0(x)|H1(x)) the results of the two hashes, which will be used for further processing.
	combinedHash := bytes.Join([][]byte{chainHash1Result[:], chainHash2Result[:]}, nil)

	// FIX H: operate on the full-width concatenated value instead of collapsing
	// it back to 32 bytes with another SHA-512/256 call. The mixing rounds below
	// now preserve the width advantage of concatenation.
	//
	// Step 4: Initialize the output hash (sphinxHash) using the full concatenated result.
	// The combined hash from the previous step becomes the starting point for further transformations.
	sphinxHashState := combinedHash // This is the current state of the hash (full width).

	// Step 5: Apply iterative rounds to increase diffusion and avalanche effects.
	rounds := 1000 // Set the number of rounds for iterative hashing to enhance diffusion.
	// The number of rounds is a critical factor for making sure that the hash undergoes substantial transformations
	// through multiple rounds of mixing and re-hashing. The higher the number of rounds, the harder it becomes
	// to predict the final output, even with a quantum computer or brute force attack.

	for round := 0; round < rounds; round++ {
		// In each round, non-commutative operations like bit rotation and XOR are applied to ensure unpredictability and security.
		// These operations are designed to make the hash resistant to reverse engineering, ensuring that small changes in input data
		// lead to drastic changes in the resulting hash, making it computationally infeasible for an attacker to predict or reverse the output.

		// FIX I: derive a unique per-round mask byte by hashing the current
		// state together with the round index and prime constant. This replaces
		// (round % 64) which caused the XOR schedule to repeat every 64 rounds,
		// significantly reducing the effective diffusion across 1000 rounds.
		maskHasher := sha512.New512_256()
		roundBuf := make([]byte, 8)
		binary.LittleEndian.PutUint64(roundBuf, uint64(round))
		maskHasher.Write(sphinxHashState)
		maskHasher.Write(roundBuf)
		maskBytes := maskHasher.Sum(nil)

		// Loop through each byte in the current sphinxHashState.
		for i := range sphinxHashState {
			// Perform a left bit rotation by 3 positions to increase the diffusion of the hash.
			// This operation ensures that small changes in input data (even one bit) lead to significant changes in the output hash.
			// The goal of this operation is to ensure that every byte of the hash contributes to the final result, diffusing
			// the input values over the entire hash. This makes brute force attacks more difficult, as attackers cannot
			// predict how input data will affect the output after the transformations.
			sphinxHashState[i] = (sphinxHashState[i] << 3) | (sphinxHashState[i] >> 5) // Bit rotation to the left by 3 bits.

			// XOR the rotated hash byte with a unique per-round mask byte for non-commutative behavior.
			// The XOR operation is a key part of making the transformation non-commutative.
			// Non-commutative means that applying the same transformation in a different order results in a different output,
			// which increases security. By XORing the rotated value with a per-round hash-derived mask,
			// we ensure that each round introduces a distinct, unpredictable transformation.
			// This is particularly important for making the function more resistant to attacks such as Grover's algorithm.
			sphinxHashState[i] ^= maskBytes[i%len(maskBytes)] // FIX I: unique per-round mask, not repeating schedule.
		}

		// Re-hash the result after each round for additional diffusion and avalanche effects.
		// Re-hashing helps to spread the effects of the previous round across the entire hash.
		// It ensures that any small change in the input (even after multiple transformations) affects the final hash.
		// This step is crucial for increasing the diffusion, meaning that each output bit of the hash depends on many input bits.
		// This makes brute force attacks more difficult because attackers have to account for the cascade of changes caused by the previous rounds.
		// Grover's algorithm, which can provide a quadratic speedup for brute-forcing quantum-resistant functions, would be less effective here.
		// The multiple rounds of hashing make it harder to guess any specific bit of the output without fully processing through each round.

		// FIX #5: allocate a fresh hasher each round so only the current
		// sphinxHashState value is hashed, not the cumulative state of all prior rounds.
		// FIX H: use SHAKE256 so the output stays at the full configured width
		// rather than collapsing back to 32 bytes on every round.
		roundShake := sha3.NewShake256()
		roundShake.Write(sphinxHashState) // Re-hash the intermediate result.
		newState := make([]byte, len(sphinxHashState))
		if _, err := roundShake.Read(newState); err != nil {
			panic(fmt.Sprintf("spxhash: failed to read round hash: %v", err))
		}
		sphinxHashState = newState // Update sphinxHashState with the new hash value after each round.
	}

	// Step 6: Truncate or expand to the configured output length, then apply
	// further mixing by adding the prime constant to each 64-bit segment.
	// This step ensures that the final result is heavily influenced by the prime constant to improve entropy and security.
	//
	// FIX H: after the mixing rounds, produce exactly shakeLength output bytes.
	finalShake := sha3.NewShake256()
	finalShake.Write(sphinxHashState)
	sphinxFinal := make([]byte, shakeLength)
	if _, err := finalShake.Read(sphinxFinal); err != nil {
		panic(fmt.Sprintf("spxhash: failed to read final hash: %v", err))
	}

	for i := 0; i < len(sphinxFinal)/8; i++ {
		// Calculate the offset for each 8-byte (64-bit) segment.
		// Each iteration processes one 64-bit segment of the hash.
		offset := i * 8 // Multiply the loop index by 8 to get the starting index of the 64-bit segment.

		// Check if the current segment goes out of bounds (this ensures we are not reading past the end of the hash).
		// The 'offset+8' ensures that we are only reading 8 bytes, i.e., 64 bits at a time.
		if offset+8 <= len(sphinxFinal) {
			// Read the current 64-bit segment of the hash in little-endian format.
			// We use the `binary.LittleEndian.Uint64` function to interpret the 8 bytes as a single 64-bit unsigned integer.
			// Little-endian means the least significant byte is stored first, which is a common format in many systems.
			val := binary.LittleEndian.Uint64(sphinxFinal[offset : offset+8]) // Read 8 bytes and convert to uint64.

			// Add the prime constant to the current value to enhance entropy and security.
			// This step ensures that the prime constant influences the final hash, making it more unpredictable and harder to reverse-engineer.
			// By adding the prime constant to each segment of the hash, we effectively "mix" it into the hash at a more granular level.
			// This provides an additional layer of randomness and protects against potential weaknesses in the hash function.
			val += primeConstant // Add the prime constant to the 64-bit segment.

			// Write the updated value back to the original slice at the same offset.
			// We use `binary.LittleEndian.PutUint64` to write the updated 64-bit value back into the `sphinxFinal` slice.
			// This operation ensures that the change is made in-place, modifying the original hash value.
			// Writing the result back to the same slice at the given offset ensures that the hash is updated with the new, mixed value.
			binary.LittleEndian.PutUint64(sphinxFinal[offset:offset+8], val) // Store the updated value back into the hash.
		}
	}

	// Step 7: Return the final SphinxHash after all the hashing and mixing operations.
	// The final hash, after iterative rounds and mixing with the prime constant, is returned as the output.
	return sphinxFinal // Output the final result after all transformations (already a []byte).
}
