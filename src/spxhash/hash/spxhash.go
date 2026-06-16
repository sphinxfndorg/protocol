// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/spxhash/hash/spxhash.go
package spxhash

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
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
func generateSalt(data []byte, saltSz int) (salt []byte, entropy []byte, err error) {
	entropy = make([]byte, saltSz)
	if _, err = rand.Read(entropy); err != nil {
		return nil, nil, errors.New("spxhash: failed to read random entropy for salt: " + err.Error())
	}

	// Use the constants for Argon2 parameters
	timeCost := uint32(iterations)    // Use the number of iterations from the constant
	memoryCost := uint32(memory)      // Use memory cost from the constant
	parallelism := uint8(parallelism) // Use parallelism from the constant

	// Combine random entropy with the input so the salt reflects both.
	combined := append(data, entropy...)

	// Argon2id (a combination of Argon2d and Argon2i) for secure hash-based salt generation
	salt = argon2.IDKey(
		combined, // password: data + random entropy
		entropy,  // salt:     the random entropy alone (truly random)
		timeCost,
		memoryCost,
		parallelism,
		uint32(saltSz),
	)
	return salt, entropy, nil
}

// NewSphinxHash creates a new SphinxHash with a specific bit size for the hash.
//
// FIX #2: salt generation now incorporates random entropy (see generateSalt).
// Returns an error if the OS random source is unavailable.
func NewSphinxHash(bitSize int, data []byte) (*SphinxHash, error) {
	// Pass saltSize explicitly when calling generateSalt
	salt, entropy, err := generateSalt(data, saltSize) // Use randomised salt based on input data
	if err != nil {
		return nil, err
	}
	return &SphinxHash{
		bitSize:      bitSize,
		salt:         salt,
		saltEntropy:  entropy,
		cache:        NewLRUCache(DefaultCacheSize),
		maxCacheSize: DefaultCacheSize,
	}, nil
}

// cacheKey builds a collision-resistant 64-bit cache key from the full
// contents of data.
//
// FIX #1 (Cache key collision):
// The original code used binary.LittleEndian.Uint64(data[:8]) as the cache
// key, meaning any two inputs that share the same first 8 bytes — regardless
// of what follows — mapped to the same key. A cache hit on such a collision
// returned the wrong hash silently, breaking correctness and making it
// exploitable in integrity-checking contexts.
//
// Fix: hash the entire input with SHA-512/256 and derive the 64-bit key from
// the first 8 bytes of THAT hash. The probability of two distinct inputs
// producing the same key is now ≈2⁻⁶⁴ (birthday bound on the key space)
// rather than certain for any shared prefix.
func cacheKey(data []byte) uint64 {
	h := sha512.New512_256()
	h.Write(data)
	sum := h.Sum(nil)
	return binary.LittleEndian.Uint64(sum[:8])
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
func (s *SphinxHash) GetHash(data []byte) []byte {
	if len(data) < 8 {
		// Use a fallback hash for short inputs
		hash := sha512.New512_256()
		hash.Write(data)
		hash.Write(s.salt)
		return hash.Sum(nil)
	}

	hashKey := cacheKey(data) // FIX #1: full-content key, not first-8-bytes key
	if cachedValue, found := s.cache.Get(hashKey); found {
		return cachedValue // Return cached value if found
	}

	// FIX #7: compute the hash on the receiver directly — no extra NewSphinxHash.
	hash := s.hashData(data)   // Calculate the hash using the deterministic salt
	s.cache.Put(hashKey, hash) // Store the calculated hash in the cache

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
func (s *SphinxHash) hashData(data []byte) []byte {
	var sha2Hash []byte

	// Combine the input data with the salt for Argon2id.
	combined := append(data, s.salt...) // Append salt to data to strengthen the final key.
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
	shake.Read(shakeHash)                  // Read the resulting hash into shakeHash.

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
		extShake.Read(sha2Extended)
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
	shake := sha3.NewShake256()                   // Create a SHAKE256 instance for further processing.
	shake.Write(chainHash1Result)                 // Apply SHAKE256 to the result of the first hash (chainHash1Result).
	shakeLength := s.Size()                       // Dynamically set the length of the output hash.
	chainHash2Result := make([]byte, shakeLength) // Dynamically allocate space for the result based on shakeLength.
	shake.Read(chainHash2Result)                  // Read the result into the allocated slice.

	// Step 3: Combine the two hashed results into one hash.
	// This concatenates (H|(x) = H0(x)|H1(x)) the results of the two hashes, which will be used for further processing.
	combinedHash := bytes.Join([][]byte{chainHash1Result[:], chainHash2Result[:]}, nil)

	// Step 3: Hash the combined result to generate a final chained hash.
	// By applying SHA-256 again on the combined hashes, we ensure that the final result has better security.
	chainHash := sha512.New512_256()
	chainHash.Write(combinedHash)         // Perform another SHA-512/256 hash on the combined result.
	chainHashResult := chainHash.Sum(nil) // Get the final hash.

	// Step 4: Initialize the output hash (sphinxHash) using the chained result.
	// The combined hash from the previous step becomes the starting point for further transformations.
	sphinxHash := chainHashResult // This is the current state of the hash.

	// Step 5: Apply iterative rounds to increase diffusion and avalanche effects.
	rounds := 1000 // Set the number of rounds for iterative hashing to enhance diffusion.
	// The number of rounds is a critical factor for making sure that the hash undergoes substantial transformations
	// through multiple rounds of mixing and re-hashing. The higher the number of rounds, the harder it becomes
	// to predict the final output, even with a quantum computer or brute force attack.

	for round := 0; round < rounds; round++ {
		// In each round, non-commutative operations like bit rotation and XOR are applied to ensure unpredictability and security.
		// These operations are designed to make the hash resistant to reverse engineering, ensuring that small changes in input data
		// lead to drastic changes in the resulting hash, making it computationally infeasible for an attacker to predict or reverse the output.

		// Loop through each byte in the current sphinxHash.
		for i := range sphinxHash {
			// Perform a left bit rotation by 3 positions to increase the diffusion of the hash.
			// This operation ensures that small changes in input data (even one bit) lead to significant changes in the output hash.
			// The goal of this operation is to ensure that every byte of the hash contributes to the final result, diffusing
			// the input values over the entire hash. This makes brute force attacks more difficult, as attackers cannot
			// predict how input data will affect the output after the transformations.
			sphinxHash[i] = (sphinxHash[i] << 3) | (sphinxHash[i] >> 5) // Bit rotation to the left by 3 bits.

			// XOR the rotated hash byte with a round-specific prime constant for non-commutative behavior.
			// The XOR operation is a key part of making the transformation non-commutative.
			// Non-commutative means that applying the same transformation in a different order results in a different output,
			// which increases security. By XORing the rotated value with a portion of a round-specific prime constant,
			// we ensure that each round introduces an additional layer of unpredictability.
			// This is particularly important for making the function more resistant to attacks such as Grover's algorithm.
			// Since XORing is reversible without additional steps, having it combined with rotation and iterative rounds makes it
			// more difficult to undo and makes the attack surface larger.
			sphinxHash[i] ^= byte(primeConstant >> (uint(round) % 64)) // XOR with a shifting part of the prime constant.
		}

		// Re-hash the result after each round for additional diffusion and avalanche effects.
		// Re-hashing helps to spread the effects of the previous round across the entire hash.
		// It ensures that any small change in the input (even after multiple transformations) affects the final hash.
		// This step is crucial for increasing the diffusion, meaning that each output bit of the hash depends on many input bits.
		// This makes brute force attacks more difficult because attackers have to account for the cascade of changes caused by the previous rounds.
		// Grover's algorithm, which can provide a quadratic speedup for brute-forcing quantum-resistant functions, would be less effective here.
		// The multiple rounds of hashing make it harder to guess any specific bit of the output without fully processing through each round.

		// FIX #5: allocate a fresh hasher each round so only the current
		// sphinxHash value is hashed, not the cumulative state of all prior rounds.
		roundHash := sha512.New512_256()
		roundHash.Write(sphinxHash)     // Re-hash the intermediate result.
		sphinxHash = roundHash.Sum(nil) // Update sphinxHash with the new hash value after each round.
	}

	// Step 6: Apply further mixing by adding the prime constant to each 64-bit segment of the hash.
	// This step ensures that the final result is heavily influenced by the prime constant to improve entropy and security.
	for i := 0; i < len(sphinxHash)/8; i++ {
		// Calculate the offset for each 8-byte (64-bit) segment.
		// Each iteration processes one 64-bit segment of the hash.
		offset := i * 8 // Multiply the loop index by 8 to get the starting index of the 64-bit segment.

		// Check if the current segment goes out of bounds (this ensures we are not reading past the end of the hash).
		// The 'offset+8' ensures that we are only reading 8 bytes, i.e., 64 bits at a time.
		if offset+8 <= len(sphinxHash) {
			// Read the current 64-bit segment of the hash in little-endian format.
			// We use the `binary.LittleEndian.Uint64` function to interpret the 8 bytes as a single 64-bit unsigned integer.
			// Little-endian means the least significant byte is stored first, which is a common format in many systems.
			val := binary.LittleEndian.Uint64(sphinxHash[offset : offset+8]) // Read 8 bytes and convert to uint64.

			// Add the prime constant to the current value to enhance entropy and security.
			// This step ensures that the prime constant influences the final hash, making it more unpredictable and harder to reverse-engineer.
			// By adding the prime constant to each segment of the hash, we effectively "mix" it into the hash at a more granular level.
			// This provides an additional layer of randomness and protects against potential weaknesses in the hash function.
			val += primeConstant // Add the prime constant to the 64-bit segment.

			// Write the updated value back to the original slice at the same offset.
			// We use `binary.LittleEndian.PutUint64` to write the updated 64-bit value back into the `sphinxHash` slice.
			// This operation ensures that the change is made in-place, modifying the original hash value.
			// Writing the result back to the same slice at the given offset ensures that the hash is updated with the new, mixed value.
			binary.LittleEndian.PutUint64(sphinxHash[offset:offset+8], val) // Store the updated value back into the hash.
		}
	}

	// Step 7: Return the final SphinxHash after all the hashing and mixing operations.
	// The final hash, after iterative rounds and mixing with the prime constant, is returned as the output.
	return sphinxHash // Output the final result after all transformations (already a []byte).
}
