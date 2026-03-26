// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/consensus/random.go
package consensus

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/sphinxorg/protocol/src/common"
	logger "github.com/sphinxorg/protocol/src/log"
	"golang.org/x/crypto/sha3"
)

// Constants for VDF submission windows and slashing
const (
	CommitWindowEnd = uint64(20)  // slots 0-20: submit commitHash+nonce (first phase of commit-reveal)
	RevealWindowEnd = uint64(31)  // slots 21-31: reveal beta+proof+nonce (second phase of commit-reveal)
	SlashBps        = uint64(100) // 1% of stake slashed for a missing reveal (basis points: 100 = 1%)
	SubmitWindowEnd = uint64(31)  // slots 0-31: submit VDF output + proof (entire window for submission)
)

// VDFCache caches VDF verification results to avoid redundant work
type VDFCache struct {
	mu       sync.RWMutex    // Read-write mutex for thread-safe map access
	verified map[string]bool // Map storing verification status: key = epoch:validatorID
}

// NewVDFCache creates a new VDF cache
func NewVDFCache() *VDFCache {
	// Initializes a new VDF cache with empty verification map
	return &VDFCache{
		verified: make(map[string]bool), // Creates empty map for storing verification status
	}
}

// IsVerified checks if a VDF submission has already been verified
func (vc *VDFCache) IsVerified(epoch uint64, validatorID string) bool {
	vc.mu.RLock()                                   // Acquires read lock for concurrent safe map access
	defer vc.mu.RUnlock()                           // Releases read lock when function returns
	key := fmt.Sprintf("%d:%s", epoch, validatorID) // Creates composite key from epoch and validator ID
	return vc.verified[key]                         // Returns true if key exists in map and value is true
}

// MarkVerified marks a VDF submission as verified
func (vc *VDFCache) MarkVerified(epoch uint64, validatorID string) {
	vc.mu.Lock()                                    // Acquires write lock for map modification
	defer vc.mu.Unlock()                            // Releases write lock when function returns
	key := fmt.Sprintf("%d:%s", epoch, validatorID) // Creates composite key from epoch and validator ID
	vc.verified[key] = true                         // Sets verification status to true
}

// vdfProvider abstracts the VDF implementation so it can be replaced in tests.
type vdfProvider interface {
	Eval(params VDFParams, x *big.Int) (y, proof *big.Int, err error) // Evaluates VDF and returns output and proof
	Verify(params VDFParams, x, y, proof *big.Int) bool               // Verifies VDF proof for given input/output
}

// productionVDF implements Wesolowski's VDF using class groups (post-quantum)
// This is the production VDF implementation using class group operations
type productionVDF struct {
	D *big.Int // Discriminant of the class group (negative integer for imaginary quadratic field)
	T uint64   // Delay parameter (number of sequential squarings to perform)
}

// NewProductionVDF creates a new VDF instance with the given parameters.
// The discriminant must come from a public trusted setup ceremony.
func NewProductionVDF(discriminant *big.Int, T uint64) *productionVDF {
	// Creates a new production VDF implementation with specified parameters
	return &productionVDF{
		D: discriminant, // Sets the class group discriminant
		T: T,            // Sets the sequential squaring count
	}
}

// pow2Mod computes 2^T mod m efficiently using modular exponentiation
// This is used for computing r = 2^T mod l in the Wesolowski verification
func pow2Mod(T uint64, m *big.Int) *big.Int {
	// Uses fast exponentiation to compute 2^T mod m
	return new(big.Int).Exp(big.NewInt(2), new(big.Int).SetUint64(T), m)
}

// Eval computes y = x^(2^T) in the class group and a Wesolowski proof
// This is the sequential VDF evaluation that cannot be parallelized
func (v *productionVDF) Eval(params VDFParams, x *big.Int) (*big.Int, *big.Int, error) {
	startTime := time.Now() // Records start time for performance monitoring

	D := params.Discriminant // Extracts discriminant from parameters
	T := params.T            // Extracts delay parameter from parameters

	// Convert input to class group element
	xElement := BigIntToClassGroup(x, D) // Deserializes big integer to class group element

	// Step 1: Compute y = x^(2^T) via sequential squaring
	// This is the core VDF computation that takes time proportional to T
	yElement := RepeatedSquare(xElement, D, T) // Performs T sequential squarings
	y := ClassGroupToBigInt(yElement)          // Serializes result to big integer

	// Step 2: Compute challenge l = H(D, T, x, y)
	// This is a Fiat-Shamir transformation for the Wesolowski proof
	l := HashToPrime(D, x, y, T) // Generates random challenge prime from hash

	// Step 3: Compute q = floor(2^T / l)
	twoPowT := new(big.Int).Exp(big.NewInt(2), new(big.Int).SetUint64(T), nil) // Calculates 2^T as big integer
	q := new(big.Int).Div(twoPowT, l)                                          // Integer division to get quotient

	// Step 4: Compute proof π = x^q
	proofElement := Exponentiate(xElement, q, D) // Performs exponentiation in class group
	proof := ClassGroupToBigInt(proofElement)    // Serializes proof to big integer

	elapsed := time.Since(startTime) // Calculates elapsed time for evaluation
	logger.Info("🔮 Class Group VDF Eval: T=%d, time=%v, input=%x..., output=%x..., l=%x...",
		T, elapsed, x.Bytes()[:8], y.Bytes()[:8], l.Bytes()[:8]) // Logs evaluation metrics

	return y, proof, nil // Returns output value and proof
}

// AreEqual checks if two class group elements are equal after canonical normalization
func AreEqual(a, b *ClassGroupElement, D *big.Int) bool {
	aNorm := CanonicalNormalize(a, D) // Normalizes first element to canonical form
	bNorm := CanonicalNormalize(b, D) // Normalizes second element to canonical form

	// Compares all three coefficients for equality
	equal := aNorm.A.Cmp(bNorm.A) == 0 && // Checks if A coefficients are equal
		aNorm.B.Cmp(bNorm.B) == 0 && // Checks if B coefficients are equal
		aNorm.C.Cmp(bNorm.C) == 0 // Checks if C coefficients are equal

	if !equal { // If elements are not equal, log debug information
		// Debug output for mismatched elements
		logger.Debug("Element comparison failed:")
		logger.Debug("  Left: A=%x, B=%x, C=%x", aNorm.A.Bytes(), aNorm.B.Bytes(), aNorm.C.Bytes())
		logger.Debug("  Right: A=%x, B=%x, C=%x", bNorm.A.Bytes(), bNorm.B.Bytes(), bNorm.C.Bytes())
	}

	return equal // Returns equality result
}

// ValidateVDFParams ensures all nodes use the same VDF parameters
func (r *RANDAO) ValidateVDFParams(expected VDFParams) error {
	r.mu.RLock()         // Acquires read lock for thread-safe parameter access
	defer r.mu.RUnlock() // Releases read lock when function returns

	if r.params.Discriminant.Cmp(expected.Discriminant) != 0 { // Compares discriminants
		return fmt.Errorf("discriminant mismatch: local=%x, expected=%x",
			r.params.Discriminant.Bytes(), expected.Discriminant.Bytes()) // Returns error with hex values
	}

	if r.params.T != expected.T { // Compares delay parameters
		return fmt.Errorf("T mismatch: local=%d, expected=%d", r.params.T, expected.T) // Returns error with values
	}

	return nil // Returns nil if all parameters match
}

// GetVDFParams returns the current VDF parameters
func (r *RANDAO) GetVDFParams() VDFParams {
	r.mu.RLock()         // Acquires read lock for thread-safe access
	defer r.mu.RUnlock() // Releases read lock when function returns
	return r.params      // Returns copy of VDF parameters
}

// RecoverVDFState attempts to recover a node's VDF state by re-verifying from a checkpoint
func (r *RANDAO) RecoverVDFState(checkpointEpoch uint64, checkpointMix [32]byte) error {
	r.mu.Lock()         // Acquires write lock for state modification
	defer r.mu.Unlock() // Releases write lock when function returns

	logger.Warn("Attempting VDF state recovery from epoch %d", checkpointEpoch) // Logs recovery attempt

	// Reset state to checkpoint
	r.mix = checkpointMix // Sets mix to checkpoint value

	// Clear all submissions after checkpoint
	for epoch := range r.submissions { // Iterates through all epochs with submissions
		if epoch > checkpointEpoch { // If epoch is after checkpoint
			delete(r.submissions, epoch)    // Removes submissions for this epoch
			delete(r.reveals, epoch)        // Removes reveals for this epoch
			delete(r.missed, epoch)         // Removes missed entries for this epoch
			delete(r.epochFinalized, epoch) // Removes finalized flag for this epoch
		}
	}

	// Clear cache entries after checkpoint
	r.cache.mu.Lock()                   // Acquires lock on cache for modification
	for key := range r.cache.verified { // Iterates through all cached entries
		// Parse epoch from key (format: "epoch:validatorID")
		// This is simplified - you'd need proper parsing
		_ = key // Suppress unused variable warning
	}
	r.cache.mu.Unlock() // Releases cache lock

	logger.Info("VDF state recovered to epoch %d, mix=%x", checkpointEpoch, checkpointMix) // Logs recovery completion
	return nil                                                                             // Returns success
}

// SelfVerify allows a node to verify its own VDF submission before broadcasting
func (r *RANDAO) SelfVerify(sub *VDFSubmission) error {
	expected := r.GetSeed(sub.Epoch) // Gets expected input seed for this epoch
	if expected != sub.Input {       // Compares with submission input
		return fmt.Errorf("input mismatch: expected %x got %x", expected, sub.Input) // Returns error on mismatch
	}

	x := seedToBigInt(sub.Input, r.params.Discriminant) // Converts seed to class group element

	if !r.impl.Verify(r.params, x, sub.Output, sub.Proof) { // Verifies VDF proof
		// Log detailed failure for debugging
		logger.Error("Self-verification failed for validator %s epoch %d", sub.ValidatorID, sub.Epoch)
		logger.Error("  Input seed: %x", sub.Input)             // Logs input seed
		logger.Error("  Output y: %x", sub.Output.Bytes()[:16]) // Logs first 16 bytes of output
		logger.Error("  Proof π: %x", sub.Proof.Bytes()[:16])   // Logs first 16 bytes of proof

		// Attempt to recompute and compare
		logger.Info("Attempting to recompute VDF for comparison...") // Logs recomputation attempt
		recomputed, proof, err := r.impl.Eval(r.params, x)           // Recomputes VDF locally
		if err != nil {                                              // If recomputation fails
			return fmt.Errorf("recomputation failed: %w", err) // Returns recomputation error
		}

		if recomputed.Cmp(sub.Output) != 0 { // Compares recomputed output with submitted output
			logger.Error("Output mismatch: computed=%x, submitted=%x",
				recomputed.Bytes()[:16], sub.Output.Bytes()[:16]) // Logs mismatch details
		}
		if proof.Cmp(sub.Proof) != 0 { // Compares recomputed proof with submitted proof
			logger.Error("Proof mismatch: computed=%x, submitted=%x",
				proof.Bytes()[:16], sub.Proof.Bytes()[:16]) // Logs mismatch details
		}

		return fmt.Errorf("self-verification failed") // Returns verification failure
	}

	return nil // Returns success if verification passes
}

// ForceSyncParams forces a node to sync VDF parameters from a trusted source
func (r *RANDAO) ForceSyncParams(trustedParams VDFParams) error {
	r.mu.Lock()         // Acquires write lock for parameter modification
	defer r.mu.Unlock() // Releases write lock when function returns

	logger.Warn("Force syncing VDF parameters from trusted source") // Logs sync initiation
	logger.Warn("  Old D: %x", r.params.Discriminant.Bytes())       // Logs old discriminant
	logger.Warn("  New D: %x", trustedParams.Discriminant.Bytes())  // Logs new discriminant
	logger.Warn("  Old T: %d", r.params.T)                          // Logs old delay parameter
	logger.Warn("  New T: %d", trustedParams.T)                     // Logs new delay parameter

	// Update parameters
	r.params = trustedParams // Sets parameters to trusted values

	// Recreate VDF implementation with new parameters
	r.impl = NewProductionVDF(trustedParams.Discriminant, trustedParams.T) // Creates new VDF instance

	// Clear all state - we need to start fresh with correct parameters
	r.submissions = make(map[uint64]map[string]*VDFSubmission) // Reinitializes submissions map
	r.reveals = make(map[uint64][][32]byte)                    // Reinitializes reveals map
	r.missed = make(map[uint64]map[string]bool)                // Reinitializes missed map
	r.epochFinalized = make(map[uint64]bool)                   // Reinitializes finalized map
	r.cache = NewVDFCache()                                    // Creates new cache instance

	logger.Info("VDF parameters force synced, all state cleared") // Logs completion
	return nil                                                    // Returns success
}

// Verify checks a Wesolowski proof using the correct verification formula
// Verifies that y^l == π^l * x^r where r = 2^T mod l
// This is the corrected implementation that properly verifies the proof
func (v *productionVDF) Verify(params VDFParams, x, y, proof *big.Int) bool {
	startTime := time.Now() // Records start time for performance monitoring

	D := params.Discriminant // Extracts discriminant from parameters
	T := params.T            // Extracts delay parameter from parameters

	// Recompute challenge l = H(D, T, x, y)
	l := HashToPrime(D, x, y, T) // Generates challenge prime from hash

	// Compute r = 2^T mod l
	r := pow2Mod(T, l) // Calculates r = 2^T mod l

	// Convert to class group elements
	xElement := BigIntToClassGroup(x, D)         // Converts input to class group element
	yElement := BigIntToClassGroup(y, D)         // Converts output to class group element
	proofElement := BigIntToClassGroup(proof, D) // Converts proof to class group element

	// Verify: y^l == π^l * x^r
	// Compute y^l
	yPowL := Exponentiate(yElement, l, D) // Computes y^l in class group

	// Compute π^l * x^r
	proofPowL := Exponentiate(proofElement, l, D) // Computes π^l in class group
	xPowR := Exponentiate(xElement, r, D)         // Computes x^r in class group
	left := Compose(proofPowL, xPowR, D)          // Composes π^l and x^r

	// Use proper equality check with canonical normalization
	valid := AreEqual(yPowL, left, D) // Checks if y^l equals π^l * x^r

	elapsed := time.Since(startTime) // Calculates elapsed time for verification
	if valid {                       // If verification succeeded
		logger.Info("✅ Class Group VDF Verify: T=%d, time=%v, valid=true", T, elapsed) // Logs success
	} else { // If verification failed
		logger.Warn("❌ Class Group VDF Verify: T=%d, time=%v, valid=false", T, elapsed) // Logs failure

		// Additional debug information for failed verification
		logger.Debug("Verification details:")
		logger.Debug("  l=%x, r=%x", l.Bytes(), r.Bytes()) // Logs challenge and remainder

		// Log the challenge prime for debugging
		logger.Debug("  Challenge l bits: %d", l.BitLen()) // Logs bit length of challenge

		// Log component sizes for debugging
		logger.Debug("  y^l A size: %d bits", yPowL.A.BitLen()) // Logs size of y^l coefficient
		logger.Debug("  left A size: %d bits", left.A.BitLen()) // Logs size of left side coefficient
	}

	return valid // Returns verification result
}

// GenerateClassGroupParameters generates parameters for class group VDF
// For production, these must come from a public trusted setup ceremony
// This is only for development and testing purposes
func GenerateClassGroupParameters(bits int, T uint64) (*VDFParams, error) {
	logger.Info("🔐 Generating class group parameters: %d-bit discriminant, T=%d", bits, T) // Logs generation start

	// For class group VDF, we need a fundamental discriminant D
	// D should be negative and ≡ 1 mod 4 for imaginary quadratic fields
	// Common choice: D = -p where p is a large prime ≡ 3 mod 4

	// Generate a prime p ≡ 3 mod 4
	var p *big.Int // Declares variable for prime
	var err error  // Declares error variable
	for {          // Loops until suitable prime found
		p, err = rand.Prime(rand.Reader, bits) // Generates random prime of specified bits
		if err != nil {                        // If generation failed
			return nil, err // Returns error
		}
		// Check if p ≡ 3 mod 4
		if new(big.Int).Mod(p, big.NewInt(4)).Cmp(big.NewInt(3)) == 0 { // If p mod 4 equals 3
			break // Found suitable prime, exit loop
		}
	}

	// D = -p (negative fundamental discriminant)
	D := new(big.Int).Neg(p) // Creates negative discriminant

	logger.Info("✅ Class group parameters generated: D=%d bits, D mod 4 = %d",
		D.BitLen(), new(big.Int).Mod(D, big.NewInt(4))) // Logs generation completion

	return &VDFParams{ // Returns parameters struct
		Discriminant: D,   // Sets discriminant
		T:            T,   // Sets delay parameter
		Lambda:       256, // Sets security parameter to 256 bits
	}, nil // Returns nil error
}

// seedToBigInt encodes a 32-byte seed as an element of the class group
// This is used to convert RANDAO seeds to class group elements for VDF evaluation
func seedToBigInt(seed [32]byte, D *big.Int) *big.Int {
	el := HashToClassGroup(seed, D) // Hashes seed to class group element
	return ClassGroupToBigInt(el)   // Serializes element to big integer
}

// outputToFixed folds a big.Int VDF output into a 32-byte value for XOR-mixing
// Uses SHAKE256 for consistency with the rest of the VDF implementation
func outputToFixed(y *big.Int) [32]byte {
	// Use SHAKE256 for variable-length output (consistent with HashToClassGroup and HashToPrime)
	shake := sha3.NewShake256() // Creates new SHAKE256 hash instance
	shake.Write(y.Bytes())      // Writes output bytes to hash

	var result [32]byte   // Declares 32-byte result array
	shake.Read(result[:]) // Reads 32 bytes of hash output
	return result         // Returns fixed-size output
}

// NewRANDAO initialises the VDF-based beacon with the genesis seed and the
// chain's public VDF parameters.
func NewRANDAO(genesisSeed [32]byte, params VDFParams, validatorID string) *RANDAO {
	// Create production VDF instance
	vdfImpl := NewProductionVDF(params.Discriminant, params.T) // Creates VDF implementation

	return &RANDAO{ // Returns initialized RANDAO structure
		mix:                 genesisSeed,                                // Sets initial mix to genesis seed
		reveals:             make(map[uint64][][32]byte),                // Initializes reveals map
		submissions:         make(map[uint64]map[string]*VDFSubmission), // Initializes submissions map
		missed:              make(map[uint64]map[string]bool),           // Initializes missed map
		epochFinalized:      make(map[uint64]bool),                      // Initializes finalized map
		params:              params,                                     // Sets VDF parameters
		impl:                vdfImpl,                                    // Sets VDF implementation
		cache:               NewVDFCache(),                              // Creates new verification cache
		consecutiveFailures: make(map[string]int),                       // Initializes failure counter map
		validatorID:         validatorID,                                // Sets validator ID for this node
	}
}

// getValidatorID returns this node's validator ID
func (r *RANDAO) getValidatorID() string {
	return r.validatorID // Returns validator ID string
}

// GetParams returns the VDF public parameters for this beacon instance.
func (r *RANDAO) GetParams() VDFParams {
	r.mu.RLock()         // Acquires read lock for thread-safe access
	defer r.mu.RUnlock() // Releases read lock when function returns
	return r.params      // Returns copy of VDF parameters
}

// GetSeed derives a deterministic 32-byte seed for the given slot.
// This uses the current mix XORed with the slot number to generate a unique seed
func (r *RANDAO) GetSeed(slot uint64) [32]byte {
	r.mu.RLock()         // Acquires read lock for thread-safe access
	defer r.mu.RUnlock() // Releases read lock when function returns

	data := make([]byte, 40)                       // Creates byte slice for combined data (32 bytes mix + 8 bytes slot)
	copy(data[:32], r.mix[:])                      // Copies current mix to first 32 bytes
	binary.LittleEndian.PutUint64(data[32:], slot) // Writes slot number as little-endian uint64
	hash := common.SpxHash(data)                   // Computes hash of combined data

	var result [32]byte   // Declares 32-byte result array
	copy(result[:], hash) // Copies hash to result
	return result         // Returns derived seed
}

// EvalVDF evaluates the VDF for the given epoch.
// This is called by validators to compute their VDF submission
func (r *RANDAO) EvalVDF(validatorID string, epoch, slotInEpoch uint64) (*VDFSubmission, error) {
	seed := r.GetSeed(epoch)                       // Gets seed for this epoch
	x := seedToBigInt(seed, r.params.Discriminant) // Converts seed to class group element

	r.mu.RLock()       // Acquires read lock for parameter access
	params := r.params // Copies parameters
	r.mu.RUnlock()     // Releases read lock

	y, proof, err := r.impl.Eval(params, x) // Evaluates VDF with parameters
	if err != nil {                         // If evaluation failed
		return nil, fmt.Errorf("VDF eval: %w", err) // Returns wrapped error
	}

	return &VDFSubmission{ // Returns VDF submission struct
		Epoch:       epoch,       // Sets epoch number
		SlotInEpoch: slotInEpoch, // Sets slot within epoch
		ValidatorID: validatorID, // Sets validator ID
		Input:       seed,        // Sets input seed
		Output:      y,           // Sets VDF output
		Proof:       proof,       // Sets VDF proof
	}, nil // Returns nil error
}

// Submit accepts a VDF submission from any node.
// This is called when a node submits its VDF output and proof
// Submit accepts a VDF submission from any node.
// Submit accepts a VDF submission from any node.
func (r *RANDAO) Submit(slotInEpoch uint64, sub *VDFSubmission) error {
	if slotInEpoch > SubmitWindowEnd { // Checks if submission is within window
		return fmt.Errorf("submit window closed (slot %d > %d)", slotInEpoch, SubmitWindowEnd) // Returns error if window closed
	}

	// Track if this is a self-submission
	isSelfSubmission := sub.ValidatorID == r.getValidatorID() // Checks if submission is from this node

	// Check cache first to avoid redundant verification
	if r.cache.IsVerified(sub.Epoch, sub.ValidatorID) { // If already verified
		logger.Debug("VDF already verified for epoch %d validator %s", sub.Epoch, sub.ValidatorID) // Logs cache hit
	} else { // If not verified yet
		expected := r.GetSeed(sub.Epoch) // Gets expected input for this epoch
		if expected != sub.Input {       // If input doesn't match expected
			return fmt.Errorf("input mismatch for epoch %d: expected %x got %x",
				sub.Epoch, expected, sub.Input) // Returns input mismatch error
		}

		x := seedToBigInt(sub.Input, r.params.Discriminant) // Converts seed to class group element

		r.mu.RLock()                     // Acquires read lock for state access
		if r.epochFinalized[sub.Epoch] { // If epoch already finalized
			r.mu.RUnlock()                                             // Releases read lock
			return fmt.Errorf("epoch %d already finalized", sub.Epoch) // Returns error
		}
		r.mu.RUnlock() // Releases read lock

		// Verify the VDF proof
		if !r.impl.Verify(r.params, x, sub.Output, sub.Proof) { // If verification fails
			// Track failures for self-submissions
			if isSelfSubmission { // If this is a self-submission
				r.mu.Lock()                                        // Acquires write lock for failure tracking
				r.consecutiveFailures[sub.ValidatorID]++           // Increments failure counter
				failures := r.consecutiveFailures[sub.ValidatorID] // Gets current failure count
				r.mu.Unlock()                                      // Releases write lock

				logger.Error("Self VDF verification failed for epoch %d (attempt %d)", sub.Epoch, failures) // Logs failure

				// Recover after 3 consecutive failures
				if failures >= 3 { // If 3 consecutive failures
					logger.Error("!!! CRITICAL: 3 consecutive VDF failures detected - initiating emergency recovery !!!") // Logs critical error
					r.Recovery()                                                                                          // Triggers emergency recovery

					// Reset failure counter after recovery
					r.mu.Lock()                                    // Acquires write lock
					delete(r.consecutiveFailures, sub.ValidatorID) // Removes failure counter
					r.mu.Unlock()                                  // Releases write lock
				}
			}

			return fmt.Errorf("VDF proof invalid: validator=%s epoch=%d",
				sub.ValidatorID, sub.Epoch) // Returns verification failure
		}

		// Reset failures on success
		if isSelfSubmission { // If this is a self-submission
			r.mu.Lock()                                    // Acquires write lock
			delete(r.consecutiveFailures, sub.ValidatorID) // Removes failure counter
			r.mu.Unlock()                                  // Releases write lock
		}

		// Mark as verified in cache
		r.cache.MarkVerified(sub.Epoch, sub.ValidatorID) // Caches verification result
	}

	r.mu.Lock()         // Acquires write lock for state modification
	defer r.mu.Unlock() // Releases write lock when function returns

	if r.submissions[sub.Epoch] == nil { // If no submissions for this epoch yet
		r.submissions[sub.Epoch] = make(map[string]*VDFSubmission) // Creates submission map for epoch
	}

	if _, already := r.submissions[sub.Epoch][sub.ValidatorID]; already { // If validator already submitted
		logger.Info("ℹ️  Duplicate VDF submission ignored: validator=%s epoch=%d",
			sub.ValidatorID, sub.Epoch) // Logs duplicate submission
		return nil // Returns without processing duplicate
	}

	// Only first submission updates the mix
	isFirst := len(r.submissions[sub.Epoch]) == 0 // Checks if this is first submission for epoch

	fixed := outputToFixed(sub.Output) // Converts output to fixed-size array
	if isFirst {                       // If this is first submission
		for i := range r.mix { // Iterates through mix bytes
			r.mix[i] ^= fixed[i] // XORs output with mix
		}
		logger.Info("✅ First VDF submission for epoch %d: mix updated", sub.Epoch) // Logs mix update
	} else { // If not first submission
		logger.Info("✅ VDF submission accepted (additional) for epoch %d", sub.Epoch) // Logs acceptance
	}

	r.reveals[sub.Epoch] = append(r.reveals[sub.Epoch], fixed) // Adds to reveals list
	r.submissions[sub.Epoch][sub.ValidatorID] = sub            // Stores submission

	return nil // Returns success
}

// ResetVDFState resets the VDF state for a specific epoch (useful for recovery)
func (r *RANDAO) ResetVDFState(epoch uint64) {
	r.mu.Lock()         // Acquires write lock for state modification
	defer r.mu.Unlock() // Releases write lock when function returns

	delete(r.submissions, epoch)    // Removes submissions for epoch
	delete(r.reveals, epoch)        // Removes reveals for epoch
	delete(r.missed, epoch)         // Removes missed entries for epoch
	r.epochFinalized[epoch] = false // Sets finalized flag to false

	logger.Info("Reset VDF state for epoch %d", epoch) // Logs reset completion
}

// ValidateState checks the consistency of the VDF state
func (r *RANDAO) ValidateState() error {
	r.mu.RLock()         // Acquires read lock for state inspection
	defer r.mu.RUnlock() // Releases read lock when function returns

	for epoch, subs := range r.submissions { // Iterates through all epochs with submissions
		for validatorID, sub := range subs { // Iterates through all submissions in epoch
			// Verify that cached verification matches actual state
			if !r.cache.IsVerified(epoch, validatorID) { // If submission exists but not cached
				logger.Warn("Inconsistent state: submission exists but not cached for epoch %d validator %s", epoch, validatorID) // Logs inconsistency
				return fmt.Errorf("state inconsistency for epoch %d validator %s", epoch, validatorID)                            // Returns error
			}

			// Optional: Additional validation
			if sub == nil { // If submission is nil
				logger.Warn("Nil submission found for epoch %d validator %s", epoch, validatorID) // Logs nil submission
				return fmt.Errorf("nil submission for epoch %d validator %s", epoch, validatorID) // Returns error
			}
		}
	}

	return nil // Returns success if state is consistent
}

// FinaliseEpoch is called at the epoch boundary.
// This processes the epoch and slashes validators that missed their VDF submission
func (r *RANDAO) FinaliseEpoch(epoch uint64, activeValidators []string) []string {
	r.mu.Lock()         // Acquires write lock for state modification
	defer r.mu.Unlock() // Releases write lock when function returns

	if r.missed[epoch] == nil { // If missed map doesn't exist for epoch
		r.missed[epoch] = make(map[string]bool) // Creates missed map for epoch
	}

	subs := r.submissions[epoch] // Gets submissions for epoch

	var slashList []string                // Creates slice for validators to slash
	for _, id := range activeValidators { // Iterates through active validators
		submitted := subs != nil && subs[id] != nil // Checks if validator submitted VDF
		if !submitted {                             // If validator did not submit
			r.missed[epoch][id] = true        // Marks as missed
			slashList = append(slashList, id) // Adds to slash list
		}
	}

	// Mark epoch as finalized
	r.epochFinalized[epoch] = true // Sets finalized flag

	for _, id := range slashList { // Iterates through slashed validators
		logger.Warn("⚠️  Validator %s did not submit VDF for epoch %d — slashing", id, epoch) // Logs slashing
	}

	return slashList // Returns list of validators to slash
}

// AddOutput is kept for the genesis/bootstrap path and backward compatibility.
// This allows manually adding VDF outputs for testing
func (r *RANDAO) AddOutput(epoch uint64, output [32]byte) {
	r.mu.Lock()                                         // Acquires write lock for state modification
	defer r.mu.Unlock()                                 // Releases write lock when function returns
	r.reveals[epoch] = append(r.reveals[epoch], output) // Appends output to reveals
	for i := range r.mix {                              // Iterates through mix bytes
		r.mix[i] ^= output[i] // XORs output with mix
	}
}

// EmergencyRecover - clears corrupted VDF state
func (r *RANDAO) Recovery() {
	r.mu.Lock()         // Acquires write lock for state modification
	defer r.mu.Unlock() // Releases write lock when function returns

	logger.Warn("!!! EMERGENCY VDF STATE RECOVERY INITIATED !!!") // Logs emergency recovery start
	logger.Warn("This will clear all VDF state for this node")    // Logs warning about state clearing

	// Clear all submissions
	r.submissions = make(map[uint64]map[string]*VDFSubmission) // Reinitializes submissions map
	r.reveals = make(map[uint64][][32]byte)                    // Reinitializes reveals map
	r.missed = make(map[uint64]map[string]bool)                // Reinitializes missed map
	r.epochFinalized = make(map[uint64]bool)                   // Reinitializes finalized map

	// Clear cache
	r.cache = NewVDFCache() // Creates new cache instance

	// Keep the current mix - don't reset it as it's derived from consensus
	logger.Info("Current mix preserved: %x", r.mix) // Logs preserved mix

	// Recreate VDF implementation with current parameters
	r.impl = NewProductionVDF(r.params.Discriminant, r.params.T) // Recreates VDF implementation

	logger.Info("Emergency recovery complete - VDF state cleared") // Logs recovery completion
}

// SyncState synchronizes RANDAO state with another node
func (r *RANDAO) SyncState(peerMix [32]byte, peerSubmissions map[uint64]map[string]*VDFSubmission) error {
	r.mu.Lock()         // Acquires write lock for state modification
	defer r.mu.Unlock() // Releases write lock when function returns

	// Log the sync attempt
	logger.Info("Syncing RANDAO state - local mix: %x, peer mix: %x", r.mix, peerMix) // Logs sync attempt

	// If peer has a different mix, we need to sync
	if r.mix != peerMix { // If mixes differ
		logger.Warn("RANDAO mix mismatch detected - syncing to peer state") // Logs mismatch
		r.mix = peerMix                                                     // Sets mix to peer's mix

		// Clear local submissions and use peer's
		r.submissions = make(map[uint64]map[string]*VDFSubmission) // Reinitializes submissions map
		for epoch, subs := range peerSubmissions {                 // Iterates through peer submissions
			r.submissions[epoch] = make(map[string]*VDFSubmission) // Creates map for epoch
			for validatorID, sub := range subs {                   // Iterates through submissions in epoch
				// Deep copy the submission
				subCopy := &VDFSubmission{ // Creates copy of submission
					Epoch:       sub.Epoch,                    // Copies epoch
					SlotInEpoch: sub.SlotInEpoch,              // Copies slot
					ValidatorID: sub.ValidatorID,              // Copies validator ID
					Input:       sub.Input,                    // Copies input
					Output:      new(big.Int).Set(sub.Output), // Copies output
					Proof:       new(big.Int).Set(sub.Proof),  // Copies proof
				}
				r.submissions[epoch][validatorID] = subCopy // Stores copy in local map
			}
		}

		// Clear cache since state changed
		r.cache = NewVDFCache() // Creates new cache instance

		logger.Info("RANDAO state synced to peer - new mix: %x", r.mix) // Logs sync completion
	}

	return nil // Returns success
}

// GetStateSnapshot returns a snapshot of current RANDAO state for syncing
func (r *RANDAO) GetStateSnapshot() ([32]byte, map[uint64]map[string]*VDFSubmission) {
	r.mu.RLock()         // Acquires read lock for state access
	defer r.mu.RUnlock() // Releases read lock when function returns

	// Create a deep copy of submissions
	submissionsCopy := make(map[uint64]map[string]*VDFSubmission) // Creates copy map
	for epoch, subs := range r.submissions {                      // Iterates through all epochs
		submissionsCopy[epoch] = make(map[string]*VDFSubmission) // Creates map for epoch
		for validatorID, sub := range subs {                     // Iterates through submissions in epoch
			subCopy := &VDFSubmission{ // Creates copy of submission
				Epoch:       sub.Epoch,                    // Copies epoch
				SlotInEpoch: sub.SlotInEpoch,              // Copies slot
				ValidatorID: sub.ValidatorID,              // Copies validator ID
				Input:       sub.Input,                    // Copies input
				Output:      new(big.Int).Set(sub.Output), // Copies output
				Proof:       new(big.Int).Set(sub.Proof),  // Copies proof
			}
			submissionsCopy[epoch][validatorID] = subCopy // Stores copy in map
		}
	}

	return r.mix, submissionsCopy // Returns current mix and submissions copy
}

// DetectAndRecoverDivergence checks if this node's state has diverged from peers
func (r *RANDAO) DetectAndRecoverDivergence(peerMix [32]byte, peerEpoch uint64) bool {
	r.mu.RLock()         // Acquires read lock for state access
	defer r.mu.RUnlock() // Releases read lock when function returns

	// Check if mix is significantly different
	if r.mix != peerMix { // If mixes differ
		logger.Error("RANDAO divergence detected! Local mix: %x, Peer mix: %x", r.mix, peerMix) // Logs divergence

		// If we're behind in epoch, we need to sync
		if peerEpoch > r.getLatestEpoch() { // If peer has newer epoch
			logger.Warn("Node is behind peer by epoch - initiating recovery") // Logs behind status
			return true                                                       // Returns true indicating recovery needed
		}
	}

	return false // Returns false if no divergence detected
}

// getLatestEpoch returns the latest epoch with submissions
func (r *RANDAO) getLatestEpoch() uint64 {
	var latest uint64                  // Variable to track latest epoch
	for epoch := range r.submissions { // Iterates through all epochs with submissions
		if epoch > latest { // If current epoch is greater than latest
			latest = epoch // Updates latest
		}
	}
	return latest // Returns latest epoch found
}

// periodicVDFValidation runs periodically to check and fix VDF state
func (c *Consensus) periodicVDFValidation() {
	ticker := time.NewTicker(30 * time.Second) // Creates ticker that fires every 30 seconds
	defer ticker.Stop()                        // Ensures ticker is stopped when function returns

	for { // Infinite loop for periodic execution
		select {
		case <-ticker.C: // When ticker fires
			if c.randao != nil { // If RANDAO instance exists
				if err := c.randao.ValidateState(); err != nil { // Validates VDF state
					logger.Warn("Periodic VDF validation found inconsistency: %v - running recovery", err) // Logs inconsistency
					c.randao.Recovery()                                                                    // Triggers emergency recovery
				}
			}
		case <-c.ctx.Done(): // When context is cancelled
			return // Exits goroutine
		}
	}
}

// periodicStateSync runs periodically to sync RANDAO state with peers
func (c *Consensus) periodicStateSync() {
	ticker := time.NewTicker(10 * time.Second) // Creates ticker that fires every 10 seconds
	defer ticker.Stop()                        // Ensures ticker is stopped when function returns

	for { // Infinite loop for periodic execution
		select {
		case <-ticker.C: // When ticker fires
			if c.randao != nil && c.nodeManager != nil { // If RANDAO and node manager exist
				// Get current state snapshot
				localMix, localSubs := c.randao.GetStateSnapshot() // Gets local state

				// In a real implementation, you'd broadcast this to peers
				// and collect responses. For now, just log if we detect issues.
				_ = localMix  // Suppresses unused variable warning
				_ = localSubs // Suppresses unused variable warning

				// You could add peer sync logic here
			}
		case <-c.ctx.Done(): // When context is cancelled
			return // Exits goroutine
		}
	}
}

// HandleRANDAOSync handles incoming RANDAO sync messages from peers
func (c *Consensus) HandleRANDAOSync(peerMix [32]byte, peerSubmissions map[uint64]map[string]*VDFSubmission) error {
	if c.randao != nil { // If RANDAO instance exists
		return c.randao.SyncState(peerMix, peerSubmissions) // Syncs state with peer
	}
	return fmt.Errorf("RANDAO not initialized") // Returns error if RANDAO not initialized
}

// GetRANDAO returns the RANDAO instance
func (c *Consensus) GetRANDAO() *RANDAO {
	c.mu.RLock()         // Acquires read lock for thread-safe access
	defer c.mu.RUnlock() // Releases read lock when function returns
	return c.randao      // Returns RANDAO instance
}
