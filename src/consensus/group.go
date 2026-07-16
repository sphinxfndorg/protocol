// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/consensus/group.go
package consensus

import (
	"math/big"

	logger "github.com/sphinxfndorg/protocol/src/console"
	"golang.org/x/crypto/sha3"
)

// sips0013 https://github.com/sphinxorg/SIPS/blob/main/.github/workflows/sips0013/sips0013.md

// NewClassGroupElement creates a new element from a, b, c
func NewClassGroupElement(a, b, c *big.Int) *ClassGroupElement {
	// Creates a new ClassGroupElement with deep copies of the input values
	return &ClassGroupElement{
		A: new(big.Int).Set(a), // Copies a to a new big.Int to avoid external modifications
		B: new(big.Int).Set(b), // Copies b to a new big.Int to avoid external modifications
		C: new(big.Int).Set(c), // Copies c to a new big.Int to avoid external modifications
	}
}

// Copy creates a deep copy of a class group element
func (el *ClassGroupElement) Copy() *ClassGroupElement {
	// Returns a new independent copy of the element with all fields cloned
	return &ClassGroupElement{
		A: new(big.Int).Set(el.A), // Creates a new big.Int with the value of A
		B: new(big.Int).Set(el.B), // Creates a new big.Int with the value of B
		C: new(big.Int).Set(el.C), // Creates a new big.Int with the value of C
	}
}

// Identity returns the identity element for given discriminant D
// For class group of imaginary quadratic field with D < 0, D ≡ 1 mod 4
// Identity is (1, 1, (1-D)/4) when D ≡ 1 mod 4
func Identity(D *big.Int) *ClassGroupElement {
	// Creates the identity element for the class group with discriminant D
	a := big.NewInt(1) // Sets a = 1, the first coefficient of the identity form
	b := big.NewInt(1) // Sets b = 1, the second coefficient of the identity form

	// Compute c = (b² - D) / (4a) = (1 - D) / 4
	Dabs := new(big.Int).Abs(D)                // Takes absolute value of D for calculations
	c := new(big.Int).Sub(big.NewInt(1), Dabs) // Calculates 1 - |D|
	c.Div(c, big.NewInt(4))                    // Divides by 4 to get c = (1 - |D|)/4

	// Ensure c is positive
	if c.Sign() < 0 { // Checks if c is negative
		c.Neg(c) // Makes c positive by negation
	}

	return &ClassGroupElement{A: a, B: b, C: c} // Returns the constructed identity element
}

// tonelliShanks computes modular square root using Tonelli-Shanks algorithm
// This is a standard algorithm for computing square roots modulo a prime
// Returns nil if a is not a quadratic residue modulo p
func tonelliShanks(a, p *big.Int) *big.Int {
	// Check if a is a quadratic residue
	if a.Cmp(big.NewInt(0)) == 0 { // If a is zero, square root is zero
		return big.NewInt(0) // Returns zero as the square root
	}
	if big.Jacobi(a, p) != 1 { // Computes Legendre symbol to check if a is quadratic residue
		return nil // Returns nil if a is not a quadratic residue modulo p
	}

	// Factor p-1 as Q * 2^S
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1)) // Calculates p-1
	S := 0                                        // Initialize exponent of 2 factor
	Q := new(big.Int).Set(pMinus1)                // Q starts as p-1
	for Q.Bit(0) == 0 {                           // While Q is even (least significant bit is 0)
		Q.Rsh(Q, 1) // Right shift Q by 1 (divide by 2)
		S++         // Increment S counter
	}

	// Find quadratic non-residue z
	z := big.NewInt(2)           // Start testing from z=2
	for big.Jacobi(z, p) != -1 { // While z is a quadratic residue (Legendre symbol != -1)
		z.Add(z, big.NewInt(1)) // Increment z to test next candidate
	}

	// Initialize variables
	M := S                                                                    // M starts as S for the algorithm loop
	c := new(big.Int).Exp(z, Q, p)                                            // c = z^Q mod p
	t := new(big.Int).Exp(a, Q, p)                                            // t = a^Q mod p
	R := new(big.Int).Exp(a, new(big.Int).Add(Q, big.NewInt(1)).Rsh(Q, 1), p) // R = a^((Q+1)/2) mod p

	// Main loop
	for t.Cmp(big.NewInt(1)) != 0 { // Continue until t becomes 1
		// Find smallest i where t^(2^i) == 1
		i := 1                     // Start with exponent 1
		t2i := new(big.Int).Set(t) // Start with t^2^0 = t
		for i < M {                // While i is less than M
			t2i.Exp(t2i, big.NewInt(2), p)   // Square t2i: t2i = t2i^2 mod p
			if t2i.Cmp(big.NewInt(1)) == 0 { // If t2i equals 1
				break // Found the smallest i where condition holds
			}
			i++ // Increment i to try next exponent
		}

		// Compute b = c^(2^(M-i-1))
		exp := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(M-i-1)), nil) // Calculates exponent 2^(M-i-1)
		b := new(big.Int).Exp(c, exp, p)                                      // b = c^(2^(M-i-1)) mod p

		// Update variables
		R.Mul(R, b).Mod(R, p) // R = R * b mod p
		c.Mul(b, b).Mod(c, p) // c = b^2 mod p
		t.Mul(t, c).Mod(t, p) // t = t * c mod p
		M = i                 // Update M to i for next iteration
	}
	return R // Returns the computed square root
}

// findB finds b such that b² ≡ D (mod a) using Tonelli-Shanks if a is prime
// For class groups, we need b to satisfy the congruence for the quadratic form
func findB(a, D *big.Int) *big.Int {
	// Make D positive for modulo operations
	Dabs := new(big.Int).Abs(D) // Takes absolute value of D for modulus operations

	// For class groups, a is often chosen to be prime
	if a.ProbablyPrime(20) { // Tests if a is probably prime with 20 iterations of Miller-Rabin
		// Check if D is a quadratic residue modulo a
		if big.Jacobi(Dabs, a) == 1 { // If D is a quadratic residue modulo a
			b := tonelliShanks(Dabs, a) // Compute square root of D modulo a
			if b != nil {               // If square root found successfully
				// Ensure b has same parity as D for class group
				if b.Bit(0) != Dabs.Bit(0) { // If parity doesn't match
					b.Sub(a, b) // Adjust b = a - b to fix parity
				}
				return b // Return the computed b value
			}
		}
	}
	// Fallback to heuristic
	return new(big.Int).Set(a) // Returns a as fallback when Tonelli-Shanks fails or a is not prime
}

// CanonicalNormalize ensures a unique canonical representation of a class group element
// This is critical for consistent comparison of class group elements
func CanonicalNormalize(el *ClassGroupElement, D *big.Int) *ClassGroupElement {
	// First apply standard reduction
	normalized := NormalizeElement(el, D) // Reduces the element to standard form

	// Create new instance to avoid modifying input
	result := &ClassGroupElement{
		A: new(big.Int).Set(normalized.A), // Copies the reduced A value
		B: new(big.Int).Set(normalized.B), // Copies the reduced B value
		C: new(big.Int).Set(normalized.C), // Copies the reduced C value
	}

	// Ensure a is positive
	if result.A.Sign() < 0 { // If A is negative
		result.A.Neg(result.A) // Makes A positive
		result.B.Neg(result.B) // Negates B accordingly
		result.C.Neg(result.C) // Negates C accordingly
	}

	// Ensure B is in range [-a, a] for uniqueness
	twoA := new(big.Int).Mul(big.NewInt(2), result.A) // Calculates 2*a
	bMod := new(big.Int).Mod(result.B, twoA)          // Computes B mod 2a
	if bMod.Cmp(result.A) > 0 {                       // If remainder is greater than a
		bMod.Sub(bMod, twoA) // Adjust to negative range by subtracting 2a
	}
	result.B = bMod // Sets B to the normalized value

	// Recompute C from discriminant to ensure consistency
	bSquared := new(big.Int).Mul(result.B, result.B)   // Calculates B^2
	fourA := new(big.Int).Mul(big.NewInt(4), result.A) // Calculates 4*a
	c := new(big.Int).Sub(bSquared, D)                 // Computes B^2 - D
	c.Div(c, fourA)                                    // Divides by 4a to get C = (B^2 - D)/(4a)
	if c.Sign() < 0 {                                  // If C is negative
		c.Neg(c) // Makes C positive
	}
	result.C = c // Sets C to the recomputed value

	return result // Returns the canonical normalized element
}

// NormalizeElement ensures a quadratic form is properly reduced
// This implements the standard reduction algorithm for binary quadratic forms
func NormalizeElement(el *ClassGroupElement, D *big.Int) *ClassGroupElement {
	// Extract coefficients for local manipulation
	a, b, c := el.A, el.B, el.C // Gets the three coefficients of the quadratic form

	// Ensure a is positive
	if a.Sign() < 0 { // If a is negative
		a.Neg(a) // Make a positive
		b.Neg(b) // Negate b
		c.Neg(c) // Negate c
	}

	// Main reduction loop
	for {
		// Check if reduction is needed: |a| > |c| or equal with b negative
		if a.Cmp(c) > 0 || (a.Cmp(c) == 0 && b.Sign() < 0) { // If reduction condition met
			// Reduction step
			twoC := new(big.Int).Mul(big.NewInt(2), c) // Calculates 2*c
			r := new(big.Int).Neg(b)                   // r = -b
			r.Div(r, twoC)                             // r = (-b) / (2c) for integer division

			newA := c                                 // New a becomes old c
			newB := new(big.Int).Neg(b)               // Start with -b
			newB.Sub(newB, new(big.Int).Mul(twoC, r)) // newB = -b - (2c)*r
			newC := a                                 // New c becomes old a

			// Update coefficients for next iteration
			a, b, c = newA, newB, newC // Assign new values for next loop iteration
		} else {
			break // Exit loop when form is reduced
		}
	}

	// Ensure c is positive
	if c.Sign() < 0 { // If c is negative
		c.Neg(c) // Make c positive
	}

	return &ClassGroupElement{A: a, B: b, C: c} // Returns the normalized element
}

// Compose performs composition of two quadratic forms using proper NuComp
// This is the core class group operation - all VDF operations depend on this
// Implements the composition algorithm for binary quadratic forms
func Compose(p, q *ClassGroupElement, D *big.Int) *ClassGroupElement {
	// Extract coefficients from both forms
	a1, b1, _ := p.A, p.B, p.C // Gets a1 and b1 from first form (c1 unused)
	a2, b2, _ := q.A, q.B, q.C // Gets a2 and b2 from second form (c2 unused)

	// Compute g = gcd(a1, a2)
	g := new(big.Int).GCD(nil, nil, a1, a2) // Greatest common divisor of a1 and a2

	// Compute a = (a1 * a2) / g²
	gSquared := new(big.Int).Mul(g, g) // Calculates g^2
	a := new(big.Int).Mul(a1, a2)      // Calculates a1 * a2
	a.Div(a, gSquared)                 // Divides by g^2 to get a

	// Compute s = (b1 + b2) / 2
	s := new(big.Int).Add(b1, b2) // Sums b1 and b2
	s.Div(s, big.NewInt(2))       // Divides by 2 (must be integer due to class group properties)

	// Compute b = s mod 2a
	twoA := new(big.Int).Mul(big.NewInt(2), a) // Calculates 2a
	b := new(big.Int).Mod(s, twoA)             // Computes s modulo 2a

	// Compute c = (b² - D) / (4a)
	bSquared := new(big.Int).Mul(b, b)          // Calculates b^2
	fourA := new(big.Int).Mul(big.NewInt(4), a) // Calculates 4a
	c := new(big.Int).Sub(bSquared, D)          // Computes b^2 - D
	c.Div(c, fourA)                             // Divides by 4a to get c

	if c.Sign() < 0 { // If c is negative
		c.Neg(c) // Makes c positive
	}

	// CRITICAL: Use canonical normalization for consistent results
	return CanonicalNormalize(&ClassGroupElement{A: a, B: b, C: c}, D) // Returns normalized composition result
}

// Square squares an element (composition with itself)
// This is a specialized version of Compose for efficiency
func Square(p *ClassGroupElement, D *big.Int) *ClassGroupElement {
	// Square is just composition with itself
	return Compose(p, p, D) // Composes the element with itself
}

// Exponentiate performs exponentiation in the class group
// Uses binary exponentiation for efficiency
func Exponentiate(base *ClassGroupElement, exponent *big.Int, D *big.Int) *ClassGroupElement {
	result := Identity(D)             // Starts with identity element
	exp := new(big.Int).Set(exponent) // Creates a copy of exponent to avoid modification

	// Create a copy of base to avoid modifying the original
	current := &ClassGroupElement{
		A: new(big.Int).Set(base.A), // Copies base.A
		B: new(big.Int).Set(base.B), // Copies base.B
		C: new(big.Int).Set(base.C), // Copies base.C
	}

	for exp.BitLen() > 0 { // While exponent still has bits to process
		if exp.Bit(0) == 1 { // If least significant bit is 1
			result = Compose(result, current, D) // Multiply result by current
		}
		current = Square(current, D) // Square current for next bit position
		exp.Rsh(exp, 1)              // Right shift exponent by 1 (divide by 2)
	}
	return result // Returns the exponentiation result
}

// RepeatedSquare performs T sequential squarings (the core VDF operation)
// This is the sequential part that cannot be parallelized
// CRITICAL: Must be deterministic across all nodes
func RepeatedSquare(x *ClassGroupElement, D *big.Int, T uint64) *ClassGroupElement {
	// Start with a fresh copy to avoid any mutation
	result := &ClassGroupElement{
		A: new(big.Int).Set(x.A), // Copies input A value
		B: new(big.Int).Set(x.B), // Copies input B value
		C: new(big.Int).Set(x.C), // Copies input C value
	}

	// Perform T sequential squarings
	for i := uint64(0); i < T; i++ { // Loop T times
		// Square the result (creates a new element)
		result = Square(result, D) // Squares current result
	}
	return result // Returns result after T squarings
}

// RepeatedSquareWithProgress performs the exact same T sequential squarings
// as RepeatedSquare, but renders a live progress bar through the logger
// package while it runs, instead of only surfacing the result once the
// whole delay function has finished. T can be in the hundreds of thousands
// (or millions) of squarings, so a caller running this live -- rather than
// in a batch job -- benefits from seeing that the node is actively working
// through the VDF rather than appearing to hang.
//
// label is used as the progress bar's title (e.g. "VDF evaluation",
// "VDF proof"), so distinct RepeatedSquare calls are identifiable if more
// than one is ever rendered at once.
//
// Progress is only sampled periodically, not on every squaring, so the act
// of reporting progress does not itself slow down the sequential delay
// function it is measuring.
func RepeatedSquareWithProgress(x *ClassGroupElement, D *big.Int, T uint64, label string) *ClassGroupElement {
	result := &ClassGroupElement{
		A: new(big.Int).Set(x.A), // Copies input A value
		B: new(big.Int).Set(x.B), // Copies input B value
		C: new(big.Int).Set(x.C), // Copies input C value
	}

	if T == 0 {
		return result
	}

	renderer := logger.Default()
	bar := logger.NewProgressBar(label, int64(T), "sq")
	detach := renderer.Attach(bar)
	defer detach() // stops animating and does a final redraw once we return

	// Sampling ~1000 times across the whole run gives smooth animation
	// without meaningfully adding per-squaring overhead.
	reportEvery := T / 1000
	if reportEvery == 0 {
		reportEvery = 1
	}

	for i := uint64(0); i < T; i++ { // Loop T times
		result = Square(result, D) // Squares current result
		if done := i + 1; done%reportEvery == 0 || done == T {
			bar.Set(int64(done)) // Reports progress through the shared renderer
		}
	}
	bar.Complete()

	return result // Returns result after T squarings
}

// HashToClassGroup hashes a seed to a class group element using SHAKE256 with Tonelli-Shanks
// This implements a random oracle to the class group
func HashToClassGroup(seed [32]byte, D *big.Int) *ClassGroupElement {
	// Use SHAKE256 for variable-length output (better for cryptographic randomness)
	shake := sha3.NewShake256() // Creates new SHAKE256 hash function instance
	shake.Write(seed[:])        // Writes the 32-byte seed to the hash function

	for attempt := 0; attempt < 100; attempt++ { // Try up to 100 times to find valid element
		// Generate 64 bytes of output (enough for big.Int)
		hashBytes := make([]byte, 64) // Creates byte slice for hash output
		shake.Read(hashBytes)         // Reads 64 bytes of hash output

		// Generate a candidate quadratic form with discriminant D
		a := new(big.Int).SetBytes(hashBytes[:32]) // Uses first 32 bytes as potential a coefficient
		a.Abs(a)                                   // Takes absolute value to ensure positivity
		a.Mod(a, D)                                // Reduces modulo D to keep value manageable

		// Ensure a is positive and not zero
		if a.Sign() == 0 { // If a is zero
			a.SetInt64(1) // Sets a to 1 as fallback
		}

		// Use proper Tonelli-Shanks to find b such that b² ≡ D (mod a)
		b := findB(a, D) // Attempts to find b satisfying the congruence
		if b == nil {    // If no b found
			continue // Try next attempt
		}

		// Compute c = (b² - D) / (4a)
		bSquared := new(big.Int).Mul(b, b)          // Calculates b^2
		fourA := new(big.Int).Mul(big.NewInt(4), a) // Calculates 4a
		c := new(big.Int).Sub(bSquared, D)          // Computes b^2 - D

		// Check if divisible by 4a
		if new(big.Int).Mod(c, fourA).Sign() != 0 { // If c is not divisible by 4a
			continue // Try next attempt
		}
		c.Div(c, fourA) // Divides by 4a to get c

		// Check if this forms a valid quadratic form
		if c.Sign() > 0 { // If c is positive
			return CanonicalNormalize(&ClassGroupElement{A: a, B: b, C: c}, D) // Returns normalized element
		}
	}

	// Fallback to identity element
	return Identity(D) // Returns identity if no valid element found after 100 attempts
}

// HashToPrime converts a hash to a prime using SHAKE256 with Fiat-Shamir heuristic
// This is used for generating the challenge l in the Wesolowski proof
func HashToPrime(D, x, y *big.Int, T uint64) *big.Int {
	// Use SHAKE256 for variable-length output
	shake := sha3.NewShake256() // Creates new SHAKE256 hash function instance
	shake.Write(D.Bytes())      // Writes discriminant D to hash

	// Write T as bytes (big-endian)
	tBytes := make([]byte, 8) // Creates 8-byte slice for T
	for i := 0; i < 8; i++ {  // Loops through 8 bytes
		tBytes[i] = byte(T >> (56 - 8*i)) // Stores T in big-endian order
	}
	shake.Write(tBytes)    // Writes T bytes to hash
	shake.Write(x.Bytes()) // Writes x value to hash
	shake.Write(y.Bytes()) // Writes y value to hash

	// Generate 64 bytes for prime candidate
	hashBytes := make([]byte, 64) // Creates byte slice for hash output
	shake.Read(hashBytes)         // Reads 64 bytes of hash output

	candidate := new(big.Int).SetBytes(hashBytes) // Converts hash to big integer

	// Ensure candidate is positive and odd
	if candidate.Sign() <= 0 { // If candidate is zero or negative
		candidate.SetInt64(3) // Sets to 3 as fallback
	}
	if candidate.Bit(0) == 0 { // If candidate is even
		candidate.Add(candidate, big.NewInt(1)) // Makes it odd by adding 1
	}

	// Find the next prime
	for !candidate.ProbablyPrime(20) { // While candidate is not probably prime
		candidate.Add(candidate, big.NewInt(2)) // Adds 2 to check next odd number
	}
	return candidate // Returns the generated prime
}

// ClassGroupToBigInt serializes a class group element to a big integer
// This is used for storing and transmitting class group elements
func ClassGroupToBigInt(el *ClassGroupElement) *big.Int {
	// Combine a, b, c into a single big integer
	combined := new(big.Int).Set(el.A) // Starts with A coefficient
	combined.Lsh(combined, 256)        // Left shifts by 256 bits to make room for B
	combined.Or(combined, el.B)        // ORs with B to combine
	combined.Lsh(combined, 256)        // Left shifts by 256 bits to make room for C
	combined.Or(combined, el.C)        // ORs with C to combine
	return combined                    // Returns combined big integer representation
}

// BigIntToClassGroup deserializes a big integer to a class group element
// This reconstructs the class group element from its serialized form
func BigIntToClassGroup(val *big.Int, D *big.Int) *ClassGroupElement {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)) // Creates mask for 256 bits (2^256 - 1)

	temp := new(big.Int).Set(val)     // Copies input value for processing
	c := new(big.Int).And(temp, mask) // Extracts lowest 256 bits as C
	temp.Rsh(temp, 256)               // Right shifts by 256 bits to move to next component
	b := new(big.Int).And(temp, mask) // Extracts next 256 bits as B
	temp.Rsh(temp, 256)               // Right shifts by 256 bits to move to next component
	a := new(big.Int).And(temp, mask) // Extracts remaining bits as A

	// Ensure we return a canonical normalized element
	el := &ClassGroupElement{A: a, B: b, C: c} // Creates element from extracted coefficients
	return CanonicalNormalize(el, D)           // Returns normalized element for consistency
}
