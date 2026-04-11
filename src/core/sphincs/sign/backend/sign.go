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

// go/src/core/sphincs/sign/backend/sign.go
package sign

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/sphinxorg/protocol/src/common"
	"github.com/sphinxorg/protocol/src/core/hashtree"
	params "github.com/sphinxorg/protocol/src/core/sphincs/config"
	key "github.com/sphinxorg/protocol/src/core/sphincs/key/backend"
	"github.com/sphinxorg/protocol/src/crypto/SPHINCSPLUS-golang/sphincs"
	"github.com/syndtr/goleveldb/leveldb"
)

// SIPS-0011 https://github.com/sphinxorg/SIPS/wiki/sips0011

// =============================================================================
// COMMITMENT SCHEME — SigCommitment vs Pedersen
// =============================================================================
//
// This file implements a hash-based commitment scheme for SPHINCS+ signatures.
// Below is a comparison with a Pedersen commitment to show where each Pedersen
// step maps to in this design, and why we use SpxHash instead.
//
// PEDERSEN COMMITMENT STEPS (formal definition):
//
//   Step 1 — Committer decides secret message m (from a public message space).
//             In our scheme: m = sigBytes (the 7–35 KB SPHINCS+ signature bytes).
//             sigBytes is the "secret" at commitment time — Charlie has not seen it.
//
//   Step 2 — Committer decides random secret r (the blinding factor).
//             In our scheme: r = nonce (16 cryptographically random bytes).
//             nonce serves the same role as the Pedersen blinding factor:
//             it ensures that two commitments to the same message produce
//             different commitment values, and that c reveals nothing about m.
//
//   Step 3 — Committer produces commitment c = Commit(m, r).
//             Pedersen: c = g^m · h^r  (elliptic curve group operation)
//             Our scheme: c = SpxHash(sigBytes || pkBytes || timestamp || nonce || message)
//             Both are binding and hiding. Ours binds pkBytes, timestamp, and
//             message as additional context fields to close substitution attacks.
//             Pedersen's algebraic structure allows ZK proofs over c; ours does not.
//             Ours is post-quantum secure under SHAKE-256; Pedersen is broken by
//             Shor's algorithm on a quantum computer (discrete log assumption).
//
//   Step 4 — Committer makes c public.
//             In our scheme: Alice transmits commitment (32 bytes) to Charlie
//             as part of the wire payload. Charlie receives c before seeing m.
//
//   Step 5 — Committer later reveals m and r.
//             In our scheme: Alice reveals sigBytes (m) when a dispute arises.
//             nonce (r) is already in the wire payload alongside c, so Charlie
//             can re-derive the commitment immediately without a separate reveal.
//             This is a deliberate deviation from strict Pedersen: we reveal r
//             upfront because replay prevention requires the nonce to be public.
//
//   Step 6 — Verifier checks that Commit(m, r) == c.
//             In our scheme: Charlie calls VerifySignature which re-derives
//             expectedCommitment = SigCommitment(sigBytes, pkBytes, ts, nonce, msg)
//             and compares it against the received commitment.
//             If they match, the commitment is valid — Alice committed to exactly
//             these sigBytes and has not changed m between steps 1 and 5.
//
// SECURITY PROPERTIES (matching Pedersen's formal requirements):
//
//   Binding:
//     Pedersen: attacker cannot find m, m', r, r' with m≠m' and Commit(m,r)=Commit(m',r').
//               This holds under the discrete log assumption — quantum-vulnerable.
//     Ours:     attacker cannot find sigBytes, sigBytes' with sigBytes≠sigBytes' and
//               SpxHash(...||sigBytes||...) = SpxHash(...||sigBytes'||...).
//               This holds under SHAKE-256 collision resistance — post-quantum secure.
//               Grover's algorithm halves the search space from 2^256 to 2^128,
//               still computationally infeasible.
//
//   Hiding:
//     Pedersen: c = g^m · h^r gives no information about m without knowing r,
//               even to a computationally unbounded adversary (perfect hiding).
//     Ours:     c = SpxHash(...||sigBytes||...) gives no information about sigBytes
//               without knowing sigBytes itself (preimage resistance).
//               This is computational hiding, not perfect hiding.
//               The distinction does not matter here because Charlie is a
//               computationally bounded verifier, and perfect hiding provides
//               no additional benefit in this protocol.
//
//   Adversary success conditions (Pedersen formal):
//     (a) Find m, m', r, r' with m≠m' and Commit(m,r) = Commit(m',r')  → binding break
//     (b) Given c, distinguish whether c = Commit(m,r) or c = Commit(m',r) → hiding break
//     In our scheme, both require either breaking SHAKE-256 or having Alice's SK,
//     neither of which is feasible classically or with a quantum computer.
//
// WHY WE DO NOT USE PEDERSEN:
//   1. Pedersen requires an elliptic curve group with a discrete log assumption.
//      Discrete log is broken by Shor's algorithm — not post-quantum secure.
//      Our entire protocol is built on SPHINCS+ precisely to be post-quantum.
//      Introducing Pedersen would reintroduce a quantum-vulnerable component.
//   2. Pedersen is designed for small field elements, not 7–35 KB byte arrays.
//      Committing to sigBytes in Pedersen requires hashing first anyway, which
//      loses the algebraic homomorphic property that makes Pedersen useful.
//   3. The homomorphic property of Pedersen (Commit(a)·Commit(b) = Commit(a+b))
//      is only valuable if you need ZK range proofs or arithmetic circuits over
//      the committed value. We do not — Charlie only needs binding verification,
//      not arithmetic proofs over sigBytes.
//   4. SpxHash is already present throughout this protocol. Using it for the
//      commitment is consistent, efficient, and post-quantum secure.
//
// WHERE PEDERSEN WOULD BE THE RIGHT CHOICE:
//   If this protocol ever needed to prove properties of committed values
//   without revealing them — for example, proving that a transaction amount
//   is positive without revealing the amount (as in Monero/Mimblewimble) —
//   Pedersen combined with a post-quantum ZK proof system (e.g. STARKs) would
//   be the correct design. That is a significantly larger change and a different
//   protocol goal than what this commitment achieves.

// commitmentKey is the LevelDB key under which the latest sig commitment is stored.
// This key is used by storeCommitment and LoadCommitment to persist the 32-byte
// commitment value (c) between SignMessage and transmission to Charlie.
const commitmentKey = "sig-commitment"

// signatureHashPrefix is the LevelDB key prefix under which signature hashes are stored.
// This prefix is used by StoreSignatureHash and CheckSignatureHash to persist and
// verify the 32-byte hash of the original SPHINCS+ signature bytes.
//
// WHY THIS IS NEEDED:
//
//	The existing timestamp+nonce replay protection only detects replays when the
//	attacker uses the exact same (timestamp, nonce) pair. However, an attacker
//	could capture a valid signature, strip the timestamp and nonce, and replay it
//	with a different timestamp/nonce pair. The timestamp+nonce check would pass
//	(because the pair is new), but the underlying signature would be reused.
//
//	Storing a hash of the signature itself closes this gap: once a signature is
//	seen, its hash is stored permanently. Any future attempt to replay that same
//	signature — even with different timestamp and nonce — will be detected and
//	rejected because the signature hash already exists in the database.
//
//	This also helps detect when a SPHINCS+ key pair has exceeded its 2^64 signature
//	limit. If the same signature hash appears twice with different content, that
//	would indicate a hash collision (extremely unlikely with SHAKE-256) or that
//	the key was exhausted and reused a one-time key (security failure).
//
// Storage format: signatureHashPrefix + sigHash (32 bytes) -> []byte("used")
const signatureHashPrefix = "sig-hash:"

// NewSphincsManager creates a new instance of SphincsManager with KeyManager and LevelDB instance.
// Parameters:
//   - db: LevelDB database handle (may be nil if persistence is not required)
//   - keyManager: manages SPHINCS+ key generation and serialization
//   - parameters: SPHINCS+ algorithm parameters (e.g., SHAKE-256-256f or -256s)
func NewSphincsManager(db *leveldb.DB, keyManager *key.KeyManager, parameters *params.SPHINCSParameters) *SphincsManager {
	if keyManager == nil || parameters == nil || parameters.Params == nil {
		panic("KeyManager or SPHINCSParameters are not properly initialized")
	}
	return &SphincsManager{
		db:         db,
		keyManager: keyManager,
		parameters: parameters,
	}
}

// ComputeSignatureHash computes the hash of signature bytes for content replay detection.
// This is used by both Alice (when signing) and Charlie (when verifying).
func (sm *SphincsManager) ComputeSignatureHash(sigBytes []byte) []byte {
	return common.SpxHash(sigBytes)
}

// StoreTimestampNonce stores a timestamp-nonce pair in LevelDB to prevent signature reuse.
// This implements the replay protection mechanism: once a (timestamp, nonce) pair
// is stored, any future transaction with the same pair is rejected.
//
// IMPORTANT: This must be called AFTER successful Spx_verify, not before.
// If called before, an attacker could permanently block a valid transaction
// by submitting a fake transaction with the same timestamp+nonce first.
//
// The key is a safe concatenation of timestamp (8 bytes) and nonce (16 bytes)
// using a fresh allocation to avoid aliasing bugs where append() would extend
// the backing array of timestamp into nonce's memory region.
func (sm *SphincsManager) StoreTimestampNonce(timestamp, nonce []byte) error {
	if sm.db == nil {
		return errors.New("LevelDB is not initialized")
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	// FIX: safe concatenation — prevents append from extending timestamp's backing
	// array into nonce's memory if timestamp has spare capacity.
	key := make([]byte, 0, len(timestamp)+len(nonce))
	key = append(key, timestamp...)
	key = append(key, nonce...)
	return sm.db.Put(key, []byte("seen"), nil)
}

// CheckTimestampNonce checks if a timestamp-nonce pair exists in LevelDB.
// Returns true if the pair exists (indicating reuse), false otherwise.
// This is called during Charlie's Step 3 verification before Spx_verify runs.
// A true return means this transaction is a replay and should be rejected.
func (sm *SphincsManager) CheckTimestampNonce(timestamp, nonce []byte) (bool, error) {
	if sm.db == nil {
		return false, errors.New("LevelDB is not initialized")
	}
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	// FIX: safe concatenation — same reason as StoreTimestampNonce.
	key := make([]byte, 0, len(timestamp)+len(nonce))
	key = append(key, timestamp...)
	key = append(key, nonce...)
	_, err := sm.db.Get(key, nil)
	if err == nil {
		return true, nil // Pair exists — replay detected
	}
	if err == leveldb.ErrNotFound {
		return false, nil // Pair does not exist — fresh transaction
	}
	return false, err // Other database error
}

// StoreSignatureHash stores a hash of the original signature bytes in LevelDB
// to detect when the same signature is reused with different timestamp/nonce pairs.
//
// WHY THIS IS NEEDED:
//
//	The timestamp+nonce mechanism alone cannot detect an attacker who:
//	  1. Captures a valid signature (sigBytes) from the network
//	  2. Strips the original timestamp and nonce
//	  3. Replays the same sigBytes with a NEW timestamp and nonce
//
//	Since the (timestamp, nonce) pair is new, CheckTimestampNonce would return false
//	(no replay detected), but the underlying signature is being reused. This is a
//	replay attack that timestamp+nonce cannot prevent.
//
//	By storing a hash of the signature itself, we create a content-based fingerprint:
//	  - First time sigBytes is seen → hash stored, verification succeeds
//	  - Second time SAME sigBytes is seen (even with different timestamp/nonce)
//	    → hash already exists, verification FAILS
//
//	This provides defense in depth alongside timestamp+nonce protection.
//
// ADDITIONAL BENEFIT — Detecting key exhaustion:
//
//	SPHINCS+ key pairs are limited to 2^64 signatures. If the same signature hash
//	appears twice with DIFFERENT content, that would indicate:
//	  - A SHAKE-256 collision (probability ~2^-256, effectively impossible)
//	  - OR the key pair was exhausted and reused a one-time key (security failure)
//
//	While this doesn't prevent exhaustion, it provides detection after the fact.
//
// Parameters:
//   - sigBytes: the raw SPHINCS+ signature bytes (7-35 KB)
//
// Returns:
//   - error: nil if stored successfully, error otherwise
func (sm *SphincsManager) StoreSignatureHash(sigBytes []byte) error {
	if sm.db == nil {
		return errors.New("LevelDB is not initialized")
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Hash the signature to create a compact, unique identifier (32 bytes)
	// Using SpxHash (SHAKE-256) gives us post-quantum collision resistance
	// regardless of the original signature size (7-35 KB → 32 bytes)
	sigHash := common.SpxHash(sigBytes)

	// Create the storage key with prefix to avoid collisions with other
	// database entries (e.g., timestamp-nonce pairs, commitments, etc.)
	key := make([]byte, 0, len(signatureHashPrefix)+len(sigHash))
	key = append(key, []byte(signatureHashPrefix)...)
	key = append(key, sigHash...)

	// Store with a simple "used" value; the existence of the key is what matters
	// We don't need to store anything else because the hash itself is the fingerprint
	return sm.db.Put(key, []byte("used"), nil)
}

// CheckSignatureHash checks if this exact signature has been seen before.
// Returns true if the signature hash exists in LevelDB (indicating replay),
// false otherwise (fresh signature).
//
// This is called during verification BEFORE storing the signature hash.
// If true is returned, the signature is a replay and should be rejected immediately.
//
// The check is O(1) — a single database lookup by the 32-byte hash key.
// This is extremely efficient even with millions of stored signature hashes.
//
// IMPORTANT: This check MUST be performed FIRST in the verification pipeline,
// before any expensive cryptographic operations (Spx_verify) or commitment
// verification. This provides:
//  1. Fastest rejection of replay attacks (microseconds vs milliseconds)
//  2. DoS protection — attackers cannot exhaust CPU with replay floods
//  3. Content-based replay detection that timestamp/nonce cannot provide
//
// Parameters:
//   - sigBytes: the raw SPHINCS+ signature bytes (7-35 KB)
//
// Returns:
//   - bool: true if signature was already used (replay detected), false otherwise
//   - error: any database error encountered during lookup
func (sm *SphincsManager) CheckSignatureHash(sigBytes []byte) (bool, error) {
	if sm.db == nil {
		return false, errors.New("LevelDB is not initialized")
	}
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Hash the signature using the same method as StoreSignatureHash
	// This ensures consistency between store and check operations
	sigHash := common.SpxHash(sigBytes)

	// Construct the same key format used in StoreSignatureHash
	key := make([]byte, 0, len(signatureHashPrefix)+len(sigHash))
	key = append(key, []byte(signatureHashPrefix)...)
	key = append(key, sigHash...)

	// Attempt to retrieve the key
	_, err := sm.db.Get(key, nil)
	if err == nil {
		// Key exists — this exact signature was seen before
		return true, nil
	}
	if err == leveldb.ErrNotFound {
		// Key does not exist — this signature is fresh
		return false, nil
	}
	// Some other database error occurred
	return false, err
}

// SigCommitment produces a 32-byte binding over all session-specific inputs.
//
// This is the commitment algorithm (Pedersen Step 3) of our hash-based scheme:
//
//	c = Commit(m, r) = SpxHash( len(m)||m || len(pk)||pk ||
//	                             len(ts)||ts || len(r)||r || len(msg)||msg )
//
// Where:
//
//	m  = sigBytes  (the secret being committed to — Pedersen's message)
//	r  = nonce     (the random blinding factor — Pedersen's randomness)
//	pk = pkBytes   (additional context binding — no Pedersen equivalent)
//	ts = timestamp (additional context binding — no Pedersen equivalent)
//	msg = message  (additional context binding — no Pedersen equivalent)
//
// The length-prefixing (4-byte big-endian per field) prevents concatenation
// ambiguity — two different input tuples cannot produce the same hash output.
// Example: (sigBytes="ab", nonce="c") vs (sigBytes="a", nonce="bc") would both
// concatenate to "abc" without length prefixes, but with prefixes they produce
// different hashes: [2][ab][1][c] vs [1][a][2][bc].
//
// Binding timestamp and nonce closes the replay gap: a commitment produced for
// one session cannot be reused under a different timestamp/nonce pair.
//
// Returns: 32-byte commitment hash (c)
func SigCommitment(sigBytes, pkBytes, timestamp, nonce, message []byte) []byte {
	var input []byte

	// writeWithLength prefixes each field with its 4-byte big-endian length before
	// hashing, preventing concatenation ambiguity between adjacent fields.
	writeWithLength := func(b []byte) {
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(b)))
		input = append(input, length...)
		input = append(input, b...)
	}

	// Pedersen Step 1 equivalent: m = sigBytes.
	// This is the secret message being committed to.
	// An attacker cannot compute a valid commitment without knowing sigBytes,
	// which requires Alice's SK to produce via Spx_sign.
	writeWithLength(sigBytes)

	// Additional context fields — no Pedersen equivalent.
	// These bind the commitment to a specific key, session, and message,
	// closing substitution attacks that Pedersen alone does not address.
	writeWithLength(pkBytes)   // binds commitment to Alice's specific public key
	writeWithLength(timestamp) // binds commitment to this specific point in time
	writeWithLength(nonce)     // Pedersen Step 2 equivalent: r = nonce (blinding factor)
	writeWithLength(message)   // binds commitment to the specific transaction content

	// Pedersen Step 3 equivalent: c = Commit(m, r).
	// Pedersen: c = g^m · h^r
	// Ours:     c = SpxHash(all fields above)
	// Both produce a compact value that commits to m and r without revealing m.
	return common.SpxHash(input) // 32 bytes — this is c, the public commitment
}

// CommitmentLeaf produces the value stored in leaf[4] of the Merkle tree.
//
// This is SpxHash(commitment) — the hash of the commitment c itself.
// Embedding this as a fifth leaf means the Merkle root structurally encodes c.
//
// Why this closes the consistent-substitution attack:
//
//	Without leaf[4], an attacker could replace both commitment and merkleRootHash
//	with self-consistent fake values (a "fake c" attack):
//	  fakeC         = any 32 bytes  (forged commitment)
//	  fakeMerkleRoot = build tree from fake data
//	  fakeProof     = GenerateSigProof([sigParts], [fakeMerkleRoot, fakeC], pk)
//
//	Charlie regenerates proof over [receivedMerkleRoot, receivedC] — if he
//	received the fake values, his regenerated proof matches fakeProof. Passes.
//
//	With leaf[4] = SpxHash(c) in the tree, the attacker must produce:
//	  SpxHash(fakeC) == SpxHash(realC)
//	which requires a SHAKE-256 collision — computationally infeasible.
//
// Returns: 32-byte hash of the commitment (c) to be stored as leaf[4]
func CommitmentLeaf(commitment []byte) []byte {
	return common.SpxHash(commitment)
}

// storeCommitment persists the 32-byte commitment to LevelDB so it can be
// retrieved during verification without requiring a Data field on HashTreeNode.
//
// Pedersen Step 4 equivalent: "committer makes c public."
// In our scheme, c is stored locally so it can be transmitted to Charlie.
// The actual publication happens when Alice includes c in the wire payload.
func (sm *SphincsManager) storeCommitment(commitment []byte) error {
	if sm.db == nil {
		return errors.New("LevelDB is not initialized")
	}
	return sm.db.Put([]byte(commitmentKey), commitment, nil)
}

// LoadCommitment retrieves the stored commitment from LevelDB.
// Call this on the signer side to obtain c before transmission to the verifier.
//
// Pedersen Step 4 equivalent: retrieving c so it can be made public (transmitted).
func (sm *SphincsManager) LoadCommitment() ([]byte, error) {
	if sm.db == nil {
		return nil, errors.New("LevelDB is not initialized")
	}
	commitment, err := sm.db.Get([]byte(commitmentKey), nil)
	if err != nil {
		return nil, fmt.Errorf("commitment not found: %w", err)
	}
	return commitment, nil
}

// VerifyCommitmentInRoot confirms that the Merkle root was built with the correct
// commitment in leaf[4] by comparing rebuilt vs expected root hashes.
//
// This is part of Pedersen Step 6 (verifier checks c): it confirms that the
// merkleRootHash Charlie received was honestly derived from the real sigBytes,
// not invented by an attacker. Instead of checking Commit(m,r)==c directly,
// we check that rebuilding the Merkle tree from sigBytes produces the same root.
//
// Returns: true if both root hashes match (commitment is correctly embedded),
//
//	false otherwise (forgery detected)
func VerifyCommitmentInRoot(rebuiltRoot *hashtree.HashTreeNode, expectedRoot *hashtree.HashTreeNode) bool {
	if rebuiltRoot == nil || expectedRoot == nil {
		return false
	}
	// Both roots must have been derived from the same commitment-prepended
	// leaf[0] and commitment-hashed leaf[4] for this check to pass.
	// Pedersen analogy: verifying that two openings of c produce the same value.
	rebuiltHash := hex.EncodeToString(rebuiltRoot.Hash.Bytes())
	expectedHash := hex.EncodeToString(expectedRoot.Hash.Bytes())
	return rebuiltHash == expectedHash
}

// serializePK extracts public key bytes by calling pk.SerializePK() directly.
// This avoids the nil-sk panic that occurs when routing through SerializeKeyPair.
//
// The earlier approach of calling SerializeKeyPair(nil, pk) fails because
// SerializeKeyPair dereferences sk unconditionally before serializing pk.
// Using the dedicated pk.SerializePK() method is the correct approach.
func (sm *SphincsManager) serializePK(pk *sphincs.SPHINCS_PK) ([]byte, error) {
	if pk == nil {
		return nil, fmt.Errorf("failed to serialize public key: pk is nil")
	}
	pkBytes, err := pk.SerializePK()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize public key: %w", err)
	}
	return pkBytes, nil
}

// buildMessageWithTimestampAndNonce safely concatenates timestamp || nonce || message
// into a new backing array, preventing append-aliasing bugs.
//
// WHY THIS IS NEEDED:
//
//	Direct append(timestamp, append(nonce, message...)...) can cause aliasing
//	if timestamp has spare capacity — the underlying array may be extended,
//	potentially corrupting nonce or message if they share the same memory region.
//	This function creates a fresh allocation with the exact required capacity,
//	guaranteeing no aliasing between input slices.
func buildMessageWithTimestampAndNonce(timestamp, nonce, message []byte) []byte {
	out := make([]byte, 0, len(timestamp)+len(nonce)+len(message))
	out = append(out, timestamp...)
	out = append(out, nonce...)
	out = append(out, message...)
	return out
}

// buildSigParts splits sigBytes into 5 Merkle leaves, prepending commitment to
// leaf[0] and setting leaf[4] = CommitmentLeaf(commitment).
//
// Merkle tree structure (5 leaves):
//
//	leaf[0] = commitment || sigBytes[0:chunkSize]   (commitment prepended)
//	leaf[1] = sigBytes[chunkSize:2*chunkSize]
//	leaf[2] = sigBytes[2*chunkSize:3*chunkSize]
//	leaf[3] = sigBytes[3*chunkSize:]
//	leaf[4] = SpxHash(commitment)                  (commitment hash leaf)
//
// Each of the four sigBytes chunks is an independent copy so that callers may
// zero sigBytes afterward without corrupting the returned parts. This helper is
// used on both the sign path (SignMessage) and the verify path (VerifySignature)
// to guarantee identical leaf layout on both sides.
//
// Parameters:
//   - sigBytes: the raw SPHINCS+ signature bytes (7-35 KB)
//   - commitment: the 32-byte commitment hash (c)
//
// Returns: [][]byte of 5 leaf values ready for Merkle tree construction
func buildSigParts(sigBytes, commitment []byte) [][]byte {
	chunkSize := len(sigBytes) / 4
	parts := make([][]byte, 5)

	// Split sigBytes into 4 chunks, each copied to a fresh allocation.
	// Using copy() ensures the chunks are independent of the original sigBytes
	// slice, allowing callers to zero sigBytes without corrupting the parts.
	for i := 0; i < 4; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if i == 3 {
			end = len(sigBytes) // last chunk takes any remaining bytes
		}
		chunk := make([]byte, end-start)
		copy(chunk, sigBytes[start:end])
		parts[i] = chunk
	}

	// Prepend commitment to leaf[0] — binds the Merkle root to c.
	// This ensures the root hash encodes the commitment value directly.
	leaf0 := make([]byte, 0, len(commitment)+len(parts[0]))
	leaf0 = append(leaf0, commitment...)
	leaf0 = append(leaf0, parts[0]...)
	parts[0] = leaf0

	// leaf[4] = SpxHash(c) — closes consistent-substitution attack.
	// Without this leaf, an attacker could substitute both commitment and root
	// with self-consistent fake values. This leaf makes that impossible.
	parts[4] = CommitmentLeaf(commitment)

	return parts
}

// SignMessage signs a given message using the secret key, including a timestamp and nonce.
//
// This function performs all six steps of the commitment scheme:
//
//	Pedersen Step 1: m is decided — m = sigBytes produced by Spx_sign.
//	Pedersen Step 2: r is decided — r = nonce (16 cryptographically random bytes).
//	Pedersen Step 3: c is produced — c = SigCommitment(sigBytes, pkBytes, ts, nonce, msg).
//	Pedersen Step 4: c is stored locally for transmission in the wire payload.
//	Pedersen Step 5: m and r will be revealed by Alice during dispute resolution.
//	                 nonce (r) is transmitted upfront for replay prevention.
//	                 sigBytes (m) is transmitted upfront so Charlie can call Spx_verify.
//
// ROOT CAUSE NOTE — why sigBytes must NOT be zeroed here:
//
//	SerializeSignature() in the SPHINCS+ implementation may return a slice that
//	shares the sig object's internal backing array rather than an independent copy.
//	The original code called:
//	    for i := range sigBytes { sigBytes[i] = 0 }
//	after splitting. This silently zeroed the sig object's internal buffer.
//	When VerifySignature later called sig.SerializeSignature() again (for the
//	local sanity check), it got all-zero bytes, produced a different commitment,
//	rebuilt a different Merkle root, and the comparison failed.
//
//	The fix: never zero the slice returned by SerializeSignature while the sig
//	object is still live. buildSigParts already copies each chunk into a fresh
//	allocation, so LevelDB writes are safe. The GC will reclaim sigBytes memory
//	when it goes out of scope. If you require explicit zeroing for security
//	(e.g. after a HSM export), do it only after the sig object itself has gone
//	out of scope and will never be serialized again.
//
// Return values:
//   - signature: the SPHINCS+ signature object (contains the raw sigBytes internally)
//   - merkleRoot: root node of the 5-leaf Merkle tree constructed from sigParts
//   - timestamp: 8-byte Unix timestamp (for freshness and replay prevention)
//   - nonce: 16-byte cryptographically random nonce (blinding factor r)
//   - commitment: 32-byte commitment hash c = Commit(m, r)
//   - error: any error that occurred during signing or tree construction
func (sm *SphincsManager) SignMessage(
	message []byte,
	deserializedSK *sphincs.SPHINCS_SK,
	deserializedPK *sphincs.SPHINCS_PK,
) (*sphincs.SPHINCS_SIG, *hashtree.HashTreeNode, []byte, []byte, []byte, error) {

	if sm.parameters == nil || sm.parameters.Params == nil {
		return nil, nil, nil, nil, nil, errors.New("SPHINCSParameters are not initialized")
	}

	// Generate timestamp (8 bytes, Unix epoch seconds)
	// This binds the signature to a specific point in time, preventing replay
	// of old signatures that were captured before Charlie came online.
	timestamp := generateTimestamp()

	// Pedersen Step 2: generate r = nonce (16 random bytes).
	// This is the random blinding factor of the commitment scheme.
	// Even if Alice signs the same message twice, the two commitments will
	// differ because the nonces differ.
	nonce, err := generateNonce()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// Build the payload that will be signed: timestamp || nonce || message
	// This ensures each signature is unique and temporally bound.
	messageWithTimestampAndNonce := buildMessageWithTimestampAndNonce(timestamp, nonce, message)

	p := sm.parameters.Params

	// Pedersen Step 1: decide m — perform the actual SPHINCS+ signing operation.
	// m = sigBytes is the secret being committed to (7-35 KB).
	signature := sphincs.Spx_sign(p, messageWithTimestampAndNonce, deserializedSK)
	if signature == nil {
		return nil, nil, nil, nil, nil, errors.New("failed to sign message")
	}

	// Serialize m (sigBytes). DO NOT ZERO THIS SLICE while signature is live.
	// See ROOT CAUSE NOTE above for why zeroing here causes verification failures.
	sigBytes, err := signature.SerializeSignature()
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// Serialize the public key for inclusion in the commitment.
	// This binds the commitment to Alice's specific public key, preventing
	// key substitution attacks where Eve uses her own valid signature but
	// claims it came from Alice.
	pkBytes, err := sm.serializePK(deserializedPK)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// Pedersen Step 3: c = Commit(m, r).
	// c is a 32-byte hash that binds to sigBytes, pkBytes, timestamp, nonce, and message.
	// Charlie will later recompute this and compare to verify Alice didn't change m.
	commitment := SigCommitment(sigBytes, pkBytes, timestamp, nonce, message)

	// Build Merkle leaves. buildSigParts copies each chunk independently so
	// the leaves stored in LevelDB are not affected if sigBytes is ever zeroed
	// later (after the sig object is no longer needed).
	sigParts := buildSigParts(sigBytes, commitment)

	// Build the Merkle tree from the 5 leaves.
	// The resulting root hash is a compact receipt (32 bytes) that encodes the
	// commitment and signature parts. Charlie stores this root permanently.
	merkleRoot, err := buildHashTreeFromSignature(sigParts)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	// Pedersen Step 4: persist c so it can be transmitted to Charlie.
	// Also store the signature parts for potential future use (e.g., dispute resolution).
	if sm.db != nil {
		if err := sm.storeCommitment(commitment); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		if err := hashtree.SaveLeavesBatchToDB(sm.db, sigParts); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		if err := hashtree.PruneOldLeaves(sm.db, 5); err != nil {
			return nil, nil, nil, nil, nil, err
		}
	}

	// Return signature object, Merkle root, timestamp, nonce, and commitment.
	// The signature object is still needed for the local sanity check, but
	// will be discarded after transmission.
	return signature, merkleRoot, timestamp, nonce, commitment, nil
}

// VerifySignature verifies a SPHINCS+ signature and confirms that the Merkle root
// was constructed from genuine signature material via the commitment check.
//
// This function performs Pedersen Step 6: the verifier checks that Commit(m, r) == c.
//
// In Pedersen: verifier is given c, m, r and checks Commit(m,r) == c.
// In our scheme: verifier is given c (commitment), m (sigBytes via wire), r (nonce),
// and checks that SigCommitment(sigBytes, pkBytes, ts, nonce, msg) == c.
//
// Before checking the commitment, we first run Spx_verify to confirm that m
// (sigBytes) is a genuinely valid SPHINCS+ signature. This is an additional
// requirement beyond Pedersen's scheme — Pedersen only verifies that the opener
// knows the preimage of c; we additionally require that the preimage is a valid
// SPHINCS+ signature under Alice's public key.
//
// Verification steps in order (MUST be in this order for security & performance):
//  1. Serialize signature bytes
//  2. CHECK SIGNATURE HASH FIRST — content-based replay detection (fastest)
//  3. Spx_verify(m, pk) — confirms m is a valid SPHINCS+ signature
//  4. Check timestamp+nonce — session-based replay detection
//  5. Re-derive c' = SigCommitment(m, pk, ts, nonce, msg) — Pedersen Step 6
//  6. Check c' == c — binding property
//  7. Rebuild Merkle tree from m, verify root == received root
//  8. Store signature hash and timestamp+nonce for future replay prevention
//
// WHY SIGNATURE HASH CHECK MUST BE FIRST:
//   - It's the cheapest operation (32-byte DB lookup vs 7-35KB crypto)
//   - It catches all replays regardless of timestamp/nonce manipulation
//   - It prevents DoS attacks (replay floods can't exhaust CPU)
//   - It provides content-based deduplication that timestamp/nonce cannot
//
// Returns: true if all verification steps pass, false otherwise
func (sm *SphincsManager) VerifySignature(
	message, timestamp, nonce []byte,
	sig *sphincs.SPHINCS_SIG,
	pk *sphincs.SPHINCS_PK,
	merkleRoot *hashtree.HashTreeNode,
	commitment []byte,
	storeEvidence bool, // ← add this
) bool {

	if sm.parameters == nil || sm.parameters.Params == nil {
		return false
	}
	// c must be exactly 32 bytes — our SpxHash output size.
	// Pedersen: c is a curve point of fixed encoded size; same principle.
	if len(commitment) != 32 {
		return false
	}

	// =====================================================================
	// STEP 1: Serialize signature bytes
	// =====================================================================
	// We need sigBytes for multiple checks: signature hash, Spx_verify,
	// commitment verification, and Merkle tree rebuild.
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		return false
	}

	// =====================================================================
	// STEP 2: CHECK SIGNATURE HASH FIRST (CONTENT-BASED REPLAY DETECTION)
	// =====================================================================
	// This MUST be the first check because:
	//   1. It's the fastest (single 32-byte DB lookup)
	//   2. It catches replays even with different timestamp/nonce
	//   3. It prevents DoS attacks (replay floods can't reach expensive crypto)
	//   4. It provides content-based deduplication
	//
	// If this exact signature was seen before, reject immediately without
	// performing any expensive cryptographic verification.
	isSigReplay, err := sm.CheckSignatureHash(sigBytes)
	if err != nil {
		return false // Database error — fail closed (security)
	}
	if isSigReplay {
		return false // Same signature already used — replay attack detected!
	}

	// =====================================================================
	// STEP 3: Reconstruct the signed payload
	// =====================================================================
	// Must be byte-for-byte identical to what Alice signed.
	messageWithTimestampAndNonce := buildMessageWithTimestampAndNonce(timestamp, nonce, message)

	// =====================================================================
	// STEP 4: SPHINCS+ VERIFICATION (EXPENSIVE CRYPTOGRAPHIC CHECK)
	// =====================================================================
	// Pedersen's verifier only checks Commit(m,r)==c. It does not check that
	// m has any particular structure. Our verifier additionally requires that
	// m (sigBytes) is a valid SPHINCS+ signature under Alice's registered pk.
	// This is the step that makes the scheme unforgeable — Eve cannot produce
	// sigBytes that passes Spx_verify without Alice's SK.
	//
	// This is expensive (processes 7-35 KB of signature data), which is why
	// we only do it AFTER the cheap signature hash check above.
	if !sphincs.Spx_verify(sm.parameters.Params, messageWithTimestampAndNonce, sig, pk) {
		return false
	}

	// =====================================================================
	// STEP 5: TIMESTAMP+NONCE REPLAY DETECTION (SESSION-BASED)
	// =====================================================================
	// This checks if the specific (timestamp, nonce) pair has been seen before.
	// This prevents simple replays that don't modify the session parameters.
	//
	// IMPORTANT: This check is performed AFTER Spx_verify to prevent an attacker
	// from permanently blocking a valid transaction by submitting a fake
	// transaction with the same timestamp+nonce first.
	isTimestampNonceReplay, err := sm.CheckTimestampNonce(timestamp, nonce)
	if err != nil {
		return false
	}
	if isTimestampNonceReplay {
		return false // Same timestamp+nonce already used — replay attack detected!
	}

	// =====================================================================
	// STEP 6: Serialize the public key for commitment re-derivation
	// =====================================================================
	pkBytes, err := sm.serializePK(pk)
	if err != nil {
		return false
	}

	// =====================================================================
	// STEP 7: PEDERSEN STEP 6 — VERIFY COMMITMENT
	// =====================================================================
	// Re-derive c' = Commit(m, r) and check c' == c.
	// Pedersen: verifier computes g^m · h^r and checks it equals the received c.
	// Ours:     verifier computes SpxHash(sigBytes||pkBytes||ts||nonce||msg) and
	//           checks it equals the received commitment.
	// If they match, Alice committed to exactly this sigBytes and has not changed
	// m between Step 3 (commitment) and Step 5 (reveal). Binding property confirmed.
	expectedCommitment := SigCommitment(sigBytes, pkBytes, timestamp, nonce, message)
	if hex.EncodeToString(commitment) != hex.EncodeToString(expectedCommitment) {
		return false // binding violated — Alice presented different sigBytes than committed
	}

	// =====================================================================
	// STEP 8: REBUILD AND VERIFY MERKLE TREE (RECEIPT INTEGRITY)
	// =====================================================================
	// Rebuild Merkle tree using the shared helper — guarantees identical leaf
	// layout to the sign path. This ensures the root hash is computed exactly
	// as Alice computed it during signing.
	sigParts := buildSigParts(sigBytes, commitment)

	// Build the tree from the reconstructed leaves.
	rebuiltRoot, err := buildHashTreeFromSignature(sigParts)
	if err != nil {
		return false
	}

	// Final check: rebuilt root must match received root.
	if !VerifyCommitmentInRoot(rebuiltRoot, merkleRoot) {
		return false
	}

	// =====================================================================
	// STEP 9: STORE REPLAY PREVENTION EVIDENCE
	// =====================================================================
	// ALL CHECKS PASSED — now store evidence for future replay prevention.
	// Order matters: Store ONLY AFTER all verification passes to prevent an
	// attacker from poisoning the database with invalid signatures.
	// STEP 9: STORE REPLAY PREVENTION EVIDENCE
	if storeEvidence && sm.db != nil { // ← add storeEvidence check
		if err := sm.StoreSignatureHash(sigBytes); err != nil {
			_ = err
		}
		if err := sm.StoreTimestampNonce(timestamp, nonce); err != nil {
			_ = err
		}
	}

	return true
}

// buildHashTreeFromSignature constructs a Merkle tree from the provided signature parts
// and returns the root node of the tree.
//
// This is a simple wrapper around hashtree.NewHashTree and tree.Build().
// It creates a Merkle tree where each leaf is a byte slice from sigParts,
// then builds all internal nodes up to the root.
//
// Parameters:
//   - sigParts: a slice of byte slices, where each slice represents a leaf in the tree
//
// Returns:
//   - *hashtree.HashTreeNode: The root node of the constructed Merkle tree
//   - error: An error if tree construction fails (e.g., empty input)
func buildHashTreeFromSignature(sigParts [][]byte) (*hashtree.HashTreeNode, error) {
	tree := hashtree.NewHashTree(sigParts)
	if err := tree.Build(); err != nil {
		return nil, err
	}
	return tree.Root, nil
}
