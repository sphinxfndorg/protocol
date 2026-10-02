// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/crypto/STHINCS/sthincs/sthincs.go
package sthincs

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/fors"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/hypertree"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/util"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/xmss"
)

type SPHINCS_PK struct {
	PKseed []byte
	PKroot []byte
}

// SPHINCS_SK is the secret key.
//
// See the topTree field below for why the top hypertree layer is cached and
// when that cache must be ignored. It is unexported and never serialized, so
// SerializeSK/DeserializeSK are unaffected.
type SPHINCS_SK struct {
	SKseed []byte
	SKprf  []byte
	PKseed []byte
	PKroot []byte

	// topTree memoizes the layer-(D-1), tree-0 Merkle tree. It is a pure
	// function of (SKseed, PKseed) and the top-layer address, none of which
	// change over a key's life, so it is valid for the whole key lifetime.
	//
	// It is guarded by a mutex because a single SK may be used to sign
	// concurrently. The cache object itself is immutable once built.
	topTree *xmss.Xmss_treeCache
	mu      sync.Mutex

	// zeroized records that Zeroize has run on this key. It is set under the
	// same sk.mu hold as the wipe and the cache drop, so the two cannot be
	// observed apart.
	//
	// It exists because a signer that snapshotted before the wipe still holds
	// valid key material and will go on to call topTreeFor, possibly after
	// Zeroize has run. Without this flag that signer could repopulate the
	// cache on a key that is supposed to be finished. topTreeFor consults the
	// flag and refuses to store in that case.
	//
	// Note what this is and is not about. The cached tree holds only public
	// data — WOTS+ public keys and the layer root — so nothing here is about
	// secrecy. The invariant is hygiene: a spent key must neither hold nor
	// serve a cache.
	//
	// It is deliberately not derived from scanning for zero bytes: a caller
	// may legitimately hand-build a key whose seed is all zeros, and a flag
	// records intent rather than guessing at it.
	zeroized bool
}

type SPHINCS_SIG struct {
	R        []byte
	SIG_FORS *fors.FORSSignature
	SIG_HT   *hypertree.HTSignature
}

func (s *SPHINCS_SIG) GetR() []byte {
	return s.R
}

func (s *SPHINCS_SIG) GetSIG_FORS() *fors.FORSSignature {
	return s.SIG_FORS
}

func (s *SPHINCS_SIG) GetSIG_HT() *hypertree.HTSignature {
	return s.SIG_HT
}

// WHY CACHE ONLY THE TOP LAYER. Layer D-1 always has tree address 0 and a
// fixed leaf set: it does not depend on idx_tree or idx_leaf, both of which
// vary per signature. So its leaves and root are constant for a given key and
// can be computed once. That saves 1/D of the tree-building work (1/3 for the
// `s` sets, which have D=3). Lower layers pick a different tree index per
// signature, so they almost never repeat and caching them would cost memory
// for no hit rate.
//
// MEMORY. 2^Hprime * N bytes of leaves plus one N-byte root; for the largest
// set here (Hprime=10, N=32) that is 32 KB. It holds only public hashes, so
// it needs no wiping and reveals nothing PKroot does not already.
//
// topTreeFor returns the cached top hypertree layer, building it on first use.
//
// The key material is taken from the caller's snapshot (skSeed, pkSeed,
// pkRoot) rather than read from sk's own fields. sk.mu still serializes access
// to the cache slot, but it is no longer what makes the reads safe: by the time
// this is called the caller already holds a private, consistent copy. Reading
// sk.SKseed here instead would reintroduce the window where a signer that
// snapshotted before Zeroize builds its top tree from a post-wipe seed.
//
// A zeroized key never serves from the cache and never repopulates it. See the
// zeroized field and Zeroize for the reasoning; in short, a signer holding a
// pre-wipe snapshot can still produce a valid signature, but the tree it builds
// must not be left behind on a spent key.
//
// That check is still load-bearing even though snapshot now rejects zeroized
// keys up front: a signer that snapshotted BEFORE the wipe is holding valid
// material and reaches this function after Zeroize has already run. Only the
// flag here stops that signer from caching what it builds.
func (sk *SPHINCS_SK) topTreeFor(params *parameters.Parameters, skSeed, pkSeed, pkRoot []byte) *xmss.Xmss_treeCache {
	sk.mu.Lock()
	defer sk.mu.Unlock()

	// Serve the cached tree only while the key is live.
	if !sk.zeroized && sk.topTree != nil && sk.topTreeValidLocked(params, skSeed, pkSeed, pkRoot) {
		return sk.topTree
	}

	// Build the layer-(D-1), tree-0 leaves and root from the caller's snapshot.
	// This is exactly the tree Ht_PKgen computed at keygen, so the root it
	// yields is PKroot — which is asserted below as a consistency check rather
	// than assumed. The build stays under sk.mu, matching the previous
	// behaviour: only one signer pays for it and publishes the result.
	adrs := new(address.ADRS)
	adrs.SetLayerAddress(params.D - 1)
	adrs.SetTreeAddress(0)
	cache, err := xmss.Xmss_cacheLeaves(params, skSeed, pkSeed, adrs)
	if err != nil {
		// Cache population must never fail signing: fall back to no cache and
		// let the normal path compute the layer.
		sk.topTree = nil
		return nil
	}
	// If the rebuilt root disagrees with the key's own PKroot, the key is
	// inconsistent (e.g. SKseed was changed without PKroot). Refuse to cache
	// so we never sign against a root that contradicts the public key.
	if len(pkRoot) != params.N || !bytes.Equal(pkRoot, cache.Root()) {
		sk.topTree = nil
		return nil
	}

	// Publish only if the key was still live when we got here. Zeroize takes
	// this same lock to wipe and to drop the cache, so it cannot interleave
	// with the build above; this covers the case where Zeroize completed
	// between this signer's snapshot and its arrival here. The tree we just
	// built is still correct for this call — it came from the caller's own
	// pre-wipe snapshot — so it is returned for use, but it is NOT stored:
	// caching it would leave a spent key holding a cache.
	//
	// The tree holds only public hashes, so this is hygiene rather than
	// secrecy: a key that has been zeroized should not be holding or serving
	// a cache at all.
	//
	// Nothing the caller owns is wiped here. The tree is freshly allocated by
	// Xmss_cacheLeaves and becomes garbage once this call returns.
	if sk.zeroized {
		return cache
	}
	sk.topTree = cache
	return sk.topTree
}

// topTreeValidLocked reports whether the existing cache can still be trusted
// for this key. Caller must hold sk.mu.
//
// The decisive check is that the cached root equals the key's PKroot. PKroot
// is the root of exactly this tree, so equality ties the cache to the key
// beyond doubt: any change to SKseed, PKseed, or a corrupted cache produces a
// different root and is rejected. Comparing N bytes per signature is
// negligible next to the tree build it replaces.
func (sk *SPHINCS_SK) topTreeValidLocked(params *parameters.Parameters, skSeed, pkSeed, pkRoot []byte) bool {
	if sk.topTree == nil {
		return false
	}
	if len(pkRoot) != params.N || len(skSeed) != params.N || len(pkSeed) != params.N {
		return false
	}
	// The all-zero scan below only matters when SKseed was overwritten
	// directly by a caller that did NOT call Zeroize. A properly zeroized key
	// never gets this far through Spx_sign: snapshot rejects it up front, and
	// a signer that snapshotted before the wipe is holding a pre-wipe seed
	// that is not all zeros. So this is defence-in-depth against a hand-mangled
	// key, not the normal Zeroize path.
	allZero := true
	for _, b := range skSeed {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}
	return bytes.Equal(pkRoot, sk.topTree.Root())
}

// snapshot copies every component of the key under sk.mu and returns private
// copies that the caller owns and must wipe.
//
// All four components are taken in a single critical section on purpose. Two
// separate locked reads would still let a concurrent Zeroize land between them
// and produce a torn key — a pre-wipe SKprf paired with a post-wipe SKseed —
// which is the same failure as the unsynchronized version, only harder to
// reproduce. One hold makes the view consistent.
//
// The lock covers the copy and nothing else. It is deliberately not held while
// signing: topTreeFor takes the same non-reentrant mutex, so holding it across
// the signing work would deadlock.
//
// The returned secret copies are wiped by the caller (util.Wipe).
//
// ZEROIZED KEYS ARE REJECTED UP FRONT. A key whose Zeroize has run is spent:
// the flag is never reset, so every subsequent snapshot fails immediately,
// before the length validation and before any allocation. This makes
// "sign with a spent key" a cheap, deterministic error rather than a full
// signing run later that discovers at the self-check that the key is gone.
//
// A signer that snapshotted BEFORE the wipe is unaffected: its copies are
// already private and it never calls snapshot again.
//
// WIPE COVERAGE ON THE ERROR PATH. Both rejections below return before any
// make(), so every named return is still nil and there is nothing to wipe. The
// order is load-bearing: if the checks are ever moved after the copies, those
// returns must wipe the partial set first, or they leak key material.
func (sk *SPHINCS_SK) snapshot(n int) (skSeed, skPrf, pkSeed, pkRoot []byte, err error) {
	sk.mu.Lock()
	defer sk.mu.Unlock()

	// Checked first, before anything else: a spent key has no usable material.
	if sk.zeroized {
		return nil, nil, nil, nil, fmt.Errorf("secret key has been zeroized")
	}

	// Length validation, still before any allocation.
	if len(sk.SKseed) != n || len(sk.SKprf) != n ||
		len(sk.PKseed) != n || len(sk.PKroot) != n {
		return nil, nil, nil, nil, fmt.Errorf("invalid secret key: every component must be exactly %d bytes", n)
	}

	skSeed = make([]byte, n)
	copy(skSeed, sk.SKseed)
	skPrf = make([]byte, n)
	copy(skPrf, sk.SKprf)
	pkSeed = make([]byte, n)
	copy(pkSeed, sk.PKseed)
	pkRoot = make([]byte, n)
	copy(pkRoot, sk.PKroot)
	return skSeed, skPrf, pkSeed, pkRoot, nil
}

// Zeroize overwrites the secret parts of the key (SKseed, SKprf) in place.
// Call it when you are done with a secret key. The public halves (PKseed,
// PKroot) are left intact. Note that any serialized copy of the key (see
// SerializeSK) is a separate buffer that the caller must wipe itself, and
// that Go cannot guarantee no other copy exists (swap, core dumps, etc.).
//
// Zeroize wipes the key's own seed fields. Spx_sign wipes its own private
// copies when it returns; Zeroize does not reach into in-flight signers. It
// does not wipe intermediate values derived from the seeds (PRF outputs such
// as WOTS+/FORS secret chain values), which live on the Go heap until
// collected.
//
// THE CONTRACT, precisely:
//
//   - A signer whose snapshot was taken BEFORE Zeroize completes normally. It
//     works entirely from its private copies, so it produces a valid signature
//     even though the key has since been wiped. That is intended: the snapshot
//     was a legitimate read of a live key.
//   - A signer whose snapshot is taken AFTER Zeroize gets an error from
//     snapshot immediately. It never reaches Hmsg, FORS, the hypertree or
//     topTreeFor, so it performs no tree-building work at all, and it never
//     returns a signature — not a valid one, not an invalid one.
//   - Zeroize never leaves a cache on a spent key. The drop happens under the
//     same lock as the wipe, and the zeroized flag makes topTreeFor refuse to
//     repopulate it, so a pre-wipe signer that is still running cannot
//     re-cache a tree built from its snapshot. The cached tree is public data
//     (WOTS+ public keys and the layer root); the rule is that a finished key
//     should neither hold nor serve a cache.
//
// A zeroized key is PERMANENTLY SPENT. The flag is never reset and Zeroize
// cannot be undone, so a key that has been through it can never sign again.
// There is no re-arming path, by design.
//
// What Zeroize does NOT do is wait for in-flight signing. It is not a barrier:
// a concurrent signer keeps its snapshot until it returns. Treat it as "no
// further signatures after I return", not "I block until current signing
// finishes".
//
// The wipe, the flag and the cache drop all happen under one sk.mu hold, so
// they are ordered against Spx_sign's snapshot and against topTreeFor.
// Without the lock this was a data race; the detector confirms it because
// util.Wipe uses an instrumented loop, precisely because clear() is invisible
// to -race.
func (sk *SPHINCS_SK) Zeroize() {
	if sk == nil {
		return
	}
	sk.mu.Lock()
	util.Wipe(sk.SKseed)
	util.Wipe(sk.SKprf)
	sk.zeroized = true
	// The cached top layer is public hashes, but it belongs to a key that no
	// longer exists; release it rather than keeping it alive.
	//
	// Inlined deliberately rather than delegated to a dropTopTreeCache helper:
	// sk.mu is a plain sync.Mutex and is NOT reentrant, so calling a helper that
	// locks it while this function already holds it would deadlock. Do not
	// reintroduce that helper.
	sk.topTree = nil
	sk.mu.Unlock()
}

// bitMask returns a mask with the low `bits` bits set (bits in 0..64).
func bitMask(bits int) uint64 {
	if bits <= 0 {
		return 0
	}
	if bits >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(bits)) - 1
}

// splitDigest splits the Hmsg output into (FORS message digest, tree index,
// leaf index), exactly as in the SPHINCS+ specification:
//
//	md       = digest[0 : ceil(K*A / 8)]
//	idx_tree = toInt(next ceil((H - H/D) / 8) bytes) mod 2^(H - H/D)
//	idx_leaf = toInt(next ceil((H/D) / 8) bytes)     mod 2^(H/D)
//
// toInt is big-endian over the actual byte slice. The slice must NOT be
// copied left-aligned into a fixed-size buffer before masking: doing that
// shifts the value into the high bits, and the low-bit mask then zeroes
// it, which makes every index 0 (a previous version of this file had that
// bug in both sign and verify, so every signature reused tree 0 / leaf 0).
func splitDigest(params *parameters.Parameters, digest []byte) (md []byte, idxTree uint64, idxLeaf int, err error) {
	hPrime := params.H / params.D
	treeBits := params.H - hPrime
	leafBits := hPrime

	mdBytes := (params.K*params.A + 7) / 8
	treeBytes := (treeBits + 7) / 8
	leafBytes := (leafBits + 7) / 8

	if treeBytes > 8 {
		return nil, 0, 0, fmt.Errorf("tree index needs %d bytes, max supported is 8", treeBytes)
	}
	if leafBytes > 4 {
		return nil, 0, 0, fmt.Errorf("leaf index needs %d bytes, max supported is 4", leafBytes)
	}

	total := mdBytes + treeBytes + leafBytes
	if len(digest) < total {
		return nil, 0, 0, fmt.Errorf("message digest too short: need %d bytes, have %d (increase MessageDigestLength)", total, len(digest))
	}

	md = digest[:mdBytes]
	treeSlice := digest[mdBytes : mdBytes+treeBytes]
	leafSlice := digest[mdBytes+treeBytes : total]

	idxTree = util.BytesToUint64(treeSlice) & bitMask(treeBits)
	idxLeaf = int(util.BytesToUint64(leafSlice) & bitMask(leafBits))

	return md, idxTree, idxLeaf, nil
}

// Spx_keygen generates a SPHINCS+ key pair
func Spx_keygen(params *parameters.Parameters) (*SPHINCS_SK, *SPHINCS_PK, error) {
	if params == nil {
		return nil, nil, fmt.Errorf("nil parameters provided")
	}

	SKseed := make([]byte, params.N)
	if _, err := rand.Read(SKseed); err != nil {
		return nil, nil, fmt.Errorf("failed to generate SKseed: %w", err)
	}

	SKprf := make([]byte, params.N)
	if _, err := rand.Read(SKprf); err != nil {
		return nil, nil, fmt.Errorf("failed to generate SKprf: %w", err)
	}

	PKseed := make([]byte, params.N)
	if _, err := rand.Read(PKseed); err != nil {
		return nil, nil, fmt.Errorf("failed to generate PKseed: %w", err)
	}

	PKroot, err := hypertree.Ht_PKgen(params, SKseed, PKseed)
	if err != nil {
		return nil, nil, fmt.Errorf("hypertree PKgen failed: %w", err)
	}

	sk := &SPHINCS_SK{
		SKseed: SKseed,
		SKprf:  SKprf,
		PKseed: PKseed,
		PKroot: PKroot,
	}

	pk := &SPHINCS_PK{
		PKseed: PKseed,
		PKroot: PKroot,
	}

	return sk, pk, nil
}

// Spx_sign generates a SPHINCS+ signature.
//
// Before returning, the signature is verified against the key's own public
// half (a "sign-then-verify" self-check). A transient fault (bit flip,
// glitched hash) during signing otherwise yields an invalid signature that
// can leak information about the secret key; with the self-check such a
// signature is discarded and an error is returned instead. Cost: one
// verification, which is small next to signing.
func Spx_sign(params *parameters.Parameters, M []byte, SK *SPHINCS_SK) (*SPHINCS_SIG, error) {
	if params == nil || params.Tweak == nil || M == nil || SK == nil {
		return nil, fmt.Errorf("nil parameters provided")
	}

	// Take one consistent snapshot of the key under sk.mu and work only from
	// it. Everything below reads these copies rather than SK's fields, so a
	// concurrent Zeroize cannot interleave with the reads and cannot leave a
	// half-wiped key in use. The lock is released before any signing work,
	// and topTreeFor (called further down) takes the same non-reentrant mutex
	// on its own, so there is no path that holds it across both.
	SKseed, SKprf, PKseed, PKroot, err := SK.snapshot(params.N)
	if err != nil {
		return nil, err
	}
	// WIPE COVERAGE. One defer, registered immediately after the snapshot
	// succeeds, covers every subsequent exit: the success return, each error
	// return below, and the self-check failure. There is no early return
	// between the snapshot and this defer.
	//
	// PKseed and PKroot are public halves and do not need wiping, but they are
	// wiped alongside the secrets so that "every copy snapshot handed out is
	// cleaned up" is a single unconditional rule rather than a judgement call
	// at each call site.
	defer func() {
		util.Wipe(SKseed)
		util.Wipe(SKprf)
		util.Wipe(PKseed)
		util.Wipe(PKroot)
	}()

	// init
	adrs := new(address.ADRS)

	// generate randomizer
	opt := make([]byte, params.N)
	if params.RANDOMIZE {
		if _, err := rand.Read(opt); err != nil {
			return nil, fmt.Errorf("failed to generate randomizer: %w", err)
		}
	}

	R := params.Tweak.PRFmsg(SKprf, opt, M)

	SIG := &SPHINCS_SIG{
		R: R,
	}

	// compute message digest and derive FORS digest + tree/leaf indices
	digest := params.Tweak.Hmsg(R, PKseed, PKroot, M)

	tmp_md, idx_tree, idx_leaf, err := splitDigest(params, digest)
	if err != nil {
		return nil, fmt.Errorf("digest split failed: %w", err)
	}

	// FORS sign
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	adrs.SetType(address.FORS_TREE)
	adrs.SetKeyPairAddress(idx_leaf)

	// SKseed/SKprf/PKseed/PKroot are the snapshot taken at the top of this
	// function, already private copies and already covered by the deferred
	// wipes. Nothing below re-reads the caller's key.
	forsSig, err := fors.Fors_sign(params, tmp_md, SKseed, PKseed, adrs)
	if err != nil {
		return nil, fmt.Errorf("FORS sign failed: %w", err)
	}
	SIG.SIG_FORS = forsSig

	PK_FORS, err := fors.Fors_pkFromSig(params, SIG.SIG_FORS, tmp_md, PKseed, adrs)
	if err != nil {
		return nil, fmt.Errorf("FORS pkFromSig failed: %w", err)
	}

	// sign FORS public key with HT
	adrs.SetType(address.TREE)
	// Pass the cached top hypertree layer (if any). Layer D-1 always has tree
	// address 0 and a fixed leaf set, so it is the same tree every time and
	// costs 1/D of a signature to rebuild. A nil cache is fine: Ht_sign falls
	// back to building that layer.
	//
	// The seeds and root come from this call's snapshot, not from SK's fields.
	// That is what makes a pre-wipe signer behave per the Zeroize contract: it
	// builds from key material it legitimately read, and topTreeFor declines to
	// cache the result if the key has since been zeroized.
	htSig, err := hypertree.Ht_signCached(params, PK_FORS, SKseed, PKseed, idx_tree, idx_leaf,
		SK.topTreeFor(params, SKseed, PKseed, PKroot))
	if err != nil {
		return nil, fmt.Errorf("hypertree sign failed: %w", err)
	}
	SIG.SIG_HT = htSig

	// Fault-attack countermeasure: never release a signature that does not
	// verify under our own public key.
	selfPK := &SPHINCS_PK{PKseed: PKseed, PKroot: PKroot}
	if !Spx_verify(params, M, SIG, selfPK) {
		return nil, fmt.Errorf("signature self-check failed (possible fault during signing); signature discarded")
	}

	return SIG, nil
}

// Spx_verify verifies a SPHINCS+ signature.
// Returns bool (no error) for compatibility; any internal error is treated
// as a failed verification. For production, consider changing to (bool, error).
//
// Signatures are attacker-controlled input, so verification is hardened:
// every length that the caller supplies is checked up front, and a recover()
// converts any panic caused by a malformed signature into a plain "invalid"
// result instead of crashing the process (remote DoS on a node).
func Spx_verify(params *parameters.Parameters, M []byte, SIG *SPHINCS_SIG, PK *SPHINCS_PK) (valid bool) {
	defer func() {
		if r := recover(); r != nil {
			valid = false
		}
	}()

	if params == nil || params.Tweak == nil || M == nil || SIG == nil || PK == nil {
		return false
	}
	if len(PK.PKseed) != params.N || len(PK.PKroot) != params.N {
		return false
	}

	// init
	adrs := new(address.ADRS)
	R := SIG.GetR()
	SIG_FORS := SIG.GetSIG_FORS()
	SIG_HT := SIG.GetSIG_HT()
	if len(R) != params.N || SIG_FORS == nil || SIG_HT == nil {
		return false
	}

	// compute message digest and derive FORS digest + tree/leaf indices
	digest := params.Tweak.Hmsg(R, PK.PKseed, PK.PKroot, M)

	tmp_md, idx_tree, idx_leaf, err := splitDigest(params, digest)
	if err != nil {
		return false
	}

	// compute FORS public key
	adrs.SetLayerAddress(0)
	adrs.SetTreeAddress(idx_tree)
	adrs.SetType(address.FORS_TREE)
	adrs.SetKeyPairAddress(idx_leaf)

	// Private copies (lengths are exactly N, checked above) so nothing below
	// can modify the caller's public key.
	PKseed := make([]byte, params.N)
	copy(PKseed, PK.PKseed)
	PKroot := make([]byte, params.N)
	copy(PKroot, PK.PKroot)

	PK_FORS, err := fors.Fors_pkFromSig(params, SIG_FORS, tmp_md, PKseed, adrs)
	if err != nil {
		return false
	}

	// verify HT signature
	adrs.SetType(address.TREE)

	ok, err := hypertree.Ht_verify(params, PK_FORS, SIG_HT, PKseed, idx_tree, idx_leaf, PKroot)
	if err != nil {
		return false
	}

	return ok
}
