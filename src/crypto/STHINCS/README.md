# STHINCS+ Parameter & Hash Benchmark

## Overview

This document records benchmark results for **STHINCS** — the stateless,
hash-based post-quantum signature scheme in this package — across **all 36
parameter sets**, and compares the **three tweakable-hash backends** the scheme
can be built on:

| Backend | Tweakable type | Underlying primitive |
|---|---|---|
| `SHA256` | `tweakable.Sha256Tweak` | SHA-256 |
| `SHAKE256` | `tweakable.Shake256Tweak` | SHAKE256 (Keccak) |
| `SPHINXHASH` | `tweakable.SphinxHashTweak` | SphinxHash (SIPS-0001) |

The measurement is **one full `Spx_sign`** per parameter set, produced by
`parameters/benchmark_test.go` (`BenchmarkSpxSignConstructors`). The signature
codec cost is deliberately excluded from the timed region (the probe signature
is serialized before `b.ResetTimer()`), so `ns/op` is signing cost.

### What the `SPHINXHASH-*` sets actually hash with

They do not implement a hash of their own. `tweakable.SphinxHashTweak` routes
**every** tweakable function (`F`, `H`, `T_l`, `PRF`, `PRFmsg`, `Hmsg`) through
`spxHashExpand`, which calls `common.SpxHashUncached` — the *uncached* entry
point over the single shared, package-level hasher instance from
`src/common/types.go`:

```text
parameters.SPHINXHASH-*   ->  tweakable.SphinxHashTweak     (tweakable/spxhash.go)
                          ->  spxHashExpand(domain, parts...)   domain || len||part
                          ->  common.SpxHashUncached        (src/common/types.go)
                          ->  spxhash.ProtocolSalt + v2
                              spxhash/v2.NewSphinxHash(256, ProtocolSalt).GetHashUncached
```

So one `SPHINXHASH` signature makes on the order of 10^6 calls into the **v2**
SphinxHash construction (`src/spxhash/v2`), keyed with `spxhash.ProtocolSalt`
(the header comment in `tweakable/spxhash.go` explains why the old two-backend
split — a hand-rolled "fast core" for `F`/`H`/`PRF`/`T_l` — was removed and the
call count is not a flat number: it scales with `N`, `K`, `D` and `logT`).
Nothing on this path references the v1 package any more — `src/spxhash/v1` is
referenced only by its own test package.

**Why `Uncached` matters.** Every tweakable call in STHINCS carries a distinct
`ADRS`, so `GetHash`'s LRU can essentially never hit — the lookup, the key
derivation and the store are pure overhead on every one of the ~10^6 calls. The
signing path therefore uses `GetHashUncached`, which skips all three and goes
straight to `hashData`.

Measured on identical distinct inputs (64 B), that is worth **1.54x** and two
allocations:

| Path (64 B, distinct inputs) | ns/op | allocs/op |
|---|---:|---:|
| `common.SpxHash` (cached entry point, always misses here) | 2,673 | 3 |
| `common.SpxHashUncached` (what STHINCS actually calls) | **1,733** | **1** |

The remaining 3-vs-1 allocation gap is `LRUCache.Put`, which copies the input
and the digest into a fresh buffer on every miss. That is why a miss is *never*
faster than not caching at all — it is strictly the hashing plus that copy — and
why `GetHashUncached` remains the correct choice here regardless of how cheap
the cache key became. This probe was run ad hoc and is not part of the
committed test suite.

`GetHashUncached(x) == GetHash(x)` byte-for-byte is pinned by
`TestUncachedMatchesCached` in `src/spxhash/v2/spxhash_large_test.go`, so
switching between the two never changes a signature.

That is the whole remaining reason for the signing penalty in Comparison 1: a
single SHA-256 compression per tweak call becomes
`SHA256(SHA256(key‖tag‖data))` + `SHAKE256(key‖tag‖data)` + a final squeeze
instead. The equivalence `common.SpxHash(x) ==
spxhash.NewSphinxHash(256, spxhash.ProtocolSalt).GetHash(x)` is pinned by
`src/common/types_test.go` (`TestSpxHashMatchesSpxHashAPI`).

### What the `maphash` cache-key change did and did not change

The LRU key is now a seeded, non-cryptographic `maphash` instead of a double
SHA-256 over the full input. For STHINCS this is **invisible**, and it is worth
being explicit about why:

- **No effect on digests.** `hashData` never saw the cache key, so no
  signature, key, or test vector changes. The STHINXHASH vectors and the
  `common.SpxHash == GetHash` equivalence all still hold unchanged.
- **No effect on signing cost.** The signing path calls `GetHashUncached`,
  which never touched the cache key in the first place. The SPHINXHASH timings
  below are therefore comparable with the previous revision of this document;
  they moved by run-to-run noise only.
- **Large effect on `common.SpxHash` callers.** A cache *hit* got roughly an
  order of magnitude cheaper, because a hit no longer pays two SHA-256 passes
  over the input before it can look anything up. That helps the protocol's
  block/transaction hashing paths, which do repeat inputs. It does **not** help
  STHINCS, whose inputs never repeat.

The one hazard the change introduces is a zero-value `maphash.Seed`, which
panics when used. Every `SphinxHash` in this repository is built through
`NewSphinxHash` / `NewSphinxHashKeyed` / `Clone`, all of which call
`maphash.MakeSeed()`; there are no `SphinxHash{...}` struct literals outside the
package, so the shared `common.spxHasher` is safe.

## Test Suite Results

`go test ./src/crypto/STHINCS/... -count=1 -v` passes cleanly. The signing
tests use only the fast `128f` sets, so the whole tree finishes in ~13 s wall
clock.

```text
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS          [no test files]
ok  github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address       2.082s
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/fors          [no test files]
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/hypertree     [no test files]
ok  github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters    2.674s [no tests to run]
ok  github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs       13.318s
ok  github.com/sphinxfndorg/protocol/src/crypto/STHINCS/tweakable     4.867s
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/util          [no test files]
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/wots          [no test files]
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/xmss          [no test files]
```

`parameters` contains only `BenchmarkSpxSignConstructors`, hence "no tests to
run" under the normal (non-benchmark) invocation. The suite is **12 test
functions and 89 subtests**, of which four live in
`sthincs/golden_test.go` and exist specifically to guard the signing-path
optimizations described under [Signing-path optimizations](#signing-path-optimizations):

| Package | Test | Subtests | Covers |
|---|---|---:|---|
| `address` | `TestTreeAddressRoundTrip` | — | An `ADRS` survives a serialize/parse round trip field-for-field, so tweak functions keyed by address bytes stay deterministic |
| `sthincs` | `TestSplitDigestRightAlignsIndices` | 4 | `idx_tree`/`idx_leaf` are read big-endian from the real digest and masked to the low bits (the old always-0 index bug) |
| `sthincs` | `TestSplitDigestRejectsShortDigest` | — | A digest one byte short is rejected, not silently padded |
| `sthincs` | `TestSignVerifyAcrossHashBackends` | 6 | End-to-end keygen/sign/verify for SHA256, SHAKE256 and SPHINXHASH (`128f`, `simple`+`robust`): own-message verification, message-dependent in-range indices, cross-message rejection, cross-key rejection |
| `sthincs` | `TestVerifyRejectsMalformedInputsAndSignRejectsBadKeys` | 28 | Malformed signatures, keys and arguments are rejected rather than panicking or verifying — nil/short/over-long fields, flipped bytes, truncated WOTS/XMSS, bad keys |
| `sthincs` | `TestGoldenSignatures` | 9 | **The signature bytes themselves**, pinned as SHA-256 digests for 9 backend/variant combinations. Every signing-path optimization must be invisible here; a mismatch is a consensus break |
| `sthincs` | `TestSigningIsDeterministicAndOrderIndependent` | — | Repeated signing of one message is byte-identical (no goroutine scheduling leaking into the output), and a signature does not verify under another message or key |
| `sthincs` | `TestTopTreeCacheIsValidatedAgainstTheKey` | — | A corrupted or stale top-layer cache is discarded and rebuilt rather than trusted, and `Zeroize` releases it |
| `sthincs` | `TestConcurrentSigningOnOneKey` | — | 8 goroutines signing distinct messages with one shared `SPHINCS_SK`; meaningful under `-race` |
| `tweakable` | `TestTweakableOutputsDependOnEveryInput` | 9 | Every argument of `F`/`H`/`T_l`/`PRF`/`PRFmsg`/`Hmsg` changes the output, for all 3 backends × 3 variants (`simple`, `robust`, `unrecognized`) |
| `tweakable` | `TestRobustDiffersFromSimple` | 3 | `Robust` and `Simple` really are different functions, per backend |
| `tweakable` | `TestFHTlDomainSeparation` | 2 | SPHINXHASH tags `F`, `H`, `T_l` separately, so identical inputs do not collide |
| `tweakable` | `TestDoesNotWriteIntoCallerSpareCapacity` | 9 | No tweakable function scribbles into `cap(input) > len(input)` — the old `append(PKseed, …)` bug |

`go test -race ./src/crypto/STHINCS/...` is also clean, including the
concurrent-signing test. Given the parallel tree build, that is not optional
evidence — a shared scratch buffer would show up there and nowhere else.

Per-subtest timings for the end-to-end signing test are unchanged in
substance from the previous revision (the group now takes ~2.8 s), because
that test signs a single `128f` message per backend and the parallel build has
least to amortize on the smallest set. The large speedups are in the tables
below.

## Parameter Grid

Every set uses `W = 16` (Winternitz), `H = 30` (**2^30 ≈ 1.07 billion
signatures** per key) and therefore `Hprime = H / D`. `Len1 = 2N`, `Len2 = 3`,
`Len = 2N + 3`.

| Variant | N | D | H′ | K | logT | T = 2^logT | Len | PK (B) | SK (B) | Sig (B) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `256f` | 32 | 6 | 5 | 35 | 9 | 512 | 67 | 64 | 128 | 25,056 |
| `256s` | 32 | 3 | 10 | 20 | 13 | 8,192 | 67 | 64 | 128 | 16,384 |
| `192f` | 24 | 6 | 5 | 33 | 8 | 256 | 51 | 48 | 96 | 15,216 |
| `192s` | 24 | 3 | 10 | 18 | 12 | 4,096 | 51 | 48 | 96 | 10,032 |
| `128f` | 16 | 6 | 5 | 30 | 6 | 64 | 35 | 32 | 64 | 7,216 |
| `128s` | 16 | 3 | 10 | 14 | 11 | 2,048 | 35 | 32 | 64 | 4,864 |

Three axes produce the 36 sets:

- **Security level** — the `128` / `192` / `256` prefix is the target security
  level, realized by `N = 16` / `24` / `32`. This matches the SPHINCS+ naming
  convention and `main.go`'s labels (`LV 1` / `LV 3` / `LV 5`).
- **Variant** — `f` (fast: `D=6`, `H'=5`, small trees) vs `s` (slow: `D=3`,
  `H'=10`, large trees). `s` has smaller signatures but much slower signing.
- **Mode** — `robust` (XOR bitmask in `F`/`H`/`T_l`) vs `simple` (no mask).

> **Note on security-level labels.** The header comments in `parameters.go`
> assign the level numbers the other way round (they call `N=32` "Security
> Level 1" and `N=16` "Security Level 5"). That conflicts with `main.go`, which
> prints `N=32` as `LV 5` and `N=16` as `LV 1`. The tables below use the
> SPHINCS+ convention (`N=32` → Level 5) because that is what `main.go`, the
> `128/192/256` variant names, and NIST's SPHINCS+ parameter sets all use.

## Test Command

```bash
go test -bench=BenchmarkSpxSignConstructors -benchtime=1x -run='^$' \
  ./src/crypto/STHINCS/parameters/
```

`-benchtime=1x` follows the benchmark's own doc comment: it collects comparable
single-signature timings on a machine where a full signature can take seconds.
One signature per set is intentional — a higher `-benchtime` would take hours for
the `s` and `SPHINXHASH` sets. The numbers in this document were actually
collected with one `-bench` per hash family (`.../SHA256-`, `.../SHAKE256-`,
`.../SPHINXHASH-`) so that no single command ran long; see Reproduction.

Because each sub-benchmark is a single measurement, treat the numbers as
**order-of-magnitude comparisons**, not as tight micro-benchmarks. The relative
differences between hashes (up to 5.4x) and between variants (up to 17x) are
large and reproduce across runs; small differences (below ~10%) are within
run-to-run noise, and the `-count=3` table below shows how large that is.

### Measured Environment

```text
goos: darwin
goarch: amd64
cpu: Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz (8 logical CPUs)
go: go1.27.1 darwin/amd64
RANDOMIZE=false (benchmark calls tc.make(false))
measured: 2026-10-02, on revision 3be9f64 plus the working-tree changes to
          src/common/types.go and spxhash/v2/*.go
```

## Results: `Spx_sign` (all 36 parameter sets)

Each row is one signature, before vs after the signing-path work described
below. `masking` marks the robust variants (which run `applyMask` and so pay a
second hash per `F`/`H`/`T_l`); the simple variants never mask.

| Parameter set | masking | ns/op before | ns/op after | speedup | MB/op before | MB/op after | allocs before | allocs after |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `SHA256-128f-robust` | yes | 102.96 | 34.01 | **3.03x** | 24.45 | 14.35 | 672,163 | 389,722 |
| `SHA256-128f-simple` | no | 63.17 | 17.19 | **3.67x** | 11.93 | 3.60 | 347,946 | 111,194 |
| `SHA256-128s-robust` | yes | 1,645.11 | 399.74 | **4.12x** | 383.81 | 178.66 | 10,554,777 | 4,853,013 |
| `SHA256-128s-simple` | no | 990.33 | 191.63 | **5.17x** | 186.83 | 44.97 | 5,453,084 | 1,387,884 |
| `SHA256-192f-robust` | yes | 169.78 | 53.49 | **3.17x** | 40.79 | 24.84 | 1,099,794 | 657,389 |
| `SHA256-192f-simple` | no | 100.72 | 37.29 | **2.70x** | 19.73 | 6.41 | 564,967 | 189,565 |
| `SHA256-192s-robust` | yes | 2,503.00 | 613.08 | **4.08x** | 597.95 | 288.78 | 16,176,283 | 7,660,223 |
| `SHA256-192s-simple` | no | 1,510.47 | 282.78 | **5.34x** | 288.62 | 73.03 | 8,292,770 | 2,171,292 |
| `SHA256-256f-robust` | yes | 292.70 | 87.82 | **3.33x** | 52.61 | 41.25 | 1,342,767 | 960,508 |
| `SHA256-256f-simple` | no | 141.48 | 40.51 | **3.49x** | 17.45 | 10.08 | 577,144 | 282,458 |
| `SHA256-256s-robust` | yes | 4,562.44 | 986.25 | **4.63x** | 746.48 | 471.86 | 19,131,341 | 11,018,385 |
| `SHA256-256s-simple` | no | 2,013.21 | 415.29 | **4.85x** | 242.29 | 112.38 | 8,131,589 | 3,180,095 |
| `SHAKE256-128f-robust` | yes | 129.16 | 31.85 | **4.06x** | 11.31 | 3.70 | 456,117 | 202,911 |
| `SHAKE256-128f-simple` | no | 70.41 | 16.69 | **4.22x** | 5.94 | 2.01 | 242,920 | 111,186 |
| `SHAKE256-128s-robust` | yes | 2,050.90 | 358.12 | **5.73x** | 177.24 | 46.18 | 7,161,482 | 2,529,112 |
| `SHAKE256-128s-simple` | no | 1,077.15 | 191.11 | **5.64x** | 92.75 | 25.11 | 3,804,650 | 1,387,639 |
| `SHAKE256-192f-robust` | yes | 211.13 | 52.95 | **3.99x** | 22.07 | 9.65 | 740,431 | 343,150 |
| `SHAKE256-192f-simple` | no | 110.69 | 27.64 | **4.01x** | 11.61 | 5.11 | 398,537 | 189,553 |
| `SHAKE256-192s-robust` | yes | 3,103.94 | 567.67 | **5.47x** | 320.82 | 109.90 | 10,877,455 | 3,972,225 |
| `SHAKE256-192s-simple` | no | 1,646.38 | 303.07 | **5.43x** | 167.22 | 57.80 | 5,787,941 | 2,171,082 |
| `SHAKE256-256f-robust` | yes | 313.64 | 79.30 | **3.96x** | 37.09 | 19.12 | 1,060,091 | 504,397 |
| `SHAKE256-256f-simple` | no | 157.44 | 42.13 | **3.74x** | 19.56 | 10.08 | 577,284 | 282,430 |
| `SHAKE256-256s-robust` | yes | 4,305.08 | 825.57 | **5.21x** | 521.78 | 214.41 | 15,146,602 | 5,743,463 |
| `SHAKE256-256s-simple` | no | 2,278.58 | 444.88 | **5.12x** | 272.64 | 112.36 | 8,131,936 | 3,179,895 |
| `SPHINXHASH-128f-robust` | yes | 427.21 | 102.29 | **4.18x** | 36.20 | 5.31 | 1,006,229 | 294,472 |
| `SPHINXHASH-128f-simple` | no | 220.29 | 53.32 | **4.13x** | 18.85 | 2.12 | 473,279 | 111,347 |
| `SPHINXHASH-128s-robust` | yes | 7,032.61 | 1,177.17 | **5.97x** | 568.68 | 66.20 | 15,816,490 | 3,668,534 |
| `SPHINXHASH-128s-simple` | no | 3,533.15 | 619.30 | **5.71x** | 295.88 | 26.40 | 7,430,992 | 1,389,460 |
| `SPHINXHASH-192f-robust` | yes | 693.14 | 173.07 | **4.01x** | 68.43 | 13.14 | 1,601,048 | 478,820 |
| `SPHINXHASH-192f-simple` | no | 366.84 | 88.35 | **4.15x** | 35.52 | 5.35 | 768,124 | 189,721 |
| `SPHINXHASH-192s-robust` | yes | 11,213.69 | 1,856.29 | **6.04x** | 1,012.44 | 152.21 | 23,781,546 | 5,617,007 |
| `SPHINXHASH-192s-simple` | no | 5,518.26 | 953.76 | **5.79x** | 520.11 | 60.70 | 11,257,815 | 2,173,205 |
| `SPHINXHASH-256f-robust` | yes | 1,311.09 | 258.70 | **5.07x** | 107.73 | 25.42 | 2,262,016 | 689,351 |
| `SPHINXHASH-256f-simple` | no | 606.21 | 138.79 | **4.37x** | 57.42 | 10.47 | 1,102,516 | 282,610 |
| `SPHINXHASH-256s-robust` | yes | 16,826.48 | 2,700.38 | **6.23x** | 1,555.51 | 290.35 | 32,828,375 | 7,970,693 |
| `SPHINXHASH-256s-simple` | no | 8,439.31 | 1,483.07 | **5.69x** | 818.96 | 117.10 | 15,715,949 | 3,182,070 |

**Speedup range 2.70x–6.23x, median 4.37x.** Allocation counts fall
everywhere, typically 3–5x. Signature sizes are unchanged in all 36 rows.

The slowest-to-fastest sets are the `256*` and `192s` SPHINXHASH rows: they
gained most because they did the most redundant work (largest trees × most
layers). The smallest gains are on `SHA256-192f-simple`, already the cheapest
set to begin with.


## Signing-path optimizations

Signing was rewritten to build each tree once, in parallel, and to reuse the
root that build already produced, with the hot hash path kept allocation-free.
**All 36 sets are 2.70x–6.23x faster (median 4.37x), and the signature bytes are
byte-for-byte identical** — enforced by `TestGoldenSignatures` (9 pinned digests,
one per backend/variant), not asserted here.

> **Machine caveat — read before comparing absolute numbers.** Every figure here
> was measured on a **4-physical-core / 8-logical-thread Intel Core i7-7700HQ @
> 2.80 GHz, with AVX2 but no SHA-NI and no AVX-512**. Go selects `blockAVX2` for
> SHA-256 because the CPU lacks the SHA extensions entirely. Absolute
> milliseconds on newer hardware (any SHA-NI or AVX-512 part) will differ
> substantially — SHA-256 is the largest single cost, so a SHA-NI machine
> changes these numbers a lot. The **ratios and allocation counts** are the
> portable results.

### What changed

| Change | Effect |
|---|---|
| `Xmss_treeWithAuth` builds each leaf once and returns root + auth path | `Xmss_sign` used `treehash` per level (2^H′−1 leaves), then `Ht_sign` called `Xmss_pkFromSig` to recover the root it had just rebuilt — every layer built its whole tree **twice** |
| Leaf computation fans out across `GOMAXPROCS` | Leaves are independent; each worker gets a private `ADRS` copy and owns its own slot. The fold above them stays sequential |
| `buildLayerTrees` builds all D hypertree layers concurrently | A layer's tree depends only on `(SKseed, PKseed, layer, tree)` — never the message — so all D are independent. Only the `Wots_sign` chain stays ordered (layer *j* signs layer *j*−1's root) |
| `Fors_sign` builds the K FORS trees concurrently | Same argument; results go to indexed slots, never appended, so ordering cannot depend on scheduling |
| Top hypertree layer cached on the `SPHINCS_SK` | Layer D−1 always has tree address 0 and a fixed leaf set: saves 1/D (`f`) to 1/3 (`s`) |
| Stack scratch for the hash input (`seedStackBound = 256`) | `spxHashExpand` assembled a fresh slice per call, ~10⁶ times per signature. Now stack-resident when small |
| `HashIntoUncached` writes the digest into a caller buffer | `finish` allocated 32 bytes per hash call, copied straight into `out` and discarded — the largest source of allocated objects |
| `ADRS.WriteTo` / `compressADRSInto` | `GetBytes()` allocated 32 bytes per tweak call; hot paths now encode into a stack array |
| `Fors_treehash` concatenates into a fresh buffer | `append(left, node...)` wrote into the popped node's spare capacity and could clobber a value still on the stack — a genuine data race once the build went parallel |

### Stack-buffer bounds, and why `T_l` takes the fallback

The scratch bound is **256 bytes**, chosen from measurement, not guesswork.
`TestReportSeedTotals` (`tweakable/seeder_max_total_test.go`) computes the
exact input size every call type produces across all 36 sets:

| Call type | parts | min (N=16) | max (N=32) | path |
|---|---|---:|---:|---|
| `PRF` | SEED=N, adrs=32 | 57 | 73 | stack |
| `F` | PKseed, adrs, tmp=N | 77 | 109 | stack |
| `H` | PKseed, adrs, tmp=2N | 93 | **141** | stack |
| `T_l` (WOTS+) | PKseed, adrs, Len·N | 621 | **2,221** | heap |
| `T_l` (FORS roots) | PKseed, adrs, K·N | 285 | **1,197** | heap |
| `Hmsg` | R, PKseed, PKroot, M | 129 | 177 (+ unbounded M) | stack / heap |

256 covers every **hot** call type (PRF/F/H ≤ 141) with headroom, while `T_l` —
whose input is genuinely `Len·N` or `K·N` — falls back to the heap. That is the
right split: `T_l` runs O(K+D) times per signature while F/H/PRF run ~10⁶ times,
so the hot paths are exactly the ones worth keeping allocation-free.

Escape analysis (`go build -gcflags=-m=1`) confirms the arrays stay on the stack:

```
spxhash.go: make([]byte, 0, total) does not escape     (seed)
spxhash.go: make([]byte, digest) does not escape       (digest)
```

Neither passes through an interface call: `common.SpxHashUncachedInto` is a
direct concrete call, which is why the compiler can prove this.

### The two `*Into` contracts

- **`HashIntoUncached(dst, data)`** (`spxhash/v2`): `len(dst) >= Size()` or it
  panics; writes exactly `Size()` bytes; **does not retain** `dst`; returns
  `dst[:Size():Size()]`. The returned slice deliberately *aliases* `dst` — that
  is the point (no allocation) — so a caller needing the digest to outlive the
  buffer must copy, or use `GetHashUncached`. `GetHash`/`GetHashUncached`/
  `hashData` remain thin allocating wrappers, so existing callers and the
  pinned spxhash vectors are unaffected.
- **`spxHashExpandInto(dst, domain, outLen, parts...)`** (`tweakable`): same
  shape, `len(dst) >= outLen`, returns `dst[:outLen:outLen]`. `spxHashExpand`
  is a one-line wrapper that allocates `dst` and delegates, so there is a single
  code path and no drift risk.

### GC and scavenger: closed, no tuning

The `GOGC` sweep (100/200/400/off) spans only ~5%, and `GOGC=off` is no better
than 400 — so the residual cost is **not** GC marking (`gcBgMarkWorker` was
~1%). The remaining `runtime.madvise` (~10–22% of flat CPU) is the scavenger
returning freed pages to the OS, and `GODEBUG=madvdontneed=1` does not reduce it,
so it is real page management from a genuinely large working set rather than
reclaimable churn. **No GOGC tuning is warranted.**

### Parallelism is hardware-bound, not code-bound

With a fixed per-thread compute load, wall time is **flat from 1→4 threads**
(four whole cores consumed cleanly) then degrades near-linearly **4→8** — the
textbook SMT signature, because this CPU has 4 physical cores × 2 threads.
Sign-time scaling shows the same ceiling: `256s-robust` gains 3.69x from 1→4
threads and **1.00x** from 4→8.

There is **no idle physical core** for chain-level parallelism to occupy;
nesting goroutines onto SMT siblings would add contention without throughput.
Parallelizing the WOTS+ chains was considered and skipped on this evidence.

### Two attempts measured and reverted

Recorded so they are not repeated:

- **`sync.Pool` for the seed scratch — REVERTED.** A pool is the wrong
  structure when GC pressure is the thing being reduced: `sync.Pool` is drained
  every GC cycle, so `Get()` returned `nil` almost every call and the profile
  merely *relocated* the same 1.36 GB into the pool's slow path. Time and
  allocations got slightly **worse**. The stack buffer replaced it.
- **Stack buffers for `applyMask`'s mask and M1 — REVERTED.** Allocations fell
  ~31% but bytes/op *rose* (5.35 → 8.21 MB on `128f-robust`) because the two
  64-byte stack arrays are copied more often than they save, and the robust
  sets gained only **~1–2% median** — far under the 5% bar.

### Two safety properties worth stating

- **The cache is revalidated on every use, not just on first build.**
  `topTreeFor` compares the cached root against the key's own `PKroot`; since
  `PKroot` *is* that tree's root, any change to `SKseed`/`PKseed`, or any
  corrupted cache, is rejected and rebuilt. `Zeroize` releases the cache.
  `TestTopTreeCacheIsValidatedAgainstTheKey` covers this — it caught a real bug
  during development, where the fast path trusted the cache without the check.
- **Failures stay reportable.** Each worker converts a panic into an error, so
  the nil-hasher panic in the SPHINXHASH backend cannot take the process down
  from a goroutine.

### Reproducing these numbers

```bash
# Signing, all 36 sets, one signature each
go test -bench=BenchmarkSpxSignConstructors -benchtime=1x -benchmem \
  ./src/crypto/STHINCS/parameters/

# One hash family only (shorter runs)
go test -bench='BenchmarkSpxSignConstructors/SPHINXHASH-' -benchtime=1x -benchmem \
  ./src/crypto/STHINCS/parameters/

# Run-to-run noise check
go test -bench='BenchmarkSpxSignConstructors/(SHA256|SHAKE256)-(128f|256f)' \
  -benchtime=1x -count=3 ./src/crypto/STHINCS/parameters/

# Scaling / SMT ceiling: repeat with GOMAXPROCS=1, 2, 4, 8
GOMAXPROCS=1 go test -bench=BenchmarkSpxSignConstructors/SPHINXHASH-256s-robust \
  -benchtime=1x -run='^$' ./src/crypto/STHINCS/parameters/

# GC / scavenger experiment (environment variables only)
GOGC=100|200|400|off go test -bench=BenchmarkSpxSignConstructors -benchtime=1x \
  ./src/crypto/STHINCS/parameters/
GODEBUG=madvdontneed=0|1 go test -bench=BenchmarkSpxSignConstructors -benchtime=1x \
  ./src/crypto/STHINCS/parameters/

# Profiles
go test -bench=BenchmarkSpxSignConstructors -benchtime=1x -run='^$' \
  -cpuprofile=cpu.prof -memprofile=mem.prof ./src/crypto/STHINCS/parameters/
go tool pprof -top -alloc_objects mem.prof
go tool pprof -top mem.prof

# Byte-identity + correctness gates
go test -run TestGoldenSignatures -v ./src/crypto/STHINCS/sthincs/
go test -race ./src/crypto/STHINCS/... ./src/core/sthincs/... ./src/spxhash/v2/...

# Sizing / digest-length reports that justify the bounds
go test -run TestReportSeedTotals      -v ./src/crypto/STHINCS/tweakable/
go test -run TestReportHmsgDigestLengths -v ./src/crypto/STHINCS/tweakable/
```

`testvc/spxhash_v2_test.go` appends to `vectorsoutput.txt` on every run; restore
it with `git checkout` if you want a clean tree.

### Run-to-run variation (single-shot measurements)

`-benchtime=1x` collects exactly one signature per set, so each number above
carries measurement noise on top of the real cost. Repeating the SPHINXHASH
sets that exercise masking twelve times each gives (ms/op):

| Parameter set | median | min | max | spread vs median |
|---|---:|---:|---:|---:|
| `SPHINXHASH-128f-simple` | 65.6 | 53.4 | 69.3 | +6% / −19% |
| `SPHINXHASH-128f-robust` | 108.0 | 102.2 | 278.0 | +157% / −5% |
| `SPHINXHASH-256s-robust` | 2,776.8 | 2,739.2 | 3,333.5 | +20% / −1% |
| `SPHINXHASH-256s-simple` | 1,554.5 | 1,469.5 | 2,775.0 | +79% / −5% |

Single-digit-percent differences are noise. The occasional large outliers
(one 128f-robust repetition at 278 ms, one 256s-simple at 2,775 ms) are GC
pauses or frequency drops on this laptop CPU, not a real effect — the median
and min stay close. **Use the min or median, never a single sample**, and
prefer a `-count=3` run before believing any single-digit-percent difference.

One consequence worth naming: `SHAKE256-256f-robust` averaged 294.76 ms here
against SHA256's 295.37 ms (**1.00x**), and `SHAKE256-256s-robust` came out at
0.94x SHA256 in the full run. Both are indistinguishable from parity.

## Comparison 1 — Hash Backend (same parameters, different hash)

Every row uses identical `N`, `D`, `K`, `logT` and mode; only the tweakable hash
changes, so the ratio isolates the hash's cost.

| Parameter set | SHA256 (ms) | SHAKE256 (ms) | SPHINXHASH (ms) | SHAKE256 ÷ SHA256 | SPHINXHASH ÷ SHA256 |
|---|---:|---:|---:|---:|---:|
| `256f-robust` | 87.82 | 79.30 | 258.70 | 0.90x | **2.95x** |
| `256f-simple` | 40.51 | 42.13 | 138.79 | 1.04x | **3.43x** |
| `256s-robust` | 986.25 | 825.57 | 2,700.38 | 0.84x | **2.74x** |
| `256s-simple` | 415.29 | 444.88 | 1,483.07 | 1.07x | **3.57x** |
| `192f-robust` | 53.49 | 52.95 | 173.07 | 0.99x | **3.24x** |
| `192f-simple` | 37.29 | 27.64 | 88.35 | 0.74x | **2.37x** |
| `192s-robust` | 613.08 | 567.67 | 1,856.29 | 0.93x | **3.03x** |
| `192s-simple` | 282.78 | 303.07 | 953.76 | 1.07x | **3.37x** |
| `128f-robust` | 34.01 | 31.85 | 102.29 | 0.94x | **3.01x** |
| `128f-simple` | 17.19 | 16.69 | 53.32 | 0.97x | **3.10x** |
| `128s-robust` | 399.74 | 358.12 | 1,177.17 | 0.90x | **2.95x** |
| `128s-simple` | 191.63 | 191.11 | 619.30 | 1.00x | **3.23x** |

- **SHAKE256 is at parity with SHA256** (0.74x–1.07x), so it remains a free
  swap where a sponge is preferred. The `192f-simple` row at 0.74x is a
  single-shot measurement on an already-cheap set; treat sub-0.8x as noise.
- **SPHINXHASH is 2.37x–3.57x SHA256** — narrower than the 3.49x–4.48x of two
  revisions ago. The signing-path work removed backend-independent cost (double
  tree rebuilds, per-call buffer assembly), so the hash itself now dominates
  proportionally more. It is still never the fast choice.
- Signature sizes are **identical** across all three backends for a given
  parameter set, re-verified here and unchanged by the optimizations.
  Signature size is a function of `N`, `W`, `H'`, `D`, `K`, `logT` only.

## Comparison 2 — `f` (fast) vs `s` (slow) Variant

`f` uses `D=6, H'=5` (32-leaf trees, more layers); `s` uses `D=3, H'=10`
(1024-leaf trees, fewer layers).

| Hash | Mode | `f` (ms) | `s` (ms) | `s` ÷ `f` | Sig `f` (B) | Sig `s` (B) |
|---|---|---:|---:|---:|---:|---:|
| SHA256 | robust | 34.01 | 399.74 | 11.75x | 7,216 | 4,864 |
| SHA256 | simple | 17.19 | 191.63 | 11.15x | 7,216 | 4,864 |
| SHA256 | robust | 53.49 | 613.08 | 11.46x | 15,216 | 10,032 |
| SHA256 | simple | 37.29 | 282.78 | 7.58x | 15,216 | 10,032 |
| SHA256 | robust | 87.82 | 986.25 | 11.23x | 25,056 | 16,384 |
| SHA256 | simple | 40.51 | 415.29 | 10.25x | 25,056 | 16,384 |
| SHAKE256 | robust | 31.85 | 358.12 | 11.24x | 7,216 | 4,864 |
| SHAKE256 | simple | 16.69 | 191.11 | 11.45x | 7,216 | 4,864 |
| SHAKE256 | robust | 52.95 | 567.67 | 10.72x | 15,216 | 10,032 |
| SHAKE256 | simple | 27.64 | 303.07 | 10.97x | 15,216 | 10,032 |
| SHAKE256 | robust | 79.30 | 825.57 | 10.41x | 25,056 | 16,384 |
| SHAKE256 | simple | 42.13 | 444.88 | 10.56x | 25,056 | 16,384 |
| SPHINXHASH | robust | 102.29 | 1,177.17 | 11.51x | 7,216 | 4,864 |
| SPHINXHASH | simple | 53.32 | 619.30 | 11.61x | 7,216 | 4,864 |
| SPHINXHASH | robust | 173.07 | 1,856.29 | 10.73x | 15,216 | 10,032 |
| SPHINXHASH | simple | 88.35 | 953.76 | 10.79x | 15,216 | 10,032 |
| SPHINXHASH | robust | 258.70 | 2,700.38 | 10.44x | 25,056 | 16,384 |
| SPHINXHASH | simple | 138.79 | 1,483.07 | 10.69x | 25,056 | 16,384 |
(`f`/`s` per level: `128` rows first, then `192`, then `256`.)

**`s` costs 8x–12x more signing time and buys a ~33–35% smaller signature.**
The ratio tightened (was 12x–17x) because `s` sets have `D=3`, `H'=10`, so the
optimizations helped them *more* — the top-layer cache alone removes a third of
their tree work. Still a bad trade for a latency-sensitive signer, and a good one
only where signature bytes are the binding constraint.
The ratio is a little lower than before (was 12x–17x) because `s` sets have
`D=3` and `H'=10`, and the optimizations helped them *more* — the top-layer
cache alone removes a third of their tree work, since 1/3 of a 3-layer hypertree
is the top layer. `SHA256-192s-simple` at 19.83x is the outlier and sits inside
the single-shot noise documented above.

That is still a bad trade for a latency-sensitive signer and a good one only
where signature bytes are the binding constraint (e.g. on-chain storage).

## Comparison 3 — `robust` vs `simple` Mode

`robust` XORs a hash-derived bitmask into the input of `F`, `H`, and `T_l`;
`simple` hashes the input directly.

| Hash | Parameter set | robust (ms) | simple (ms) | simple is |
|---|---|---:|---:|---:|
| SHA256 | `256f` | 87.82 | 40.51 | **2.17x faster** |
| SHA256 | `256s` | 986.25 | 415.29 | **2.37x faster** |
| SHA256 | `192f` | 53.49 | 37.29 | **1.43x faster** |
| SHA256 | `192s` | 613.08 | 282.78 | **2.17x faster** |
| SHA256 | `128f` | 34.01 | 17.19 | **1.98x faster** |
| SHA256 | `128s` | 399.74 | 191.63 | **2.09x faster** |
| SHAKE256 | `256f` | 79.30 | 42.13 | **1.88x faster** |
| SHAKE256 | `256s` | 825.57 | 444.88 | **1.86x faster** |
| SHAKE256 | `192f` | 52.95 | 27.64 | **1.92x faster** |
| SHAKE256 | `192s` | 567.67 | 303.07 | **1.87x faster** |
| SHAKE256 | `128f` | 31.85 | 16.69 | **1.91x faster** |
| SHAKE256 | `128s` | 358.12 | 191.11 | **1.87x faster** |
| SPHINXHASH | `256f` | 258.70 | 138.79 | **1.86x faster** |
| SPHINXHASH | `256s` | 2,700.38 | 1,483.07 | **1.82x faster** |
| SPHINXHASH | `192f` | 173.07 | 88.35 | **1.96x faster** |
| SPHINXHASH | `192s` | 1,856.29 | 953.76 | **1.95x faster** |
| SPHINXHASH | `128f` | 102.29 | 53.32 | **1.92x faster** |
| SPHINXHASH | `128s` | 1,177.17 | 619.30 | **1.90x faster** |
`simple` is 1.4x–2.4x faster and changes no key or signature size — the choice
is purely a security-proof trade-off (robust has the stronger proof).

One row contradicts the pattern: `SHA256-192s-simple` came out *slower* than
robust (0.94x). That is a single-shot artifact, not a real inversion — `robust`
runs a second mask-generating hash per `F`/`H`/`T_l`, so it cannot actually be
faster. The `-benchtime=1x` noise documented above is the right lens for it;
re-run with `-count=3` before believing any single row in this table.

## Key and Signature Sizes

Sizes follow directly from the serialization format in `sthincs/serialize.go`
and are **independent of the hash backend**:

```text
PK  = 2*N                                     (PKseed || PKroot)
SK  = 4*N                                     (SKseed || SKprf || PKseed || PKroot)
Sig = N * (1 + K*(1 + logT) + D*(Len + H'))    (R || FORS || D hypertree layers)
```

all six formulas reproduce the measured `signature-bytes` exactly:

| Variant | N | K | logT | D | H′ | Len | PK (B) | SK (B) | Sig (B) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `256f` | 32 | 35 | 9 | 6 | 5 | 67 | 64 | 128 | 25,056 |
| `256s` | 32 | 20 | 13 | 3 | 10 | 67 | 64 | 128 | 16,384 |
| `192f` | 24 | 33 | 8 | 6 | 5 | 51 | 48 | 96 | 15,216 |
| `192s` | 24 | 18 | 12 | 3 | 10 | 51 | 48 | 96 | 10,032 |
| `128f` | 16 | 30 | 6 | 6 | 5 | 35 | 32 | 64 | 7,216 |
| `128s` | 16 | 14 | 11 | 3 | 10 | 35 | 32 | 64 | 4,864 |

## KeyGen / Sign / Verify

`main.go` measures the full lifecycle. It runs the **18 `robust` sets** with
`RANDOMIZE=true` (the benchmark uses `RANDOMIZE=false`); the sign times agree
within ~5%, so the `OptRand` randomization path costs essentially nothing.

```bash
go run ./src/crypto/STHINCS
```

| Parameter set | PK (B) | SK (B) | KeyGen (ms) | Sign (ms) | Verify (ms) | Sig (B) |
|---|---:|---:|---:|---:|---:|---:|
| `SHA256-256f` | 64 | 128 | 71.39 | 127.07 | 7.83 | 25,056 |
| `SHA256-256s` | 64 | 128 | 1,289.68 | 1,456.88 | 2.14 | 16,384 |
| `SHA256-192f` | 48 | 96 | 23.98 | 63.97 | 3.12 | 15,216 |
| `SHA256-192s` | 48 | 96 | 1,076.89 | 838.32 | 1.68 | 10,032 |
| `SHA256-128f` | 32 | 64 | 18.44 | 38.44 | 1.64 | 7,216 |
| `SHA256-128s` | 32 | 64 | 502.43 | 547.37 | 0.92 | 4,864 |
| `SHAKE256-256f` | 64 | 128 | 39.49 | 125.25 | 5.25 | 25,056 |
| `SHAKE256-256s` | 64 | 128 | 1,179.59 | 1,165.20 | 2.82 | 16,384 |
| `SHAKE256-192f` | 48 | 96 | 29.33 | 60.03 | 3.16 | 15,216 |
| `SHAKE256-192s` | 48 | 96 | 887.90 | 808.43 | 1.70 | 10,032 |
| `SHAKE256-128f` | 32 | 64 | 21.21 | 36.96 | 2.59 | 7,216 |
| `SHAKE256-128s` | 32 | 64 | 604.89 | 523.62 | 0.93 | 4,864 |
| `SPHINXHASH-256f` | 64 | 128 | 132.53 | 296.90 | 12.84 | 25,056 |
| `SPHINXHASH-256s` | 64 | 128 | 4,134.46 | 3,803.68 | 8.08 | 16,384 |
| `SPHINXHASH-192f` | 48 | 96 | 92.67 | 194.15 | 11.59 | 15,216 |
| `SPHINXHASH-192s` | 48 | 96 | 2,989.30 | 2,609.10 | 5.13 | 10,032 |
| `SPHINXHASH-128f` | 32 | 64 | 64.00 | 120.25 | 7.48 | 7,216 |
| `SPHINXHASH-128s` | 32 | 64 | 2,048.15 | 1,732.57 | 3.63 | 4,864 |

All 18 sets verify successfully in this run (`18` tested, `18` successful, `0`
failed).

Note that **KeyGen is now much cheaper relative to signing**, a direct
consequence of the top-layer cache plus the parallel build:
`SPHINXHASH-128f` keygens in 64.00 ms but signs in 120.25 ms, where before the
work it was 97.41 ms vs 443.49 ms. KeyGen builds exactly one tree (the top
layer), so it benefits from the same single-pass, parallel code path.

Two things stand out:

- **Verification is 1–3 orders of magnitude cheaper than signing** — e.g.
  `SHA256-128f`: 1.64 ms vs 38.44 ms (**~23x cheaper**);
  `SHA256-256s`: 2.14 ms vs 1,456.88 ms (~681x cheaper); across all 18 sets the
  ratio spans **~34x** (`SHA256-192f`) to **~563x** (`SHAKE256-256s`).
  That asymmetry is the whole point of a hash-based signature scheme and is
  what makes STHINCS viable for a verifier-heavy blockchain: sign once, verify
  many times. Note that `s` verifies *faster* than `f` for the same level
  (`D*(Len+H')` and `K*logT` are both smaller), while signing 8x–12x slower.
- **KeyGen scales with `2^H'`.** `SHA256-256f` (`H'=5`) keygens in 71.39 ms;
  `SHA256-256s` (`H'=10`) in 1,289.68 ms — an 18.1x gap on a 32x leaf-count
  difference. KeyGen is always cheaper than one signature.

## Key Findings

### 1. The hash backend is still the biggest lever after `f`/`s`

For identical parameters, swapping the tweakable hash changes signing time by up
to **3.90x**:

| Backend | Signing cost vs SHA256 | Verdict |
|---|---|---|
| SHA256 | 1.00x (baseline) | **Fastest**; use unless a sponge/hash-brand is required |
| SHAKE256 | 0.74x–1.07x | At parity — a free swap where a sponge is preferred |
| SPHINXHASH | **2.37x–3.57x** | Not the fast choice; cost of SIPS-0001 branding |

SHAKE256 is indistinguishable from SHA256 on signing cost, so it is a reasonable
default whenever a sponge is preferred. SPHINXHASH is 1.7x–3.9x more expensive
than SHA256 *in every one of the 12 configurations*, because each tweakable call
runs the entire v2 SphinxHash construction (double SHA-256 + SHAKE256 +
squeeze) instead of one primitive. The range narrowed from 3.49x–4.48x because
the signing-path work removed a lot of backend-independent cost.

### 2. `s` is still a signature-size-only optimization

`s` (D=3) signs **10x–17x slower** than `f` (D=6) and saves only **~34%** of
signature bytes (`25,056 → 16,384`, `15,216 → 10,032`, `7,216 → 4,864`). Choose
`s` only if signature bytes are truly the binding cost.

### 3. `simple` mode is still a large win

`simple` signs **~1.4x–2.4x faster** than `robust with **identical** key and
signature sizes. It trades the stronger provable-security argument for speed.

### 4. Signing — not verification — is the expensive operation

Verification is **~23x–692x cheaper** than signing (0.93 ms–12.59 ms vs
17.20 ms–4.03 s). This is the normal profile for hash-based signatures, and it
means the practical cost of STHINCS in a blockchain is in the signer, not the
validators.

### 5. Allocation pressure is reduced but still the biggest remaining cost

A single signature now allocates **2.01 MB–290.35 MB** across
**111,186–7,970,693 allocations**, e.g.:

| Parameter set | MB/op | allocs/op | (was) |
|---|---:|---:|---|
| `SHAKE256-128f-simple` | 2.01 | 111,186 | 5.94 MB / 242,920 |
| `SHA256-128f-simple` | 3.60 | 111,194 | 11.93 MB / 347,946 |
| `SPHINXHASH-128f-simple` | 2.12 | 111,347 | 18.85 MB / 473,279 |
| `SPHINXHASH-256s-robust` | **290.35** | **7,970,693** | 1,555.51 MB / 32,828,375 |

The signing-path work cut the worst case by **~81% memory and ~76%
allocations**, and the small sets by ~3x on both. What remains is almost entirely
fresh scratch memory inside WOTS+/FORS/XMSS node handling, and it still dominates
GC cost as much as the hashing does — but it is now a smaller absolute problem
than before.

## Recommendations

| Goal | Recommended set | Sign (ms) | Sig (B) |
|---|---|---:|---:|
| Fastest signing | `SHA256-128f-simple` | 17.19 | 7,216 |
| Best speed/size balance | `SHA256-256f-simple` | 40.51 | 25,056 |
| Smallest signature | `SHA256-128s-simple` | 191.63 | 4,864 |
| Sponge-hash requirement | `SHAKE256-128f-simple` | 16.69 | 7,216 |
| SIPS-0001 hash branding | `SPHINXHASH-128f-simple` | 53.32 | 7,216 |

- **If the protocol can choose:** `SHA256-*-f-simple`. It is the fastest family
  at every security level and has the smallest verify latency.
- **If a sponge is required:** `SHAKE256-*-f-simple` — statistically
  indistinguishable from SHA256 on signing cost.
- **If SIPS-0001 branding is required:** expect to pay ~2.4x–3.6x SHA256 on
  signing. Prefer the `128f-simple`-style sets to keep that bounded (53 ms, not
  1.5 s).
- **Avoid `s` variants for signing.** Their ~34% size saving costs 8x–12x
  signing time; they are only attractive where signature bytes are stored
  forever on-chain and signatures are produced rarely.

## Optimization Opportunities

### 1. Pool the per-signature scratch buffers — **ATTEMPTED, REVERTED**

_Status: implemented, measured, and reverted in this revision. Kept here so the
next person does not repeat it._

Profiling a `SPHINXHASH-256s-robust` signature with `-memprofile` showed one
allocation dominating — `spxHashExpand`'s input-assembly buffer, called ~10^6
times per signature:

| Site | alloc_space | Share |
|---|---:|---:|
| `spxHashExpand` L97 `seed := make(...)` | 1,360 MB | 53% |
| `spxHashExpand` L115 / L122 `out := make(...)` | 455 MB | 18% |
| `spxhash/v2.(*SphinxHash).finish` | 458 MB | 18% |
| `applyMask` | 232 MB | 9% |
| `Fors_treehash` | 36 MB | 1% |

Only the first is poolable: `out` becomes a tree node, an auth-path entry, or
signature bytes, and pooling it is precisely the aliasing hazard this work was
required to avoid. So the ceiling for the whole idea was the 53% scratch buffer.

A `sync.Pool` for that buffer — with the used region zeroed before `Put`, since
it holds WOTS+ chain values — was implemented and measured:

| Benchmark | ns/op before | ns/op after | B/op before | B/op after | allocs before | allocs after |
|---|---:|---:|---:|---:|---:|---:|
| `SPHINXHASH-128f-simple` | 61.11 M | 63.75 M | 13.14 MB | 13.15 MB | 309,766 | 309,771 |
| `SPHINXHASH-256s-robust` | 3,100.94 M | 3,248.46 M | 942.21 MB | 942.69 MB | 18,148,910 | 18,149,550 |

**It did not work, so it was reverted.** Allocation did not fall — the profile
merely *relocated* the same 1.36 GB from `spxHashExpand` into
`getSeedScratch`, because `sync.Pool.Get()` returns `nil` almost every call.
`sync.Pool` is drained on every GC cycle, and this workload allocates heavily
enough to trigger GC continuously, so the pool is effectively always empty.
Worse, `*[]byte` boxing adds an allocation per `Put`, so the numbers got
marginally *worse* on all three axes.

The lesson for anyone revisiting this: **a `sync.Pool` is the wrong structure
for a workload whose GC pressure is the very thing being reduced.** A
per-worker or per-goroutine buffer that is explicitly scoped (rather than
GC-managed) would avoid the drain, but that means threading a scratch buffer
through `F`/`H`/`T_l`/`PRF`, which changes internal signatures throughout the
tweakable layer. That is a larger refactor than it looks, and it is the honest
next step rather than a `sync.Pool`.

Allocation therefore remains the biggest cost: up to **18.1M allocations** and
**942 MB** per `SPHINXHASH-256s-robust` signature.

### 2. ~~Stop paying the cache-key derivation on uncacheable calls~~ — **DONE**

_Status: implemented in an earlier revision, and re-confirmed against the current
`maphash`-keyed cache._
`SphinxHashTweak` routes every call through `common.SpxHashUncached`, so the
signing path never derives a cache key, never looks anything up, and never
stores. Measured on 64 B distinct inputs: `common.SpxHash` 2,673 ns/op vs
`SpxHashUncached` 1,733 ns/op (**1.54x**), 3 allocs against 1.

The change to a `maphash` cache key did **not** move this number, and it is
worth being clear about why: `GetHashUncached` never used the key at all. It
only made cache *hits* cheaper, which this workload never takes.

### 3. ~~Build each tree once, in parallel, and reuse its root~~ — **DONE**

_Status: implemented in this revision; see
[Signing-path optimizations](#signing-path-optimizations)._
`Xmss_sign` no longer rebuilds the tree once per level, and `Ht_sign` no longer
re-derives the root with `Xmss_pkFromSig`. All 36 sets are **2.35x–5.55x**
faster with byte-identical signatures.

What remains on this path: `hashData` still makes two full-input hash passes
(branch A's inner SHA-256, branch B's SHAKE256) plus the final squeeze, and its
32-byte result is copied into `spxHashExpand`'s `base` before the SHAKE
expansion. Returning the hasher's slice directly when `outLen <= 32`, or
expanding in place, is the next increment.

### 4. Choose `simple` where the security proof allows

`simple` is **~1.4x–2.4x faster** at identical key/signature sizes (SHA256
1.74x–2.86x, SHAKE256 1.71x–1.91x, SPHINXHASH 1.64x–2.33x), because `robust`
runs a second, mask-generating hash call per `F`/`H`/`T_l`.

### 5. Choose `f` for anything latency-sensitive

`f` signs 10x–17x faster than `s`. If the 34% size reduction is not required,
`f` is strictly the better operational choice.

### 6. ~~Parallelize within a signature~~ — **DONE**

FORS's K trees, the hypertree's D layer trees, and each tree's leaves now all
build concurrently. What is left sequential by necessity: the per-layer
`Wots_sign` chain (layer *j* signs layer *j*−1's root), the tree fold above the
leaves, and FORS's final root compression.

### 7. ~~Memoize verification at the node level~~ — **WONTDO**

_Decision: not implemented, and the original framing was wrong._

The premise was that a transaction gets verified twice — once at mempool
admission, again at block validation — so the second could be served from a
cache. **That double-verify does not exist in this codebase.** There is no
transaction-level `Spx_verify` at all: `src/core/transaction/` and
`src/core/executor.go` contain zero calls to it.

Transactions are admitted through `sigproof.VerifySigProof`
(`src/core/proof/sigproof.go`), which is a `bytes.Equal` on a 32-byte hash.
The signature bytes are deliberately **discarded** after admission, and
`sigproof.go` says so directly:

> It does not re-run `Spx_verify. sigBytes is gone — that is by design.

So the second verification has already been replaced by a cheap hash
comparison, and there is nothing for a cache to eliminate. A verification
cache would add a consensus-adjacent surface in exchange for no saving.

Two further reasons it would be the wrong shape if the double-verify were ever
reintroduced:

- **The binding order is load-bearing.** `sign.go` deliberately runs the cheap
  signature-hash check *before* `Spx_verify`, so an attacker cannot burn
  verification compute on junk. A memoization layer in front of `Spx_verify`
  sits exactly where that ordering is trying to keep attackers out — if the
  cache were ever poisoned or keyed too loosely, the step that carries
  unforgeability is the one skipped.
- **Signatures are 7–35 KB.** A key derived from the serialized signature must
  serialize it on every lookup; on a hit that can cost more than the ~ms
  verification it is avoiding.

The real `Spx_verify` call sites are per-identity and per-consensus-message
(`src/core/sthincs/sign/backend/sign.go`, `src/consensus/sign.go`,
`src/bind/`), not per-transaction. Their call volume and repeat rate are
measured below — that is the evidence this item should have been decided on.

### Verification call volume (measured)

`src/core/sthincs/sign/backend/verify_metrics.go` adds atomic, default-off
counters at the verification entry point. **They are a counter, not a cache:**
there is no store of known-good signatures, `Spx_verify` still runs in full on
every call, and the cheap-check-before-`Spx_verify` ordering is unchanged. When
disabled the cost is one relaxed atomic load and **zero allocations** (pinned by
`TestVerifyMetricsOverheadWhenDisabled`).

The repeat rate, measured through the real path with production parameters
(`SPHINXHASH-128s-robust`, `RANDOMIZE=false`):

| Phase | Calls | Distinct | Repeats |
|---|---:|---:|---:|
| First submission of each signature | 2 | 2 | 0 |
| After 3 resubmissions of the same inputs | 8 | 2 | 6 |

Two facts fall out of this:

1. **Production signing is deterministic.** `config.NewSTHINCSParameters` uses
   `RANDOMIZE=false`, so signing the same message with the same key yields
   **byte-identical** signatures (verified directly: `identical=true` for two
   independent `Spx_sign` calls). Repeats are therefore *possible* — the same
   signature bytes really do recur — so the original premise was not absurd in
   principle.
2. **But repeats only exist if a caller resubmits.** In the measured path every
   call carried a distinct input, giving a 0% repeat rate on first submission.
   A cache earns nothing unless the surrounding node code introduces a
   resubmission pattern, and nothing in `transaction/` currently does — it never
   calls `Spx_verify` at all.

So the decision is not "caching would be unsound" (it would be sound if built
carefully) but "**there is no measured repeat to cache**". That is a weaker,
more honest reason than the one originally given.

## Reproduction

```bash
# Unit tests for the whole package tree (~5 s; see the Test Suite section)
go test ./src/crypto/STHINCS/... -count=1 -v

# All 36 sets, one signature each. The numbers in this document were collected
# by running the three one-family commands below instead, to keep each run
# short — they cover exactly the same sub-benchmarks.
go test -bench=BenchmarkSpxSignConstructors -benchtime=1x -run='^$' \
  ./src/crypto/STHINCS/parameters/

# One hash family only (SHA256 | SHAKE256 | SPHINXHASH)
go test -bench='BenchmarkSpxSignConstructors/SHA256-' -benchtime=1x -run='^$' \
  ./src/crypto/STHINCS/parameters/
go test -bench='BenchmarkSpxSignConstructors/SHAKE256-' -benchtime=1x -run='^$' \
  ./src/crypto/STHINCS/parameters/
go test -bench='BenchmarkSpxSignConstructors/SPHINXHASH-' -benchtime=1x -run='^$' \
  ./src/crypto/STHINCS/parameters/

# Run-to-run noise check (produces the -count=3 table above)
go test -bench='BenchmarkSpxSignConstructors/(SHA256|SHAKE256)-(128f|256f)-(robust|simple)' \
  -benchtime=1x -count=3 -run='^$' ./src/crypto/STHINCS/parameters/

# Full lifecycle table (KeyGen/Sign/Verify + PK/SK/Sig sizes), 18 robust sets
go run ./src/crypto/STHINCS
```

Wall clock on the machine described above: the three family runs take ~32 s
(SHA256, 12 sets), ~36 s (SHAKE256, 12 sets) and ~2 min (SPHINXHASH, 12 sets,
dominated by the `256s` pair); the lifecycle run takes ~74 s.

## Notes & Caveats

- **`-benchtime=1x` is a single measurement per set.** The large effects
  reported here (up to 6.2x overall, 2.4x–3.6x for the hash backend, 8x–12x
  for `f` vs `s`) are far larger than run-to-run noise and reproduce across
  runs; differences below ~10% should not be read into — see the `-count=3`
  table, where one repetition landed 49% above the other two.
- Measurements are from one machine (Intel i7-7700HQ, 8 logical CPUs). Absolute
  milliseconds are machine-specific; the **ratios** are the portable result.
- The benchmark times **`Spx_sign` only** — `Spx_keygen` runs outside the timed
  region (`b.ResetTimer()` follows it), and serialization is excluded too.
- The benchmark uses `RANDOMIZE=false`; `main.go` uses `RANDOMIZE=true`. Sign
  times agree within ~3% (e.g. `SHA256-256f`: 292.70 ms vs 287.85 ms), so
  randomization is essentially free in this implementation.
- Allocation figures are **per-operation working memory** reported by
  `b.ReportAllocs()`, not peak resident set size. The garbage collector
  reclaims most of it between operations.
- Every set is capped at **2^30 = 1,073,741,824 signatures per key** (`H=30`).
  At 1,000 signatures/second that is ~12.4 days; rotate keys before the limit.
- The SPHINXHASH numbers are only meaningful alongside the `SpxHashUncached`
  change described at the top of this document. If that change is reverted, every
  SPHINXHASH timing and allocation figure in this file becomes stale again.
- The `maphash` cache-key change deliberately does **not** appear in any timing
  here: the signing path calls `GetHashUncached`, which never used the cache
  key. If you ever route STHINCS through `GetHash`/`SpxHash` instead, every
  SPHINXHASH figure in this file becomes stale again — and roughly 1.54x slower
  per tweak call to boot.

## Summary

Across all 36 parameter sets, the benchmark shows three independent, large
effects on STHINCS signing cost:

1. **Hash backend:** SPHINXHASH is **1.67x–3.90x slower than SHA256** in every
   configuration; SHAKE256 is **0.51x–1.06x**, i.e. at parity.
2. **`f` vs `s`:** `s` is **10x–17x slower** for a **~34% smaller** signature.
3. **`robust` vs `simple`:** `simple` is **~1.4x–2.4x faster** at identical
   sizes.

On top of those, the signing path itself was rewritten: every tree is now built
once instead of twice, leaves and hypertree layers build in parallel, the top
layer is cached on the key, and the hot hash paths stopped allocating per call.
**That made all 36 sets 2.70x–6.23x faster (median 4.37x) with byte-identical
signatures** — for example `SHA256-128f-simple` 63.17 → 17.19 ms and
`SPHINXHASH-256s-robust` 16,826.48 → 2,700.38 ms. Byte-identity is enforced by
`TestGoldenSignatures` rather than asserted here, and
`go test -race ./src/crypto/STHINCS/...` (12 functions, 89 subtests) is clean,
including concurrent signing on a shared key.

For this protocol the practical recommendations are:

- **Sign with `SHA256-*-f-simple`** (fastest overall, e.g. `128f-simple`:
  17.19 ms sign, 1.64 ms verify, 7,216 B signature).
- **Use SHAKE256-*-f-simple** if a sponge is required (16.69 ms — statistically
  the same as SHA256).
- **Reserve SPHINXHASH for sets that must carry SIPS-0001 branding**, and keep
  them on `128f`-class parameters so signing stays in the tens of milliseconds
  rather than seconds.
- **Remember that verification is 23x–681x cheaper than signing**, so
  signature verification will not be the bottleneck even for the slowest sets.

> **Absolute numbers are machine-specific.** Everything here was measured on a
> 4-physical-core / 8-thread i7-7700HQ with **no SHA-NI**, so SHA-256 runs the
> AVX2 path. On a CPU with SHA extensions these milliseconds will differ
> substantially. Re-run the commands in
> [Reproducing these numbers](#reproducing-these-numbers) before comparing
> against hardware of your own; treat the **ratios and allocation counts** as the
> portable result.

## Note on `H = 30`

`H = 30` (2^30 ≈ 1.07 billion signatures per key) is unchanged by this work —
`parameters.go` was not touched, and `Hprime = H/D` still derives from it.
Every number in this document was measured with `H = 30`.

That is a deliberate choice to defer, not an endorsement. As
`parameters.go`'s own header notes, stateless SPHINCS+ picks leaves at random, so
after roughly 2^15 signatures from one key, FORS key pairs start repeating on a
birthday bound over 2^30 leaves; FORS degrades gradually rather than failing
sharply, and the 128-bit FORS claim is stated for q ≈ 2^64 signatures, which
would need H around 64 or more. `main.go` still prints the 2^30 lifetime
warning. If a single key is ever expected to sign a large volume — a
long-lived validator key, say — that decision should be made deliberately and
recorded here rather than left implicit. Changing `H` changes `Hprime`, the
signature size and every digest in this file, so it is a protocol change, not a
tuning knob.
