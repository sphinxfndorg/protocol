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
`spxHashExpand`, which calls `common.SpxHashUncachedInto` — the *uncached*,
buffer-writing entry point over the single shared, package-level hasher
instance from `src/common/types.go`:

```text
parameters.SPHINXHASH-*   ->  tweakable.SphinxHashTweak     (tweakable/spxhash.go)
                          ->  spxHashExpand(domain, parts...)   domain || len||part
                          ->  common.SpxHashUncachedInto   (src/common/types.go)
                          ->  spxhash/v2.NewProtocolHash(256)   // immutable v2 salt
                              ->  .HashIntoUncached(dst, seed)   // in-place, no alloc
```

The digest is written into a **stack-resident** buffer (`digestStackBound = 64`)
rather than a freshly allocated slice, because this path runs on the order of
10^6 times per signature.

So one `SPHINXHASH` signature makes on the order of 10^6 calls into the **v2**
SphinxHash construction (`src/spxhash/v2`), keyed with the immutable v2
protocol salt (`NewProtocolHash` reads the package's internal constant, not the
mutable `ProtocolSalt` slice)
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

Measured on identical distinct inputs (64 B), that is worth **1.19x** and one
allocation:

| Path (64 B, distinct inputs) | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `common.SpxHash` (cached entry point, always misses here) | 1,672 | 207 | 2 |
| `common.SpxHashUncached` (what STHINCS actually calls) | **1,404** | 32 | **1** |

The extra allocation is `LRUCache.Put`, which copies the input and the digest
into a fresh buffer on every miss. That is why a miss is *never* faster than
not caching at all — it is strictly the hashing plus that copy — and why
`GetHashUncached` remains the correct choice here regardless of how cheap the
cache key became. This probe was run ad hoc (not part of the committed test
suite) and was re-run after the branch-`A` change: the ratio narrowed from the
1.54x previously recorded because branch `A` is now one SHA-512/256 pass
instead of a double SHA-256, which makes the base hash cheaper for *both*
paths.

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
tests use only the fast `128f` sets, so the whole tree finishes in ~30 s wall
clock (dominated by the `sthincs` package, which carries the zeroize lifecycle
tests and signs nine golden signatures).

```text
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS          [no test files]
ok  github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address       0.494s
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/fors          [no test files]
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/hypertree     [no test files]
ok  github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters    1.005s [no tests to run]
ok  github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs      28.468s
ok  github.com/sphinxfndorg/protocol/src/crypto/STHINCS/tweakable     2.177s
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/util          [no test files]
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/wots          [no test files]
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/xmss          [no test files]
```

> **Consensus change — SPHINXHASH golden signatures re-baselined.**
> `TestGoldenSignatures` pins nine signatures; three of them (**all three
> `SPHINXHASH-*` rows**) no longer matched. The cause is not the
> `tweakable/spxhash.go` cleanup — it is the `spxhash/v2` branch-`A`
> primitive changing from a double SHA-256 to a single **SHA-512/256**
> (documented in `src/spxhash/v2/README.md`, "Changed (branch A)"). Only the
> SPHINXHASH backend routes through `spxhash/v2`, so the **SHA256-\* and
> SHAKE256-\* goldens are byte-for-byte unchanged**, and signature *lengths*
> are unchanged — only the SPHINXHASH bytes moved. The three SPHINXHASH digests
> were re-baselined in `sthincs/golden_test.go`, which is exactly the
> deliberate, documented protocol change that file's own comment permits.
> **A node on the old code and a node on the new code disagree about a
> SPHINXHASH signature** — this is not a no-op refactor.

`parameters` contains only `BenchmarkSpxSignConstructors`, hence "no tests to
run" under the normal (non-benchmark) invocation. The suite is **24 test
functions and 74 subtests** (98 `=== RUN` lines), of which four live in
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
| `sthincs` | `TestZeroizeConcurrentWithSign` | — | `Zeroize` and `Spx_sign` race deliberately; every outcome is a safe one (sign fails fast, or completes on a consistent snapshot) |
| `sthincs` | `TestSnapshotLengthValidationWipesNothing` | — | A snapshot rejected for the wrong length wipes nothing — length validation must not destroy the key |
| `sthincs` | `TestZeroizedKeyDoesNotRecache` | — | A zeroized key never (re)populates the top-layer cache, deterministically |
| `sthincs` | `TestZeroizedKeyNeverServesFromCache` | — | The other half of the flag: a zeroized key never *reads* a previously cached top tree |
| `sthincs` | `TestSnapshotRejectsZeroizedKey` | — | `Snapshot` fails fast on a zeroized key instead of serializing wiped material |
| `sthincs` | `TestSpxSignOnZeroizedKeyFailsFast` | — | Signing with a spent key is an error, not a panic and not a garbage signature |
| `sthincs` | `TestZeroizeBetweenSnapshotAndTopTreeFor` | 4 | The deterministic version of the zeroize-during-sign race: `Zeroize` landing between snapshot and top-tree lookup still yields a safe outcome |
| `sthincs` | `TestZeroizeDuringSignOutcomes` | — | The randomized, whole-signature race: `Zeroize` at an arbitrary point during `Spx_sign` |
| `tweakable` | `TestSeedTotalMatchesEncoding` | — | The duplicated sizing arithmetic in the bounds report is guarded against drifting from the real encoder |
| `tweakable` | `TestReportSeedTotals` | — | Diagnostic: exact input size per call type across all 36 sets — the table under [Stack-buffer bounds](#stack-buffer-bounds-and-why-t_l-takes-the-fallback) |
| `tweakable` | `TestReportHmsgDigestLengths` | — | Diagnostic: Hmsg output length vs digest size — settles from data whether `spxHashExpand` ever takes its XOF-expansion branch |

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
measured: 2026-10-03, on revision daeb96d plus the working-tree changes to
          src/common/types.go, spxhash/v2/*.go, tweakable/spxhash.go and
          sthincs/golden_test.go (SPHINXHASH golden re-baseline)
```

## Results: `Spx_sign` (all 36 parameter sets)

Each row is one signature, before vs after the signing-path work described
below. `masking` marks the robust variants (which run `applyMask` and so pay a
second hash per `F`/`H`/`T_l`); the simple variants never mask.

| Parameter set | masking | ns/op before | ns/op after | speedup | MB/op before | MB/op after | allocs before | allocs after |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `SHA256-128f-robust` | yes | 102.96 | 30.93 | **3.33x** | 24.45 | 14.35 | 672,163 | 389,718 |
| `SHA256-128f-simple` | no | 63.17 | 17.01 | **3.71x** | 11.93 | 3.60 | 347,946 | 111,200 |
| `SHA256-128s-robust` | yes | 1,645.11 | 349.84 | **4.70x** | 383.81 | 178.67 | 10,554,777 | 4,853,142 |
| `SHA256-128s-simple` | no | 990.33 | 183.61 | **5.39x** | 186.83 | 44.94 | 5,453,084 | 1,387,595 |
| `SHA256-192f-robust` | yes | 169.78 | 51.65 | **3.29x** | 40.79 | 24.84 | 1,099,794 | 657,379 |
| `SHA256-192f-simple` | no | 100.72 | 26.73 | **3.77x** | 19.73 | 6.41 | 564,967 | 189,562 |
| `SHA256-192s-robust` | yes | 2,503.00 | 650.08 | **3.85x** | 597.95 | 288.79 | 16,176,283 | 7,660,209 |
| `SHA256-192s-simple` | no | 1,510.47 | 286.92 | **5.26x** | 288.62 | 73.01 | 8,292,770 | 2,171,174 |
| `SHA256-256f-robust` | yes | 292.70 | 85.66 | **3.42x** | 52.61 | 41.22 | 1,342,767 | 960,431 |
| `SHA256-256f-simple` | no | 141.48 | 39.37 | **3.59x** | 17.45 | 10.08 | 577,144 | 282,457 |
| `SHA256-256s-robust` | yes | 4,562.44 | 937.90 | **4.86x** | 746.48 | 471.91 | 19,131,341 | 11,018,504 |
| `SHA256-256s-simple` | no | 2,013.21 | 408.08 | **4.93x** | 242.29 | 112.35 | 8,131,589 | 3,179,863 |
| `SHAKE256-128f-robust` | yes | 129.16 | 32.18 | **4.01x** | 11.31 | 3.70 | 456,117 | 202,911 |
| `SHAKE256-128f-simple` | no | 70.41 | 16.82 | **4.19x** | 5.94 | 2.01 | 242,920 | 111,187 |
| `SHAKE256-128s-robust` | yes | 2,050.90 | 357.42 | **5.74x** | 177.24 | 46.15 | 7,161,482 | 2,528,858 |
| `SHAKE256-128s-simple` | no | 1,077.15 | 196.25 | **5.49x** | 92.75 | 25.07 | 3,804,650 | 1,387,329 |
| `SHAKE256-192f-robust` | yes | 211.13 | 53.48 | **3.95x** | 22.07 | 9.65 | 740,431 | 343,153 |
| `SHAKE256-192f-simple` | no | 110.69 | 28.27 | **3.91x** | 11.61 | 5.11 | 398,537 | 189,550 |
| `SHAKE256-192s-robust` | yes | 3,103.94 | 564.51 | **5.50x** | 320.82 | 109.89 | 10,877,455 | 3,972,120 |
| `SHAKE256-192s-simple` | no | 1,646.38 | 304.98 | **5.40x** | 167.22 | 57.82 | 5,787,941 | 2,171,232 |
| `SHAKE256-256f-robust` | yes | 313.64 | 74.68 | **4.20x** | 37.09 | 19.15 | 1,060,091 | 504,508 |
| `SHAKE256-256f-simple` | no | 157.44 | 42.33 | **3.72x** | 19.56 | 10.08 | 577,284 | 282,439 |
| `SHAKE256-256s-robust` | yes | 4,305.08 | 815.77 | **5.28x** | 521.78 | 214.45 | 15,146,602 | 5,743,705 |
| `SHAKE256-256s-simple` | no | 2,278.58 | 454.37 | **5.02x** | 272.64 | 112.36 | 8,131,936 | 3,179,919 |
| `SPHINXHASH-128f-robust` | yes | 427.21 | 84.37 | **5.06x** | 36.20 | 5.31 | 1,006,229 | 294,464 |
| `SPHINXHASH-128f-simple` | no | 220.29 | 44.45 | **4.96x** | 18.85 | 2.12 | 473,279 | 111,364 |
| `SPHINXHASH-128s-robust` | yes | 7,032.61 | 972.83 | **7.23x** | 568.68 | 66.22 | 15,816,490 | 3,668,705 |
| `SPHINXHASH-128s-simple` | no | 3,533.15 | 512.59 | **6.89x** | 295.88 | 26.39 | 7,430,992 | 1,389,375 |
| `SPHINXHASH-192f-robust` | yes | 693.14 | 147.44 | **4.70x** | 68.43 | 13.14 | 1,601,048 | 478,786 |
| `SPHINXHASH-192f-simple` | no | 366.84 | 82.16 | **4.46x** | 35.52 | 5.35 | 768,124 | 189,720 |
| `SPHINXHASH-192s-robust` | yes | 11,213.69 | 1,638.62 | **6.84x** | 1,012.44 | 152.19 | 23,781,546 | 5,616,833 |
| `SPHINXHASH-192s-simple` | no | 5,518.26 | 908.44 | **6.07x** | 520.11 | 60.69 | 11,257,815 | 2,173,071 |
| `SPHINXHASH-256f-robust` | yes | 1,311.09 | 210.30 | **6.23x** | 107.73 | 25.44 | 2,262,016 | 689,448 |
| `SPHINXHASH-256f-simple` | no | 606.21 | 119.00 | **5.09x** | 57.42 | 10.47 | 1,102,516 | 282,605 |
| `SPHINXHASH-256s-robust` | yes | 16,826.48 | 2,330.11 | **7.22x** | 1,555.51 | 290.34 | 32,828,375 | 7,970,578 |
| `SPHINXHASH-256s-simple` | no | 8,439.31 | 1,319.36 | **6.40x** | 818.96 | 117.09 | 15,715,949 | 3,181,976 |

**Speedup range 3.29x–7.23x, median 4.95x.** Allocation counts fall
everywhere, typically 3–5x. Signature sizes are unchanged in all 36 rows.

Two things drive the SPHINXHASH column. The signing-path rework removed the
redundant work (double tree builds, per-call buffer assembly) for every
backend, and the branch-`A` change — a single SHA-512/256 where the old draft
used a double SHA-256 — took a further full pass off each of the ~10^6 tweak
calls, but **only for SPHINXHASH**. So SPHINXHASH speedups (4.46x–7.23x) now
run ahead of SHA256/SHAKE256 (3.29x–5.74x) instead of tracking them, and the
smallest gains are on the already-cheap `SHA256-192f-robust` /
`SHA256-128f-robust`.


## Signing-path optimizations

Signing was rewritten to build each tree once, in parallel, and to reuse the
root that build already produced, with the hot hash path kept allocation-free.
**All 36 sets are 3.29x–7.23x faster (median 4.95x)**, and the signature bytes
are byte-for-byte identical between revisions — except for the three
`SPHINXHASH-*` digests, which were deliberately re-baselined for the
branch-`A` change (see [Test Suite Results](#test-suite-results)).
`TestGoldenSignatures` (9 pinned digests, one per backend/variant) enforces
both facts; it is not asserted here.

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
- **`spxHashExpand(domain, outLen, parts...)`** (`tweakable`): there is **no**
  second exported `*Into` entry point here — `spxHashExpand` owns both buffers
  itself. It assembles `domain || len||part` into a **stack-resident** `seed`
  (`seedStackBound = 256`, heap only for `T_l` and large `Hmsg`), hashes it into
  a **stack-resident** digest (`digestStackBound = 64`) through
  `common.SpxHashUncachedInto`, then wipes both `seed` and the whole `stack`
  array with `util.Wipe` (kept alive by `runtime.KeepAlive`) because the seed
  carries WOTS+ chain values and PRF output. Only the returned `out` is
  heap-allocated, at its exact length, so no caller can append into spare
  capacity.

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
carries measurement noise on top of the real cost. Repeating four SPHINXHASH
sets (two that exercise masking, two that do not) three times each — 12
samples — gives (ms/op):

| Parameter set | median | min | max | spread vs median |
|---|---:|---:|---:|---:|
| `SPHINXHASH-128f-simple` | 44.5 | 44.1 | 50.5 | +13% / −1% |
| `SPHINXHASH-128f-robust` | 84.5 | 83.6 | 84.7 | +0.3% / −1% |
| `SPHINXHASH-256s-robust` | 2,298.9 | 2,291.8 | 2,343.6 | +2% / −0.3% |
| `SPHINXHASH-256s-simple` | 1,314.1 | 1,311.2 | 1,323.5 | +0.7% / −0.2% |

Single-digit-percent differences are noise. This particular run produced no
large outliers, but earlier runs on this laptop did (a `128f-robust` repetition
at 278 ms, a `256s-simple` at 2,775 ms), traced to GC pauses or frequency
drops rather than a real effect. **Use the min or median, never a single
sample**, and prefer a `-count=3` run before believing any single-digit-percent
difference.

One consequence worth naming: `SHAKE256-256f-robust` came in *under* SHA256
(74.68 ms vs 85.66 ms, **0.87x**) and `SHAKE256-256s-robust` likewise
(815.77 ms vs 937.90 ms, **0.87x**). Both are within run-to-run noise, so they
mean parity — not that SHAKE256 is genuinely faster.

## Comparison 1 — Hash Backend (same parameters, different hash)

Every row uses identical `N`, `D`, `K`, `logT` and mode; only the tweakable hash
changes, so the ratio isolates the hash's cost.

| Parameter set | SHA256 (ms) | SHAKE256 (ms) | SPHINXHASH (ms) | SHAKE256 ÷ SHA256 | SPHINXHASH ÷ SHA256 |
|---|---:|---:|---:|---:|---:|
| `256f-robust` | 85.66 | 74.68 | 210.30 | 0.87x | **2.46x** |
| `256f-simple` | 39.37 | 42.33 | 119.00 | 1.08x | **3.02x** |
| `256s-robust` | 937.90 | 815.77 | 2,330.11 | 0.87x | **2.48x** |
| `256s-simple` | 408.08 | 454.37 | 1,319.36 | 1.11x | **3.23x** |
| `192f-robust` | 51.65 | 53.48 | 147.44 | 1.04x | **2.85x** |
| `192f-simple` | 26.73 | 28.27 | 82.16 | 1.06x | **3.07x** |
| `192s-robust` | 650.08 | 564.51 | 1,638.62 | 0.87x | **2.52x** |
| `192s-simple` | 286.92 | 304.98 | 908.44 | 1.06x | **3.17x** |
| `128f-robust` | 30.93 | 32.18 | 84.37 | 1.04x | **2.73x** |
| `128f-simple` | 17.01 | 16.82 | 44.45 | 0.99x | **2.61x** |
| `128s-robust` | 349.84 | 357.42 | 972.83 | 1.02x | **2.78x** |
| `128s-simple` | 183.61 | 196.25 | 512.59 | 1.07x | **2.79x** |

- **SHAKE256 is at parity with SHA256** (0.87x–1.11x), so it remains a free
  swap where a sponge is preferred.
- **SPHINXHASH is 2.46x–3.23x SHA256** — down from the 3.49x–4.48x of two
  revisions ago. Two things shrank it: the signing-path work removed
  backend-independent cost (double tree rebuilds, per-call buffer assembly),
  and the branch-`A` change replaced a double SHA-256 with a single
  SHA-512/256, taking a whole pass off each tweak call **for this backend
  only**. It is still never the fast choice.
- Signature sizes are **identical** across all three backends for a given
  parameter set, re-verified here and unchanged by the optimizations.
  Signature size is a function of `N`, `W`, `H'`, `D`, `K`, `logT` only.

## Comparison 2 — `f` (fast) vs `s` (slow) Variant

`f` uses `D=6, H'=5` (32-leaf trees, more layers); `s` uses `D=3, H'=10`
(1024-leaf trees, fewer layers).

| Hash | Mode | `f` (ms) | `s` (ms) | `s` ÷ `f` | Sig `f` (B) | Sig `s` (B) |
|---|---|---:|---:|---:|---:|---:|
| SHA256 | robust | 30.93 | 349.84 | 11.31x | 7,216 | 4,864 |
| SHA256 | simple | 17.01 | 183.61 | 10.80x | 7,216 | 4,864 |
| SHA256 | robust | 51.65 | 650.08 | 12.59x | 15,216 | 10,032 |
| SHA256 | simple | 26.73 | 286.92 | 10.73x | 15,216 | 10,032 |
| SHA256 | robust | 85.66 | 937.90 | 10.95x | 25,056 | 16,384 |
| SHA256 | simple | 39.37 | 408.08 | 10.36x | 25,056 | 16,384 |
| SHAKE256 | robust | 32.18 | 357.42 | 11.11x | 7,216 | 4,864 |
| SHAKE256 | simple | 16.82 | 196.25 | 11.67x | 7,216 | 4,864 |
| SHAKE256 | robust | 53.48 | 564.51 | 10.55x | 15,216 | 10,032 |
| SHAKE256 | simple | 28.27 | 304.98 | 10.79x | 15,216 | 10,032 |
| SHAKE256 | robust | 74.68 | 815.77 | 10.92x | 25,056 | 16,384 |
| SHAKE256 | simple | 42.33 | 454.37 | 10.73x | 25,056 | 16,384 |
| SPHINXHASH | robust | 84.37 | 972.83 | 11.53x | 7,216 | 4,864 |
| SPHINXHASH | simple | 44.45 | 512.59 | 11.53x | 7,216 | 4,864 |
| SPHINXHASH | robust | 147.44 | 1,638.62 | 11.11x | 15,216 | 10,032 |
| SPHINXHASH | simple | 82.16 | 908.44 | 11.06x | 15,216 | 10,032 |
| SPHINXHASH | robust | 210.30 | 2,330.11 | 11.08x | 25,056 | 16,384 |
| SPHINXHASH | simple | 119.00 | 1,319.36 | 11.09x | 25,056 | 16,384 |
(`f`/`s` per level: `128` rows first, then `192`, then `256`.)

**`s` costs ~10x–13x more signing time and buys a ~33–35% smaller signature.**
The ratio sits below the 12x–17x of two revisions ago because `s` sets have
`D=3`, `H'=10`, so the optimizations helped them *more* — the top-layer cache
alone removes a third of their tree work (1/3 of a 3-layer hypertree is the top
layer). That is still a bad trade for a latency-sensitive signer, and a good one
only where signature bytes are the binding constraint (e.g. on-chain storage).

## Comparison 3 — `robust` vs `simple` Mode

`robust` XORs a hash-derived bitmask into the input of `F`, `H`, and `T_l`;
`simple` hashes the input directly.

| Hash | Parameter set | robust (ms) | simple (ms) | simple is |
|---|---|---:|---:|---:|
| SHA256 | `256f` | 85.66 | 39.37 | **2.18x faster** |
| SHA256 | `256s` | 937.90 | 408.08 | **2.30x faster** |
| SHA256 | `192f` | 51.65 | 26.73 | **1.93x faster** |
| SHA256 | `192s` | 650.08 | 286.92 | **2.27x faster** |
| SHA256 | `128f` | 30.93 | 17.01 | **1.82x faster** |
| SHA256 | `128s` | 349.84 | 183.61 | **1.91x faster** |
| SHAKE256 | `256f` | 74.68 | 42.33 | **1.76x faster** |
| SHAKE256 | `256s` | 815.77 | 454.37 | **1.80x faster** |
| SHAKE256 | `192f` | 53.48 | 28.27 | **1.89x faster** |
| SHAKE256 | `192s` | 564.51 | 304.98 | **1.85x faster** |
| SHAKE256 | `128f` | 32.18 | 16.82 | **1.91x faster** |
| SHAKE256 | `128s` | 357.42 | 196.25 | **1.82x faster** |
| SPHINXHASH | `256f` | 210.30 | 119.00 | **1.77x faster** |
| SPHINXHASH | `256s` | 2,330.11 | 1,319.36 | **1.77x faster** |
| SPHINXHASH | `192f` | 147.44 | 82.16 | **1.79x faster** |
| SPHINXHASH | `192s` | 1,638.62 | 908.44 | **1.80x faster** |
| SPHINXHASH | `128f` | 84.37 | 44.45 | **1.90x faster** |
| SPHINXHASH | `128s` | 972.83 | 512.59 | **1.90x faster** |
`simple` is 1.8x–2.3x faster and changes no key or signature size — the choice
is purely a security-proof trade-off (robust has the stronger proof).

Every row now follows the pattern, as it must: `robust` runs a second
mask-generating hash per `F`/`H`/`T_l`, so it cannot lose to `simple`. (A
previous run showed `SHA256-192s-simple` at 0.94x — a single-shot artifact,
not an inversion, and it does not reproduce here.) These are still
`-benchtime=1x` measurements, so re-run with `-count=3` before believing any
single-digit-percent difference.

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
| `SHA256-256f` | 64 | 128 | 39.67 | 92.13 | 4.29 | 25,056 |
| `SHA256-256s` | 64 | 128 | 1,170.44 | 1,282.31 | 2.25 | 16,384 |
| `SHA256-192f` | 48 | 96 | 24.79 | 62.81 | 3.43 | 15,216 |
| `SHA256-192s` | 48 | 96 | 729.97 | 816.57 | 1.61 | 10,032 |
| `SHA256-128f` | 32 | 64 | 15.65 | 37.45 | 2.17 | 7,216 |
| `SHA256-128s` | 32 | 64 | 582.44 | 589.98 | 0.84 | 4,864 |
| `SHAKE256-256f` | 64 | 128 | 36.96 | 86.26 | 3.52 | 25,056 |
| `SHAKE256-256s` | 64 | 128 | 1,164.85 | 1,300.38 | 2.87 | 16,384 |
| `SHAKE256-192f` | 48 | 96 | 28.18 | 60.45 | 2.67 | 15,216 |
| `SHAKE256-192s` | 48 | 96 | 962.07 | 804.78 | 2.34 | 10,032 |
| `SHAKE256-128f` | 32 | 64 | 18.87 | 36.60 | 2.36 | 7,216 |
| `SHAKE256-128s` | 32 | 64 | 596.88 | 516.71 | 1.19 | 4,864 |
| `SPHINXHASH-256f` | 64 | 128 | 106.01 | 243.17 | 11.86 | 25,056 |
| `SPHINXHASH-256s` | 64 | 128 | 3,406.29 | 3,180.26 | 7.09 | 16,384 |
| `SPHINXHASH-192f` | 48 | 96 | 81.77 | 170.09 | 10.67 | 15,216 |
| `SPHINXHASH-192s` | 48 | 96 | 2,569.08 | 2,261.56 | 5.03 | 10,032 |
| `SPHINXHASH-128f` | 32 | 64 | 51.46 | 98.03 | 4.59 | 7,216 |
| `SPHINXHASH-128s` | 32 | 64 | 1,627.69 | 1,371.06 | 3.37 | 4,864 |

All 18 sets verify successfully in this run (`18` tested, `18` successful, `0`
failed).

Note that **KeyGen is much cheaper relative to signing**, a direct consequence
of the top-layer cache plus the parallel build: `SPHINXHASH-128f` keygens in
51.46 ms but signs in 98.03 ms, where before the work it was 97.41 ms vs
443.49 ms. KeyGen builds exactly one tree (the top layer), so it benefits from
the same single-pass, parallel code path. It is *not* universally cheaper
though — for the `s` sets the top layer **is** the dominant tree, so keygen
costs about as much as a sign (`SPHINXHASH-256s`: 3,406 ms vs 3,180 ms).

Two things stand out:

- **Verification is 1–3 orders of magnitude cheaper than signing** — e.g.
  `SHA256-128f`: 2.17 ms vs 37.45 ms (**~17x cheaper**);
  `SHA256-256s`: 2.25 ms vs 1,282.31 ms (~570x cheaper); across all 18 sets the
  ratio spans **~16x** (`SHAKE256-128f`) to **~702x** (`SHA256-128s`).
  That asymmetry is the whole point of a hash-based signature scheme and is
  what makes STHINCS viable for a verifier-heavy blockchain: sign once, verify
  many times. Note that `s` verifies *faster* than `f` for the same level
  (`D*(Len+H')` and `K*logT` are both smaller), while signing 10x–13x slower.
- **KeyGen scales with `2^H'`.** `SHA256-256f` (`H'=5`) keygens in 39.67 ms;
  `SHA256-256s` (`H'=10`) in 1,170.44 ms — a 29.5x gap on a 32x leaf-count
  difference.

## Key Findings

### 1. The hash backend is still the biggest lever after `f`/`s`

For identical parameters, swapping the tweakable hash changes signing time by up
to **3.23x**:

| Backend | Signing cost vs SHA256 | Verdict |
|---|---|---|
| SHA256 | 1.00x (baseline) | **Fastest**; use unless a sponge/hash-brand is required |
| SHAKE256 | 0.87x–1.11x | At parity — a free swap where a sponge is preferred |
| SPHINXHASH | **2.46x–3.23x** | Not the fast choice; cost of SIPS-0001 branding |

SHAKE256 is indistinguishable from SHA256 on signing cost, so it is a reasonable
default whenever a sponge is preferred. SPHINXHASH is 2.5x–3.2x more expensive
than SHA256 *in every one of the 12 configurations*, because each tweakable call
runs the entire v2 SphinxHash construction (SHA-512/256 + SHAKE256 + squeeze)
instead of one primitive. The range narrowed from 3.49x–4.48x because the
signing-path work removed backend-independent cost **and** branch `A` dropped
from a double SHA-256 to a single SHA-512/256 (SPHINXHASH-only).

### 2. `s` is still a signature-size-only optimization

`s` (D=3) signs **10x–13x slower** than `f` (D=6) and saves only **~34%** of
signature bytes (`25,056 → 16,384`, `15,216 → 10,032`, `7,216 → 4,864`). Choose
`s` only if signature bytes are truly the binding cost.

### 3. `simple` mode is still a large win

`simple` signs **~1.8x–2.3x faster** than `robust` with **identical** key and
signature sizes. It trades the stronger provable-security argument for speed.

### 4. Signing — not verification — is the expensive operation

Verification is **~16x–702x cheaper** than signing (0.84 ms–11.86 ms vs
36.60 ms–3.18 s). This is the normal profile for hash-based signatures, and it
means the practical cost of STHINCS in a blockchain is in the signer, not the
validators.

### 5. Allocation pressure is reduced but still the biggest remaining cost

A single signature now allocates **2.01 MB–290.34 MB** across
**111,187–7,970,578 allocations**, e.g.:

| Parameter set | MB/op | allocs/op | (was) |
|---|---:|---:|---|
| `SHAKE256-128f-simple` | 2.01 | 111,187 | 5.94 MB / 242,920 |
| `SHA256-128f-simple` | 3.60 | 111,200 | 11.93 MB / 347,946 |
| `SPHINXHASH-128f-simple` | 2.12 | 111,364 | 18.85 MB / 473,279 |
| `SPHINXHASH-256s-robust` | **290.34** | **7,970,578** | 1,555.51 MB / 32,828,375 |

The signing-path work cut the worst case by **~81% memory and ~76%
allocations**, and the small sets by ~3x on both. What remains is almost entirely
fresh scratch memory inside WOTS+/FORS/XMSS node handling, and it still dominates
GC cost as much as the hashing does — but it is now a smaller absolute problem
than before.

## Recommendations

| Goal | Recommended set | Sign (ms) | Sig (B) |
|---|---|---:|---:|
| Fastest signing | `SHA256-128f-simple` | 17.01 | 7,216 |
| Best speed/size balance | `SHA256-256f-simple` | 39.37 | 25,056 |
| Smallest signature | `SHA256-128s-simple` | 183.61 | 4,864 |
| Sponge-hash requirement | `SHAKE256-128f-simple` | 16.82 | 7,216 |
| SIPS-0001 hash branding | `SPHINXHASH-128f-simple` | 44.45 | 7,216 |

- **If the protocol can choose:** `SHA256-*-f-simple`. It is the fastest family
  at every security level and has the smallest verify latency.
- **If a sponge is required:** `SHAKE256-*-f-simple` — statistically
  indistinguishable from SHA256 on signing cost.
- **If SIPS-0001 branding is required:** expect to pay ~2.5x–3.2x SHA256 on
  signing. Prefer the `128f-simple`-style sets to keep that bounded (44 ms, not
  1.3 s).
- **Avoid `s` variants for signing.** Their ~34% size saving costs 10x–13x
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
`SphinxHashTweak` routes every call through `common.SpxHashUncachedInto`, so
the signing path never derives a cache key, never looks anything up, and never
stores. Measured on 64 B distinct inputs: `common.SpxHash` 1,672 ns/op vs
`SpxHashUncached` 1,404 ns/op (**1.19x**), 2 allocs against 1.

The change to a `maphash` cache key did **not** move this number, and it is
worth being clear about why: `GetHashUncached` never used the key at all. It
only made cache *hits* cheaper, which this workload never takes.

### 3. ~~Build each tree once, in parallel, and reuse its root~~ — **DONE**

_Status: implemented in this revision; see
[Signing-path optimizations](#signing-path-optimizations)._
`Xmss_sign` no longer rebuilds the tree once per level, and `Ht_sign` no longer
re-derives the root with `Xmss_pkFromSig`. All 36 sets are **3.29x–7.23x**
faster, with byte-identical signatures (SPHINXHASH re-baselined as noted).

What remains on this path: `hashData` still makes two full-input hash passes
(branch A's SHA-512/256, branch B's SHAKE256) plus the final squeeze, and its
32-byte result is copied into `spxHashExpand`'s `base` before the SHAKE
expansion. Writing the digest straight through without that intermediate copy
is the next increment.

### 4. Choose `simple` where the security proof allows

`simple` is **~1.8x–2.3x faster** at identical key/signature sizes (SHA256
1.82x–2.30x, SHAKE256 1.76x–1.91x, SPHINXHASH 1.77x–1.90x), because `robust`
runs a second, mask-generating hash call per `F`/`H`/`T_l`.

### 5. Choose `f` for anything latency-sensitive

`f` signs ~10x–13x faster than `s`. If the 34% size reduction is not required,
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
# Unit tests for the whole package tree (~30 s; see the Test Suite section)
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
go test -bench='BenchmarkSpxSignConstructors/SPHINXHASH-(128f|256s)-(simple|robust)' \
  -benchtime=1x -count=3 -run='^$' ./src/crypto/STHINCS/parameters/

# Full lifecycle table (KeyGen/Sign/Verify + PK/SK/Sig sizes), 18 robust sets
go run ./src/crypto/STHINCS
```

Wall clock on the machine described above: the three family runs take ~12 s
(SHA256, 12 sets), ~12 s (SHAKE256, 12 sets) and ~33 s (SPHINXHASH, 12 sets,
dominated by the `256s` pair); the lifecycle run takes about a minute.

## Notes & Caveats

- **`-benchtime=1x` is a single measurement per set.** The large effects
  reported here (up to 7.2x overall, 2.5x–3.2x for the hash backend, 10x–13x
  for `f` vs `s`) are far larger than run-to-run noise and reproduce across
  runs; differences below ~10% should not be read into — see the `-count=3`
  table, where one repetition landed 49% above the other two.
- Measurements are from one machine (Intel i7-7700HQ, 8 logical CPUs). Absolute
  milliseconds are machine-specific; the **ratios** are the portable result.
- The benchmark times **`Spx_sign` only** — `Spx_keygen` runs outside the timed
  region (`b.ResetTimer()` follows it), and serialization is excluded too.
- The benchmark uses `RANDOMIZE=false`; `main.go` uses `RANDOMIZE=true`. Both
  are single-shot per set, and `main.go`'s numbers land inside the run-to-run
  spread documented below (e.g. `SHA256-256f` 85.66 ms benchmarked vs 92.13 ms
  in `main.go`), so treat them as an order-of-magnitude cross-check rather than
  a like-for-like match.
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
  SPHINXHASH figure in this file becomes stale again — and roughly 1.19x slower
  per tweak call to boot.

## Summary

Across all 36 parameter sets, the benchmark shows three independent, large
effects on STHINCS signing cost:

1. **Hash backend:** SPHINXHASH is **2.46x–3.23x slower than SHA256** in every
   configuration; SHAKE256 is **0.87x–1.11x**, i.e. at parity.
2. **`f` vs `s`:** `s` is **10x–13x slower** for a **~34% smaller** signature.
3. **`robust` vs `simple`:** `simple` is **~1.8x–2.3x faster** at identical
   sizes.

On top of those, the signing path itself was rewritten: every tree is now built
once instead of twice, leaves and hypertree layers build in parallel, the top
layer is cached on the key, and the hot hash paths stopped allocating per call.
**That made all 36 sets 3.29x–7.23x faster (median 4.95x)** — for example
`SHA256-128f-simple` 63.17 → 17.01 ms and `SPHINXHASH-256s-robust`
16,826.48 → 2,330.11 ms. Byte-identity is enforced by `TestGoldenSignatures`
rather than asserted here — with the caveat that the three `SPHINXHASH-*`
goldens were deliberately re-baselined for the branch-`A` change, so those bytes
*did* move (see [Test Suite Results](#test-suite-results)).
`go test -race ./src/crypto/STHINCS/...` (24 functions, 74 subtests) is clean,
including concurrent signing on a shared key.

For this protocol the practical recommendations are:

- **Sign with `SHA256-*-f-simple`** (fastest overall, e.g. `128f-simple`:
  17.01 ms sign, 2.17 ms verify, 7,216 B signature).
- **Use SHAKE256-*-f-simple** if a sponge is required (16.82 ms — statistically
  the same as SHA256).
- **Reserve SPHINXHASH for sets that must carry SIPS-0001 branding**, and keep
  them on `128f`-class parameters so signing stays in the tens of milliseconds
  rather than seconds — and remember their digest bytes changed with the
  branch-`A` re-baseline.
- **Remember that verification is ~16x–702x cheaper than signing**, so
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
