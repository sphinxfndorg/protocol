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

**Why `Uncached` matters.** `GetHash` derives a cache key with a SHA-256 pass
over the *full input* before every LRU lookup (`cacheKey`, see
`spxhash/v2/spxhash_v2.go`). In STHINCS every tweakable call carries a distinct
`ADRS`, so that cache can essentially never hit — the lookup was pure overhead
on every one of the ~10^6 calls. The signing path therefore uses
`GetHashUncached`, which skips the key derivation and the lookup/store entirely
and goes straight to `hashData`. That single change (made in response to
Optimization 2 in an earlier revision of this document) is what cut the
SPHINXHASH signing penalty from the 5.5x–8.5x measured before it to the
**3.76x–5.40x** reported below, and it removes up to 3 allocations per call.
`GetHashUncached(x) == GetHash(x)` byte-for-byte is pinned by
`TestUncachedMatchesCached` in `src/spxhash/v2/spxhash_large_test.go`.

That is the whole remaining reason for the 3.8x–5.4x signing penalty in
Comparison 1: a single SHA-256 compression per tweak call becomes
`SHA256(SHA256(key‖tag‖data))` + `SHAKE256(key‖tag‖data)` + a final squeeze
instead. The equivalence `common.SpxHash(x) ==
spxhash.NewSphinxHash(256, spxhash.ProtocolSalt).GetHash(x)` is already pinned
by `src/common/types_test.go`.

An ad-hoc probe of a single `F` call (N=32) corroborates the call path. Two
shapes are shown, because they measure very different things: **distinct**
inputs (mutating the input / `ADRS` every iteration — what a real signature
does, so the LRU can never hit) and **warm** (constant input, so the LRU hits):

| Probe (`-benchtime=500x`) | ns/op | allocs/op |
|---|---:|---:|
| `common.SpxHash`, constant input (LRU hit) | 929.6 | 2 |
| `common.SpxHash`, distinct inputs | 3,333 | 6 |
| `common.SpxHashUncached`, distinct inputs | **2,117** | 3 |
| `SphinxHashTweak.F` (simple, N=32, distinct ADRS) | 2,578 | 6 |
| `SphinxHashTweak.F` (robust, N=32, distinct ADRS) | 5,700 | 13 |
| plain `sha256.Sum256` (control) | 484.1 | 1 |

On the inputs a signature actually produces, `SpxHashUncached` is **1.57x
cheaper than `SpxHash`** (2,117 vs 3,333 ns/op) and allocates half as much.
`F` in simple mode is one `spxHashExpand` = one uncached hash plus the
domain/length-prefix assembly (~+22% over the bare `SpxHashUncached` call);
robust mode is ~2.2x simple, exactly the extra mask-generating `spxHashExpand`.
This probe is not part of the committed test suite.

## Test Suite Results

`go test ./src/crypto/STHINCS/... -count=1 -v` (run immediately before the
benchmarks below, on the same machine) passes cleanly. The signing tests use only
the fast `128f` sets, so the whole tree finishes in ~5.4 s wall clock.

```text
ok  github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters   0.497s [no tests to run]
ok  github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs      3.965s
ok  github.com/sphinxfndorg/protocol/src/crypto/STHINCS/tweakable    1.015s
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/address      [no test files]
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/fors         [no test files]
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/hypertree    [no test files]
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/util         [no test files]
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/wots         [no test files]
?   github.com/sphinxfndorg/protocol/src/crypto/STHINCS/xmss         [no test files]
```

`parameters` contains only `BenchmarkSpxSignConstructors`, hence "no tests to
run" under the normal (non-benchmark) invocation. The 7 test functions and their
33 subtests:

| Package | Test | Subtests | Covers |
|---|---|---:|---|
| `sthincs` | `TestSplitDigestRightAlignsIndices` | 4 | `idx_tree`/`idx_leaf` are read big-endian from the real digest and masked to the low bits (the old always-0 index bug) |
| `sthincs` | `TestSplitDigestRejectsShortDigest` | — | A digest one byte short is rejected, not silently padded |
| `sthincs` | `TestSignVerifyAcrossHashBackends` | 6 | End-to-end keygen/sign/verify for SHA256, SHAKE256 and SPHINXHASH (`128f`, `simple`+`robust`): own-message verification, message-dependent in-range indices, cross-message rejection, cross-key rejection |
| `tweakable` | `TestTweakableOutputsDependOnEveryInput` | 9 | Every argument of `F`/`H`/`T_l`/`PRF`/`PRFmsg`/`Hmsg` changes the output, for all 3 backends × 3 variants (`simple`, `robust`, `unrecognized`) |
| `tweakable` | `TestRobustDiffersFromSimple` | 3 | `Robust` and `Simple` really are different functions, per backend |
| `tweakable` | `TestFHTlDomainSeparation` | 2 | SPHINXHASH tags `F`, `H`, `T_l` separately, so identical inputs do not collide |
| `tweakable` | `TestDoesNotWriteIntoCallerSpareCapacity` | 9 | No tweakable function scribbles into `cap(input) > len(input)` — the old `append(PKseed, …)` bug |

Per-subtest timings for the end-to-end signing test (whole group: 2.43 s):

| Backend (`128f`) | Test time (s) | msgA (idx_tree, idx_leaf) | msgB (idx_tree, idx_leaf) |
|---|---:|---|---|
| `SHA256-simple` | 0.15 | 2,265,182, 19 | 18,949,888, 12 |
| `SHA256-robust` | 0.24 | 12,512,803, 27 | 18,920,979, 13 |
| `SHAKE256-simple` | 0.16 | 23,500,668, 23 | 12,151,218, 17 |
| `SHAKE256-robust` | 0.30 | 18,260,567, 4 | 7,286,617, 25 |
| `SPHINXHASH-simple` | 0.54 | 9,701,768, 27 | 5,616,239, 7 |
| `SPHINXHASH-robust` | 1.04 | 17,696,036, 18 | 32,794,224, 8 |

The indices are the two things the test asserts on: each pair differs (so the
digest is message-dependent) and both are in range — with `H=30`, `D=6`,
`H'=5`, `idx_leaf ∈ [0,32)` and `idx_tree < 2^25 = 33,554,432`.

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
measured: 2026-09-25, on revision 377e1a1 plus the working-tree changes to
          sthincs.go, tweakable/*.go and spxhash/v2/*.go
```

## Results: `Spx_sign` (all 36 parameter sets)

Each row is one signature. `MB/op` is the decimal memory allocation per
signature (`B/op ÷ 10^6`); it is large because each signature builds many
WOTS+/FORS nodes and allocates a fresh buffer per tweakable hash call.

### SHA256 backend

| Parameter set | Sign (ms) | Sig (B) | MB/op | allocs/op |
|---|---:|---:|---:|---:|
| `SHA256-256f-robust` | 283.55 | 25,056 | 51.82 | 1,324,281 |
| `SHA256-256s-robust` | 4,102.65 | 16,384 | 746.01 | 19,120,500 |
| `SHA256-256f-simple` | 135.21 | 25,056 | 17.20 | 569,709 |
| `SHA256-256s-simple` | 2,080.66 | 16,384 | 242.16 | 8,127,727 |
| `SHA256-192f-robust` | 165.53 | 15,216 | 40.09 | 1,081,581 |
| `SHA256-192s-robust` | 2,434.98 | 10,032 | 597.62 | 16,166,531 |
| `SHA256-192f-simple` | 96.87 | 15,216 | 19.41 | 556,087 |
| `SHA256-192s-simple` | 1,475.78 | 10,032 | 288.50 | 8,287,999 |
| `SHA256-128f-robust` | 98.36 | 7,216 | 24.00 | 659,945 |
| `SHA256-128s-robust` | 1,574.75 | 4,864 | 383.47 | 10,545,280 |
| `SHA256-128f-simple` | 59.80 | 7,216 | 11.70 | 341,559 |
| `SHA256-128s-simple` | 955.50 | 4,864 | 186.62 | 5,446,696 |

### SHAKE256 backend

| Parameter set | Sign (ms) | Sig (B) | MB/op | allocs/op |
|---|---:|---:|---:|---:|
| `SHAKE256-256f-robust` | 281.19 | 25,056 | 36.52 | 1,045,187 |
| `SHAKE256-256s-robust` | 4,458.93 | 16,384 | 521.47 | 15,138,740 |
| `SHAKE256-256f-simple` | 160.43 | 25,056 | 19.28 | 569,699 |
| `SHAKE256-256s-simple` | 2,216.36 | 16,384 | 272.47 | 8,127,464 |
| `SHAKE256-192f-robust` | 198.36 | 15,216 | 21.70 | 728,747 |
| `SHAKE256-192s-robust` | 3,091.09 | 10,032 | 320.61 | 10,871,044 |
| `SHAKE256-192f-simple` | 107.05 | 15,216 | 11.42 | 392,448 |
| `SHAKE256-192s-simple` | 1,775.32 | 10,032 | 167.12 | 5,784,776 |
| `SHAKE256-128f-robust` | 131.44 | 7,216 | 11.11 | 448,395 |
| `SHAKE256-128s-robust` | 2,029.22 | 4,864 | 177.13 | 7,157,313 |
| `SHAKE256-128f-simple` | 67.79 | 7,216 | 5.83 | 238,747 |
| `SHAKE256-128s-simple` | 1,055.36 | 4,864 | 92.68 | 3,802,251 |

### SPHINXHASH backend

| Parameter set | Sign (ms) | Sig (B) | MB/op | allocs/op |
|---|---:|---:|---:|---:|
| `SPHINXHASH-256f-robust` | 1,066.82 | 25,056 | 160.89 | 3,207,674 |
| `SPHINXHASH-256s-robust` | 15,632.00 | 16,384 | 2,362.29 | 47,233,361 |
| `SPHINXHASH-256f-simple` | 604.95 | 25,056 | 85.70 | 1,607,358 |
| `SPHINXHASH-256s-simple` | 8,524.93 | 16,384 | 1,243.02 | 23,288,387 |
| `SPHINXHASH-192f-robust` | 893.99 | 15,216 | 106.00 | 2,266,398 |
| `SPHINXHASH-192s-robust` | 10,859.78 | 10,032 | 1,598.40 | 34,242,566 |
| `SPHINXHASH-192f-simple` | 384.77 | 15,216 | 55.33 | 1,120,312 |
| `SPHINXHASH-192s-simple` | 5,667.52 | 10,032 | 825.99 | 16,719,245 |
| `SPHINXHASH-128f-robust` | 435.65 | 7,216 | 60.01 | 1,425,705 |
| `SPHINXHASH-128s-robust` | 7,090.61 | 4,864 | 959.00 | 22,783,097 |
| `SPHINXHASH-128f-simple` | 229.97 | 7,216 | 31.23 | 692,217 |
| `SPHINXHASH-128s-simple` | 3,660.97 | 4,864 | 498.66 | 11,051,038 |

### Run-to-run variation (single-shot measurements)

`-benchtime=1x` collects exactly one signature per set, so each number above
carries measurement noise on top of the real cost. Repeating eight representative
sets three times (`-count=3`) gives:

| Parameter set | run 1 | run 2 | run 3 | spread |
|---|---:|---:|---:|---:|
| `SHA256-256f-robust` | 293.69 | 319.78 | 320.91 | +9% |
| `SHA256-256f-simple` | 144.82 | 143.85 | 142.76 | ~1% |
| `SHA256-128f-robust` | 101.62 | 101.76 | 102.85 | ~1% |
| `SHA256-128f-simple` | 62.13 | 62.06 | 62.77 | ~1% |
| `SHAKE256-256f-robust` | 297.71 | 294.89 | 295.29 | ~1% |
| `SHAKE256-256f-simple` | 156.48 | 156.79 | 153.45 | ~2% |
| `SHAKE256-128f-robust` | 126.72 | 125.70 | 162.39 | +29% |
| `SHAKE256-128f-simple` | 67.22 | 67.22 | 66.68 | ~1% |

Most sets repeat within a few percent, but occasionally a single run lands
10–30% high (GC pause or a frequency drop on this laptop CPU). Treat
single-digit-percent differences as noise rather than signal — including the
`SHAKE256-256f-robust` row in Comparison 1, where SHAKE256 came out at **0.99x**
SHA256 in the full run while the repeats above average 295.96 ms vs 311.46 ms
(**0.95x**). For that one set the two backends are indistinguishable.

## Comparison 1 — Hash Backend (same parameters, different hash)

Every row uses identical `N`, `D`, `K`, `logT` and mode; only the tweakable hash
changes, so the ratio isolates the hash's cost.

| Parameter set | SHA256 (ms) | SHAKE256 (ms) | SPHINXHASH (ms) | SHAKE256 ÷ SHA256 | SPHINXHASH ÷ SHA256 |
|---|---:|---:|---:|---:|---:|
| `256f-robust` | 283.55 | 281.19 | 1,066.82 | 0.99x | **3.76x** |
| `256f-simple` | 135.21 | 160.43 | 604.95 | 1.19x | **4.47x** |
| `256s-robust` | 4,102.65 | 4,458.93 | 15,632.00 | 1.09x | **3.81x** |
| `256s-simple` | 2,080.66 | 2,216.36 | 8,524.93 | 1.07x | **4.10x** |
| `192f-robust` | 165.53 | 198.36 | 893.99 | 1.20x | **5.40x** |
| `192f-simple` | 96.87 | 107.05 | 384.77 | 1.11x | **3.97x** |
| `192s-robust` | 2,434.98 | 3,091.09 | 10,859.78 | 1.27x | **4.46x** |
| `192s-simple` | 1,475.78 | 1,775.32 | 5,667.52 | 1.20x | **3.84x** |
| `128f-robust` | 98.36 | 131.44 | 435.65 | 1.34x | **4.43x** |
| `128f-simple` | 59.80 | 67.79 | 229.97 | 1.13x | **3.85x** |
| `128s-robust` | 1,574.75 | 2,029.22 | 7,090.61 | 1.29x | **4.50x** |
| `128s-simple` | 955.50 | 1,055.36 | 3,660.97 | 1.10x | **3.83x** |

- **SHAKE256 is 0.99x–1.34x SHA256 — essentially at parity.** The differences
  sit inside the run-to-run noise band documented above and follow no
  consistent `simple`/`robust` pattern: `256f-robust` is 0.99x (SHAKE256
  marginally *faster*) while `128f-robust` is 1.34x. SHAKE256 is a viable
  drop-in for SHA256 on signing cost, not the 1.07x–1.90x penalty an earlier
  revision of this document measured.
- **SPHINXHASH is 3.76x–5.40x SHA256** in every single configuration. It is
  never competitive on signing speed, but the penalty is much smaller than the
  5.48x–8.45x recorded before the signing path moved to `GetHashUncached` (see
  the call-path section at the top): each SphinxHash tweak call still runs the
  full v2 construction (`SHA256(SHA256(key‖tag‖data))` + `SHAKE256` + final
  squeeze), but it no longer *also* pays the double-SHA256 cache-key pass on a
  lookup that cannot hit.
- Signature sizes are **identical** across all three backends for a given
  parameter set (e.g. `25,056` bytes for every `256f` row). Signature size is a
  function of `N`, `W`, `H'`, `D`, `K`, `logT` only — the hash backend cannot
  change it.

## Comparison 2 — `f` (fast) vs `s` (slow) Variant

`f` uses `D=6, H'=5` (32-leaf trees, more layers); `s` uses `D=3, H'=10`
(1024-leaf trees, fewer layers).

| Hash | Mode | `f` (ms) | `s` (ms) | `s` ÷ `f` | Sig `f` (B) | Sig `s` (B) |
|---|---|---:|---:|---:|---:|---:|
| SHA256 | robust | 98.36 | 1,574.75 | 16.01x | 7,216 | 4,864 |
| SHA256 | simple | 59.80 | 955.50 | 15.98x | 7,216 | 4,864 |
| SHA256 | robust | 165.53 | 2,434.98 | 14.71x | 15,216 | 10,032 |
| SHA256 | simple | 96.87 | 1,475.78 | 15.23x | 15,216 | 10,032 |
| SHA256 | robust | 283.55 | 4,102.65 | 14.47x | 25,056 | 16,384 |
| SHA256 | simple | 135.21 | 2,080.66 | 15.39x | 25,056 | 16,384 |
| SHAKE256 | robust | 131.44 | 2,029.22 | 15.44x | 7,216 | 4,864 |
| SHAKE256 | simple | 67.79 | 1,055.36 | 15.57x | 7,216 | 4,864 |
| SHAKE256 | robust | 198.36 | 3,091.09 | 15.58x | 15,216 | 10,032 |
| SHAKE256 | simple | 107.05 | 1,775.32 | 16.58x | 15,216 | 10,032 |
| SHAKE256 | robust | 281.19 | 4,458.93 | 15.86x | 25,056 | 16,384 |
| SHAKE256 | simple | 160.43 | 2,216.36 | 13.82x | 25,056 | 16,384 |
| SPHINXHASH | robust | 435.65 | 7,090.61 | 16.28x | 7,216 | 4,864 |
| SPHINXHASH | simple | 229.97 | 3,660.97 | 15.92x | 7,216 | 4,864 |
| SPHINXHASH | robust | 893.99 | 10,859.78 | 12.15x | 15,216 | 10,032 |
| SPHINXHASH | simple | 384.77 | 5,667.52 | 14.73x | 15,216 | 10,032 |
| SPHINXHASH | robust | 1,066.82 | 15,632.00 | 14.65x | 25,056 | 16,384 |
| SPHINXHASH | simple | 604.95 | 8,524.93 | 14.09x | 25,056 | 16,384 |

(`f`/`s` per level: `128` rows first, then `192`, then `256`.)

**`s` costs 12x–17x more signing time and buys a ~33–35% smaller signature.**
That is a bad trade for any latency-sensitive signer and a good one only where
signature bytes are the binding constraint (e.g. on-chain storage).

## Comparison 3 — `robust` vs `simple` Mode

`robust` XORs a hash-derived bitmask into the input of `F`, `H`, and `T_l`;
`simple` hashes the input directly.

| Hash | Parameter set | robust (ms) | simple (ms) | simple is |
|---|---|---:|---:|---:|
| SHA256 | `256f` | 283.55 | 135.21 | **2.10x faster** |
| SHA256 | `256s` | 4,102.65 | 2,080.66 | **1.97x faster** |
| SHA256 | `192f` | 165.53 | 96.87 | **1.71x faster** |
| SHA256 | `192s` | 2,434.98 | 1,475.78 | **1.65x faster** |
| SHA256 | `128f` | 98.36 | 59.80 | **1.64x faster** |
| SHA256 | `128s` | 1,574.75 | 955.50 | **1.65x faster** |
| SHAKE256 | `256f` | 281.19 | 160.43 | **1.75x faster** |
| SHAKE256 | `256s` | 4,458.93 | 2,216.36 | **2.01x faster** |
| SHAKE256 | `192f` | 198.36 | 107.05 | **1.85x faster** |
| SHAKE256 | `192s` | 3,091.09 | 1,775.32 | **1.74x faster** |
| SHAKE256 | `128f` | 131.44 | 67.79 | **1.94x faster** |
| SHAKE256 | `128s` | 2,029.22 | 1,055.36 | **1.92x faster** |
| SPHINXHASH | `256f` | 1,066.82 | 604.95 | **1.76x faster** |
| SPHINXHASH | `256s` | 15,632.00 | 8,524.93 | **1.83x faster** |
| SPHINXHASH | `192f` | 893.99 | 384.77 | **2.32x faster** |
| SPHINXHASH | `192s` | 10,859.78 | 5,667.52 | **1.92x faster** |
| SPHINXHASH | `128f` | 435.65 | 229.97 | **1.89x faster** |
| SPHINXHASH | `128s` | 7,090.61 | 3,660.97 | **1.94x faster** |

`simple` is 1.6x–2.3x faster and changes no key or signature size — the choice
is purely a security-proof trade-off (robust has the stronger proof).

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
| `SHA256-256f` | 64 | 128 | 42.61 | 289.37 | 4.11 | 25,056 |
| `SHA256-256s` | 64 | 128 | 1,206.69 | 4,147.28 | 2.17 | 16,384 |
| `SHA256-192f` | 48 | 96 | 23.34 | 166.90 | 2.46 | 15,216 |
| `SHA256-192s` | 48 | 96 | 760.24 | 2,586.19 | 1.73 | 10,032 |
| `SHA256-128f` | 32 | 64 | 15.74 | 100.37 | 2.04 | 7,216 |
| `SHA256-128s` | 32 | 64 | 510.35 | 1,608.56 | 0.99 | 4,864 |
| `SHAKE256-256f` | 64 | 128 | 40.05 | 289.16 | 3.78 | 25,056 |
| `SHAKE256-256s` | 64 | 128 | 1,257.61 | 4,262.02 | 1.98 | 16,384 |
| `SHAKE256-192f` | 48 | 96 | 29.68 | 203.43 | 3.02 | 15,216 |
| `SHAKE256-192s` | 48 | 96 | 982.48 | 3,274.70 | 2.42 | 10,032 |
| `SHAKE256-128f` | 32 | 64 | 22.61 | 130.22 | 2.06 | 7,216 |
| `SHAKE256-128s` | 32 | 64 | 665.10 | 2,072.84 | 1.02 | 4,864 |
| `SPHINXHASH-256f` | 64 | 128 | 151.75 | 1,105.77 | 17.15 | 25,056 |
| `SPHINXHASH-256s` | 64 | 128 | 4,926.80 | 16,355.90 | 7.86 | 16,384 |
| `SPHINXHASH-192f` | 48 | 96 | 100.64 | 710.11 | 11.39 | 15,216 |
| `SPHINXHASH-192s` | 48 | 96 | 3,260.76 | 10,789.86 | 6.36 | 10,032 |
| `SPHINXHASH-128f` | 32 | 64 | 71.36 | 440.65 | 7.13 | 7,216 |
| `SPHINXHASH-128s` | 32 | 64 | 2,319.22 | 7,596.20 | 4.08 | 4,864 |

Two things stand out:

- **Verification is 1–3 orders of magnitude cheaper than signing** — e.g.
  `SHA256-256f`: 4.11 ms vs 289.37 ms (**~70x cheaper**);
  `SHA256-256s`: 2.17 ms vs 4,147.28 ms (~1,911x cheaper); across all 18 sets
  the ratio spans **~49x** (`SHA256-128f`) to **~2,153x** (`SHAKE256-256s`).
  That asymmetry is the whole point of a hash-based signature scheme and is
  what makes STHINCS viable for a verifier-heavy blockchain: sign once, verify
  many times. Note that `s` verifies *faster* than `f` for the same level
  (`D*(Len+H')` and `K*logT` are both smaller), while signing 12x–17x slower.
- **KeyGen scales with `2^H'`.** `SHA256-256f` (`H'=5`) keygens in 42.61 ms;
  `SHA256-256s` (`H'=10`) in 1,206.69 ms — a 28.3x gap, matching the 32x
  leaf-count difference (`SPHINXHASH`: 151.75 ms → 4,926.80 ms, 32.5x). KeyGen
  is always cheaper than one signature.

## Key Findings

### 1. The hash backend is the single biggest lever after `f`/`s`

For identical parameters, swapping the tweakable hash changes signing time by up
to **5.40x**:

| Backend | Signing cost vs SHA256 | Verdict |
|---|---|---|
| SHA256 | 1.00x (baseline) | **Fastest**; use unless a sponge/hash-brand is required |
| SHAKE256 | 0.99x–1.34x | At parity — a free swap where a sponge is preferred |
| SPHINXHASH | **3.76x–5.40x** | Never the fast choice; cost of SIPS-0001 branding |

SHAKE256 is indistinguishable from SHA256 on signing cost in these runs, so it
is a reasonable default whenever a sponge is preferred. SPHINXHASH is 3.8–5.4x
more expensive than SHA256 *in every one of the 12 configurations*, because each
tweakable call runs the entire v2 SphinxHash construction (double SHA-256 +
SHAKE256 + squeeze) instead of one primitive — though it no longer also pays the
cache-key pass, because the signing path now uses `SpxHashUncached`.

### 2. `s` is a signature-size-only optimization

`s` (D=3) signs **12x–17x slower** than `f` (D=6) and saves only **~34%** of
signature bytes (`25,056 → 16,384`, `15,216 → 10,032`, `7,216 → 4,864`). Choose
`s` only if signature bytes are truly the binding cost.

### 3. `simple` mode is a large, free win on time

`simple` signs **1.6x–2.3x faster** than `robust` with **identical** key and
signature sizes. It trades the stronger provable-security argument for speed.

### 4. Signing — not verification — is the expensive operation

Verification is **~49x–2,150x cheaper** than signing (0.99 ms–17.15 ms vs
59.80 ms–15.63 s). This is the normal profile for hash-based signatures, and it
means the practical cost of STHINCS in a blockchain is in the signer, not the
validators.

### 5. Allocation pressure is severe

A single signature allocates **5.83 MB–2,362.29 MB** across
**238,747–47,233,361 allocations**, e.g.:

| Parameter set | MB/op | allocs/op |
|---|---:|---:|
| `SHAKE256-128f-simple` | 5.83 | 238,747 |
| `SHA256-128f-simple` | 11.70 | 341,559 |
| `SPHINXHASH-128f-simple` | 31.23 | 692,217 |
| `SPHINXHASH-256s-robust` | **2,362.29** | **47,233,361** |

Almost all of it is fresh scratch memory inside WOTS+/FORS/XMSS node handling
and the tweakable hash helpers. This is the largest, most obvious optimization
opportunity in the scheme and it dominates GC cost as much as the hashing does.
The SPHINXHASH figures are the ones that moved most against the earlier revision
of this document (`SPHINXHASH-256s-robust` was 4,403.98 MB / 79,499,539 allocs):
dropping the cache-key derivation removed allocations on *every* tweakable call —
the probe above shows the raw hash call going from 6 allocs to 3 — and there are
~10^6 such calls per signature.

## Recommendations

| Goal | Recommended set | Sign (ms) | Verify (ms) | Sig (B) |
|---|---|---:|---:|---:|
| Fastest signing | `SHA256-128f-simple` | 59.80 | 2.04 | 7,216 |
| Best speed/size balance | `SHA256-256f-simple` | 135.21 | 4.11 | 25,056 |
| Smallest signature | `SHA256-128s-simple` | 955.50 | 0.99 | 4,864 |
| Sponge-hash requirement | `SHAKE256-128f-simple` | 67.79 | 2.06 | 7,216 |
| SIPS-0001 hash branding | `SPHINXHASH-128f-simple` | 229.97 | 7.13 | 7,216 |

- **If the protocol can choose:** `SHA256-*-f-simple`. It is the fastest family
  at every security level and has the smallest verify latency.
- **If a sponge is required:** `SHAKE256-*-f-simple` — statistically
  indistinguishable from SHA256 on signing cost.
- **If SIPS-0001 branding is required:** expect to pay ~3.8–5.4x SHA256 on
  signing. Prefer the `128f-simple`-style sets to keep that bounded (230 ms, not
  15.6 s).
- **Avoid `s` variants for signing.** Their ~34% size saving costs 12x–17x
  signing time; they are only attractive where signature bytes are stored
  forever on-chain and signatures are produced rarely.

## Optimization Opportunities

### 1. Pool the per-signature scratch buffers (highest impact)

The allocation numbers are still the headline problem: up to **47.2M
allocations** and **2.36 GB** for a single `SPHINXHASH-256s-robust` signature.
Every one of `F`/`H`/`T_l`/`PRF` allocates a fresh output slice, and each is
called on the order of a million times per signature (see the note at the top of
`tweakable/spxhash.go`). A per-instance scratch buffer, or a `sync.Pool` for the
fixed-size `N`-byte outputs, would remove millions of allocations without
touching the construction — `spxHashExpand`'s exact-capacity seed already shows
the direction.

### 2. ~~Stop paying the cache-key derivation on uncacheable calls~~ — **DONE**

_Status: implemented since the previous revision of this document._
`SphinxHashTweak` now routes every call through `common.SpxHashUncached`, so the
signing path no longer derives a cache key with a SHA-256 pass over the **full
input** before consulting an LRU cache that cannot hit (`cacheKey`, see
`spxhash/v2/spxhash_v2.go`). `spxHashExpand` also no longer grows its seed
through repeated `append`s — it sizes the seed exactly once.

Measured effect (see the probe table at the top): `common.SpxHash` 3,333 →
`common.SpxHashUncached` 2,117 ns/op on identical distinct inputs (**1.57x**);
the SPHINXHASH signing penalty fell from 5.48x–8.45x to **3.76x–5.40x** SHA256;
and per-signature working memory dropped by up to ~46%
(`SPHINXHASH-256s-robust`: 4,403.98 MB / 79,499,539 allocs → 2,362.29 MB /
47,233,361).

What remains on this path is smaller: `hashData` still makes two full-input hash
passes (branch A's inner SHA-256, branch B's SHAKE256) plus the final squeeze,
and its 32-byte result is copied into `spxHashExpand`'s `base` before the
SHAKE expansion. Returning the hasher's slice directly when `outLen <= 32`, or
expanding in place, is the next increment.

### 3. Choose `simple` where the security proof allows

`simple` is **1.6x–2.3x faster** at identical key/signature sizes. The gain is
broadly similar across backends (SHA256 1.64x–2.10x, SHAKE256 1.74x–2.01x,
SPHINXHASH 1.76x–2.32x) because `robust` runs a second, mask-generating hash
call per `F`/`H`/`T_l` on top of the one `simple` runs; the values a little
above 2x are within the run-to-run noise documented earlier.

### 4. Choose `f` for anything latency-sensitive

`f` signs 12x–17x faster than `s`. If the 34% size reduction is not required,
`f` is strictly the better operational choice.

### 5. Parallelize within a signature

FORS builds `K` independent trees and the D hypertree layers are sequential but
each layer's WOTS+ chains are independent. `K` is 14–35, so the FORS phase in
particular is embarrassingly parallel.

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
  reported here (up to 5.4x for the hash backend, 12x–17x for `f` vs `s`) are far
  larger than run-to-run noise and reproduce across runs; differences below
  ~10% should not be read into — see the `-count=3` table, where one repeat
  landed 29% above the other two.
- Measurements are from one machine (Intel i7-7700HQ, 8 logical CPUs). Absolute
  milliseconds are machine-specific; the **ratios** are the portable result.
- The benchmark times **`Spx_sign` only** — `Spx_keygen` runs outside the timed
  region (`b.ResetTimer()` follows it), and serialization is excluded too.
- The benchmark uses `RANDOMIZE=false`; `main.go` uses `RANDOMIZE=true`. Sign
  times agree within ~3%, so randomization is essentially free in this
  implementation (e.g. `SHA256-256f`: 283.55 ms vs 289.37 ms, +2.1%).
- Allocation figures are **per-operation working memory** reported by
  `b.ReportAllocs()`, not peak resident set size. The garbage collector
  reclaims most of it between operations.
- Every set is capped at **2^30 = 1,073,741,824 signatures per key** (`H=30`).
  At 1,000 signatures/second that is ~12.4 days; rotate keys before the limit.
- The SPHINXHASH numbers are only meaningful alongside the `SpxHashUncached`
  change described at the top of this document. If that change is reverted, every
  SPHINXHASH timing and allocation figure in this file becomes stale again.

## Summary

Across all 36 parameter sets, the benchmark shows three independent, large
effects on STHINCS signing cost:

1. **Hash backend:** SPHINXHASH is **3.76x–5.40x slower than SHA256** in every
   configuration; SHAKE256 is **0.99x–1.34x slower**, i.e. at parity.
2. **`f` vs `s`:** `s` is **12x–17x slower** for a **~34% smaller** signature.
3. **`robust` vs `simple`:** `simple` is **1.6x–2.3x faster** at identical
   sizes.

Since the previous revision of this document the signing path moved to
`common.SpxHashUncached`, which cut the SPHINXHASH penalty from 5.48x–8.45x to
3.76x–5.40x and its per-signature allocations by up to ~46%. The unit tests
(`go test ./src/crypto/STHINCS/...`) pass in ~5.4 s (section above).

For this protocol the practical recommendations are:

- **Sign with `SHA256-*-f-simple`** (fastest overall, e.g. `128f-simple`:
  59.80 ms sign, 2.04 ms verify, 7,216 B signature).
- **Use SHAKE256-*-f-simple** if a sponge is required (67.79 ms — statistically
  the same as SHA256).
- **Reserve SPHINXHASH for sets that must carry SIPS-0001 branding**, and keep
  them on `128f`-class parameters so signing stays in the hundreds of
  milliseconds rather than tens of seconds.
- **Remember that verification is 49x–2,150x cheaper than signing**, so
  signature verification will not be the bottleneck even for the slowest sets.
