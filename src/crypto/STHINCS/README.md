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
single-signature timings on a machine where a full signature can take tens of
seconds. One signature per set is intentional — a higher `-benchtime` would take
hours for the `s` and `SPHINXHASH` sets.

Because each sub-benchmark is a single measurement, treat the numbers as
**order-of-magnitude comparisons**, not as tight micro-benchmarks. The
relative differences between hashes and between variants are large (5x–17x) and
reproducible; small differences (below ~10%) are within run-to-run noise.

### Measured Environment

```text
goos: darwin
goarch: amd64
cpu: Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz (8 logical CPUs)
go: go1.27.1 darwin/amd64
RANDOMIZE=false (benchmark calls tc.make(false))
```

## Results: `Spx_sign` (all 36 parameter sets)

Each row is one signature. `MB/op` is the decimal memory allocation per
signature (`B/op ÷ 10^6`); it is large because each signature builds many
WOTS+/FORS nodes and allocates a fresh buffer per tweakable hash call.

### SHA256 backend

| Parameter set | Sign (ms) | Sig (B) | MB/op | allocs/op |
|---|---:|---:|---:|---:|
| `SHA256-256f-robust` | 285.55 | 25,056 | 51.81 | 1,324,132 |
| `SHA256-256s-robust` | 4,153.57 | 16,384 | 746.00 | 19,120,279 |
| `SHA256-256f-simple` | 137.07 | 25,056 | 17.20 | 569,672 |
| `SHA256-256s-simple` | 1,989.42 | 16,384 | 242.15 | 8,127,580 |
| `SHA256-192f-robust` | 164.81 | 15,216 | 40.08 | 1,081,409 |
| `SHA256-192s-robust` | 2,478.69 | 10,032 | 597.62 | 16,166,533 |
| `SHA256-192f-simple` | 103.45 | 15,216 | 19.41 | 556,084 |
| `SHA256-192s-simple` | 1,490.10 | 10,032 | 288.49 | 8,287,823 |
| `SHA256-128f-robust` | 104.84 | 7,216 | 24.01 | 660,206 |
| `SHA256-128s-robust` | 1,610.55 | 4,864 | 383.48 | 10,545,550 |
| `SHA256-128f-simple` | 64.80 | 7,216 | 11.70 | 341,474 |
| `SHA256-128s-simple` | 980.70 | 4,864 | 186.62 | 5,446,748 |

### SHAKE256 backend

| Parameter set | Sign (ms) | Sig (B) | MB/op | allocs/op |
|---|---:|---:|---:|---:|
| `SHAKE256-256f-robust` | 435.96 | 25,056 | 94.84 | 1,045,247 |
| `SHAKE256-256s-robust` | 6,493.47 | 16,384 | 1,373.94 | 15,138,955 |
| `SHAKE256-256f-simple` | 153.09 | 25,056 | 19.28 | 569,644 |
| `SHAKE256-256s-simple` | 2,471.95 | 16,384 | 272.48 | 8,127,538 |
| `SHAKE256-192f-robust` | 297.44 | 15,216 | 52.33 | 728,634 |
| `SHAKE256-192s-robust` | 4,700.58 | 10,032 | 781.06 | 10,871,064 |
| `SHAKE256-192f-simple` | 111.30 | 15,216 | 11.42 | 392,302 |
| `SHAKE256-192s-simple` | 1,646.49 | 10,032 | 167.11 | 5,784,713 |
| `SHAKE256-128f-robust` | 134.70 | 7,216 | 23.87 | 448,382 |
| `SHAKE256-128s-robust` | 2,314.22 | 4,864 | 381.22 | 7,157,269 |
| `SHAKE256-128f-simple` | 70.55 | 7,216 | 5.83 | 238,708 |
| `SHAKE256-128s-simple` | 1,051.30 | 4,864 | 92.68 | 3,802,204 |

### SPHINXHASH backend

| Parameter set | Sign (ms) | Sig (B) | MB/op | allocs/op |
|---|---:|---:|---:|---:|
| `SPHINXHASH-256f-robust` | 1,751.61 | 25,056 | 298.41 | 5,388,791 |
| `SPHINXHASH-256s-robust` | 24,573.04 | 16,384 | 4,403.98 | 79,499,539 |
| `SPHINXHASH-256f-simple` | 1,158.50 | 25,056 | 175.60 | 2,872,898 |
| `SPHINXHASH-256s-simple` | 13,002.94 | 16,384 | 2,573.20 | 41,871,587 |
| `SPHINXHASH-192f-robust` | 1,189.46 | 15,216 | 202.59 | 3,993,343 |
| `SPHINXHASH-192s-robust` | 16,773.14 | 10,032 | 3,064.38 | 60,429,263 |
| `SPHINXHASH-192f-simple` | 610.20 | 15,216 | 104.89 | 2,031,016 |
| `SPHINXHASH-192s-simple` | 8,742.21 | 10,032 | 1,571.10 | 30,391,115 |
| `SPHINXHASH-128f-robust` | 689.14 | 7,216 | 118.22 | 2,515,475 |
| `SPHINXHASH-128s-robust` | 11,025.92 | 4,864 | 1,890.38 | 40,222,441 |
| `SPHINXHASH-128f-simple` | 355.13 | 7,216 | 63.51 | 1,259,404 |
| `SPHINXHASH-128s-simple` | 5,839.18 | 4,864 | 1,014.48 | 20,112,055 |

## Comparison 1 — Hash Backend (same parameters, different hash)

Every row uses identical `N`, `D`, `K`, `logT` and mode; only the tweakable hash
changes, so the ratio isolates the hash's cost.

| Parameter set | SHA256 (ms) | SHAKE256 (ms) | SPHINXHASH (ms) | SHAKE256 ÷ SHA256 | SPHINXHASH ÷ SHA256 |
|---|---:|---:|---:|---:|---:|
| `256f-robust` | 285.55 | 435.96 | 1,751.61 | 1.53x | **6.13x** |
| `256f-simple` | 137.07 | 153.09 | 1,158.50 | 1.12x | **8.45x** |
| `256s-robust` | 4,153.57 | 6,493.47 | 24,573.04 | 1.56x | **5.92x** |
| `256s-simple` | 1,989.42 | 2,471.95 | 13,002.94 | 1.24x | **6.54x** |
| `192f-robust` | 164.81 | 297.44 | 1,189.46 | 1.80x | **7.22x** |
| `192f-simple` | 103.45 | 111.30 | 610.20 | 1.08x | **5.90x** |
| `192s-robust` | 2,478.69 | 4,700.58 | 16,773.14 | 1.90x | **6.77x** |
| `192s-simple` | 1,490.10 | 1,646.49 | 8,742.21 | 1.10x | **5.87x** |
| `128f-robust` | 104.84 | 134.70 | 689.14 | 1.28x | **6.57x** |
| `128f-simple` | 64.80 | 70.55 | 355.13 | 1.09x | **5.48x** |
| `128s-robust` | 1,610.55 | 2,314.22 | 11,025.92 | 1.44x | **6.85x** |
| `128s-simple` | 980.70 | 1,051.30 | 5,839.18 | 1.07x | **5.95x** |

- **SHAKE256 is 1.07x–1.90x SHA256.** The penalty is smallest in `simple` mode
  (1.07x–1.24x) and largest in `robust` mode (1.28x–1.90x), because `robust`
  adds a second, mask-generating hash call per `F`/`H`/`T_l` invocation and
  that extra call is relatively more expensive for the sponge.
- **SPHINXHASH is 5.48x–8.45x SHA256** in every single configuration. It is
  never competitive on signing speed. Each SphinxHash tweak call runs the full
  v2 construction (`SHA256(SHA256(key‖tag‖data))` + `SHAKE256` + final
  squeeze) plus a double-SHA256 cache-key derivation, so it replaces one cheap
  primitive with several.
- Signature sizes are **identical** across all three backends for a given
  parameter set (e.g. `25,056` bytes for every `256f` row). Signature size is a
  function of `N`, `W`, `H'`, `D`, `K`, `logT` only — the hash backend cannot
  change it.

## Comparison 2 — `f` (fast) vs `s` (slow) Variant

`f` uses `D=6, H'=5` (32-leaf trees, more layers); `s` uses `D=3, H'=10`
(1024-leaf trees, fewer layers).

| Hash | Mode | `f` (ms) | `s` (ms) | `s` ÷ `f` | Sig `f` (B) | Sig `s` (B) |
|---|---|---:|---:|---:|---:|---:|
| SHA256 | robust | 104.84 | 1,610.55 | 15.36x | 7,216 | 4,864 |
| SHA256 | simple | 64.80 | 980.70 | 15.13x | 7,216 | 4,864 |
| SHA256 | robust | 164.81 | 2,478.69 | 15.04x | 15,216 | 10,032 |
| SHA256 | simple | 103.45 | 1,490.10 | 14.40x | 15,216 | 10,032 |
| SHA256 | robust | 285.55 | 4,153.57 | 14.55x | 25,056 | 16,384 |
| SHA256 | simple | 137.07 | 1,989.42 | 14.51x | 25,056 | 16,384 |
| SHAKE256 | robust | 134.70 | 2,314.22 | 17.18x | 7,216 | 4,864 |
| SHAKE256 | simple | 70.55 | 1,051.30 | 14.90x | 7,216 | 4,864 |
| SHAKE256 | robust | 297.44 | 4,700.58 | 15.80x | 15,216 | 10,032 |
| SHAKE256 | simple | 111.30 | 1,646.49 | 14.79x | 15,216 | 10,032 |
| SHAKE256 | robust | 435.96 | 6,493.47 | 14.90x | 25,056 | 16,384 |
| SHAKE256 | simple | 153.09 | 2,471.95 | 16.15x | 25,056 | 16,384 |
| SPHINXHASH | robust | 689.14 | 11,025.92 | 16.00x | 7,216 | 4,864 |
| SPHINXHASH | simple | 355.13 | 5,839.18 | 16.44x | 7,216 | 4,864 |
| SPHINXHASH | robust | 1,189.46 | 16,773.14 | 14.10x | 15,216 | 10,032 |
| SPHINXHASH | simple | 610.20 | 8,742.21 | 14.33x | 15,216 | 10,032 |
| SPHINXHASH | robust | 1,751.61 | 24,573.04 | 14.03x | 25,056 | 16,384 |
| SPHINXHASH | simple | 1,158.50 | 13,002.94 | 11.22x | 25,056 | 16,384 |

(`f`/`s` per level: `128` rows first, then `192`, then `256`.)

**`s` costs 11x–17x more signing time and buys a ~33–35% smaller signature.**
That is a bad trade for any latency-sensitive signer and a good one only where
signature bytes are the binding constraint (e.g. on-chain storage).

## Comparison 3 — `robust` vs `simple` Mode

`robust` XORs a hash-derived bitmask into the input of `F`, `H`, and `T_l`;
`simple` hashes the input directly.

| Hash | Parameter set | robust (ms) | simple (ms) | simple is |
|---|---|---:|---:|---:|
| SHA256 | `256f` | 285.55 | 137.07 | **2.08x faster** |
| SHA256 | `256s` | 4,153.57 | 1,989.42 | **2.09x faster** |
| SHA256 | `192f` | 164.81 | 103.45 | **1.59x faster** |
| SHA256 | `192s` | 2,478.69 | 1,490.10 | **1.66x faster** |
| SHA256 | `128f` | 104.84 | 64.80 | **1.62x faster** |
| SHA256 | `128s` | 1,610.55 | 980.70 | **1.64x faster** |
| SHAKE256 | `256f` | 435.96 | 153.09 | **2.85x faster** |
| SHAKE256 | `256s` | 6,493.47 | 2,471.95 | **2.63x faster** |
| SHAKE256 | `192f` | 297.44 | 111.30 | **2.67x faster** |
| SHAKE256 | `192s` | 4,700.58 | 1,646.49 | **2.85x faster** |
| SHAKE256 | `128f` | 134.70 | 70.55 | **1.91x faster** |
| SHAKE256 | `128s` | 2,314.22 | 1,051.30 | **2.20x faster** |
| SPHINXHASH | `256f` | 1,751.61 | 1,158.50 | **1.51x faster** |
| SPHINXHASH | `256s` | 24,573.04 | 13,002.94 | **1.89x faster** |
| SPHINXHASH | `192f` | 1,189.46 | 610.20 | **1.95x faster** |
| SPHINXHASH | `192s` | 16,773.14 | 8,742.21 | **1.92x faster** |
| SPHINXHASH | `128f` | 689.14 | 355.13 | **1.94x faster** |
| SPHINXHASH | `128s` | 11,025.92 | 5,839.18 | **1.89x faster** |

`simple` is 1.5x–2.9x faster and changes no key or signature size — the choice
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
| `SHA256-256f` | 64 | 128 | 38.74 | 273.43 | 3.52 | 25,056 |
| `SHA256-256s` | 64 | 128 | 1,152.31 | 4,436.08 | 2.58 | 16,384 |
| `SHA256-192f` | 48 | 96 | 27.03 | 170.00 | 2.94 | 15,216 |
| `SHA256-192s` | 48 | 96 | 936.18 | 2,376.72 | 1.52 | 10,032 |
| `SHA256-128f` | 32 | 64 | 15.38 | 97.60 | 1.56 | 7,216 |
| `SHA256-128s` | 32 | 64 | 494.63 | 1,653.26 | 1.09 | 4,864 |
| `SHAKE256-256f` | 64 | 128 | 55.30 | 415.51 | 6.62 | 25,056 |
| `SHAKE256-256s` | 64 | 128 | 1,759.73 | 6,320.54 | 3.89 | 16,384 |
| `SHAKE256-192f` | 48 | 96 | 40.80 | 286.83 | 5.13 | 15,216 |
| `SHAKE256-192s` | 48 | 96 | 1,311.60 | 4,271.04 | 2.93 | 10,032 |
| `SHAKE256-128f` | 32 | 64 | 20.35 | 126.59 | 2.11 | 7,216 |
| `SHAKE256-128s` | 32 | 64 | 649.71 | 2,033.42 | 1.13 | 4,864 |
| `SPHINXHASH-256f` | 64 | 128 | 210.49 | 1,562.15 | 22.11 | 25,056 |
| `SPHINXHASH-256s` | 64 | 128 | 6,711.49 | 23,000.43 | 10.45 | 16,384 |
| `SPHINXHASH-192f` | 48 | 96 | 152.62 | 1,064.12 | 16.74 | 15,216 |
| `SPHINXHASH-192s` | 48 | 96 | 4,909.28 | 16,113.03 | 9.06 | 10,032 |
| `SPHINXHASH-128f` | 32 | 64 | 107.12 | 671.21 | 11.65 | 7,216 |
| `SPHINXHASH-128s` | 32 | 64 | 3,895.46 | 10,632.99 | 6.37 | 4,864 |

Two things stand out:

- **Verification is 1–3 orders of magnitude cheaper than signing** — e.g.
  `SHA256-256f`: 3.52 ms vs 273.43 ms (**~78x cheaper**);
  `SHA256-256s`: 2.58 ms vs 4,436.08 ms (~1,719x cheaper). That asymmetry is
  the whole point of a hash-based signature scheme and is what makes STHINCS
  viable for a verifier-heavy blockchain: sign once, verify many times.
  Note that `s` verifies *faster* than `f` for the same level (`D*(Len+H')`
  and `K*logT` are both smaller), while signing 11x–17x slower.
- **KeyGen scales with `2^H'`.** `256f` (`H'=5`) keygens in 38.74 ms;
  `256s` (`H'=10`) in 1,152.31 ms — a 29.7x gap, matching the 32x leaf-count
  difference. KeyGen is always cheaper than one signature.

## Key Findings

### 1. The hash backend is the single biggest lever after `f`/`s`

For identical parameters, swapping the tweakable hash changes signing time by up
to **8.45x**:

| Backend | Signing cost vs SHA256 | Verdict |
|---|---|---|
| SHA256 | 1.00x (baseline) | **Fastest**; use unless a sponge/hash-brand is required |
| SHAKE256 | 1.07x–1.90x | Small, predictable penalty; `simple` mode is nearly free |
| SPHINXHASH | **5.48x–8.45x** | Never the fast choice; cost of SIPS-0001 branding |

SHAKE256 is cheap enough to be a reasonable default when a sponge is preferred.
SPHINXHASH is 5–8x more expensive than SHA256 *in every one of the 12
configurations*, because each tweakable call runs the entire v2 SphinxHash
construction (double SHA-256 + SHAKE256 + squeeze + double-SHA256 cache key)
instead of one primitive.

### 2. `s` is a signature-size-only optimization

`s` (D=3) signs **11x–17x slower** than `f` (D=6) and saves only **~34%** of
signature bytes (`25,056 → 16,384`, `15,216 → 10,032`, `7,216 → 4,864`). Choose
`s` only if signature bytes are truly the binding cost.

### 3. `simple` mode is a large, free win on time

`simple` signs **1.5x–2.9x faster** than `robust` with **identical** key and
signature sizes. It trades the stronger provable-security argument for speed.

### 4. Signing — not verification — is the expensive operation

Verification is **~70x–1,700x cheaper** than signing (1.09 ms–22.11 ms vs
64.80 ms–24.57 s). This is the normal profile for hash-based signatures, and it
means the practical cost of STHINCS in a blockchain is in the signer, not the
validators.

### 5. Allocation pressure is severe

A single signature allocates **11.70 MB–4,403.98 MB** across **341,474–79,499,539
allocations**, e.g.:

| Parameter set | MB/op | allocs/op |
|---|---:|---:|
| `SHA256-128f-simple` | 11.70 | 341,474 |
| `SHA256-256s-robust` | 746.00 | 19,120,279 |
| `SPHINXHASH-256s-robust` | **4,403.98** | **79,499,539** |

Almost all of it is fresh scratch memory inside WOTS+/FORS/XMSS node handling
and the tweakable hash helpers. This is the largest, most obvious optimization
opportunity in the scheme and it dominates GC cost as much as the hashing does.

## Recommendations

| Goal | Recommended set | Sign (ms) | Verify (ms) | Sig (B) |
|---|---|---:|---:|---:|
| Fastest signing | `SHA256-128f-simple` | 64.80 | 1.09 | 7,216 |
| Best speed/size balance | `SHA256-256f-simple` | 137.07 | 3.52 | 25,056 |
| Smallest signature | `SHA256-128s-simple` | 980.70 | 1.09 | 4,864 |
| Sponge-hash requirement | `SHAKE256-128f-simple` | 70.55 | 2.11 | 7,216 |
| SIPS-0001 hash branding | `SPHINXHASH-128f-simple` | 355.13 | 11.65 | 7,216 |

- **If the protocol can choose:** `SHA256-*-f-simple`. It is the fastest family
  at every security level and has the smallest verify latency.
- **If a sponge is required:** `SHAKE256-*-f-simple` — within ~10% of SHA256 in
  `simple` mode.
- **If SIPS-0001 branding is required:** expect to pay ~5–8x SHA256 on signing.
  Prefer the `128f-simple`-style sets to keep that bounded (355 ms, not 24 s).
- **Avoid `s` variants for signing.** Their ~34% size saving costs 11x–17x
  signing time; they are only attractive where signature bytes are stored
  forever on-chain and signatures are produced rarely.

## Optimization Opportunities

### 1. Pool the per-signature scratch buffers (highest impact)

The allocation numbers are the headline problem: up to **79.5M allocations** and
**4.4 GB** for a single `SPHINXHASH-256s-robust` signature. Every one of
`F`/`H`/`T_l`/`PRF` allocates a fresh output slice, and each is called on the
order of a million times per signature (see the call-frequency note at the top
of `tweakable/spxhash.go`). A per-instance scratch buffer, or a `sync.Pool` for
the fixed-size `N`-byte outputs, would remove millions of allocations without
touching the construction.

### 2. Stop paying the cache-key derivation on uncacheable calls

`SphinxHashTweak` routes every call through `common.SpxHash`, which derives a
cache key with a SHA-256 pass over the **full input** *before* consulting its
LRU cache (`cacheKey`, see `spxhash/v2/spxhash_v2.go`). In STHINCS every call
carries a distinct `ADRS`, so that cache essentially never hits — yet the pass
is paid anyway. Since `hashData` adds one more full-input SHA-256 pass plus one
full-input SHAKE256 pass, **roughly a third of the full-input hashing on this
path is spent on a lookup that cannot succeed.** A no-cache entry point for
known-unique inputs would cut SphinxHash-backed signing substantially, and the
same 5.48x–8.45x penalty would shrink.

### 3. Choose `simple` where the security proof allows

`simple` is **1.5x–2.9x faster** at identical key/signature sizes. SPHINXHASH
gains the least (1.51x–1.95x) because its fixed per-call cost dominates.

### 4. Choose `f` for anything latency-sensitive

`f` signs 11x–17x faster than `s`. If the 34% size reduction is not required,
`f` is strictly the better operational choice.

### 5. Parallelize within a signature

FORS builds `K` independent trees and the D hypertree layers are sequential but
each layer's WOTS+ chains are independent. `K` is 14–35, so the FORS phase in
particular is embarrassingly parallel.

## Reproduction

```bash
# All 36 sets, one signature each (~5 minutes wall clock; individual
# SPHINXHASH-256s signatures take ~25 s)
go test -bench=BenchmarkSpxSignConstructors -benchtime=1x -run='^$' \
  ./src/crypto/STHINCS/parameters/

# One hash family only (SHA256 | SHAKE256 | SPHINXHASH)
go test -bench='BenchmarkSpxSignConstructors/SHA256' -benchtime=1x -run='^$' \
  ./src/crypto/STHINCS/parameters/

# Full lifecycle table (KeyGen/Sign/Verify + PK/SK/Sig sizes), 18 robust sets
go run ./src/crypto/STHINCS
```

## Notes & Caveats

- **`-benchtime=1x` is a single measurement per set.** The 5x–17x effects
  reported here are far larger than run-to-run noise and reproduce across runs;
  differences below ~10% should not be read into.
- Measurements are from one machine (Intel i7-7700HQ, 8 logical CPUs). Absolute
  milliseconds are machine-specific; the **ratios** are the portable result.
- The benchmark times **`Spx_sign` only** — `Spx_keygen` runs outside the timed
  region (`b.ResetTimer()` follows it), and serialization is excluded too.
- The benchmark uses `RANDOMIZE=false`; `main.go` uses `RANDOMIZE=true`. Sign
  times agree within ~5%, so randomization is essentially free in this
  implementation.
- Allocation figures are **per-operation working memory** reported by
  `b.ReportAllocs()`, not peak resident set size. The garbage collector
  reclaims most of it between operations.
- Every set is capped at **2^30 = 1,073,741,824 signatures per key** (`H=30`).
  At 1,000 signatures/second that is ~12.4 days; rotate keys before the limit.

## Summary

Across all 36 parameter sets, the benchmark shows three independent, large
effects on STHINCS signing cost:

1. **Hash backend:** SPHINXHASH is **5.48x–8.45x slower than SHA256** in every
   configuration; SHAKE256 is only **1.07x–1.90x slower**, and nearly free in
   `simple` mode alongside SHA256.
2. **`f` vs `s`:** `s` is **11x–17x slower** for a **~34% smaller** signature.
3. **`robust` vs `simple`:** `simple` is **1.5x–2.9x faster** at identical
   sizes.

For this protocol the practical recommendations are:

- **Sign with `SHA256-*-f-simple`** (fastest overall, e.g. `128f-simple`:
  64.80 ms sign, 1.09 ms verify, 7,216 B signature).
- **Use SHAKE256-*-f-simple** if a sponge is required (70.55 ms — within 10%).
- **Reserve SPHINXHASH for sets that must carry SIPS-0001 branding**, and keep
  them on `128f`-class parameters so signing stays in the hundreds of
  milliseconds rather than tens of seconds.
- **Remember that verification is 70x–1,700x cheaper than signing**, so
  signature verification will not be the bottleneck even for the slowest sets.
