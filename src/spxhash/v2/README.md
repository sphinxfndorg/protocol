# SpxHash v2 Benchmark Analysis

## Overview

This document records the SpxHash **v2** test-vector output and the benchmark
comparison against SHA-512/256.

v2 is a deliberate speed/weight redesign of v1 with a **narrowed threat model**:

- **Kept:** length-extension resistance and collision resistance that survives
  a break in either SHA-512/256 or SHAKE256 (concatenation combiner).
- **Removed:** Argon2id key derivation and the 1000-round SHAKE256 mixing loop.
  Pre-image resistance under a memory-hard KDF is explicitly out of scope.
- **Changed (branch `A`):** the earlier v2 draft used a Bitcoin-style *double
  SHA-256* for branch `A`; this build uses a single **SHA-512/256** call. That
  removes one pass over the payload and changes every digest.
- **Bumped:** `ProtocolSalt` is `"sphinx-protocol-hash-v2"`, so v1 and v2 nodes
  can never silently agree on the wrong digest. This is a breaking,
  consensus-critical change.

The construction is three fast hash calls per digest:

```text
A   = SHA512/256(key || 0x01 || data)          // 32 bytes, one pass
B   = SHAKE256(key || 0x02 || data), 32 bytes  // independent of A
out = SHAKE256(0x03 || A || B), Size() bytes
```

Inputs larger than 1 MiB are first compressed to a 64-byte prehash,
`SHA512/256(key || 0x10 || data) || SHAKE256(key || 0x13 || data)`, then run
through the same construction under different tags (`0x11`/`0x12`) so a large
input can never alias the small input equal to its prehash.

**Bottom line: SpxHash v2 is slower than SHA-512/256 for every input size
measured here *when it actually hashes*.** A single cold digest costs roughly
**3.0x–5.4x** a SHA-512/256 digest (the uncached, long-lived-instance path is
**~2.7x–4.0x**). v2 pays for its dual-primitive collision resistance and
length-extension resistance with CPU time, and it does that on purpose. What it
does *not* pay is Argon2 latency, and — since the LRU key changed from a double
SHA-256 to a seeded `maphash` — a **repeated** digest is now served from cache
*faster* than SHA-512/256. See
[Cached vs uncached](#cached-vs-uncached-read-this-before-comparing-to-sthincs)
for why those two facts are both true and do not conflict.

## Test Command

```bash
go test -v -bench=. -benchtime=2s -cpuprofile=cpu.prof
```

The captured run (`testvc/test_output.log`) completed successfully:

```text
--- PASS: TestVectors (0.00s)
--- PASS: TestRandomSaltNonDeterminism (0.00s)
--- PASS: TestFixedSaltDeterminism (0.00s)
--- PASS: TestDifferentBitSizes (0.00s)
--- PASS: BenchmarkSpxHash
--- PASS: BenchmarkSpxHashCached
--- PASS: BenchmarkSpxHashUncached
--- PASS: BenchmarkSHA512_256
PASS
ok      github.com/sphinxfndorg/protocol/src/spxhash/v2/testvc    67.791s
```

Tests and benchmarks both ran, and the pins in the vector table in
`testvc/spxhash_v2_test.go` were asserted (not just printed) — see
[Test Vectors](#test-vectors). The table numbers below come from a separate
best-of-3 `-count=3` measurement, since single runs on this machine vary by up
to ~30%.

## Test Vectors

These are the pinned, asserted vectors from `testvc/spxhash_v2_test.go`
(bitSize 256, fixed salt `SPXHASH_TEST_VECTOR_SALT_2024`, input pattern
`i % 251`). They differ from v1 for the same input by design.

| Input Length | Hash |
|---:|---|
| 0 | `95137d3704f1dcdab0e3554e9aa69e9f0bc11cc80b3115a184a10e4a206d6ea9` |
| 1 | `8056e9fefb4abb330b9abdb140a4078429aa26cbc723eedbfdd085cc4325e520` |
| 1023 | `695ca40f30c64ec1cd9e63c0f826706d307bb5dff549b9d3c5727e268ec5f5ea` |
| 1024 | `d87ca72102aedae10889f7e0425f62930463752481c4d8a48a36e1c937854f57` |
| 2048 | `0ec378cb0b9584412038f88348c19ea9fe703af96b45cfa2907f2a5f0e64a902` |
| 4096 | `0b7e69435fee14f84379ae2ea3a1d7748ffcae9db7d0e09ef6d78ec5354c7443` |

Note the v1 <-> v2 difference for the length-0 input:

| Version | inputLen=0 hash |
|---|---|
| v1 | `56e5cb4244edd633a76ea4a63ab21ac7590e8773b4e23baac7cbc7135b035297` |
| v2 (double-SHA-256 draft) | `9e9bc2e34f1d3da65fdb52b36c80918fee908bf367cfdbdc6dc87988a26acba5` |
| v2 (this build, SHA-512/256 branch `A`) | `95137d3704f1dcdab0e3554e9aa69e9f0bc11cc80b3115a184a10e4a206d6ea9` |

The two v2 rows exist because branch `A` was rewritten from a double SHA-256 to
a single SHA-512/256; any vector, golden signature, or stored hash produced by
the earlier draft must be regenerated.

## Structured Vector Output

```text
<vector inputLen=0 hash=95137d3704f1dcdab0e3554e9aa69e9f0bc11cc80b3115a184a10e4a206d6ea9 keyedHash=c098615604bb025f47999595c04e030f364e5435a7577d7ababb03a271e9989e deriveKey=be538a2f83a53f6d4665e56557f43acf90ba82f97fa5d7bf746be24370054ca0>
<vector inputLen=1 hash=8056e9fefb4abb330b9abdb140a4078429aa26cbc723eedbfdd085cc4325e520 keyedHash=ea27697ab40a291b93dc90c1618337974d06462882918405420871911fcb29ec deriveKey=be538a2f83a53f6d4665e56557f43acf90ba82f97fa5d7bf746be24370054ca0>
<vector inputLen=1023 hash=695ca40f30c64ec1cd9e63c0f826706d307bb5dff549b9d3c5727e268ec5f5ea keyedHash=8002a9d0715ee58d3e796d0a2474c7eaefb5d38544d2e7ca4e1c636b9e2ddfce deriveKey=3e9251161692adb640c8dd76685c50c048297fe3360828e16c912f429c397bab>
<vector inputLen=1024 hash=d87ca72102aedae10889f7e0425f62930463752481c4d8a48a36e1c937854f57 keyedHash=a5e689a6065c86606c29be00b70d9fb777ef8273c212a8caa574dd51dd39a714 deriveKey=353ff083ae5cbbe9ccb806be665e3136ebd78bfb3fe82103b249934127a53f9f>
<vector inputLen=2048 hash=0ec378cb0b9584412038f88348c19ea9fe703af96b45cfa2907f2a5f0e64a902 keyedHash=1b8dbedc8bb976b4a5b5eae089397f6c0db4f3ece3159b917774ee6e2a26d6d1 deriveKey=7f9ea132acaf84f492804b9dc11f0e08f8fa38907394ea9a1094b52568eb0acf>
<vector inputLen=4096 hash=0b7e69435fee14f84379ae2ea3a1d7748ffcae9db7d0e09ef6d78ec5354c7443 keyedHash=950c63a2454e97c3a12e78804c23c65944436b53b1f513fbf72d874f22446995 deriveKey=3c4416bedf98988efd9a0ce301d7317c4548d95514e680d334727ab98167ae00>
```

`keyedHash` (raw HMAC-SHA-512/256) and `deriveKey` (raw HKDF-SHA-512/256) are
computed directly against `testVectorKey`/`testVectorContext` in the test
driver, independent of the `spxhash` package, so they are unaffected by the v2
redesign and match the v1 values byte-for-byte.

## Benchmark Results

Final high-iteration rows only. Early rows with `b.N = 1`, `100`, or `10000`
are warm-up/calibration runs and are ignored. `SpxHash (cold)` creates a fresh
instance per op (worst case, empty LRU cache); `SpxHash (cached)` reuses one
instance for the same input so the digest is served from its LRU cache.

### Current measurement (this build)

**Measured on this machine** (i7-7700HQ, 4C/8T; Go 1.27; best-of-3 `-count=3` at
`-benchtime=2s`, minimum `ns/op` per size). These are real numbers from
`go test ./src/spxhash/v2/testvc/ -run '^$' -bench 'SpxHash|SHA512_256'`, not
carried over from an earlier run:

| Input | cold (ns) | uncached (ns) | cached (ns) | SHA-512/256 (ns) | cold vs SHA-512/256 | uncached vs SHA-512/256 | cached vs SHA-512/256 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 B | 1,698.8 | 1,239.6 | **47.5** | 312.4 | 5.44x slower | 3.97x slower | **6.58x faster** |
| 1 B | 1,716.3 | 1,285.8 | **49.8** | 317.1 | 5.41x slower | 4.05x slower | **6.36x faster** |
| 1,023 B | 6,748.5 | 6,379.8 | **175.0** | 2,215.3 | 3.05x slower | 2.88x slower | **12.66x faster** |
| 1,024 B | 7,062.8 | 6,019.9 | **168.6** | 2,165.0 | 3.26x slower | 2.78x slower | **12.84x faster** |
| 2,048 B | 12,387.9 | 11,080.9 | **301.5** | 3,976.6 | 3.12x slower | 2.79x slower | **13.19x faster** |
| 4,096 B | 23,518.0 | 20,762.4 | **567.9** | 7,698.3 | 3.05x slower | 2.70x slower | **13.56x faster** |

Allocations:

| Benchmark | B/op | allocs/op |
|---|---:|---:|
| `BenchmarkSpxHash` (cold) | 496 → 5,328 (scales with input) | 8 |
| `BenchmarkSpxHashCached` | 32 | 1 |
| `BenchmarkSpxHashUncached` | 0 (digest stack-allocated when discarded) | 0 |
| `BenchmarkSHA512_256` | not reported (no `b.ReportAllocs()`) | — |

Fitting the 0 B and 4 KB rows gives a useful mental model:

```text
SpxHash v2, cold:      ~1,700 ns fixed + ~5.3 ns per input byte
SpxHash v2, uncached:  ~1,240 ns fixed + ~4.8 ns per input byte
SpxHash v2, cached:    ~47 ns fixed  + ~0.13 ns per input byte
SHA-512/256:           ~312 ns fixed + ~1.8 ns per input byte
```

### Historical (double-SHA-256 draft, pre-`maphash`) — comparison only

Kept to show what the branch-`A` and cache-key changes bought. The `cached`
column here is the OLD cost (a double SHA-256 key derivation ran on every call,
so a cache hit was *slower* than just hashing). These are **not** current
numbers.

| Input Size | cold, OLD (ns/op) | cached, OLD (ns/op) | SHA-512/256 (ns/op) | Cold vs SHA-512/256 | Cached vs SHA-512/256 (OLD) |
|---:|---:|---:|---:|---:|---:|
| 0 bytes | 2,781.00 | 603.01 | 329.26 | **8.45x slower** | **1.83x slower** |
| 1 byte | 2,763.00 | 580.23 | 333.98 | **8.27x slower** | **1.74x slower** |
| 1,023 bytes | 11,483.00 | 3,451.22 | 2,326.27 | **4.94x slower** | **1.48x slower** |
| 1,024 bytes | 11,492.00 | 3,423.62 | 2,241.18 | **5.13x slower** | **1.53x slower** |
| 2,048 bytes | 20,687.00 | 6,179.07 | 4,137.05 | **5.00x slower** | **1.49x slower** |
| 4,096 bytes | 38,549.00 | 11,748.67 | 7,932.42 | **4.86x slower** | **1.48x slower** |

## Cached vs uncached (read this before comparing to STHINCS)

Two benchmark sets can appear to contradict each other. They do not, because
they measure **different code paths**:

| Path | What it does | vs SHA-512/256 |
|---|---|---|
| `GetHashUncached` / a **cache miss** | Runs the full v2 construction every call | **~2.7x–4.0x slower** (cold, incl. per-op instance: **3.0x–5.4x**) |
| `GetHash` on a **cache hit** | Skips hashing entirely; returns the stored digest | **~6.4x–13.6x faster** |

Which one you pay depends entirely on **whether the same input repeats**:

- **Repeating inputs** (a block/transaction hash seen again, a memoized
  address) hit the LRU and are *much* faster than a single SHA-512/256.
- **Never-repeating inputs** always miss, so they pay the full construction
  *plus* the `Put` copy — the worst of both, and slower than not caching.

**STHINCS is the never-repeating case.** Every tweakable call (`F`, `H`, `T_l`,
`PRF`) absorbs a distinct `ADRS` or a distinct WOTS+ chain value into its
input, so across the ~10^6 calls in one signature the cache hit rate is
essentially zero. That is exactly why `tweakable.SphinxHashTweak` calls
`common.SpxHashUncached` — not `SpxHash`. Using the cached entry point there
would add key derivation and a store on every call for no possible hit.

So the STHINCS benchmark's "`SPHINXHASH` is slower than `SHA256`" is measuring
the **uncached** path, and the micro-benchmark's "cache hits are ~6x–14x
faster" is measuring the **cached** path. Both are correct; they apply to
different workloads.

Practical rule:

- Hashing the same bytes repeatedly → use `GetHash`, it wins decisively.
- Hashing fresh bytes every time → use `GetHashUncached`, it avoids paying for
  a cache that cannot hit.

## Key Findings

### Small inputs

For 0-byte and 1-byte inputs, SpxHash v2 is about **5.4x slower** than
SHA-512/256 on the **cold** path (1,716 ns vs 317 ns) and ~**4.0x slower** on
the **uncached, long-lived-instance** path (1,286 ns vs 317 ns) — the ratio is
worst for tiny inputs because the fixed cost (final SHAKE256 squeeze, plus the
per-op LRU map on the cold path) dominates when there is no payload to amortize
it over. On a **cache hit** the same inputs are ~**6.5x faster** than
SHA-512/256 (47.5 ns vs 312 ns), because a hit skips hashing entirely.

### Medium inputs (~1 KB)

At 1 KB the cold gap is ~**3.1x–3.3x slower** (6,748–7,063 ns vs
2,165–2,215 ns); the uncached path is ~**2.8x–2.9x slower** (6,020–6,380 ns),
and a cache hit is ~**12.7x faster** (169–175 ns).

### Larger inputs (2 KB – 4 KB)

At 2 KB and 4 KB the cold ratio is ~**3.1x slower** (12,388 ns and 23,518 ns vs
3,977 ns and 7,698 ns); the uncached path is ~**2.7x–2.8x slower** (11,081 ns
and 20,762 ns), and a cache hit is ~**13x–14x faster** (302 ns and 568 ns).
Unlike v1, SpxHash v2 is **not flat** across input sizes — its cold cost grows
roughly linearly with the input, because the data is walked more than once:

| Pass over the input | Purpose | Applies to |
|---|---|---|
| 1 x SHA-512/256 | branch `A` | every call |
| 1 x SHAKE256 | branch `B` | every call |
| — | final `SHAKE256(0x03 ‖ A ‖ B)` squeeze over 68 bytes | every call |
| `maphash` | LRU bucket selection only (not a cryptographic pass) | `GetHash` only |

That is **2 cryptographic passes** over the payload (one SHA-512/256, one
SHAKE256) versus one SHA-512/256 pass for the baseline, plus the final squeeze
over a fixed 68 bytes. The ~3.0x–5.4x cold ratio is consistent with that.

The historical double-SHA-256 draft paid a **third** SHA-256 compression pass
(branch `A` was itself two compressions), on top of a double-SHA-256 cache-key
derivation on every `GetHash` call, which is what made its ratio ~4.9x–8.5x.

### Why these numbers look worse than v1's

v1's published SpxHash numbers (~4,600–4,900 ns/op, essentially flat from 0 to
4,096 bytes) were **not** measuring hash computation. v1's `BenchmarkSpxHash`
warm-up populated a module-level `hashCache` keyed by input length, and the
timed loop then took the cache-hit branch, which does a `fmt.Sprintf` and a
`fmt.Print` to stdout — one write syscall per iteration. Flat ~4,600 ns/op
regardless of input size is the signature of a syscall, not of hashing 4 KB.

v2's driver does not route the timed loop through that memoizing helper: it
calls `hash.NewSphinxHash(...).GetHash(...)` directly, so the numbers above are
real cold-cache hash costs. They are therefore **not directly comparable to the
v1 README's table**, and the honest comparison to SHA-512/256 is the one in this
document.

### The LRU cache

Repeated hashing of the *same* input on the *same* instance is now **~41x**
faster than cold (e.g. 4,096 bytes: 23,518 -> 568 ns/op), and lands well
under a plain SHA-512/256 digest.

That is a change from before the `maphash` switch. The old cache key was a
double SHA-256 over the full input, so a hit still paid two SHA-256 passes and
landed *slower* than just hashing the data directly (~1.5x). Selecting the
bucket with a seeded `maphash` is a non-cryptographic pass over the input, so
the hit path is now dominated by the map lookup and the `bytes.Equal`
confirmation.

Collision safety is unchanged in kind: `Get(key, input)` only reports a hit
when the stored input compares equal, so a key collision is a **miss**, never a
wrong digest.

## CPU Profile

The run also generated a CPU profile:

```text
File: testvc.test
Type: cpu
Time: 2026-10-03 22:25:31 WIB
Duration: 67.67s, Total samples = 60.54s (89.46%)
```

Top frames, which match the construction exactly:

```text
    16.63s 27.47%  crypto/internal/fips140/sha512.blockAVX2   // branch A + SHA-512/256 baseline
    14.51s 23.97%  crypto/internal/fips140/sha3.keccakF1600   // SHAKE256 branch + squeeze
     4.37s  7.22%  internal/runtime/maps.memHashAES           // seeded maphash cache key
     4.05s  6.69%  runtime.madvise                            // page release from per-op allocs
     3.84s  6.34%  runtime.kevent
     0.73s  1.21%  memeqbody                                  // cache-hit input comparison
```

`sha256` no longer appears at all: branch `A` is a single SHA-512/256 pass, not
a double SHA-256.

Analyze the profile with:

```bash
go tool pprof cpu.prof
```

For browser-based inspection:

```bash
go tool pprof -http=:8080 cpu.prof
```

## Determinism Note

The test vectors are stable and deterministic. `TestVectors` **asserts** each
computed digest against the pinned value in the `vectors` table and calls
`t.Errorf` on a mismatch, so a change to branch `A`'s primitive, the domain
tags, the combiner, the large-input prehash path, or the key handling will fail
the build rather than silently reprinting a new digest. All runs with a fixed
key and `ProtocolSalt` reproduce the same output. The pins were last regenerated
for the double-SHA-256 → SHA-512/256 branch-`A` change.

Two constructors with different guarantees remain:

- `NewSphinxHash(bitSize, key)` — deterministic; `key` must be non-empty.
- `NewSphinxHashKeyed(bitSize)` — fresh random key per instance.

## Recommendations

### Use SpxHash v2 when

- The same input is hashed repeatedly and the LRU cache can absorb the cost
  (a cache hit is ~6x–14x *faster* than SHA-512/256).
- Length-extension resistance and dual-primitive (SHA-512/256 + SHAKE256)
  collision resistance are required properties of the protocol.
- Deterministic, consensus-critical digests are needed and a coordinated
  protocol version bump is acceptable.

### Use SHA-512/256 when

- Raw single-shot throughput matters and the extra security properties are not
  needed. It wins on **every** input size measured here.
- Low CPU and low allocation budgets matter. SHA-512/256 allocates nothing per
  digest, while cold SpxHash v2 allocates up to 5,328 B across 8 allocations.

Do **not** choose SpxHash v2 for cold throughput — it is slower than
SHA-512/256 in every measured uncached case. Choose it for its security
properties, and choose `GetHashUncached` for never-repeating inputs so you do
not pay for a cache that cannot hit.

## Optimization Opportunities

### 1. ~~Stop re-deriving the cache key over the whole input~~ — **DONE**

_Status: implemented. The key is now a seeded `maphash`, not a double SHA-256._

`GetHash` previously computed `cacheKey(data)` — a double SHA-256 over
`key || 0x00 || data` — before every lookup, so on every cache hit it paid two
SHA-256 passes for a cache index that a non-cryptographic hash serves just as
well. `CacheKey` is now a `uint64` from `maphash.Bytes` with a per-instance
seed, which is what took the hit path from ~600 ns to ~50 ns.

### 2. ~~Reuse branch `A`'s inner digest~~ — **OBSOLETE, dropped**

_Status: superseded. This only made sense when the cache key and branch `A`
were structurally similar double SHA-256s. The key is now a `maphash` and
branch `A` is a single SHA-512/256, so there is no SHA-256 work left to reuse._

### 3. Cut per-op allocation

`NewSphinxHash` allocates an `LRUCache` with a `map` (8 allocs/op in the cold
benchmark; 496 B–5,328 B depending on the stored input). For hot paths, reuse
one instance (or accept distinct inputs on a long-lived instance) instead of
constructing one per op, and pool the scratch buffers in `hashData`.

### 4. Batch inputs

```go
func (s *SphinxHash) GetHashBatch(data [][]byte) [][]byte {
	results := make([][]byte, len(data))

	var wg sync.WaitGroup
	for i, d := range data {
		wg.Add(1)
		go func(idx int, input []byte) {
			defer wg.Done()
			results[idx] = s.GetHash(input)
		}(i, d)
	}

	wg.Wait()
	return results
}
```

### 5. Measure cached workloads

If the workload repeats inputs, benchmark and tune against
`BenchmarkSpxHashCached` rather than the cold path — the cache is worth
**~35x–42x** versus the cold path and beats SHA-512/256 by ~13x at 4 KB.

## Summary

SpxHash v2 is **slower than SHA-512/256 on the uncached path for every input
size measured** — about **4.0x** for tiny inputs and **~2.7x–2.9x** from 1 KB to
4 KB (cold, which also constructs a fresh instance per op, is **5.4x** and
**~3.05x–3.26x**) — and **much faster than it on a cache hit**
(**~6.4x–13.6x**).

That is the expected consequence of the design, not a regression: v2 trades the
Argon2id KDF and 1000-round mixing loop for three fast hash calls, and keeps
length-extension resistance plus collision resistance that survives a break in
either SHA-512/256 or SHAKE256. Collision/dual-primitive hardness and
length-extension resistance are the reasons to select it; raw speed is not.

Which column you actually pay depends on your workload:

- **Hashing mostly unique inputs** (STHINCS tweaks, tree hashing, any
  non-repeating stream) → the uncached path, and SHA-512/256 is several times
  faster. Use `GetHashUncached`; a cache there can only ever miss and adds a
  store per call.
- **Hashing the same bytes repeatedly** (re-validating a known address, a
  re-submitted transaction, a memoized key) → the cached path, where SpxHash v2
  wins by roughly an order of magnitude.

If it must resist a length-extension attack *and* survive a break in a single
one of its two hash primitives, SpxHash v2 is the right tool and ~3x on the
cold path (under 3x via `GetHashUncached`) is the bill.
