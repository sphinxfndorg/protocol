# SpxHash v2 Benchmark Analysis

## Overview

This document records the SpxHash **v2** test-vector output and the benchmark
comparison against SHA-512/256.

v2 is a deliberate speed/weight redesign of v1 with a **narrowed threat model**:

- **Kept:** length-extension resistance and collision resistance that survives
  a break in either SHA-256 or SHAKE256 (concatenation combiner).
- **Removed:** Argon2id key derivation and the 1000-round SHAKE256 mixing loop.
  Pre-image resistance under a memory-hard KDF is explicitly out of scope.
- **Bumped:** `ProtocolSalt` is now `"sphinx-protocol-hash-v2"`, so v1 and v2
  nodes can never silently agree on the wrong digest. This is a breaking,
  consensus-critical change.

The construction is three fast hash calls per digest:

```text
A   = SHA256(SHA256(key || 0x01 || data))     // Bitcoin-style double hash
B   = SHAKE256(key || 0x02 || data), 32 bytes
out = SHAKE256(0x03 || A || B), Size() bytes
```

**Bottom line: SpxHash v2 is slower than SHA-512/256 for every input size
measured here *when it actually hashes*.** A single cold digest costs roughly
**3.2x–4.7x** a SHA-512/256 digest. v2 pays for its dual-primitive collision
resistance and length-extension resistance with CPU time, and it does that on
purpose. What it does *not* pay is Argon2 latency, and — since the LRU key
changed from a double SHA-256 to a seeded `maphash` — a **repeated** digest is
now served from cache *faster* than SHA-512/256. See
[Cached vs uncached](#cached-vs-uncached-read-this-before-comparing-to-sthincs)
for why those two facts are both true and do not conflict.

## Test Command

```bash
go test -v -bench=. -benchtime=2s -cpuprofile=cpu.prof
```

The captured run completed successfully:

```text
PASS
ok      github.com/sphinxfndorg/protocol/src/spxhash/v2/testvc    48.746s
```

Tests and benchmarks both ran, and the pins in the vector table in
`testvc/spxhash_v2_test.go` were asserted (not just printed) — see
[Test Vectors](#test-vectors).

## Test Vectors

These are the pinned, asserted vectors from `testvc/spxhash_v2_test.go`
(bitSize 256, fixed salt `SPXHASH_TEST_VECTOR_SALT_2024`, input pattern
`i % 251`). They differ from v1 for the same input by design.

| Input Length | Hash |
|---:|---|
| 0 | `9e9bc2e34f1d3da65fdb52b36c80918fee908bf367cfdbdc6dc87988a26acba5` |
| 1 | `da4cb911569fe117213087cbbfb056b16b82376d4449f3c1dba7c0e597d1b814` |
| 1023 | `d858517d03f20da691682fc90f3649e21df846a5f7f8b6e5f3b9d5e74c7a8ebe` |
| 1024 | `05afa62fba53e9da77cf4e24b6964221e7a400faf1a255de6465e304b8dd4a54` |
| 2048 | `be20b69a1691a8b42933e71b93eb694f961fe9b1921b980e6b57a6530d20ff86` |
| 4096 | `a4db67bf23b223a2917b0c56cc1fd9db39336fbfb0035a78b17b50131c5d5557` |

Note the v1 <-> v2 difference for the length-0 input:

| Version | inputLen=0 hash |
|---|---|
| v1 | `56e5cb4244edd633a76ea4a63ab21ac7590e8773b4e23baac7cbc7135b035297` |
| v2 | `9e9bc2e34f1d3da65fdb52b36c80918fee908bf367cfdbdc6dc87988a26acba5` |

## Structured Vector Output

```text
<vector inputLen=0 hash=9e9bc2e34f1d3da65fdb52b36c80918fee908bf367cfdbdc6dc87988a26acba5 keyedHash=c098615604bb025f47999595c04e030f364e5435a7577d7ababb03a271e9989e deriveKey=be538a2f83a53f6d4665e56557f43acf90ba82f97fa5d7bf746be24370054ca0>
<vector inputLen=1 hash=da4cb911569fe117213087cbbfb056b16b82376d4449f3c1dba7c0e597d1b814 keyedHash=ea27697ab40a291b93dc90c1618337974d06462882918405420871911fcb29ec deriveKey=be538a2f83a53f6d4665e56557f43acf90ba82f97fa5d7bf746be24370054ca0>
<vector inputLen=1023 hash=d858517d03f20da691682fc90f3649e21df846a5f7f8b6e5f3b9d5e74c7a8ebe keyedHash=8002a9d0715ee58d3e796d0a2474c7eaefb5d38544d2e7ca4e1c636b9e2ddfce deriveKey=3e9251161692adb640c8dd76685c50c048297fe3360828e16c912f429c397bab>
<vector inputLen=1024 hash=05afa62fba53e9da77cf4e24b6964221e7a400faf1a255de6465e304b8dd4a54 keyedHash=a5e689a6065c86606c29be00b70d9fb777ef8273c212a8caa574dd51dd39a714 deriveKey=353ff083ae5cbbe9ccb806be665e3136ebd78bfb3fe82103b249934127a53f9f>
<vector inputLen=2048 hash=be20b69a1691a8b42933e71b93eb694f961fe9b1921b980e6b57a6530d20ff86 keyedHash=1b8dbedc8bb976b4a5b5eae089397f6c0db4f3ece3159b917774ee6e2a26d6d1 deriveKey=7f9ea132acaf84f492804b9dc11f0e08f8fa38907394ea9a1094b52568eb0acf>
<vector inputLen=4096 hash=a4db67bf23b223a2917b0c56cc1fd9db39336fbfb0035a78b17b50131c5d5557 keyedHash=950c63a2454e97c3a12e78804c23c65944436b53b1f513fbf72d874f22446995 deriveKey=3c4416bedf98988efd9a0ce301d7317c4548d95514e680d334727ab98167ae00>
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

The rows below are the **pre-`maphash` historical measurements**, kept only to
show what the cache-key change bought. The `cached` column here is the OLD cost
(a double SHA-256 key derivation ran on every call, so a cache hit was *slower*
than just hashing). They are **not** current numbers — see
`testvc/README.md` for the current benchmark run.

| Input Size | cold, OLD (ns/op) | cached, OLD (ns/op) | SHA-512/256 (ns/op) | Cold vs SHA-512/256 | Cached vs SHA-512/256 (OLD) |
|---:|---:|---:|---:|---:|---:|
| 0 bytes | 2,781.00 | 603.01 | 329.26 | **8.45x slower** | **1.83x slower** |
| 1 byte | 2,763.00 | 580.23 | 333.98 | **8.27x slower** | **1.74x slower** |
| 1,023 bytes | 11,483.00 | 3,451.22 | 2,326.27 | **4.94x slower** | **1.48x slower** |
| 1,024 bytes | 11,492.00 | 3,423.62 | 2,241.18 | **5.13x slower** | **1.53x slower** |
| 2,048 bytes | 20,687.00 | 6,179.07 | 4,137.05 | **5.00x slower** | **1.49x slower** |
| 4,096 bytes | 38,549.00 | 11,748.67 | 7,932.42 | **4.86x slower** | **1.48x slower** |

**Measured on this machine** (i7-7700HQ, 4C/8T; `-benchtime=300ms`, highest
iteration count row). These are real numbers from
`go test ./src/spxhash/v2/testvc/ -run '^$' -bench 'Cached|Uncached|SHA512_256'`,
not carried over from an earlier run:

| Input | cold / uncached | cached (hit) | SHA-512/256 | cold vs SHA-512/256 | cached vs SHA-512/256 |
|---:|---:|---:|---:|---:|---:|
| 0 B | 1,524 ns | **52 ns** | 327 ns | 4.66x slower | **0.16x — 6.3x faster** |
| 1 B | 1,504 ns | **57 ns** | 328 ns | 4.58x slower | **0.17x — 5.8x faster** |
| 1,023 B | 7,693 ns | **184 ns** | 2,285 ns | 3.37x slower | **0.08x — 12.4x faster** |
| 1,024 B | 7,625 ns | **179 ns** | 2,262 ns | 3.37x slower | **0.08x — 12.6x faster** |
| 2,048 B | 14,194 ns | **302 ns** | 4,130 ns | 3.44x slower | **0.07x — 13.7x faster** |
| 4,096 B | 25,042 ns | **538 ns** | 7,859 ns | 3.19x slower | **0.07x — 14.6x faster** |

Allocations:

| Benchmark | B/op | allocs/op |
|---|---:|---:|
| `BenchmarkSpxHash` (cold) | 832 | 11 |
| `BenchmarkSpxHashCached` | 64 | 2 |
| `BenchmarkSHA512_256` | not reported (no `b.ReportAllocs()`) | — |

Fitting the cold numbers gives a useful mental model:

```text
SpxHash v2, cold:   ~2,780 ns fixed + ~8.7 ns per input byte
SpxHash v2, cached:   ~590 ns fixed + ~2.7 ns per input byte
SHA-512/256:          ~330 ns fixed + ~1.9 ns per input byte
```

## Cached vs uncached (read this before comparing to STHINCS)

Two benchmark sets can appear to contradict each other. They do not, because
they measure **different code paths**:

| Path | What it does | vs SHA-512/256 |
|---|---|---|
| `GetHashUncached` / a **cache miss** | Runs the full v2 construction every call | **3.2x–4.7x slower** |
| `GetHash` on a **cache hit** | Skips hashing entirely; returns the stored digest | **~6x–15x faster** |

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

So the STHINCS benchmark's "`SPHINXHASH` is 2.4x–3.6x slower than `SHA256`"
is measuring the **uncached** path, and the micro-benchmark's "cache hits are
6x–14x faster" is measuring the **cached** path. Both are correct; they apply to
different workloads.

Practical rule:

- Hashing the same bytes repeatedly → use `GetHash`, it wins decisively.
- Hashing fresh bytes every time → use `GetHashUncached`, it avoids paying for
  a cache that cannot hit.

## Key Findings

### Small inputs

For 0-byte and 1-byte inputs, SpxHash v2 is about **4.6x slower** than
SHA-512/256 on the **cold/uncached** path (1,524 ns vs 327 ns) — the ratio is
worst for tiny inputs because the fixed cost (final SHAKE256 squeeze plus
per-instance allocation of an LRU cache and map) dominates when there is no
payload to amortize it over. On a **cache hit** the same inputs are ~**6x
faster** than SHA-512/256 (52 ns vs 327 ns), because a hit skips hashing
entirely.

### Medium inputs (~1 KB)

At 1 KB the cold gap is ~**3.4x slower** (7,625 ns vs 2,262 ns), while a cache
hit is ~**12.6x faster** (179 ns).

### Larger inputs (2 KB – 4 KB)

At 2 KB and 4 KB the cold ratio is ~**3.2x–3.4x slower** (14,194 ns and
25,042 ns vs 4,130 ns and 7,859 ns); a cache hit is ~**14x faster** (302 ns and
538 ns). Unlike v1, SpxHash v2 is **not flat** across input sizes — its
cold cost grows roughly linearly with the input, because the data is walked
several times:

| Pass over the input | Purpose | Applies to |
|---|---|---|
| 1 x SHA-256 | branch `A` inner digest (its outer digest is over 32 bytes) | every call |
| 1 x SHAKE256 | branch `B` | every call |
| — | final `SHAKE256(0x03 ‖ A ‖ B)` squeeze over 68 bytes | every call |
| `maphash` | LRU bucket selection only (not a cryptographic pass) | `GetHash` only |

That is **2 SHA-256 passes** over the payload (one inner, plus an outer over the
32-byte inner digest) plus 1 SHAKE256 pass, versus one SHA-512/256 pass for the
baseline. The ~3.2x–4.7x cold ratio is consistent with that. The old key
derivation added 2 more SHA-256 passes, which is what used to make the ratio
~5x–8.5x.

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

Repeated hashing of the *same* input on the *same* instance is now **~46x**
faster than cold (e.g. 4,096 bytes: 25,042 -> 538 ns/op), and lands well
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
Time: 2026-09-25 03:13:19 WIB
Duration: 48.23s, Total samples = 43.42s (90.03%)
```

Top frames, which match the construction exactly:

```text
    15.23s 35.08%  crypto/internal/fips140/sha256.blockAVX2   // branch A (1 pass/digest)
     9.88s 22.75%  crypto/internal/fips140/sha512.blockAVX2   // the SHA-512/256 baseline
     4.84s 11.15%  runtime.madvise                            // page release from per-op allocs
     3.90s  8.98%  crypto/internal/fips140/sha3.keccakF1600   // SHAKE256 branches + squeeze
     2.18s  5.02%  runtime.kevent
```

Analyze the profile with:

```bash
go tool pprof cpu.prof
```

For browser-based inspection:

```bash
go tool pprof -http=:8080 cpu.prof
```

## Determinism Note

The test vectors are stable and deterministic. `TestVectors` now **asserts**
each computed digest against the pinned value in the `vectors` table and calls
`t.Errorf` on a mismatch, so a change to the domain tags, the combiner, or the
key handling will fail the build rather than silently reprinting a new digest.
All runs with a fixed key and `ProtocolSalt` reproduce the same output.

Two constructors with different guarantees remain:

- `NewSphinxHash(bitSize, key)` — deterministic; `key` must be non-empty.
- `NewSphinxHashKeyed(bitSize)` — fresh random key per instance.

## Recommendations

### Use SpxHash v2 when

- The same input is hashed repeatedly and the LRU cache can absorb the cost
  (roughly 1.5x SHA-512/256 instead of ~5x).
- Length-extension resistance and dual-primitive (SHA-256 + SHAKE256)
  collision resistance are required properties of the protocol.
- Deterministic, consensus-critical digests are needed and a coordinated
  protocol version bump is acceptable.

### Use SHA-512/256 when

- Raw single-shot throughput matters and the extra security properties are not
  needed. It wins on **every** input size measured here.
- Low CPU and low allocation budgets matter. SHA-512/256 allocates nothing per
  digest, while a cold SpxHash v2 op allocates 832 B across 11 allocations.

Do **not** choose SpxHash v2 for cold throughput — it is slower than
SHA-512/256 in every measured uncached case. Choose it for its security
properties, and choose `GetHashUncached` for never-repeating inputs so you do
not pay for a cache that cannot hit.

## Optimization Opportunities

### 1. ~~Stop re-deriving the cache key over the whole input~~ — **DONE**

_Status: implemented. The key is now a seeded `maphash`, not a double SHA-256._

`GetHash` previously computed `cacheKey(data)` — a double SHA-256 over
`key || 0x00 || data` — before every lookup, so two of the three SHA-256
passes per call were spent on a cache index that a non-cryptographic hash
serves just as well. `CacheKey` is now a `uint64` from `maphash.Bytes` with a
per-instance seed.

### 2. ~~Reuse branch `A`'s inner digest~~ — **OBSOLETE, dropped**

_Status: superseded. This only made sense when the cache key was a double
SHA-256 structurally similar to branch `A`. With a `maphash` key there is no
SHA-256 work left to reuse, so there is nothing to save._

### 3. Cut per-op allocation

`NewSphinxHash` allocates an `LRUCache` with a `map` (832 B, 11 allocs/op). For
hot paths, reuse one instance (or accept distinct inputs on a long-lived
instance) instead of constructing one per op, and pool the scratch buffers in
`hashData`.

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
`BenchmarkSpxHashCached` rather than the cold path — the cache is worth up to
~4.6x at small sizes.

## Summary

SpxHash v2 is **slower than SHA-512/256 on the uncached path for every input
size measured** — about **4.6x** for tiny inputs and **~3.2x–3.4x** from 1 KB to
4 KB — and **much faster than it on a cache hit** (**~6x–15x**).

That is the expected consequence of the design, not a regression: v2 trades the
Argon2id KDF and 1000-round mixing loop for three fast hash calls, and keeps
length-extension resistance plus collision resistance that survives a break in
either SHA-256 or SHAKE256. Collision/dual-primitive hardness and
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
one of its two hash primitives, SpxHash v2 is the right tool and ~3.4x on the
cold path is the bill.
