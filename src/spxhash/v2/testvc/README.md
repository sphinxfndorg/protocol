# SphinxHash v2 Test Suite

## Overview

This test suite validates the SpxHash **v2** implementation in
`src/spxhash/v2` and generates the test vectors in the required format.

It is a black-box (external) test package: every file here declares
`package spxhash_test` and imports the implementation as
`hash "github.com/sphinxfndorg/protocol/src/spxhash/v2"`.

> **File naming:** the driver **must** end in `_test.go` for `go test` to
> discover it. This package previously shipped as `spxhash_test_v2.go`, which
> Go treats as an ordinary (non-test) source file — `go test` reported
> `[no test files]` and silently ran nothing. It is now
> `spxhash_v2_test.go`.

The suite covers:

- **`TestVectors`** — computes the v2 digest for each pinned input length,
  **asserts** it against the expected value, and writes
  `inputLen: <len>, hash: <hash>` plus the `<vector ...>` line.
- **`TestRandomSaltNonDeterminism`** — two `NewSphinxHashKeyed` instances must
  disagree on the same input.
- **`TestFixedSaltDeterminism`** — the same key must reproduce the same digest
  across instances and across repeated calls.
- **`TestDifferentBitSizes`** — 256/384/512 produce 32/48/64-byte output.
- **`BenchmarkSpxHash`** — cold-cache cost (fresh instance per op).
- **`BenchmarkSpxHashCached`** — repeated-query cost (LRU cache hit).
- **`BenchmarkSpxHashUncached`** — `GetHashUncached` on a repeated input, i.e.
  a full recomputation with no key derivation and no cache traffic. This is
  the path STHINCS signing uses; it is the closest proxy in this suite for a
  workload whose inputs never repeat.
- **`BenchmarkSHA512_256`** — the baseline for comparison.

Note there is no Argon2 dependency here: v2 removed the Argon2id KDF, so the
benchmarks are fast and do not need long per-op timings.

> **Why the six pins changed (branch-`A` rewrite).** Branch `A` is now a single
> `SHA512/256(key || 0x01 || data)` call instead of the earlier v2 draft's
> double SHA-256, and inputs larger than 1 MiB take a separate prehash path
> (tags `0x10`/`0x13`, then `0x11`/`0x12`). Both changes alter the digest for
> every input, so **all six pinned vectors were regenerated** for this build.
> For example, `inputLen=0` moved from the double-SHA-256 draft's
> `9e9bc2e3…` to `95137d37…`. `keyedHash`/`deriveKey` are unaffected — they are
> computed directly from `testVectorKey`, not through this package.
>
> The earlier `maphash` cache-key change, by contrast, is deliberately
> invisible in the digests: `hashData` never sees the cache key, so it moved
> only the timings, not the pins.

The white-box unit tests for the package — cache-collision safety,
`HashIntoUncached`/`GetHashUncached` equivalence, and the large-input prehash
path — live alongside the implementation in `src/spxhash/v2` (`cache_test.go`,
`hashinto_equiv_test.go`, `spxhash_large_test.go`) and run with
`go test ./src/spxhash/v2/`. This `testvc` package is the black-box vector and
benchmark driver.

## Prerequisites

- Go 1.16 or higher (the module targets Go 1.25)
- All dependencies installed:

```bash
go mod tidy
```

## Running Tests

### 1. Clear Test Cache

Optional, but useful for fresh results:

```bash
go clean -testcache
```

### 2. Run Unit Tests

Runs `TestVectors` and the determinism/size tests, and generates the initial
output:

- `Using opcode: SphinxHash=0x10` messages
- `inputLen: <length>, hash: <hash>` lines
- `<vector ...>` entries with `keyedHash` and `deriveKey`

```bash
go test -v
```

To run only the vector test:

```bash
go test -v -run TestVectors
```

### 3. Run Benchmarks

Runs `BenchmarkSpxHash`, `BenchmarkSpxHashCached`,
`BenchmarkSpxHashUncached`, and `BenchmarkSHA512_256`, appending benchmark
results:

- `Using opcode: SphinxHash=0x10 (cached)` messages
- Benchmark results in `ns/op`
- Header and footer entries such as `=== RUN` and `--- PASS`

```bash
go test -bench=. -run=^$
```

### 4. Run All Tests

Recommended command for running unit tests and benchmarks together:

```bash
go test -v -bench=.
```

### 5. Run Stable Benchmarks

For more consistent benchmark results, increase benchmark duration:

```bash
go test -v -bench=. -benchtime=2s
```

### 6. CPU Profiling

Generate and inspect a CPU profile:

```bash
go test -bench=. -benchtime=2s -cpuprofile=cpu.prof
go tool pprof cpu.prof
```

For interactive analysis:

```bash
go tool pprof -http=:8080 cpu.prof
```

### 7. Memory Profiling

Analyze memory allocation patterns:

```bash
go test -bench=. -benchmem -memprofile=mem.prof
go tool pprof mem.prof
```

### 8. Save All Output

Capture both terminal output and test results:

```bash
go test -v -bench=. -benchtime=2s 2>&1 | tee test_output.log
```

## Output Files

### `vectorsoutput.txt`

Automatically created output file containing:

1. Test vectors with hashes for each input length
2. `keyedHash` and `deriveKey` values
3. Benchmark results with `ns/op` metrics

### `test_vectors_output.txt`

A **hand-maintained, human-readable** restatement of the same vectors in
`inputLen` / `keyedHash` / `deriveKey` form. No code in this repository writes
it — unlike `vectorsoutput.txt`, it is not regenerated by a test run, so it must
be updated by hand when the vectors change.

### `cpu.prof` / `mem.prof`

Performance profile files for analysis.

### `test_output.log`

Full captured run (tests plus benchmarks), written by the `tee` command above.

## Interpreting Results

### Benchmark Output Format

```text
BenchmarkSpxHash/inputLen=0-8          1339750      1760 ns/op      496 B/op      8 allocs/op
BenchmarkSpxHashUncached/inputLen=0-8  1838464      1299 ns/op        0 B/op      0 allocs/op
```

- `inputLen=0`: Input size in bytes
- `-8`: Number of CPU cores
- `1000000`: Number of iterations
- `1960 ns/op`: Average time per operation
- `496 B/op`, `8 allocs/op`: Allocations per operation

`BenchmarkSpxHashCached` and `BenchmarkSpxHashUncached` are the pair to compare
when reasoning about a repeated-input workload; `BenchmarkSpxHash` is the
worst case because it also pays per-op instance construction.

### Stable Results

- Higher iteration counts, such as values above `100000`, indicate more stable
  measurements.
- Single-iteration benchmark runs are unreliable and should be ignored.
- Use `-benchtime=2s` or higher for consistent results.

### Performance Expectations

Measured on the reference machine for this repository after the branch-`A`
rewrite (single SHA-512/256) and the `maphash` cache-key change. These numbers
are current; the tables in `../README.md` describe the historical
double-SHA-256 draft and are kept only for comparison.

Reference machine: darwin/amd64, Intel Core i7-7700HQ @ 2.80GHz, `-8` (GOMAXPROCS
8), Go 1.27. Values are the **best of 3** `-count=3` repetitions at
`-benchtime=2s`, taken as the minimum `ns/op` per size — on this machine single
runs vary by up to ~30% (cold 2,048 B measured anywhere from 13.2 µs to
19.4 µs), so treat anything under ~15% as noise.

| Benchmark | Input Size | ns/op (current) | ns/op (pre-branch-`A`) | Allocs |
|---|---|---:|---:|---:|
| `BenchmarkSpxHash` (cold) | 0 bytes | ~1,700 | ~2,780 | 8 |
| `BenchmarkSpxHash` (cold) | 1 byte | ~1,720 | ~2,760 | 8 |
| `BenchmarkSpxHash` (cold) | 1,023–4,096 bytes | ~6,750–23,500 | ~11,480–38,550 | 8 |
| `BenchmarkSpxHashUncached` | 0 bytes | ~1,240 | not measured | 0 |
| `BenchmarkSpxHashUncached` | 1,023–4,096 bytes | ~6,380–20,760 | not measured | 0 |
| `BenchmarkSpxHashCached` | 0 bytes | ~47 | ~600 | 1 |
| `BenchmarkSpxHashCached` | 1,023–4,096 bytes | ~175–570 | ~3,450–11,750 | 1 |
| `BenchmarkSHA512_256` | 0–1 bytes | ~312–317 | ~329–334 | not reported |
| `BenchmarkSHA512_256` | 1,023–4,096 bytes | ~2,215–7,698 | ~2,241–7,932 | not reported |

Full best-of-3 table (ns/op; lower is better):

| Input | cold | uncached | cached | SHA-512/256 |
|---:|---:|---:|---:|---:|
| 0 B | 1,698.8 | 1,239.6 | **47.5** | 312.4 |
| 1 B | 1,716.3 | 1,285.8 | **49.8** | 317.1 |
| 1,023 B | 6,748.5 | 6,379.8 | **175.0** | 2,215.3 |
| 1,024 B | 7,062.8 | 6,019.9 | **168.6** | 2,165.0 |
| 2,048 B | 12,387.9 | 11,080.9 | **301.5** | 3,976.6 |
| 4,096 B | 23,518.0 | 20,762.4 | **567.9** | 7,698.3 |

Two changes dominate this table:

1. **The cached path is an order of magnitude faster than cold, and faster than
   SHA-512/256 at every size**: **6.6x** faster at 0 bytes, rising to **~13x**
   at 1–4 KB. A cache hit runs a single seeded `maphash` pass plus a map probe
   and a `bytes.Equal` confirmation — no cryptographic hashing at all.
2. **The cold path is now ~3.0x–5.4x slower than SHA-512/256** instead of the
   ~4.9x–8.5x of the double-SHA-256 draft: branch `A` is one SHA-512/256 pass
   rather than two SHA-256 passes, so a whole pass over the payload is gone.

Allocation behaviour: cold allocates an `LRUCache` map plus the stored input
(**8 allocs/op**, 496 B at 0 bytes up to 5,328 B at 4 KB); the cached path sits
at **1 alloc / 32 B** (the returned digest copy); `BenchmarkSpxHashUncached`
reports **0 B/op / 0 allocs/op** because the benchmark discards the digest and
escape analysis stack-allocates it — a real caller that retains the value pays
1 alloc / 32 B.

Rough model for the current implementation (fit on the 0 B and 4 KB rows):

```text
SpxHash v2, cold:      ~1,700 ns fixed + ~5.3 ns per input byte
SpxHash v2, uncached:  ~1,240 ns fixed + ~4.8 ns per input byte
SpxHash v2, cached:    ~47 ns fixed  + ~0.13 ns per input byte
SHA-512/256:           ~312 ns fixed + ~1.8 ns per input byte
```

Because the cache key is per-instance, the same instance must be reused for a
hit. `BenchmarkSpxHash` constructs a fresh instance (and its LRU map) per op,
which is why its numbers sit above `BenchmarkSpxHashUncached` on the same input.

## Troubleshooting

### `[no test files]` / Tests Are Not Running

**Issue:** `go test` reports `[no test files]` even though the driver exists.

**Solution:** The driver must end in `_test.go`. Go ignores `*.go` files whose
names do not have that suffix when building a test binary. Confirm the filename:

```bash
ls *_test.go
```

### Vector Mismatch Failure

**Issue:** `TestVectors` fails with `vector mismatch`.

**Cause:** The computed digest no longer matches the pinned value. That means
the v2 construction changed — branch `A`'s primitive (now SHA-512/256 under tag
`0x01`), a domain tag (`0x01`/`0x02`/`0x03` for the small path;
`0x10`/`0x13` then `0x11`/`0x12` for the large-input prehash path), the
concatenation combiner, the key handling, or `ProtocolSalt` in `params.go`.

**Action items:**

1. Confirm the change was intentional and consensus-critical.
2. If intentional, regenerate the pins and update `vectors` in
   `spxhash_v2_test.go`, and update the tables in `../README.md`.
3. If not intentional, revert the change rather than the pins.

### Inconsistent Benchmark Results

**Issue:** Multiple benchmark runs produce varying iteration counts.

**Solution:** Use `-benchtime=2s` to stabilize measurements:

```bash
go test -bench=. -benchtime=2s
```

### High `ns/op` Values

**Issue:** Hash computation is slower than expected.

This is expected for v2 — it is a composite hash (a SHA-512/256 branch and a
SHAKE256 branch combined, then squeezed through SHAKE256) and is slower than
SHA-512/256 by design. If the numbers are worse than the table above, check:

1. Whether you are looking at `BenchmarkSpxHash` (cold) or
   `BenchmarkSpxHashUncached` rather than `BenchmarkSpxHashCached`.
2. Whether the input exceeds `MaxCachedInputSize` (4 KiB), which bypasses the
   cache entirely.
3. Whether another process is competing for CPU during the run.

```bash
go test -bench=. -cpuprofile=cpu.prof
go tool pprof -top cpu.prof
```

The profile is dominated by `sha512.blockAVX2` (branch `A` plus the SHA-512/256
baseline), then `sha3.keccakF1600` (branch `B` and the final squeeze), then
`internal/runtime/maps.memHashAES` (the seeded `maphash` LRU key) and
`memeqbody` (the input comparison that confirms a cache hit). `sha256` no longer
appears at all — branch `A` is no longer a double SHA-256.

### Cache Not Working

**Issue:** `Using opcode: SphinxHash=0x10 (cached)` messages are not appearing.

**Solution:** Ensure `TestVectors` runs before benchmarks:

```bash
go test -v -bench=.
```

Remember the LRU cache is per-instance. `BenchmarkSpxHash` deliberately creates
a fresh instance per op, so it never reports cache hits; only
`BenchmarkSpxHashCached` exercises the hit path.

Note also that inputs longer than `MaxCachedInputSize` (4 KiB) bypass the cache
entirely in `GetHash`, so a workload that only ever hashes large buffers will
never see a hit regardless of repetition. Use `BenchmarkSpxHashUncached` for
that case — it is the honest model of a large-input or never-repeating
workload, and it costs far less than `BenchmarkSpxHash` because it skips both
the key derivation and the LRU insert.

### `vectorsoutput.txt` Keeps Growing

**Issue:** the file has the same `=== RUN TestPrintHashes` block repeated many
times and gets larger on every run.

**Cause:** the driver opens it with `O_APPEND` and never truncates, so every
run adds another copy. This is pre-existing behaviour, not a failure.

**Workaround:** reset it before a run you intend to keep:

```bash
git checkout src/spxhash/v2/testvc/vectorsoutput.txt
```

## Quick Reference

```bash
# Most comprehensive test run
go test -v -bench=. -benchtime=2s -cpuprofile=cpu.prof

# Quick test run without benchmarks
go test -v

# Vector test only
go test -v -run TestVectors

# Benchmarks only
go test -bench=. -run=^$

# Benchmarks with memory stats
go test -bench=. -benchmem

# Coverage report
go test -cover -coverprofile=coverage.out
go tool cover -html=coverage.out

# Race detection
go test -race -v
```

## Note on Determinism

`NewSphinxHash` and `NewSphinxHashKeyed` are two separate constructors with
different guarantees:

- **`NewSphinxHash(bitSize, key)` — deterministic, key required.**
  `key` must be non-nil and non-empty; passing `nil` or an empty slice returns
  an error instead of silently substituting randomness. Given the same
  `bitSize` and the same `key`, `GetHash` always returns the same output,
  regardless of process or instance. Use this constructor anywhere the output
  must be independently reproducible — transaction hashes, block hashes,
  Merkle leaves/roots, address derivation, and test vectors.
- **`NewSphinxHashKeyed(bitSize)` — randomized, no key argument.**
  Each call generates its own fresh, cryptographically random key internally,
  so two instances will (with overwhelming probability) produce different
  output for the same input, even across runs. Use this constructor for
  password-storage / MAC-like use cases where non-determinism across instances
  is the point. Do not use it anywhere the hash must be reproduced later,
  unless you also persist the key via `EncodedSalt()`.
- **Test vectors:** always use `NewSphinxHash` with a fixed key
  (`fixedSalt` in `spxhash_v2_test.go`), never `NewSphinxHashKeyed`, so vectors
  stay reproducible across runs and machines.

Unlike v1, there is no Argon2id step, so a fixed `key` maps directly to a fixed
digest with no KDF parameters (memory/iterations/parallelism) to pin as well.

## Dependencies

- `github.com/sphinxfndorg/protocol/src/spxhash/v2` — main hash implementation
- `golang.org/x/crypto/sha3` — SHAKE256 (branches `B` and the final squeeze)
- `crypto/sha512` (standard library, via `sha512.New512_256`) — branch `A`, and
  the SHA-512/256 half of the large-input prehash
- `hash/maphash` (standard library) — the seeded non-cryptographic LRU cache
  key; it selects a bucket only, and hits are confirmed by comparing the stored
  input, so a collision can never return a wrong digest
- `golang.org/x/crypto/hkdf` — HKDF for the `deriveKey` vector value
- `github.com/sphinxfndorg/protocol/src/core/kernel/opcodes` — `SphinxHash`
  opcode constant (`0x10`) used for the log labels

There is **no** `golang.org/x/crypto/argon2` dependency: v2 removed the
Argon2id KDF.

## Running in CI/CD

For continuous integration:

```bash
go test -v -bench=. -benchtime=2s -cover -race
```

This ensures:

- Unit tests pass, including the pinned vector assertion
- Benchmarks run with stable results
- Code coverage is reported
- Race conditions are detected

## Expected Output

The test output should include:

1. `Using opcode: SphinxHash=0x10` messages
2. `inputLen: X, hash: Y` lines
3. `<vector ...>` entries with `keyedHash` and `deriveKey`
4. Benchmark results with stable `ns/op` values
5. `--- PASS` for each test and benchmark, ending in
   `ok  github.com/sphinxfndorg/protocol/src/spxhash/v2/testvc  <duration>`
