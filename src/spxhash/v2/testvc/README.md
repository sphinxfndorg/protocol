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
- **`BenchmarkSHA512_256`** — the baseline for comparison.

Note there is no Argon2 dependency here: v2 removed the Argon2id KDF, so the
benchmarks are fast and do not need long per-op timings.

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

Runs `BenchmarkSpxHash`, `BenchmarkSpxHashCached`, and
`BenchmarkSHA512_256`, appending benchmark results:

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

Contains detailed test vector information in a structured format (the
`inputLen` / `keyedHash` / `deriveKey` block per vector).

### `cpu.prof` / `mem.prof`

Performance profile files for analysis.

### `test_output.log`

Full captured run (tests plus benchmarks), written by the `tee` command above.

## Interpreting Results

### Benchmark Output Format

```text
BenchmarkSpxHash/inputLen=0-8         934699      2781 ns/op      832 B/op      11 allocs/op
```

- `inputLen=0`: Input size in bytes
- `-8`: Number of CPU cores
- `934699`: Number of iterations
- `2781 ns/op`: Average time per operation
- `832 B/op`, `11 allocs/op`: Allocations per operation

### Stable Results

- Higher iteration counts, such as values above `100000`, indicate more stable
  measurements.
- Single-iteration benchmark runs are unreliable and should be ignored.
- Use `-benchtime=2s` or higher for consistent results.

### Performance Expectations

Measured on the reference run recorded in `../README.md`:

| Benchmark | Input Size | Expected ns/op | Allocs |
|---|---|---:|---:|
| `BenchmarkSpxHash` (cold) | 0 bytes | ~2,780 | 11 |
| `BenchmarkSpxHash` (cold) | 1–4,096 bytes | ~2,760–38,550 | 11 |
| `BenchmarkSpxHashCached` | 0 bytes | ~600 | 2 |
| `BenchmarkSpxHashCached` | 1–4,096 bytes | ~580–11,750 | 2 |
| `BenchmarkSHA512_256` | 0–1 bytes | ~330 | not reported |
| `BenchmarkSHA512_256` | 1,024+ bytes | ~2,240–7,930 | not reported |

Rough model: `~2,780 ns + ~8.7 ns/byte` cold, `~590 ns + ~2.7 ns/byte` cached.

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
the v2 construction changed — a domain tag (`0x01`/`0x02`/`0x03`), the
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

This is expected for v2 — it is a composite hash (double-SHA256 + SHAKE256
combiner) and is slower than SHA-512/256 by design. If the numbers are worse
than the table above, check:

1. Whether you are looking at `BenchmarkSpxHash` (cold) rather than
   `BenchmarkSpxHashCached`.
2. Whether another process is competing for CPU during the run.

```bash
go test -bench=. -cpuprofile=cpu.prof
go tool pprof -top cpu.prof
```

The profile should be dominated by `sha256.blockAVX2` (three passes per
digest), then `sha3.keccakF1600` (the SHAKE256 branches).

### Cache Not Working

**Issue:** `Using opcode: SphinxHash=0x10 (cached)` messages are not appearing.

**Solution:** Ensure `TestVectors` runs before benchmarks:

```bash
go test -v -bench=.
```

Remember the LRU cache is per-instance. `BenchmarkSpxHash` deliberately creates
a fresh instance per op, so it never reports cache hits; only
`BenchmarkSpxHashCached` exercises the hit path.

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
- `crypto/sha256` (standard library) — branches `A` and the cache-key hash
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
