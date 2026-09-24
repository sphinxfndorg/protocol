# SphinxHash Test Suite

## Overview

This test suite validates the SphinxHash implementation and generates test vectors in the required format.

## Prerequisites

- Go 1.16 or higher
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

Runs `TestVectors` and generates the initial output:

- `Using opcode: SphinxHash=0x10` messages
- `inputLen: <length>, hash: <hash>` lines
- Test vector entries with `keyedHash` and `deriveKey`

```bash
go test -v -run TestVectors
```

### 3. Run Benchmarks

Runs `BenchmarkSpxHash` and `BenchmarkSHA512_256`, appending benchmark results:

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
go test -v -bench=. -benchtime=5s
```

### 6. CPU Profiling

Generate and inspect a CPU profile:

```bash
go test -bench=. -benchtime=5s -cpuprofile=cpu.prof
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
go test -v -bench=. -benchtime=5s 2>&1 | tee test_output.log
```

## Output Files

### `vectorsoutput.txt`

Automatically created output file containing:

1. Test vectors with hashes for each input length
2. `KeyedHash` and `DeriveKey` values
3. Benchmark results with `ns/op` metrics

### `test_vectors_output.txt`

Contains detailed test vector information in a structured format.

### `cpu.prof` / `mem.prof`

Performance profile files for analysis.

## Interpreting Results

### Benchmark Output Format

```text
BenchmarkSpxHash/inputLen=0-8   845132   4909.421180 ns/op
```

- `inputLen=0`: Input size in bytes
- `-8`: Number of CPU cores
- `845132`: Number of iterations
- `4909.421180 ns/op`: Average time per operation

### Stable Results

- Higher iteration counts, such as values above `100000`, indicate more stable measurements.
- Single-iteration benchmark runs are unreliable and should be ignored.
- Use `-benchtime=5s` or higher for consistent results.

### Performance Expectations

| Function | Input Size | Expected ns/op |
|---|---:|---:|
| SphinxHash | 0 bytes | ~5,000 ns/op |
| SphinxHash | 1-4096 bytes | ~4,500-5,000 ns/op |
| SHA-512/256 | 0-1 bytes | ~370-400 ns/op |
| SHA-512/256 | 1024+ bytes | ~2,500-8,700 ns/op |

## Troubleshooting

### Inconsistent Benchmark Results

**Issue:** Multiple benchmark runs produce varying iteration counts.

**Solution:** Use `-benchtime=5s` to stabilize measurements:

```bash
go test -bench=. -benchtime=5s
```

### High `ns/op` Values

**Issue:** Hash computation is slower than expected.

**Action items:**

1. Check Argon2 parameters, including memory, iterations, and parallelism.
2. Profile the code:

```bash
go test -bench=. -cpuprofile=cpu.prof
```

3. Look for bottlenecks in the `sphinxHash` function, especially the 1000-round section.

### Cache Not Working

**Issue:** `Using opcode: SphinxHash=0x10 (cached)` messages are not appearing.

**Solution:** Ensure `TestVectors` runs before benchmarks:

```bash
go test -v -bench=.
```

## Quick Reference

```bash
# Most comprehensive test run
go test -v -bench=. -benchtime=5s -cpuprofile=cpu.prof

# Quick test run without benchmarks
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
different guarantees — there is no longer a single constructor whose
behavior changes based on whether `nil` is passed:

- **`NewSphinxHash(bitSize, salt)` — deterministic, salt required.**
  `salt` must be non-nil and non-empty. Given the same `bitSize` and the
  same `salt`, `GetHash` always returns the same output, regardless of
  process or instance. Passing `nil` or an empty slice now returns an
  error instead of silently substituting randomness. Use this constructor
  anywhere the output must be independently reproducible — transaction
  hashes, block hashes, Merkle leaves/roots, address derivation, and test
  vectors.
- **`NewSphinxHashKeyed(bitSize)` — randomized, no salt argument.**
  Each call generates its own fresh, cryptographically random salt
  internally, so two instances will (with overwhelming probability)
  produce different output for the same input, even across runs. Use
  this constructor for password-storage / MAC-like use cases where
  non-determinism across instances is the point. Do not use it anywhere
  the hash must be reproduced later, unless you also persist the salt via
  `EncodedSalt()`.
- **Test vectors:** always use `NewSphinxHash` with a fixed salt (see
  `generate_vectors.go`), never `NewSphinxHashKeyed`, so vectors stay
  reproducible across runs and machines.

## Dependencies

- `github.com/sphinxfndorg/protocol/src/spxhash/hash` - Main hash implementation
- `golang.org/x/crypto/argon2` - Argon2id key derivation used by both constructors
- `golang.org/x/crypto/hkdf` - HKDF for key derivation
- `golang.org/x/crypto/sha3` - SHAKE256 support

## Running in CI/CD

For continuous integration:

```bash
go test -v -bench=. -benchtime=3s -cover -race
```

This ensures:

- Unit tests pass
- Benchmarks run with stable results
- Code coverage is reported
- Race conditions are detected

## Expected Output

The test output should include:

1. `Using opcode: SphinxHash=0x10` messages
2. `inputLen: X, hash: Y` lines
3. Test vector entries
4. Benchmark results with stable `ns/op` values