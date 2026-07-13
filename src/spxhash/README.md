# SpxHash Benchmark Analysis

## Overview

This document records the SpxHash test-vector output and benchmark comparison against SHA-512/256.

Based on the benchmark results, **SpxHash is not faster than SHA-512/256 for small inputs**. SpxHash has a higher fixed cost because it uses Argon2 key derivation, repeated mixing rounds, and multiple hash functions. The gap narrows as input size grows, and SpxHash can become competitive for larger inputs.

## Test Command

```bash
go test -v -bench=. -cpuprofile=cpu.prof
```

The captured run completed successfully:

```text
PASS
ok      github.com/sphinxfndorg/protocol/src/spxhash/testvc    21.007s
```

## Test Vectors

The test run generated the following SpxHash outputs:

| Input Length | Hash |
|---:|---|
| 0 | `56e5cb4244edd633a76ea4a63ab21ac7590e8773b4e23baac7cbc7135b035297` |
| 1 | `2af7c7d05bc732f9de7419584c33a10eb915764d062e6006edbc5489c1f9503e` |
| 1023 | `ce7112cb19705cc64ce1b2b23c1fff233dfb90d0c80bcb2efaed263a846b899a` |
| 1024 | `c7d42022a989a7f1905b279323d1ae757da51b38817459d741b9a6c6c71a93a0` |
| 2048 | `a5dc8a410b85caaf17a77b4bbe55d3a33b4dbc72d2ad8731d433c10f78af1e96` |
| 4096 | `f9bca90ff831e41cdd8400a321191fccb122cbf007c9c284faac8420efdb734e` |

## Structured Vector Output

```text
<vector inputLen=0 hash=56e5cb4244edd633a76ea4a63ab21ac7590e8773b4e23baac7cbc7135b035297 keyedHash=c098615604bb025f47999595c04e030f364e5435a7577d7ababb03a271e9989e deriveKey=be538a2f83a53f6d4665e56557f43acf90ba82f97fa5d7bf746be24370054ca0>
<vector inputLen=1 hash=2af7c7d05bc732f9de7419584c33a10eb915764d062e6006edbc5489c1f9503e keyedHash=ea27697ab40a291b93dc90c1618337974d06462882918405420871911fcb29ec deriveKey=be538a2f83a53f6d4665e56557f43acf90ba82f97fa5d7bf746be24370054ca0>
<vector inputLen=1023 hash=ce7112cb19705cc64ce1b2b23c1fff233dfb90d0c80bcb2efaed263a846b899a keyedHash=8002a9d0715ee58d3e796d0a2474c7eaefb5d38544d2e7ca4e1c636b9e2ddfce deriveKey=3e9251161692adb640c8dd76685c50c048297fe3360828e16c912f429c397bab>
<vector inputLen=1024 hash=c7d42022a989a7f1905b279323d1ae757da51b38817459d741b9a6c6c71a93a0 keyedHash=a5e689a6065c86606c29be00b70d9fb777ef8273c212a8caa574dd51dd39a714 deriveKey=353ff083ae5cbbe9ccb806be665e3136ebd78bfb3fe82103b249934127a53f9f>
<vector inputLen=2048 hash=a5dc8a410b85caaf17a77b4bbe55d3a33b4dbc72d2ad8731d433c10f78af1e96 keyedHash=1b8dbedc8bb976b4a5b5eae089397f6c0db4f3ece3159b917774ee6e2a26d6d1 deriveKey=7f9ea132acaf84f492804b9dc11f0e08f8fa38907394ea9a1094b52568eb0acf>
<vector inputLen=4096 hash=f9bca90ff831e41cdd8400a321191fccb122cbf007c9c284faac8420efdb734e keyedHash=950c63a2454e97c3a12e78804c23c65944436b53b1f513fbf72d874f22446995 deriveKey=3c4416bedf98988efd9a0ce301d7317c4548d95514e680d334727ab98167ae00>
```

## Benchmark Results

Only the final high-iteration benchmark rows are used for comparison. Early benchmark rows with `b.N = 1`, `100`, or `10000` are warm-up and calibration runs.

| Input Size | SpxHash (ns/op) | SHA-512/256 (ns/op) | Result |
|---:|---:|---:|---|
| 0 bytes | 4,909.421180 | 371.875256 | SpxHash is **13.20x slower** |
| 1 byte | 4,896.340497 | 373.999618 | SpxHash is **13.09x slower** |
| 1,023 bytes | 4,642.113743 | 2,529.907787 | SpxHash is **1.83x slower** |
| 1,024 bytes | 4,671.465734 | 2,456.479531 | SpxHash is **1.90x slower** |
| 2,048 bytes | 4,612.987844 | 4,502.802242 | SpxHash is **1.02x slower** |
| 4,096 bytes | 4,653.949254 | 8,675.261782 | SpxHash is **1.86x faster** |

## Key Findings

### Small Inputs

For 0-byte and 1-byte inputs, SpxHash is about **13x slower** than SHA-512/256.

This is expected because SpxHash has fixed overhead from Argon2, repeated mixing rounds, SHA-512/256, and SHAKE256.

### Medium Inputs

For inputs around 1 KB, SpxHash is still slower, but the gap drops below 2x.

At 2 KB, the two implementations are nearly equal:

- SpxHash: `4,612.987844 ns/op`
- SHA-512/256: `4,502.802242 ns/op`

### Larger Inputs

At 4 KB, SpxHash is faster in this benchmark:

- SpxHash: `4,653.949254 ns/op`
- SHA-512/256: `8,675.261782 ns/op`

This happens because SHA-512/256 scales with input size, while SpxHash is dominated by fixed overhead.

## CPU Profile

The run also generated a CPU profile:

```text
File: testvc.test
Type: cpu
Time: 2025-07-30 03:47:15 WIB
Duration: 18.68s
Total samples = 9.54s (51.08%)
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

The test vectors are now stable and deterministic. All test runs with `ProtocolSalt` produce consistent results. The previous variability was due to earlier test runs using different salt configurations before the deterministic `ProtocolSalt` was standardized.

## Recommendations

### Use SpxHash When

- Input sizes are usually larger than 2 KB.
- Memory-hardness is required.
- Security is more important than raw hashing speed.
- Consistent runtime across variable input sizes is useful.
- Repeated hash calls benefit from caching.

### Use SHA-512/256 When

- Input sizes are usually smaller than 1 KB.
- Low latency is important.
- High-throughput hashing is required.
- CPU and memory usage must stay low.
- Memory-hardness is not required.

## Optimization Opportunities

### Reduce Mixing Rounds

```go
// Current: 1000 rounds
// Consider reducing only if acceptable for the security model.
rounds := 500
```

### Tune Argon2 Parameters

```go
const (
    memory     = 8 * 1024
    iterations = 1
)
```

Reducing Argon2 memory or iteration count can improve speed, but it also reduces memory-hardness.

### Batch Inputs

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

## Summary

SpxHash is **not faster than SHA-512/256 for small inputs**. For inputs below roughly 2 KB, SHA-512/256 is the faster choice.

SpxHash becomes competitive around 2 KB and was faster at 4 KB in this benchmark. The trade-off is security versus speed:

- **SpxHash** provides memory-hardness through Argon2, but has higher fixed overhead.
- **SHA-512/256** is faster for small inputs and better suited for high-throughput workloads.

For most blockchain or cryptocurrency workloads where inputs are commonly below 1 KB, SHA-512/256 will usually be significantly faster. For large data hashing or cases where memory-hardness is required, SpxHash is a viable option.
