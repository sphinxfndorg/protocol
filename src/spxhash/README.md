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
ok      github.com/sphinxorg/protocol/src/spxhash/testvc    21.007s
```

## Test Vectors

The test run generated the following SpxHash outputs:

| Input Length | Hash |
|---:|---|
| 0 | `c20f4bc14267aad693be2bb6e9799675ec4c494c654a6ad275b3124ae3182782` |
| 1 | `350a3ccb38261de839186ee3faf07ce6582cc4255edadba80e9afc29889a2a25` |
| 1023 | `080afb7b8fa2f060d639a75968a56ccbf7ccafa73f17a04a837bbcc0d71798c3` |
| 1024 | `c05d1a039284c225a7e2c62a3f5b55e513772526e436e8795314ed75c52263e6` |
| 2048 | `474d4f92c82cc17d428f310153ef88b2ef9564c85f89e3b0b8e84df2a806365c` |
| 4096 | `0182389897ec0a966907c29a08f157581fef96b475c35b7d98914d2630c31090` |

## Structured Vector Output

```text
<vector inputLen=0 hash=c20f4bc14267aad693be2bb6e9799675ec4c494c654a6ad275b3124ae3182782 keyedHash=c098615604bb025f47999595c04e030f364e5435a7577d7ababb03a271e9989e deriveKey=6012eaca7a9daf58879ab88bb04fdecf36774425a22074274605b50a5ce0b6f6>
<vector inputLen=1 hash=350a3ccb38261de839186ee3faf07ce6582cc4255edadba80e9afc29889a2a25 keyedHash=ea27697ab40a291b93dc90c1618337974d06462882918405420871911fcb29ec deriveKey=6012eaca7a9daf58879ab88bb04fdecf36774425a22074274605b50a5ce0b6f6>
<vector inputLen=1023 hash=080afb7b8fa2f060d639a75968a56ccbf7ccafa73f17a04a837bbcc0d71798c3 keyedHash=8002a9d0715ee58d3e796d0a2474c7eaefb5d38544d2e7ca4e1c636b9e2ddfce deriveKey=91c42dbe900f6de7d935d03c9b4353e85af0ec3a2dc6855afcabf4c389156a61>
<vector inputLen=1024 hash=c05d1a039284c225a7e2c62a3f5b55e513772526e436e8795314ed75c52263e6 keyedHash=a5e689a6065c86606c29be00b70d9fb777ef8273c212a8caa574dd51dd39a714 deriveKey=c94bb9e8fe57faa53c52166f203ddbcc7fd7b4f981c331f238e8e83c28cc7f4d>
<vector inputLen=2048 hash=474d4f92c82cc17d428f310153ef88b2ef9564c85f89e3b0b8e84df2a806365c keyedHash=1b8dbedc8bb976b4a5b5eae089397f6c0db4f3ece3159b917774ee6e2a26d6d1 deriveKey=c423e784acd3624b2b1bdf929e881132d8613aadffc5f2630e95b979e882e423>
<vector inputLen=4096 hash=0182389897ec0a966907c29a08f157581fef96b475c35b7d98914d2630c31090 keyedHash=950c63a2454e97c3a12e78804c23c65944436b53b1f513fbf72d874f22446995 deriveKey=6191b71d1a551df206de55b3563e266f656234c1d7ecb0194fef8c1c8a650eb0>
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

The pasted output includes additional later runs where the SpxHash values changed:

- First run, `inputLen=0`: `c20f4bc14267aad693be2bb6e9799675ec4c494c654a6ad275b3124ae3182782`
- Later run, `inputLen=0`: `875bb731c84bd2813a30618e4214e3678e4ea2a900f63175ff6484b44e1d0d87`
- Later run, `inputLen=0`: `56e5cb4244edd633a76ea4a63ab21ac7590e8773b4e23baac7cbc7135b035297`

This indicates that part of the hash flow is using a changing salt, seed, or derived key. If stable test vectors are required, the implementation should use fixed deterministic inputs for every value that contributes to the final hash.

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
