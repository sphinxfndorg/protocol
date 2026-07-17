# core/bloom

A reusable, Ethereum-`logsBloom`-inspired probabilistic membership filter.
Zero blockchain dependencies — operates purely on `[]byte` keys, so it can be
embedded in a block header, an index file, a cache layer, or any other
application that needs a fast "definitely not present" / "maybe present"
membership test.

Blockchain-specific logic (deciding *which* objects to insert — sender
addresses, tx IDs, contract addresses) intentionally does **not** live here.
It lives in `core/transaction/bloomindex.go` and `bloomquery.go`, which import
this package. Keeping the dependency one-directional (`transaction -> bloom`,
never `bloom -> transaction`) is what lets `BlockHeader` hold a Bloom filter
without an import cycle.

## Install / import

```go
import "github.com/sphinxfndorg/protocol/src/core/bloom"
```

## Bloom filter in Sphinx

Sphinx uses this the same way Ethereum uses `logsBloom` — not as a wallet
feature, but as a field inside every block header.

Each Sphinx block header carries:

```
LogsBloom []byte  // 256 bytes = 2048 bits
```

### What is stored

Whenever a block is assembled, every transaction in it contributes:

- `Sender` — the address that sent it
- `Receiver` — the address that received it
- `ToContract` — the contract address, if it's a contract call
- `ID` — the transaction hash itself

into the filter. Nothing else about the transaction is stored in the Bloom
filter — no amount, no timestamp, no signature. It only records *fingerprints*
of these four fields, so `Contains()` can answer "might this address/tx be in
this block?" without needing the full block body in hand.

Suppose block 100 contains:

```
tx1: xAlice  -> xBob
tx2: xCarol  -> xDave
tx3: xEve    -> xContract123
```

`BuildBlockBloomFilter` adds six keys to the filter: `xAlice`, `xBob`,
`xCarol`, `xDave`, `xEve`, `xContract123` (plus the three tx IDs). The filter
itself doesn't remember *which* transaction each address came from, or how
many times — it just remembers that these bytes were added, in 2048 bits
shared by all of them.

### Why: the search problem this solves

Say a wallet or explorer wants to answer: *"has address `xAlice` ever sent or
received a transaction?"* The naive way:

```
for every block in the chain:
    for every transaction in the block:
        if tx.Sender == "xAlice" or tx.Receiver == "xAlice":
            found it
```

That's a full transaction scan of every block, forever, for one address
lookup. With the Bloom filter embedded in each header, the check becomes:

```
for every block in the chain:
    if !block.Header.MayContainAddress("xAlice"):
        skip block            # cheap: one filter check, no body needed
    else:
        open block body        # only now read actual transactions
        confirm xAlice really is in it
```

`MayContainAddress` only needs the 256-byte header field already in memory —
it never touches the block body. Opening the body (`BlockContainsAddress`) is
the expensive part, and the filter's job is to make sure you almost never do
that for a block that doesn't actually involve the address.

### Worked example

Chain has 1,000,000 blocks. You're looking for every block `xAlice` appears
in.

**Without a Bloom filter:**

```
1,000,000 blocks
      │
      ▼
open every block body
scan every transaction inside
      │
      ▼
~1,000,000 full block reads
```

**With the Bloom filter:**

```
1,000,000 blocks
      │
      ▼
check block.Header.MayContainAddress("xAlice")
      │
   ┌──┴──┐
   No          Maybe
   │            │
 skip        open block body
(cheap)      BlockContainsAddress("xAlice")
             │
          ┌──┴──┐
        true    false (rare false positive)
        │         │
      record    skip
      match
```

At `BloomBits = 2048`, `HashFunctions = 3`, and a typical few-hundred keys per
block, the false-positive rate is roughly 1–2% (see the math in
`config.go`). So instead of opening all 1,000,000 block bodies, you open
roughly the number of blocks that actually contain `xAlice`, plus a ~1-2%
sliver of blocks that don't (which `BlockContainsAddress` then correctly
rules out). The header-only check is orders of magnitude cheaper than a body
read, so this turns an O(all blocks × all txs) scan into something close to
O(blocks that matter).

### Code

```go
for height := uint64(0); height <= tip; height++ {
    header := chain.GetHeaderByHeight(height)

    if !header.MayContainAddress("xAlice") {
        continue // header says "definitely not" — skip, no I/O for the body
    }

    block := chain.GetBlockByHeight(height) // now pay the cost
    if block.BlockContainsAddress("xAlice") {
        matches = append(matches, block)
    }
}
```

## Quick start

```go
bf := bloom.NewDefault()

bf.Add([]byte("xAbc123..."))       // insert a sender address
bf.Add([]byte("txid-0001"))        // insert a transaction id

bf.Contains([]byte("xAbc123..."))  // true
bf.Contains([]byte("someone-else")) // false, or rarely a false positive
```

A `false` result from `Contains` is certain. A `true` result may be a false
positive — always verify against the real data before trusting it (see
`core/transaction/bloomquery.go`'s `MayContainAddress` + `BlockContainsAddress`
pattern).

## Files

| File | Contents |
|---|---|
| `config.go` | `BloomBits` (2048), `BloomBytes` (256), `HashFunctions` (3) — the consensus-critical defaults — plus `Config`/`Validate()` for custom (non-consensus) filters. |
| `bitset.go` | Unexported `bitset`: `SetBit`/`GetBit`/`ClearBit`/`CountBits`/`ResetBits`, `or()`, `clone()`. Out-of-range indices are silent no-ops, never panics. |
| `hash.go` | `positions(key, bits, k)` — deterministic bit-position generator using the Kirsch–Mitzenmacher double-hashing construction over SHA-256 and SHA3-256. |
| `bloom.go` | The public `BloomFilter` type: `New`, `NewDefault`, `Add`, `Contains`, `Merge`, `Reset`, `Copy`, `Config`, `CountBits`. Safe for concurrent use (many readers, one writer). |
| `serialize.go` | `Bytes`/`Load`/`LoadFilter` for the raw wire format, plus `MarshalBinary`/`UnmarshalBinary`/`MarshalJSON`/`UnmarshalJSON`. |

Tests: `bitset_test.go`, `hash_test.go`, `bloom_test.go`, `serialize_test.go`,
`benchmark_test.go`, `fuzz_test.go`.

## Design notes

**Double hashing, not k hash functions.** A textbook Bloom filter wants `k`
independent hashes per key. Instead of computing `k` full digests, this
package computes exactly one SHA-256 and one SHA3-256 digest per key and
derives all `k` positions from those two via `position_i = (h1 + i*h2) mod m`
(Kirsch & Mitzenmacher, 2006). Same guarantees, a fraction of the hashing
cost.

**Determinism is the whole point.** `positions()` is a pure function of its
input — no salt, no seed. Every node computes byte-identical filters for the
same block, which is what makes header-embedded Bloom filters usable for
consensus at all.

**No false negatives, ever.** If a key was `Add()`-ed, `Contains()` is
guaranteed to return `true`. This is the one property every test file in this
package (including the fuzz tests) checks first.

**2048 bits / k=3 are consensus parameters.** `DefaultConfig()` is what every
block-header filter across the network must use — changing it changes wire
size and hash positions, i.e. a coordinated hard fork. `NewConfig()` exists
for non-consensus, out-of-protocol uses (e.g. an explorer's secondary index)
that want a different size/k without touching the network default.

**Concurrency lives in `bloom.go`, not `bitset.go`.** `bitset` has no mutex —
it's a low-level, single-owner primitive. `BloomFilter` wraps it with a
`sync.RWMutex` at the layer where the actual access pattern (many concurrent
readers querying a finalized block, one writer building it) is known.

## How this plugs into the blockchain

- `core/transaction/bloomindex.go` — `BuildBlockBloomFilter(body)` scans a
  block's transactions (`Sender`, `Receiver`, `ToContract`, `ID`) and returns
  a populated filter; `BlockHeader.SetBloomFilter` / `DecodeBloomFilter`
  convert to/from the header's `LogsBloom []byte` field.
- `core/transaction/bloomquery.go` — `MayContainAddress`/`MayContainTxID`
  (cheap, probabilistic) and `BlockContainsAddress` (definitive body scan).
- `core/executor.go` (`CreateBlock`) and `core/genesis.go` (`BuildBlock`) call
  `Block.PopulateLogsBloom()` exactly once, right after the transaction list
  is finalized and before the block hash is computed — never inside the
  nonce-mining loop, since building a filter scans every transaction and must
  not be repeated per nonce attempt.
- `LogsBloom` is included in both `GenerateBlockHash` and `FinalizeHash`'s
  hash input, so this is a consensus-breaking change requiring a coordinated
  network upgrade, not something that can roll out node-by-node.

## Testing

```bash
go build ./...
go vet ./...
gofmt -l .
go test ./...
go test -race ./...
go test -fuzz=FuzzAddContains -fuzztime=30s .
```

All of the above pass as of this package's last verification (build, vet,
gofmt, full unit suite, race detector, and a fuzzing run each for
`Add`/`Contains`, `Load` round-tripping, and `positions()` range safety).