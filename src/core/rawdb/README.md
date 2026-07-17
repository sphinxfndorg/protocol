# core/rawdb — design spec (not yet implemented)

## 1. Problem

Right now block/header/tx persistence in Sphinx doesn't have a package the
way Ethereum has `core/rawdb` or Bitcoin Core has its block/chainstate
layout. What exists instead:

- `core/state/database.go` — a generic LevelDB wrapper (`DB.Put/Get/Delete/Has`,
  `ListKeysWithPrefix`). No opinion about what's stored under which key.
- `core/state_db.go` — builds *account* state on top of it with one key
  scheme: `acct:<address>` → JSON `{balance, nonce}`. This part is fine and
  out of scope here.
- `bc.storage *storage.Storage` — the type that actually calls
  `StoreBlock`, `GetBlockByNumber`, reads/writes `chain_state.json` /
  `block_index.json`. This package wasn't shared, but the naming strongly
  suggests block persistence today is file/JSON based, not a keyed database
  with an index.
- `state_db.go`'s `GetTransactionHistory` scans up to 1,000 blocks backwards,
  opening each one, to find transactions for an address — there's no
  tx→block index anywhere. That's the concrete cost of not having this.

`core/rawdb` fixes this: one deterministic key→value schema, over the
LevelDB you already have, for every block-shaped object (header, body,
canonical-chain index, tx lookup index). It does **not** replace `StateDB`
(account state) or the `JournalManager` (crash-safe commit journal) — those
stay as-is. It replaces whatever `storage.Storage` currently does for block
bytes on disk.

## 2. Design goals

1. **One key scheme, one place.** Every key prefix used for block data is
   declared once, in `schema.go`, and nowhere else. No feature invents its
   own ad-hoc key string.
2. **JSON encoding, matching the rest of the codebase.** `BlockHeader` /
   `BlockBody` already have hand-rolled `MarshalJSON`/`UnmarshalJSON` with
   hex-encoded byte fields (see `block.go`). Reuse that — don't introduce
   RLP or a second encoding scheme just for storage.
3. **Height-ordered keys where it matters.** Canonical-index keys use a
   fixed-width, hex-encoded big-endian height so `ListKeysWithPrefix` returns
   results in ascending height order for free — no separate sort step for
   range scans.
4. **Atomic multi-key writes.** Storing a block touches 4+ keys (header,
   body, canonical hash, tx index entries). `database.go` already has
   `DB.NewWriteBatch()` / `WriteBatch.Commit()` — `rawdb.WriteBlock` uses it
   so a crash mid-write can't leave a header with no matching body, or a
   canonical pointer to a block that was never actually written.
5. **Read functions never panic on a missing key.** Every `Read*` function
   returns `(value, bool)` or `(value, error)` distinguishing "not found"
   from "corrupt data" — callers like `GetBlockByNumber` currently return a
   bare `nil` on any failure; that ambiguity moves into this package instead
   of leaking into `Blockchain`.

## 3. Package layout

```
go/src/core/rawdb/
├── schema.go       — every key-prefix constant + key-builder functions
├── header.go        — ReadHeader / WriteHeader / DeleteHeader / HasHeader
├── body.go          — ReadBody / WriteBody / DeleteBody / HasBody
├── block.go          — ReadBlock / WriteBlock / DeleteBlock (composes header+body)
├── canonical.go      — height<->hash index, head pointers
├── txlookup.go       — tx ID -> (block hash, height, index in body)
└── iterator.go       — range helpers: blocks between heights, tx history by address
```

All functions take a `*database.DB` (or a thin `rawdb.Reader`/`rawdb.Writer`
interface over it, for testability) as their first argument — no package-level
global DB handle, so multiple chains/tests can use independent instances.

## 4. Key schema

All keys are strings; heights are encoded as 16 hex characters (8-byte
big-endian, hex-encoded) so they sort correctly and stay human-readable in
logs, matching this codebase's existing hex-everywhere convention.

| Prefix | Full key | Value | Purpose |
|---|---|---|---|
| `hdr:` | `hdr:<hash>` | JSON `BlockHeader` | Header by hash |
| `bdy:` | `bdy:<hash>` | JSON `BlockBody` | Body by hash |
| `H:` | `H:<hex16(height)>` | hash string | Canonical height → hash |
| `h:` | `h:<hash>` | hex16(height) | Reverse: hash → height |
| `tx:` | `tx:<txID>` | JSON `TxLookupEntry` | tx ID → locate its block |
| `head:block` | `head:block` | hash string | Current chain tip |
| `head:header` | `head:header` | hash string | Current header-chain tip (usually == head:block; kept distinct in case header sync ever runs ahead of body sync) |
| `genesis:hash` | `genesis:hash` | hash string | Genesis block hash, written once, never overwritten |

`TxLookupEntry`:

```go
type TxLookupEntry struct {
    BlockHash   string `json:"block_hash"`
    BlockHeight uint64 `json:"block_height"`
    Index       int    `json:"index"` // position within BlockBody.TxsList
}
```

None of these collide with the existing `acct:`, `supply:total`,
`supply:genesis`, `supply:rewards` keys used by `StateDB` — same LevelDB
instance, disjoint namespaces.

## 5. Function surface

```go
// header.go
func WriteHeader(db *database.DB, h *types.BlockHeader) error
func ReadHeader(db *database.DB, hash string) (*types.BlockHeader, error) // error wraps "not found"
func HasHeader(db *database.DB, hash string) bool
func DeleteHeader(db *database.DB, hash string) error

// body.go
func WriteBody(db *database.DB, hash string, b *types.BlockBody) error
func ReadBody(db *database.DB, hash string) (*types.BlockBody, error)
func HasBody(db *database.DB, hash string) bool
func DeleteBody(db *database.DB, hash string) error

// block.go
func WriteBlock(db *database.DB, block *types.Block) error   // atomic: header+body+canonical+txindex
func ReadBlock(db *database.DB, hash string) (*types.Block, error)
func DeleteBlock(db *database.DB, hash string) error          // atomic: reverse of WriteBlock

// canonical.go
func WriteCanonicalHash(db *database.DB, height uint64, hash string) error
func ReadCanonicalHash(db *database.DB, height uint64) (string, error)
func ReadHeightByHash(db *database.DB, hash string) (uint64, error)
func WriteHeadBlockHash(db *database.DB, hash string) error
func ReadHeadBlockHash(db *database.DB) (string, error)
func WriteHeadHeaderHash(db *database.DB, hash string) error
func ReadHeadHeaderHash(db *database.DB) (string, error)
func WriteGenesisHash(db *database.DB, hash string) error      // no-op (returns error) if already set to a different value
func ReadGenesisHash(db *database.DB) (string, error)

// txlookup.go
func WriteTxLookupEntries(db *database.DB, block *types.Block) error // called from WriteBlock, also exposed standalone for backfill/reindex
func ReadTxLookupEntry(db *database.DB, txID string) (*TxLookupEntry, error)
func DeleteTxLookupEntries(db *database.DB, block *types.Block) error

// iterator.go
func ReadBlocksByHeightRange(db *database.DB, from, to uint64) ([]*types.Block, error)
func ReadCanonicalHashRange(db *database.DB, from, to uint64) ([]string, error)
```

`WriteBlock` is the one entry point that matters operationally — it's what
`executor.go`'s `CreateBlock`/commit path and `chain_maker.go`'s
`ApplyCheckpointBlocks` would call instead of today's
`bc.storage.StoreBlock(block)`. Internally:

```go
func WriteBlock(db *database.DB, block *types.Block) error {
    hash := block.GetHash()
    batch := db.NewWriteBatch()

    headerJSON, err := json.Marshal(block.Header)
    if err != nil { return fmt.Errorf("rawdb: marshal header: %w", err) }
    batch.Put(headerKey(hash), headerJSON)

    bodyJSON, err := json.Marshal(&block.Body)
    if err != nil { return fmt.Errorf("rawdb: marshal body: %w", err) }
    batch.Put(bodyKey(hash), bodyJSON)

    batch.Put(canonicalKey(block.GetHeight()), []byte(hash))
    batch.Put(heightLookupKey(hash), []byte(encodeHeight(block.GetHeight())))

    for i, tx := range block.Body.TxsList {
        if tx == nil { continue }
        entry := TxLookupEntry{BlockHash: hash, BlockHeight: block.GetHeight(), Index: i}
        data, err := json.Marshal(entry)
        if err != nil { return fmt.Errorf("rawdb: marshal tx lookup %s: %w", tx.ID, err) }
        batch.Put(txLookupKey(tx.ID), data)
    }

    return batch.Commit() // single atomic LevelDB write
}
```

## 6. What this fixes concretely

- **`GetTransactionHistory`** (`state_db.go`) currently walks up to 1,000
  blocks backwards per call. With `ReadTxLookupEntry`, a wallet/explorer
  lookup for "all txs involving address X" still needs *some* index by
  address (see §8, open question) — but "find the block a given tx ID is
  in" becomes O(1) instead of O(blocks scanned).
- **`GetBlockByNumber`/`GetBlockByHash`** (`blockchain.go`, `utils.go`)
  become thin wrappers over `ReadCanonicalHash` + `ReadBlock` /
  `ReadBlock` directly, instead of whatever in-memory-slice-plus-file-lookup
  they do today.
- **Startup/restart** — `ReadHeadBlockHash` + `ReadCanonicalHash` gives you
  the tip and full canonical chain without replaying `block_index.json`.
- **Reorgs** — disconnecting a block is `DeleteBlock` (removes header, body,
  canonical pointer, tx lookups) in one atomic batch; connecting is
  `WriteBlock`. `chain_maker.go`'s reorg journal already tracks *which*
  blocks to disconnect/connect — it would call into this package to actually
  do it, instead of hand-rolling file deletes.

## 7. What this deliberately does NOT do

- No receipts. Sphinx transactions don't currently produce a separate
  receipt object (gas used, logs, status) distinct from the transaction
  itself — if/when they do, `receipt.go` + a `rcpt:` prefix slots into this
  same schema without disturbing anything above.
- No freezer/ancient-store split. Ethereum moves data older than the
  reorg window into flat append-only files so LevelDB doesn't grow
  unboundedly; that's a real concern at mainnet scale but premature for
  devnet/testnet. Noted as future work, not designed here.
- No change to `StateDB` (account balances/nonces) or `JournalManager`
  (crash-safe commit journal) — both stay exactly as they are.

## 8. Open questions before implementation

1. **Address→tx index or not?** `ReadTxLookupEntry` answers "where is tx
   `X`" in O(1), but "all txs involving address `Y`" still needs either (a)
   keeping the current backward block scan for that specific query, or (b)
   an additional `addrtx:<address>:<height>:<txID> -> {}` index written
   alongside the tx lookup entries in `WriteBlock`. (b) is more writes per
   block; (a) keeps `GetTransactionHistory` as-is but bounded/slow. Which do
   you want?
2. **Does `storage.Storage` need to keep existing on-disk formats for
   backward compatibility** (i.e. do currently-running devnet nodes need a
   migration path from `block_index.json`/file-per-block into this schema),
   or is a clean cutover acceptable since devnet can be wiped?
3. **Where does `WriteBlock` get called from** — should it fully replace
   `bc.storage.StoreBlock`, or sit underneath it (i.e. `storage.Storage`
   keeps its current external API but delegates the actual disk write to
   `rawdb.WriteBlock`)? I'd default to the latter (smallest blast radius),
   but it depends on what `storage.Storage` looks like today, which I don't
   have.

Once these are answered I'll implement `core/rawdb` against your actual
`database.DB` (already have it) and, ideally, the real `storage.Storage`
source so `WriteBlock`/`ReadBlock` slot in without guessing at its current
external contract.