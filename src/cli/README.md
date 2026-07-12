# Sphinx Blockchain CLI — Node Networking & Synchronization

## Overview

This document explains how Sphinx blockchain nodes discover each other, synchronize blockchain data, and participate in PBFT consensus. A node can **join at any time** and always synchronizes with the existing network — there is no requirement for all nodes to start simultaneously.

### Peer Discovery Architecture (Current)

Sphinx uses a **hybrid** of static seeds, peer exchange (PEX), and Kademlia DHT iterative lookups. All three are now active:

| Mechanism | Type | Status |
|---|---|---|
| EIP-1459 DNS discovery (`enrtree://`) | Authenticated bootstrap via DNS TXT records | ✅ Implemented (`p2p/seed` package resolves DNS trees) |
| Static seed addresses (`--seeds=IP:PORT`) | Plain TCP bootstrap | ✅ Implemented |
| Peer exchange (PEX) — "ask a peer who they know" | Gossip-based peer list sharing | ✅ Implemented (`requestPeerListSync` / `discoverAndRegisterPeers`) |
| Kademlia DHT iterative lookup / routing | Ethereum-style discv4/discv5 | ✅ **Wired up** — `StartNode` creates a `dht.DHT` instance bound to the node's UDP port, seeded with `--seeds` addresses as routers, and passes it to `NodeManager` for `FindClosestPeers` / iterative routing |

**What this means in practice:**  
Sphinx bootstraps via DNS tree or static seeds (like Ethereum), discovers peers-of-peers via PEX gossip (like Bitcoin), and additionally performs Kademlia iterative lookups against the routing table (like Ethereum's discv4). The `--seeds` addresses serve a dual role: they are used both as plain TCP bootstrap targets for the initial key exchange + block sync, and as UDP router addresses for the DHT join request. On a real device network, the routing table fills organically as the DHT processes ping/pong/find-node responses.

---

## Architecture: Three Separate Responsibilities

The node lifecycle separates three distinct concerns:

| Phase | What Happens | PBFT Required? |
|-------|-------------|----------------|
| **Bootstrap** | Load or create genesis block | ❌ No — trusted setup |
| **Synchronization** | Download and verify existing chain from peers | ❌ No — historical sync |
| **Consensus** | Participate in PBFT for new blocks | ✅ Yes — ≥3 validators |

This separation is critical. A node must always be able to synchronize historical state **without** participating in consensus.

---

## How Genesis Works

### First Node (Node-A)

When the very first node starts:

1. No blockchain data exists locally
2. The node creates the **genesis block** (block 0) using hardcoded parameters
3. The genesis block is a **trusted setup** — it does NOT require:
   - Any peer connection
   - PBFT quorum
   - Validator approval
4. Node-A immediately starts mining **block 1** and subsequent blocks **solo** (without PBFT)

```
Node-A starts
  ↓
No existing chain found
  ↓
Create genesis block (trusted setup, no quorum needed)
  ↓
Mine block 1 (solo mode, no peers required)
  ↓
Mine block 2, 3, 4... (solo mode)
  ↓
Wait for other nodes to join
```

### Why Genesis Is Trusted

The genesis block is compiled into the binary. Every node produces the **same genesis hash** from the same parameters (timestamp, difficulty, gas limit, extra data, allocations). This means:

- All nodes agree on genesis without any communication
- A peer with a different genesis hash is on a fundamentally incompatible chain
- Genesis hash is verified during the key exchange handshake — mismatches are rejected

---

## How Late Joiners Work

### Node-B Joins (Minutes, Hours, or Days Later)

When a second node starts:

1. Node-B detects it has no local blockchain data
2. It connects to Node-A (or any seed peer) via TCP
3. It performs a **key exchange** that includes genesis hash verification
4. It requests the genesis block from Node-A
5. It requests all missing blocks in **batches of 500**
6. Each block is verified before being committed locally
7. Once caught up, Node-B enters **periodic monitoring mode**

```
Node-B starts (late joiner)
  ↓
No local chain — late joiner mode activated
  ↓
Connect to seed peer (Node-A)
  ↓
Key exchange + genesis hash verification
  ↓
Request genesis block from peer
  ↓
Request blocks 1→N in batches of 500
  ↓
Verify each block (parent hash, attestations, continuity)
  ↓
Commit verified blocks locally
  ↓
Reach CAUGHT_UP state
  ↓
Enter periodic monitoring (re-check every 10 seconds)
  ↓
Wait for more validators (need ≥3 for PBFT)
```

### Node-C Joins (Same Behavior)

Node-C follows the exact same process as Node-B:
- Downloads genesis from any reachable peer
- Downloads all missing blocks
- Verifies and commits each block
- Catches up to the network tip

### Node-D, E, F...N Join (Years Later)

Every subsequent node behaves identically:
- The sync loop **never gives up** — it retries with exponential backoff (up to 5 minutes)
- It tries all known peers until one responds
- It downloads the entire chain from genesis to tip
- It enters periodic monitoring after catching up

---

## Synchronization Protocol

### Block Download (Chunked)

Blocks are downloaded in **batches of 500** to prevent memory pressure and handle disconnections gracefully:

```
GetBlocksRequest{FromHeight: 1, ToHeight: 500}
  ↓
Peer responds with 500 blocks + their tip height
  ↓
Verify each block sequentially
  ↓
Commit each block
  ↓
Repeat: GetBlocksRequest{FromHeight: 501, ToHeight: 1000}
  ↓
...continue until caught up
```

### Block Verification Pipeline

Every downloaded block passes through this verification pipeline **before** being committed:

```
Receive Block
  ↓
Verify previous hash matches local tip
  ↓
Verify block height is contiguous
  ↓
Verify block attestations (PBFT quorum for blocks > 0)
  ↓
Verify parent hash chain continuity
  ↓
Commit block to local storage
```

### Periodic Sync Monitoring

After catching up, the sync loop does **not** exit. It enters a periodic check mode:

```
Every 10 seconds:
  ↓
Query all peers for their chain tip height
  ↓
If any peer has a higher height:
    ↓
  Download missing blocks in batches
    ↓
  Verify and commit
  ↓
If all peers at same height:
    ↓
  Sleep 10 seconds, repeat
```

This ensures nodes stay synchronized without restarting, even after temporary network partitions.

---

## PBFT Consensus Activation

PBFT only activates when **3 or more validators** are connected:

```
1 validator (Node-A alone):
  → Solo mode: mine blocks independently via CommitBlock
  → No PBFT voting needed

2 validators (Node-A + Node-B):
  → Both sync to same height
  → Still not enough for PBFT (need ≥3)
  → Wait for third validator

3+ validators (Node-A + Node-B + Node-C):
  → PBFT activates automatically
  → Leader election begins
  → Block proposals use 2/3 quorum
  → All subsequent blocks use PBFT
```

> **Fixed:** The handoff from solo mining to PBFT is now coordinated rather than racy. Node-A (the bootstrap node) explicitly **stops solo mining → syncs to the latest confirmed tip → then enters PBFT** once the third validator connects. Previously, the bootstrap node could keep mining solo blocks after the validator set reached 3, producing a block that peers never voted on — this is the mechanism that caused forks like the one in the "Block N parent hash mismatch ... stopping batch" symptom.

### Sync State Machine

```
SYNCING
  ↓ (sync loop catches up)
CAUGHT_UP
  ↓ (block production loop transitions)
CONSENSUS_PARTICIPANT
  ↓ (PBFT rounds begin)
Active PBFT validator
```

A node in `SYNCING` state will **never** participate in PBFT rounds. It waits until the sync loop transitions it to `CAUGHT_UP`, then the block production loop transitions it to `CONSENSUS_PARTICIPANT`.

---

## Peer Discovery

### Seed Nodes

Nodes discover each other through:
1. **Static configuration** (Legacy Same-Box Mode only — no `--seeds`, no custom `--tcp-addr`: `--nodes=3` pre-registers the fixed-port peer addresses for that mode)
2. **Seed addresses** (`--seeds=IP:PORT` — plain TCP addresses)
3. **DNS discovery** (`--seeds=enrtree://...` — EIP-1459 authenticated peer lists)

> **Fixed:** `--nodes=3` on its own no longer pre-registers peers as validators. A bootstrap node started without `--seeds` now stays genuinely solo (no phantom peer entries) until a real peer connects and completes key exchange. `--nodes=3` only tells the node how many validators to expect for PBFT quorum math — it does not add validators by itself.

### Key Exchange Handshake

Every peer connection includes a key exchange that verifies:

| Field | Purpose |
|-------|---------|
| `NodeID` | Unique peer identifier |
| `PublicKey` | SPHINCS+ public key for signature verification |
| `RewardAddress` | SPIF wallet address for staking (optional) |
| `GenesisHash` | Peer's claimed genesis block hash |

**If the peer's genesis hash differs from ours, the connection is rejected.** This prevents accidental network splits.

### Peer Exchange (PEX)

After key exchange, nodes ask peers "who else do you know about?" and share their known peer lists. This allows the network to grow organically.

### Validator Registration on Discovery

> **Fixed:** Previously, a discovered peer was only added as a **network/gossip peer** — it was never added to the validator set unless it separately supplied a `RewardAddress` *and* that address had a verified on-chain balance. In test/permissioned setups (no `--reward-address`), neither condition was ever met, so every node's validator set silently stayed at size 1 forever — each node saw itself as the only validator, "won" 100% of its own quorum, and mined its own independent chain.
>
> Discovered peers are now granted **minimum validator stake immediately** upon successful key exchange, so the validator set grows to match the number of connected peers. This is what makes `validators=3` (and real 2-of-3 PBFT quorum) actually reachable in the Quick Test flow below.
>
> ⚠️ This immediate-stake grant is intended for local/test/permissioned networks. If this code path is ever exposed on a public network, it should be gated (e.g. behind a `--test-mode` flag) — as written, any peer that can complete a TCP key exchange gets voting power with no real stake behind it.

---

## Running Tests from Terminal

### About Ports and Data Directories

**The real trigger for "synthetic" (auto-assigned) addressing is whether `--tcp-addr` is provided and differs from the default same-box port — not whether `--nodes=3` is present.** `--nodes=3` only tells the node how many validators to expect for PBFT quorum math; it does not by itself override your address or data directory.

- **If you omit `--tcp-addr`** (or pass a value equal to the hardcoded default `32307 + node-index`), the node falls back to fully synthetic same-box addressing: fixed ports starting at **32307** (TCP) / **32418** (UDP), and `--datadir` is ignored — data always lands in `data/Node-127.0.0.1:<synthetic-port>/`. This is the **Legacy Same-Box Mode** described below.
- **If you explicitly pass `--tcp-addr`** with a port that differs from that default (as in the Quick Test commands below), your address *and* your `--datadir` are both honored exactly as given. This is the normal, recommended mode.

> **Fixed:** Passing a custom `--tcp-addr` (including a custom loopback port, as in the Quick Test commands below) used to also incorrectly collapse the node's internal validator/peer address list down to size 1 — as if it were a single, isolated node — even though the address itself was handled correctly. That collapse only happens now for a genuine public/real network address; custom loopback ports no longer trigger it. This was the actual root cause behind nodes never seeing each other as validators in the Quick Test flow, and is distinct from the address/datadir handling described above.

> ⚠️ **The single most common setup mistake:** giving two or more terminals the **same `--datadir`**. Each node's data directory must be unique to that node — `data/node1` for node 1, `data/node2` for node 2, and so on. Reusing one `--datadir` across terminals doesn't corrupt anything (each node's data still lands in its own `Node-<address>` subfolder, since that subfolder is keyed by address, not by whatever base dir you gave it) — but it does mean you'll find every node's storage nested under one confusingly-named folder instead of separated the way you intended. Before starting multiple nodes, double check: **one terminal → one `--tcp-addr` → one matching, unique `--datadir`.**

To use custom ports and data directories, use **seed-based mode** (`--seeds=`) which operates like real blockchain nodes: a late joiner connects to a seed, downloads the chain, then discovers additional peers via PEX gossip.

### ⚡ Quick Test: Seed-Based Mode (Recommended)

This approach uses `--seeds=` to point late joiners at the first node. On a real network, DNS discovery and PEX gossip propagate peer information after the initial seed connection.

**Important:** When testing on localhost (127.0.0.1), the CLI detects loopback addresses and requires `--nodes=3` even with `--seeds`. On real machines with public IPs, `--nodes=3` is not needed.

**Before you open any terminals, write down the mapping below and keep it visible.** Every value in the "changes per node" columns must be different in every terminal — this is the table that would have caught the `--datadir` mix-up:

| Terminal | `--tcp-addr` | `--http-port` | `--datadir` | `--node-index` |
|----------|-------------|---------------|-------------|----------------|
| 1 | `127.0.0.1:30303` | `127.0.0.1:8545` | `data/node1` | `0` |
| 2 | `127.0.0.1:30304` | `127.0.0.1:8546` | `data/node2` | `1` |
| 3 | `127.0.0.1:30305` | `127.0.0.1:8547` | `data/node3` | `2` |
| 4 | `127.0.0.1:30306` | `127.0.0.1:8548` | `data/node4` | *(none — see below)* |

**Terminal 1 — First validator (creates genesis, mines solo):**
```bash
cd Desktop/protocol
go run src/cli/main.go node --role=validator \
    --tcp-addr=127.0.0.1:30303 \
    --http-port=127.0.0.1:8545 \
    --datadir=data/node1 \
    --nodes=3 --node-index=0 \
    --pbft
```

**Expected:** Creates genesis, starts mining blocks solo without waiting for peers.

**Terminal 2 — Second validator (late joiner, connects via --seeds):**

Wait for Node-1 to produce a few blocks, then:

> `--datadir=data/node2` and `--tcp-addr=127.0.0.1:30304` must both differ from Terminal 1 — that's the pairing that gets mixed up most often.

```bash
cd Desktop/protocol
go run src/cli/main.go node --role=validator \
    --tcp-addr=127.0.0.1:30304 \
    --http-port=127.0.0.1:8546 \
    --datadir=data/node2 \
    --nodes=3 --node-index=1 \
    --seeds=127.0.0.1:30303 \
    --pbft
```

**Expected:** Downloads genesis + all blocks from Node-1, catches up, enters periodic monitoring.

**Terminal 3 — Third validator (PBFT activates):**
```bash
cd Desktop/protocol
go run src/cli/main.go node --role=validator \
    --tcp-addr=127.0.0.1:30305 \
    --http-port=127.0.0.1:8547 \
    --datadir=data/node3 \
    --nodes=3 --node-index=2 \
    --seeds=127.0.0.1:30303 \
    --pbft
```

**Expected:** Syncs, all 3 validators connect, PBFT activates for block 2+.

**Terminal 4 — Fourth node (joins established network):**
```bash
cd Desktop/protocol
go run src/cli/main.go node --role=validator \
    --tcp-addr=127.0.0.1:30306 \
    --http-port=127.0.0.1:8548 \
    --datadir=data/node4 \
    --seeds=127.0.0.1:30303 \
    --pbft
```

**Expected:** Syncs full chain from any peer, catches up, joins existing PBFT.

> **Note:** `--nodes=3` is only needed for localhost testing. On real machines with public IPs, omit `--nodes` and `--node-index` — the validator set is discovered dynamically via `--seeds`.

### Legacy Same-Box Mode (Fixed Ports)

This mode uses hardcoded ports (32307, 32308, 32309) and auto-generated data directories (`data/Node-127.0.0.1:32307/`, etc.) regardless of `--datadir` and `--tcp-addr` flags. Each `--node-index` maps to a specific port.

> **Fixed:** Each node's list of *peer* addresses in this mode used to be computed from a hardcoded base of `32307`, which broke if a node's own port didn't start from that base. Peer addresses are now derived as `port - node-index`, so the peer list is correct regardless of which port a given node actually bound to.

**Terminal 1 — Node-index 0 (port 32307):**
```bash
go run src/cli/main.go node --role=validator \
    --http-port=127.0.0.1:8545 \
    --datadir=data \
    --nodes=3 \
    --node-index=0 \
    --pbft
```

**Terminal 2 — Node-index 1 (port 32308):**
```bash
go run src/cli/main.go node --role=validator \
    --http-port=127.0.0.1:8546 \
    --datadir=data \
    --nodes=3 \
    --node-index=1 \
    --pbft
```

**Terminal 3 — Node-index 2 (port 32309):**
```bash
go run src/cli/main.go node --role=validator \
    --http-port=127.0.0.1:8547 \
    --datadir=data \
    --nodes=3 \
    --node-index=2 \
    --pbft
```

Data will be stored in:
- `data/Node-127.0.0.1:32307/` (node-index=0)
- `data/Node-127.0.0.1:32308/` (node-index=1)
- `data/Node-127.0.0.1:32309/` (node-index=2)

### Verify Your Data Directories Are Actually Separate

After starting all your nodes, confirm each `--datadir` only ever produced **one** `Node-<address>` subfolder — if you see more than one under any single `data/nodeN`, two terminals were pointed at the same `--datadir`:

```bash
# macOS
for d in data/node*; do echo "$d:"; ls "$d"; done

# Each line should show exactly ONE Node-<address> folder.
# More than one means two terminals shared a --datadir — recheck the table above.
```

### Check Balance via RPC

While any node is running:

```bash
go run src/cli/main.go get-balance \
    --rpc http://127.0.0.1:8545 \
    --address 0000000000000000000000000000000000000001
```

### Clean Up and Restart

```bash
# Stop all nodes with Ctrl+C
# Clear data directories to start fresh:
rm -rf data/
```

---

## Expected Behavior Summary

| Scenario | Expected Result |
|----------|----------------|
| Node-A starts alone | Creates genesis, mines blocks solo (no PBFT) |
| Node-B joins 5 min later | Downloads genesis + all blocks from A |
| Node-C joins 10 min later | Downloads genesis + all blocks, PBFT activates |
| Node-D joins 1 hour later | Downloads full chain, joins existing PBFT |
| Node-D joins 1 day later | Same — syncs from any peer |
| Node-D joins 1 year later | Same — chain can be millions of blocks |
| Kill Node-B, restart | Resumes from last committed block |
| Disconnect during sync | Resumes from last committed height |
| Different genesis hash | Connection rejected during key exchange |
| Network partition | Reconnects and syncs missing blocks |

---

## Changelog: Validator Set Discovery Fix

Earlier versions of this doc described the behavior below as intended, but two bugs in `src/bind/nodes.go` meant it never actually worked across more than one process: every node stayed in `validators=1` forever, each mined its own chain independently, and late joiners saw repeated `parent hash mismatch` / "stopping batch" errors trying to sync a chain that didn't match what they'd already committed themselves.

Six fixes across `nodes.go` and `helpers.go` address this:

| File | Bug | Fix |
|------|-----|-----|
| `nodes.go` | A custom `--tcp-addr` (including loopback) incorrectly collapsed the validator/address list to size 1 | Only a genuine public/real address collapses the count |
| `nodes.go` | Legacy Same-Box Mode derived peer addresses from a hardcoded base port (`32307`) | Peer addresses are derived as `port - node-index` |
| `nodes.go` | `registerDiscoveredPeer` added peers as network contacts only, never as validators | Discovered peers now get minimum validator stake immediately on key exchange |
| `nodes.go` | A bootstrap node with `--nodes=3` (but no `--seeds`) pre-registered peers that hadn't actually connected | Pre-registration only happens when `--seeds` is explicitly provided |
| `nodes.go` | The Legacy Same-Box fallback logic could still activate during seed-based (`--seeds=`) runs, interfering with peer discovery | Scoped so seed-based mode and Legacy Same-Box Mode no longer cross-interfere — **re-verify this one against a fresh test run**, since the exact condition wasn't fully confirmed against logs at the time of writing |
| `helpers.go` | Bootstrap node could keep mining solo blocks after the 3rd validator joined, racing with the new PBFT round | Solo mining stops → node syncs to tip → then enters PBFT, as an explicit sequence |

**Net effect:** the "Quick Test: Seed-Based Mode" flow below is the flow these fixes were built for — Terminal 1 stays genuinely solo with no `--seeds`, Terminals 2 and 3 join via `--seeds=127.0.0.1:30303`, and all three nodes should now converge on `validators=3` with real 2-of-3 PBFT quorum, instead of each silently voting alone.

If you re-run the Quick Test commands below, confirm in the logs that all three nodes report `validators=3` (not `validators=1`), that no `parent hash mismatch` messages appear, and that view changes settle rather than climbing rapidly.

---

## File Reference

| File | Purpose |
|------|---------|
| `src/cli/main.go` | CLI entry point |
| `src/cli/utils/cli.go` | Command routing and flag parsing |
| `src/bind/nodes.go` | `StartNode()` — full node startup |
| `src/bind/helpers.go` | `runBlockSyncLoop()` — block download |
| `src/bind/helpers.go` | `runBlockProductionLoop()` — block mining |
| `src/bind/helpers.go` | `exchangeKeyWithPeerSync()` — peer handshake |
| `src/bind/types.go` | `SyncState`, `GetBlocksRequest/Response` |
| `src/core/sync.go` | `SyncManager` — sync state machine |
| `src/core/blockchain.go` | `NewBlockchain()` — genesis creation |
| `src/core/genesis.go` | `GenesisState.BuildBlock()` — deterministic genesis |