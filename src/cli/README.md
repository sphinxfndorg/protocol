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
| Kademlia DHT iterative lookup / routing | Ethereum-style discv4/discv5 | ✅ **Wired up** — `StartNode` creates a `dht.DHT` instance bound to the node's deterministic same-box UDP port (TCP port + 1000), translates same-box TCP seeds to matching UDP routers, and passes it to `NodeManager` for `FindClosestPeers` / iterative routing |

**What this means in practice:**  
Sphinx bootstraps via DNS tree or static seeds (like Ethereum), discovers peers-of-peers via PEX gossip (like Bitcoin), and additionally performs Kademlia iterative lookups against the routing table (like Ethereum's discv4). The `--seeds` addresses are used as plain TCP bootstrap targets for initial key exchange and block sync. In the localhost test mode, a seed's TCP port is deterministically translated to its same-box DHT UDP port (TCP + 1000), so `30303` becomes DHT router `31303`; public-device deployments retain their configured UDP-port behavior. On a real device network, the routing table fills organically as the DHT processes ping/pong/find-node responses.

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
4. What happens next depends on the configured network size:
   - With `totalNodes <= 1` (for example, a genuine single-node run), the node enters solo mode and mines blocks without PBFT.
   - With `--nodes=3` in the seed-based localhost flow, the node creates genesis but waits for the configured validators to connect and become ready before proposing block 1. It does **not** mine a solo chain in this mode.

For the recommended three-node flow:

```
Bootstrap node starts
  ↓
No existing chain found
  ↓
Create genesis block (trusted setup, no quorum needed)
  ↓
Wait for the other validators to connect and install genesis
  ↓
Wait until the configured validators are ready
  ↓
Start PBFT and propose block 1
```

A single-node run still follows the trusted-genesis path and can mine solo:

```
Single-node start
  ↓
Create genesis block
  ↓
Enter SOLO_MODE
  ↓
Mine blocks independently
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

1. Node-B detects it has no local blockchain data and enters **late-joiner mode** (`Late-joiner mode: skipping ExecuteGenesisBlock()… will sync genesis+blocks from peers`)
2. It connects to Node-A (or any seed peer) via TCP
3. It performs a **key exchange** that includes genesis hash verification
4. If blocks already exist on the network, it requests genesis + all missing blocks in **batches of 500** and verifies each one before committing
5. If no blocks exist yet, there is nothing to download: it registers as a validator and participates in the **first PBFT round** from genesis onward
6. Once at the tip it enters **periodic monitoring mode**

> ⚠️ **Which of step 4/step 5 you get depends on the node's validator-set size, not on timing.** With the same-box harness the set size comes from `--nodes`, so a joiner must use the *same* `--nodes` as the rest of the network — see the growth-limit warning in the Quick Test section. A node started with the default `--nodes=1` believes it is a one-validator network, cannot resolve any other validator's attestations, and can never verify a downloaded block.

```
Node-B starts (late joiner)
  ↓
No local chain — late joiner mode activated
  ↓
Connect to seed peer (Node-A)
  ↓
Key exchange + genesis hash verification
  ↓
Blocks already committed on the network?
  ├─ yes → request genesis + blocks 1→N in batches of 500,
  │        verify (parent hash, attestation quorum, continuity), commit
  └─ no  → join the first PBFT round at genesis and follow it forward
  ↓
Reach CAUGHT_UP state
  ↓
Enter periodic monitoring (re-check every 10 seconds)
  ↓
Wait for more validators (need ≥3 for PBFT)
```

### Node-C Joins (Same Behavior)

Node-C follows the exact same process as Node-B:
- Verifies genesis hash with any reachable peer
- If blocks already exist, downloads and verifies them; otherwise joins the PBFT round at genesis
- Catches up to the network tip

### Node-D, E, F...N Join (Years Later)

Every subsequent node behaves identically, **provided it is configured with the network's validator-set size** (same-box harness: the same `--nodes`, and its own `--node-index`):

- The sync loop **never gives up** — it retries with exponential backoff (up to 5 minutes)
- It tries all known peers until one responds
- It downloads the chain from genesis to tip (in 500-block batches) and enters periodic monitoring after catching up

> ⚠️ **The retry loop will keep retrying a chain it can never accept.** If the joiner's effective validator set is larger than what the historical blocks attest, every batch is rejected with
> `Block 1 failed attestation quorum check: block 1 attestation quorum not met: 96.00 / 160.00 SPX attested (need ≥ 106.67)`
> and the node stays at height `0` forever. This is the growth limit documented in the Quick Test section (3 → 4 validators works; 4 → 5 does not).

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
1 validator (a genuine single-node run):
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

In the `--nodes=3` localhost flow, the bootstrap node does not enter the one-validator solo branch. It creates genesis, waits for the other validators to become ready, and then starts PBFT. Solo mining is reserved for `totalNodes <= 1`; mining solo blocks in a configured multi-node network can create a chain that peers never voted on.

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

> **Fixed:** `--nodes=3` on its own no longer pre-registers peers as validators. A bootstrap node started without `--seeds` does not treat the other configured nodes as connected. In the recommended localhost flow it waits for real peers to complete key exchange, install genesis, and become ready before proposing; only a genuine `totalNodes <= 1` run enters solo mode. `--nodes=3` tells the node how many validators to expect for PBFT quorum math — it does not add validators by itself.

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

| Terminal | `--tcp-addr` | `--http-port` | wallet RPC (derived) | `--datadir` | `--node-index` |
|----------|-------------|---------------|----------------------|-------------|----------------|
| 1 | `127.0.0.1:30303` | `127.0.0.1:8545` | `127.0.0.1:8700` | `data/node1` | `0` |
| 2 | `127.0.0.1:30304` | `127.0.0.1:8546` | `127.0.0.1:8701` | `data/node2` | `1` |
| 3 | `127.0.0.1:30305` | `127.0.0.1:8547` | `127.0.0.1:8702` | `data/node3` | `2` |
| 4 | `127.0.0.1:30306` | `127.0.0.1:8548` | `127.0.0.1:8703` | `data/node4` | `3` |
| 5 | `127.0.0.1:30307` | `127.0.0.1:8549` | `127.0.0.1:8704` | `data/node5` | `4` |
| 6 | `127.0.0.1:30308` | `127.0.0.1:8550` | `127.0.0.1:8705` | `data/node6` | `5` |
| 7 | `127.0.0.1:30309` | `127.0.0.1:8551` | `127.0.0.1:8706` | `data/node7` | `6` |
| 8 | `127.0.0.1:30310` | `127.0.0.1:8552` | `127.0.0.1:8707` | `data/node8` | `7` |

The **wallet/JSON-RPC port is not a flag** — it is always derived as **`8700 + --node-index`**, and it is the port `--rpc` must target for `get-balance`/`watch-tx`, the port peers use for tip queries and block downloads, and the *first* thing that collides if `--node-index` is missing. It is listed above so you never have to derive it by hand.

> ⚠️ **Always pass `--node-index` on a single machine, and give every node the *same* `--nodes=N`.**
>
> - **Omitting `--node-index` defaults it to `0`**, so the node tries to bind wallet RPC `8700` — already held by Terminal 1 — and exits during startup with:
>   `failed to bind wallet RPC listener on 127.0.0.1:8700: listen tcp 127.0.0.1:8700: bind: address already in use`
>   If you must run a node without a free `--node-index`, override the derived port explicitly: `--ws-port=127.0.0.1:8710` (any value other than the `127.0.0.1:8600` default is honoured as-is).
> - **`--nodes` sizes the local validator set for every node on this machine.** `--nodes=N` with `--node-index=i` requires `i < N` (`node-index 3 out of range for 3 nodes` otherwise), and a node started with the default `--nodes=1` believes it is a one-validator network: its validator set stays size 1, so it can never resolve the other validators' attestations and can never verify a downloaded block. Give every node the same `N` — the total number of validators you intend to run.

**Terminal 1 — First validator (creates genesis, then waits for the configured validators):**
```bash
cd Desktop/protocol
go run src/cli/main.go node --role=validator \
    --tcp-addr=127.0.0.1:30303 \
    --http-port=127.0.0.1:8545 \
    --datadir=data/node1 \
    --nodes=3 --node-index=0 \
    --pbft
```

**Expected:** Creates genesis, waits for nodes 2 and 3 to connect and become ready, then starts PBFT. It does not mine a solo chain in this `--nodes=3` flow.

> **Multisig treasury spend — no flags, runs on every node.** The custody watcher starts automatically inside every node's process whenever a multisig policy is provisioned — nothing on the command line and nothing that differs between terminals. The node is never told a destination or amount: it scans `config/spend_proposals/` for spends the custodian quorum has already signed (each file is a complete `multisig spend --dry-run --out` transaction, so destination/amount/nonce live *inside* the signed payload) and broadcasts at most one per cycle, deduped by transaction id. It can never authorize a spend on its own — the node re-verifies the witness at admission.
>
> - **Creating a proposal** (an operator action, not the node's): assemble the usual spend and drop it into the proposals directory instead of broadcasting by hand —
>   `go run src/cli/main.go multisig spend --policy config/escrow_multisig.json --to <addr> --amount-spx <n> --keys-dir data/custody/escrow --rpc 127.0.0.1:8700 --dry-run --out config/spend_proposals/<id>.json`
>   The next watcher cycle re-verifies it against the **live** policy — sender address, chain id, expiry window, the witness's embedded policy, and a real M-of-N signature check over the exact spend — then broadcasts it.
> - ⚠️ **`config/spend_proposals/` is a trust boundary, not an inbox.** Anything that can write there can force a broadcast *attempt* of a payment the quorum already signed; protect it like the custodian keys themselves. A malformed or invalid file is logged and skipped, never fatal, so one bad drop cannot block the others.
> - **Replay-safe:** the watcher dedupes by transaction id — a proposal already broadcast, already on-chain, or already rejected is never resubmitted, and it survives a restart (each candidate is checked against `gettransactionreceipt` before broadcasting).
> - **Prerequisite:** run `go run src/cli/main.go multisig devnet --role escrow` **before** starting any node, so `config/escrow_multisig.json` exists before genesis is created — the policy's address is what block 0 funds, and every node re-verifies proposals against it. If this file is missing when a node starts, that node logs `no multisig policy at config/escrow_multisig.json — auto multisig spend watcher disabled` and starts normally with the watcher off — it does not fail startup.
> - **Broadcaster ≠ custodian — no custodian keys on watcher nodes.** A node running the watcher only broadcasts spends the quorum already signed, so it needs **no custodian key files**. `data/custody/escrow/…` belongs only on the machines that *sign* proposals (`multisig devnet` / `message` / `sign` / `combine`); do **not** copy M-of-N of them onto every broadcasting node — that widens the key-distribution surface for a signing authority the watcher never exercises. Startup is gated only on the policy being present and parseable.
> - **Every terminal is identical** — there's no per-terminal spend configuration to keep in sync. Ctrl+C stops the watcher and the node together; a transient broadcast failure (e.g. this node's RPC not listening yet) is logged and retried next interval, and a fatal loop error logs `auto multisig spend watcher stopped: …` while the node keeps running.

**Terminal 2 — Second validator (late joiner, connects via --seeds):**

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

**Expected:** Registers as a validator, waits for the other validators to connect, then participates in the PBFT rounds. Since no blocks exist yet, there is nothing to download — the download path only runs for a joiner that arrives after blocks are already committed.

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

**Expected:** Registers as the third validator; once all three are connected, PBFT starts and produces block 1.

**Terminal 4 — Fourth validator (joins the network that Terminals 1–3 are already running):**

> **Corrected:** this command previously omitted `--nodes`/`--node-index`, which made the node attempt wallet RPC port `8700` (already held by Terminal 1) and exit with `bind: address already in use`. Pass `--node-index=3` and raise `--nodes` to `4` — see the warning in the table above for why both are required.

```bash
cd Desktop/protocol
go run src/cli/main.go node --role=validator \
    --tcp-addr=127.0.0.1:30306 \
    --http-port=127.0.0.1:8548 \
    --datadir=data/node4 \
    --nodes=4 --node-index=3 \
    --seeds=127.0.0.1:30303 \
    --pbft
```

**Expected:** Binds wallet RPC on `127.0.0.1:8703`, passes key exchange with all three running peers (identical genesis hash), converges on `validators=4` / 128 SPX total stake, downloads blocks `1→N` from any peer and catches up to the tip, then validates (and can itself propose) blocks.

**Scaling up: an N-node network must be sized up front.**

The set size a node believes in comes from `--nodes`, and every node must agree on it. So the commands above are two *separate* scenarios — do not mix their `--nodes` values:

| Scenario | Terminals 1–3 | Terminal 4 | Result |
|---|---|---|---|
| **A — 3-node network** (the Quick Test above) | `--nodes=3` | — | ✅ converged, `validators=3` |
| **B — grow a running 3-node chain by one** | `--nodes=3` (already running) | `--nodes=4 --node-index=3` | ✅ node 4 syncs and validates |
| **C — 8-node network, sized up front** | `--nodes=8 --node-index=0..2` | `--nodes=8 --node-index=3..7` | ✅ only variant that scales past 4 |

**Scenario C — all eight nodes, `--nodes=8` on every one of them.** Terminals 1–4 are the same addresses/datadirs as above, but with `--nodes=8 --node-index=0|1|2|3`; Terminals 5–8 are:

```bash
# Terminal 5
go run src/cli/main.go node --role=validator \
    --tcp-addr=127.0.0.1:30307 --http-port=127.0.0.1:8549 \
    --datadir=data/node5 --nodes=8 --node-index=4 \
    --seeds=127.0.0.1:30303 --pbft

# Terminal 6
go run src/cli/main.go node --role=validator \
    --tcp-addr=127.0.0.1:30308 --http-port=127.0.0.1:8550 \
    --datadir=data/node6 --nodes=8 --node-index=5 \
    --seeds=127.0.0.1:30303 --pbft

# Terminal 7
go run src/cli/main.go node --role=validator \
    --tcp-addr=127.0.0.1:30309 --http-port=127.0.0.1:8551 \
    --datadir=data/node7 --nodes=8 --node-index=6 \
    --seeds=127.0.0.1:30303 --pbft

# Terminal 8
go run src/cli/main.go node --role=validator \
    --tcp-addr=127.0.0.1:30310 --http-port=127.0.0.1:8552 \
    --datadir=data/node8 --nodes=8 --node-index=7 \
    --seeds=127.0.0.1:30303 --pbft
```

For N nodes the general rule is: `--node-index = i` (0-based), `--tcp-addr = 127.0.0.1:(30303+i)`, `--http-port = 127.0.0.1:(8545+i)`, wallet RPC auto-derives to `127.0.0.1:(8700+i)`, `--datadir=data/node(i+1)`, and `--nodes=N` on **every** node — with a large enough TCP port range if `i` pushes past `30310`.

> ⚠️ **Growth limit — read this before adding a 5th+ node to a chain that is already producing blocks.** Blocks record the attestations that existed when they were produced. With no per-epoch validator snapshots (`core.SnapshotValidatorSet` has no callers), a syncing node verifies historical blocks against its **current** validator set, so the 2/3 threshold it enforces rises as nodes are added, while old blocks keep their original attestation weight. Measured on this repo:
>
> | Scenario | Result |
> |---|---|
> | 3 validators running (`--nodes=3`), start node 4 with `--nodes=4 --node-index=3` | ✅ syncs, catches up (old blocks carry 3 × 32 = 96 SPX ≥ 2/3 × 128 = 85.33) |
> | Same, but start node 4 with `--nodes` omitted | ❌ validator set stays 1 → `0.00 / 32.00 SPX attested (need ≥ 21.33)`, never syncs |
> | 4 validators running, start node 5 with `--nodes=5 --node-index=4` | ❌ `block 1 attestation quorum not met: 96.00 / 160.00 SPX attested (need ≥ 106.67)` — retries forever, stays at height 0 |
> | All 5 started together with `--nodes=5 --node-index=0..4` | ✅ all reach the same height, `validators=5`, zero errors |
>
> **So: size the network up front** (start every node with `--nodes=N`), or grow only while `2/3 × (new validators × 32) ≤ ` the attestation weight on the oldest block you must verify. Going 3 → 4 works; 4 → 5 does not. Lifting this limitation is a code fix (populate `SnapshotValidatorSet` at epoch transitions so historical blocks verify against the set that actually signed them), not a flag.

> **Note:** `--nodes`/`--node-index` are the same-box harness. On real machines with public IPs, omit both and let `--seeds` + PEX discovery populate the validator set dynamically.

### Testing late-joiner sync against an existing chain

Use this procedure to verify that a node can rejoin after its local state is
removed while the other validators continue producing blocks. Use the exact
per-node ports and datadirs from the Quick Test above; do not reuse a datadir
between nodes.

1. Start all three nodes with the Quick Test commands.
2. Wait until all three nodes report at least height `5` and confirm their
   block indexes agree.
3. Stop only node 3 with `Ctrl+C`. Leave nodes 1 and 2 running.
4. Wait until nodes 1 and 2 report at least height `8`.
5. Remove **only** node 3's datadir:

   ```bash
   rm -rf data/node3
   ```

   Do not remove `data/node1`, `data/node2`, or the shared repository-level
   `artifact-db` directory.
6. Restart node 3 with the same command:

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

7. Verify that node 3 reports genesis installation, catches up to the current
   tip, and rejoins PBFT. Compare the three `block_index.json` files after the
   catch-up completes; their block hash-to-height maps must match.

A successful run has no `parent hash mismatch` or `stopping batch` messages,
and the restarted node's final height is not lower than the other nodes'.

> **Identity note:** A node's SPHINCS+ identity key is stored under its
> `Node-<address>/keys` directory. A full `rm -rf data/node3` therefore removes
> the key as well as the chain. The running peers correctly reject the same node
> ID when it presents a newly generated key, so a datadir-only wipe can verify
> chain synchronization and index equality but cannot rejoin under the old
> identity. To test a true restart with the same identity, preserve and restore
> the node's `keys` directory separately; to rotate identity, start with a new
> node ID/address instead.

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

While any node is running, query **that node's** wallet RPC port — `8700 + --node-index`, i.e. `8700` for node 1, `8701` for node 2, `8702` for node 3, and so on:

```bash
# Node 1 (--node-index=0 → wallet RPC 8700)
go run src/cli/main.go get-balance \
    --rpc 127.0.0.1:8700 \
    --address 0000000000000000000000000000000000000001

# Node 3 (--node-index=2 → wallet RPC 8702)
go run src/cli/main.go get-balance \
    --rpc 127.0.0.1:8702 \
    --address 0000000000000000000000000000000000000001
```

`0000…0001` is the genesis vault: it mints the full supply in block 0 and pays every allocation out of itself in the same block, so it correctly reads `0` afterwards. The CGE escrow `0000…0002` holds the time-locked portion — e.g. `424,999,985 SPX` shortly after genesis, releasing as chain time advances.

> ⚠️ Pointing `--rpc` at the `--http-port` value (`8545`…) fails with
> `handshake with 127.0.0.1:8547: … i/o timeout` — that listener speaks HTTP, not the handshake-authenticated JSON-RPC wire format `get-balance` needs.

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
| Node-A starts with `--nodes=3` | Creates genesis, waits for the configured validators, then starts PBFT |
| Node-A starts as a genuine single-node run | Creates genesis and mines blocks solo (no PBFT) |
| Node-B joins 5 min later, same `--nodes` | Joins the PBFT round at genesis (nothing committed yet to download) |
| Node-C joins 10 min later, same `--nodes` | Same; `validators=3`, PBFT produces block 1 |
| Node 4 joins while blocks already exist, `--nodes=4 --node-index=3` | Downloads and verifies blocks `1→N`, catches up, validates ✅ |
| Node 4 joins with the same command but `--nodes` omitted | ❌ validator set stays 1 → `0.00 / 32.00 SPX attested (need ≥ 21.33)`, stuck at height 0 |
| Node 5 joins a running 4-validator chain, `--nodes=5` | ❌ `96.00 / 160.00 SPX attested (need ≥ 106.67)` on block 1 — sees the growth limit above |
| All N nodes started together with `--nodes=N` | ✅ All converge, `validators=N`, identical tip |
| Killing Node-B, restarting with the same datadir | Resumes from last committed block |
| Disconnect during sync | Resumes from last committed height |
| Different genesis hash | Connection rejected during key exchange |
| Network partition | Reconnects and syncs missing blocks |
| Omitting `--node-index` on a second same-machine node | ❌ startup failure: `bind wallet RPC listener on 127.0.0.1:8700: address already in use` |

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

**Net effect:** the "Quick Test: Seed-Based Mode" flow below is the flow these fixes were built for — with `--nodes=3`, Terminal 1 creates genesis and waits for real peers to become ready, Terminals 2 and 3 join via `--seeds=127.0.0.1:30303`, and all three nodes converge on `validators=3` with real 2-of-3 PBFT quorum. A genuine single-node run (`totalNodes <= 1`) remains the only path that mines solo.

If you re-run the Quick Test commands below, confirm in the logs that all three nodes report `validators=3` (not `validators=1`), that no `parent hash mismatch` messages appear, and that view changes settle rather than climbing rapidly.

---

## Changelog: Quick-Test Tutorial Corrections (measured)

The Quick Test commands were re-run against this tree with three, four and five real
node processes. Findings, and what was changed in this document:

| # | Symptom (reproduced) | Cause | Doc change |
|---|----------------------|-------|-----------|
| 1 | **Terminal 4 exited at startup:** `failed to bind wallet RPC listener on 127.0.0.1:8700: … address already in use` | The tutorial's Terminal 4 omitted `--node-index`; wallet RPC is always derived as `8700 + node-index`, so it defaulted to `0` and collided with Terminal 1 | Terminal 4 now passes `--nodes=4 --node-index=3`; the port table lists the derived wallet-RPC port per node and documents the `--ws-port` override |
| 2 | A joiner with `--nodes` omitted stayed at `validators=1` and never synced: `0.00 / 32.00 SPX attested (need ≥ 21.33)` | `--nodes=1` tells the node it is a one-validator network, so it can never resolve the other validators' attestations | Added the "always pass `--node-index`, give every node the same `--nodes`" warning next to the port table |
| 3 | Nodes 2 and 3 documented as "downloads genesis + all blocks", but they never issued a single block request (0 `Syncing blocks` lines) — they reached CAUGHT_UP at height 0 and joined the first PBFT round | Nothing was committed yet when they joined; the download path only runs for a joiner that arrives after blocks exist | Late-joiner section and Expected Behavior table now distinguish "join the PBFT round at genesis" from "download and verify blocks" |
| 4 | **A 5th node cannot join a running chain:** `block 1 attestation quorum not met: 96.00 / 160.00 SPX attested (need ≥ 106.67)`, stuck at height 0 forever | Blocks carry the attestations that existed when produced, but sync-time verification uses the joiner's *current* validator set, so the 2/3 threshold rises as nodes are added. `core.SnapshotValidatorSet` — which exists exactly to verify historical blocks against the set that signed them — **has no callers**, so `GetValidatorSetAtEpoch` always returns nil and every check falls back to the live set | Documented the measured growth limit (3 → 4 works; 4 → 5 does not) and the "size the network up front with `--nodes=N`" workaround |

Verified-good baseline in the same run: 3-node PBFT converged to `validators=3` and an
identical tip hash across all three processes; 5 nodes started together with
`--nodes=5 --node-index=0..4` converged with `validators=5` and zero errors; genesis hash
matched across every process; `get-balance` reported the CGE escrow at `424,999,985 SPX`
with the vault correctly drained after block 0.

Still open (code fixes, not documentation): (a) derive a non-colliding wallet-RPC default
when `--node-index` is absent, and (b) call `SnapshotValidatorSet` at epoch transitions so
validators can be added to a live network without invalidating historical block
verification.

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