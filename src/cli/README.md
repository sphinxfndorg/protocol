# Sphinx Node Operator Guide

This guide covers everything you need to run a Sphinx validator node —
from downloading the software to minting blocks and earning SPX rewards.

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [How Sphinx Works](#2-how-sphinx-works)
3. [Prerequisites](#3-prerequisites)
4. [Running a Validator Node](#4-running-a-validator-node)
5. [Multi-Node Network](#5-multi-node-network)
6. [EIP-1459 DNS Discovery](#6-eip-1459-dns-discovery)
7. [Validator Rewards](#7-validator-rewards)
8. [CLI Reference](#8-cli-reference)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Quick Start

### Single node (development / testing)

```bash
# From the protocol directory
cd desktop/protocol/src/cli
go run main.go node --role=validator \
    --tcp-addr=127.0.0.1:30303 \
    --udp-port=30304 \
    --http-port=127.0.0.1:8545 \
    --datadir=data/validator \
    --pbft
```

This starts a validator on your local machine. It will create the genesis
block, register itself, and begin participating in consensus.


### This will open 6 new Terminal windows (on macOS) and start each node. You can monitor each node live.

```bash
cd desktop/protocol/src/cli
chmod +x run.sh
./run.sh cluster 10
```

### Example: 10 Nodes (Commands to Paste into 10 Terminals local testnet)

```bash
# Terminal 1 — Node 0
cd desktop/protocol/src/cli
go run main.go node --role=validator --tcp-addr=127.0.0.1:32307 --udp-port=32308 --http-port=127.0.0.1:8545 --datadir=data0 --nodes=10 --node-index=0 --pbft

# Terminal 2 — Node 1
cd desktop/protocol/src/cli
go run main.go node --role=validator --tcp-addr=127.0.0.1:32308 --udp-port=32309 --http-port=127.0.0.1:8546 --datadir=data1 --nodes=10 --node-index=1 --seeds=127.0.0.1:32307 --pbft

# Terminal 3 — Node 2
cd desktop/protocol/src/cli
go run main.go node --role=validator --tcp-addr=127.0.0.1:32309 --udp-port=32310 --http-port=127.0.0.1:8547 --datadir=data2 --nodes=10 --node-index=2 --seeds=127.0.0.1:32307 --pbft


# Terminal 4 — Node 3
cd desktop/protocol/src/cli
go run main.go node --role=validator --tcp-addr=127.0.0.1:32310 --udp-port=32311 --http-port=127.0.0.1:8548 --datadir=data3 --nodes=10 --node-index=3 --seeds=127.0.0.1:32307 --pbft

# Terminal 5 — Node 4
cd desktop/protocol/src/cli
go run main.go node --role=validator --tcp-addr=127.0.0.1:32311 --udp-port=32312 --http-port=127.0.0.1:8549 --datadir=data4 --nodes=10 --node-index=4 --seeds=127.0.0.1:32307 --pbft

# Terminal 6 — Node 5
cd desktop/protocol/src/cli
go run main.go node --role=validator --tcp-addr=127.0.0.1:32312 --udp-port=32313 --http-port=127.0.0.1:8550 --datadir=data5 --nodes=10 --node-index=5 --seeds=127.0.0.1:32307 --pbft


# Terminal 7 — Node 6
cd desktop/protocol/src/cli
go run main.go node --role=validator --tcp-addr=127.0.0.1:32313 --udp-port=32314 --http-port=127.0.0.1:8551 --datadir=data6 --nodes=10 --node-index=6 --seeds=127.0.0.1:32307 --pbft

# Terminal 8 — Node 7
cd desktop/protocol/src/cli
go run main.go node --role=validator --tcp-addr=127.0.0.1:32314 --udp-port=32315 --http-port=127.0.0.1:8552 --datadir=data7 --nodes=10 --node-index=7 --seeds=127.0.0.1:32307 --pbft


# Terminal 9 — Node 8
cd desktop/protocol/src/cli
go run main.go node --role=validator --tcp-addr=127.0.0.1:32315 --udp-port=32316 --http-port=127.0.0.1:8553 --datadir=data8 --nodes=10 --node-index=8 --seeds=127.0.0.1:32307 --pbft

# Terminal 10 — Node 9
cd desktop/protocol/src/cli
go run main.go node --role=validator --tcp-addr=127.0.0.1:32316 --udp-port=32317 --http-port=127.0.0.1:8554 --datadir=data9 --nodes=10 --node-index=9 --seeds=127.0.0.1:32307 --pbft
```

Within seconds all three nodes will connect, elect a leader, and begin
producing blocks. Each node's JSON-RPC is available on its `--http-port`.

**Note:** Each node automatically creates its own subdirectory based on its
TCP address (e.g., `data/Node-127.0.0.1:32307/`, `data/Node-127.0.0.1:32308/`,
`data/Node-127.0.0.1:32309/`). You do not need to specify different `--datadir`
values for each node.

### Three nodes on three machines (real network)

```bash
# Device A (first seed, no --seeds needed)
cd desktop/protocol/src/cli
go run main.go node --role=validator \
    --tcp-addr=<A-PUBLIC-IP>:30303 \
    --udp-port=30304 \
    --http-port=<A-PUBLIC-IP>:8545 \
    --datadir=data/validator \
    --pbft

# Device B (joins via A)
cd desktop/protocol/src/cli
go run main.go node --role=validator \
    --tcp-addr=<B-PUBLIC-IP>:30303 \
    --udp-port=30304 \
    --http-port=<B-PUBLIC-IP>:8545 \
    --datadir=data/validator \
    --seeds=<A-PUBLIC-IP>:30303 \
    --pbft

# Device C (joins via A or B)
cd desktop/protocol/src/cli
go run main.go node --role=validator \
    --tcp-addr=<C-PUBLIC-IP>:30303 \
    --udp-port=30304 \
    --http-port=<C-PUBLIC-IP>:8545 \
    --datadir=data/validator \
    --seeds=<A-PUBLIC-IP>:30303,<B-PUBLIC-IP>:30303 \
    --pbft
```

No `--nodes` or `--node-index` needed for real devices — the network
discovers peers dynamically.

---

## 2. How Sphinx Works

### The Bootstrap Chain

When a new node starts, it follows this flow to join the network:

```
New Node
   │
   ├── 1. Parse --seeds flag
   │        │
   │        ├── enrtree:// URL? → EIP-1459 DNS Discovery
   │        │                      ├── Fetch signed Merkle tree from DNS TXT
   │        │                      ├── Verify SPHINCS+ cryptographic signature
   │        │                      ├── Traverse tree → discover 100s of peers
   │        │                      └── Register discovered peers
   │        │
   │        └── Plain ip:port? → Direct TCP connection
   │                               ├── Exchange SPHINCS+ public keys
   │                               ├── Request peer list (PEX)
   │                               └── Propagate outward up to 2 hops
   │
   ├── 2. Join Kademlia DHT
   │        ├── UDP-based peer discovery
   │        ├── k-bucket routing table
   │        └── FIND_NODE / PING / PONG protocol
   │
   └── 3. Participate in PBFT consensus
            ├── VDF-based leader election
            ├── Block proposal, prepare, commit
            └── Earn block rewards
```

### Consensus (PBFT + VDF)

Sphinx uses a hybrid consensus combining:

- **VDF (Verifiable Delay Function)** — post-quantum leader election based
  on class group arithmetic. The VDF discriminant is derived from the
  genesis hash, so every node agrees on leader selection without any
  communication round.

- **PBFT (Practical Byzantine Fault Tolerance)** — three-phase commit
  protocol (propose → prepare → commit). A block is final once ⅔ of
  validators have committed to it. No forks, no reorgs, instant finality.

**Phases:**

| Blocks | Phase | Requirements |
|--------|-------|-------------|
| 0 | Genesis | Vault funded with total allocation supply |
| 1 | Distribution | Genesis vault distributes to allocation addresses |
| 2+ | Normal | Validators mint blocks, earn rewards |

### Supply Cap

Sphinx has a hard supply cap of **5,000,000,000 SPX** (5 billion). Block
rewards are minted up to this cap; once reached, no more SPX can be created.

---

## 3. Prerequisites

### Software

- Go toolchain matching this repo's `go.mod` (Go 1.25+)
- Git (to clone the repository)

### Network

Each validator needs inbound access on:

| Protocol | Port | Default | Purpose |
|----------|------|---------|---------|
| TCP | 30303 | `--tcp-addr` | P2P, key exchange, consensus |
| UDP | 30304 | `--udp-port` | Kademlia peer discovery |
| TCP | 8545 | `--http-port` | JSON-RPC API |

If behind NAT: configure port forwarding or use a LAN IP for same-network
setups. There is currently no automatic NAT traversal.

### Token Balance

To participate as a validator after Block 1, you need at least the minimum
stake in SPX tokens at your SPIF address. During devnet/testnet, validators
with no balance automatically get the minimum stake.

On mainnet, validators must deposit SPX through the on-chain staking
mechanism to increase their voting power and earn proportional rewards.

---

## 4. Running a Validator Node

### Step 1: Build the binary

```bash
git clone https://github.com/sphinxfndorg/protocol.git
cd protocol
go build -o sphinx ./src/cli/main.go
```

This creates a `sphinx` binary in the current directory. You can move it to
a `PATH` directory or use `./sphinx` directly.

### Step 2: Choose your network type

| Network | Flag | Purpose |
|---------|------|---------|
| Devnet | `--network=devnet` (default) | Local testing, single machine |
| Testnet | `--network=testnet` | Multi-device staging |
| Mainnet | `--network=mainnet` | Production |

### Step 3: Start the node

**Development mode** (single machine, multiple validators):

```bash
./sphinx node --role=validator \
    --tcp-addr=127.0.0.1:32307 \
    --udp-port=32308 \
    --http-port=127.0.0.1:8545 \
    --datadir=data \
    --nodes=3 --node-index=0 --pbft
```

**Production mode** (real device, auto-discovery):

```bash
./sphinx node --role=validator \
    --tcp-addr=<YOUR_PUBLIC_IP>:30303 \
    --udp-port=30304 \
    --http-port=0.0.0.0:8545 \
    --datadir=data/validator \
    --seeds=<BOOTNODE_IP>:30303 \
    --mode=production \
    --pbft
```

### Step 4: Verify it's working

Check the logs for these key messages:

```
✅ Genesis vault funded
✅ Consensus engine started successfully
✅ PBFT CONSENSUS ACTIVE with 2 known validators
⛏ Solo-mined block height=1 txs=...
```

To query the node's status via JSON-RPC:

```bash
curl -X POST http://127.0.0.1:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"spx_getBlockCount","params":[],"id":1}'
```

### Step 5: Check your rewards

After blocks are being minted, check the supply status:

```bash
curl -X POST http://127.0.0.1:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"spx_getSupplyStatus","params":[],"id":1}'
```

Look for the `rewards_minted_spx` field — this shows how much has been
minted in block rewards. Your validator's SPIF address receives its share
of these rewards on every block it proposes.

---

## 5. Multi-Node Network

### Same-box (development)

Use `--nodes=N` and `--node-index=0..N-1` on loopback addresses:

```bash
./run.sh cluster
```

Or start manually:

```bash
# Node 0
./sphinx node --role=validator \
    --tcp-addr=127.0.0.1:32307 --udp-port=32308 \
    --http-port=127.0.0.1:8545 --datadir=data \
    --nodes=3 --node-index=0 --pbft

# Node 1
./sphinx node --role=validator \
    --tcp-addr=127.0.0.1:32308 --udp-port=32309 \
    --http-port=127.0.0.1:8546 --datadir=data \
    --nodes=3 --node-index=1 --pbft

# Node 2
./sphinx node --role=validator \
    --tcp-addr=127.0.0.1:32309 --udp-port=32310 \
    --http-port=127.0.0.1:8547 --datadir=data \
    --nodes=3 --node-index=2 --pbft
```

### Multi-device (real network)

When `--tcp-addr` is a non-loopback IP, `--nodes` and `--node-index` are
ignored. The validator set is built dynamically from `--seeds` + PEX.

**Device A (bootnode):**

```bash
./sphinx node --role=validator \
    --tcp-addr=<A-IP>:30303 \
    --udp-port=30304 \
    --http-port=<A-IP>:8545 \
    --datadir=data/validator \
    --pbft
```

No `--seeds` needed — Device A is the first node.

**Device B (joiner):**

```bash
./sphinx node --role=validator \
    --tcp-addr=<B-IP>:30303 \
    --udp-port=30304 \
    --http-port=<B-IP>:8545 \
    --datadir=data/validator \
    --seeds=<A-IP>:30303 \
    --pbft
```

**Device C (joiner):**

```bash
./sphinx node --role=validator \
    --tcp-addr=<C-IP>:30303 \
    --udp-port=30304 \
    --http-port=<C-IP>:8545 \
    --datadir=data/validator \
    --seeds=<A-IP>:30303,<B-IP>:30303 \
    --pbft
```

PBFT activates automatically once ≥ 3 validators are connected.

### Confirming it worked

On a successful join, the logs show:

```
🌱 Discovering peers via 1 configured seed(s)
✅ Key exchange complete with Node-<A-IP>:30303
🌐 Discovered new peer Node-<A-IP>:30303 at <A-IP>:30303 — registering
✅ PBFT CONSENSUS ACTIVE with 2 known validators
```

The seed node logs:

```
🔍 Peer exchange request from Node-<B-IP>:30303 — sharing N known peer(s)
```

---

## 6. EIP-1459 DNS Discovery

Sphinx implements **EIP-1459** — cryptographically authenticated DNS-based
node discovery, the same standard used by Ethereum Geth.

### Why DNS discovery?

Instead of trusting plain DNS records (which can be spoofed), node lists
are published as **signed Merkle trees** in DNS TXT records. Clients
verify the SPHINCS+ signature against a public key embedded in the
`enrtree://` URL. Even a compromised DNS server cannot inject fake peers.

### How it works

```
New Node
   │
   ├── Parse enrtree://<pubkey>@<domain> from --seeds
   │
   ├── DNS TXT lookup at root.<domain>
   │     Returns: enrtree-root:v1 e=<hash> seq=<N> sig=<sig> pk=<pk>
   │
   ├── Verify SPHINCS+ signature on the tree root
   │     If invalid → reject entire tree (zero-trust DNS)
   │
   ├── Traverse Merkle tree via DNS TXT records
   │     Branch: enrtree-branch:<child_hash>,<child_hash>,...
   │     Leaf:   enr:<id>;<kad>;<addr>;<udp>;<pk>
   │
   └── Connect to discovered peers → Kademlia DHT takes over
```

### URL format

```
enrtree://<public_key_hex>@<dns_domain>
```

Example:
```
enrtree://AEDA4B62B4B4E4E4@nodes.sphinx.network
```

The public key is embedded directly in the URL — no out-of-band key
distribution needed.

### Usage

Mix `enrtree://` URLs with plain `ip:port` seeds:

```bash
# DNS discovery tree as the only seed
./sphinx node --role=validator \
    --tcp-addr=<PUBLIC_IP>:30303 \
    --seeds=enrtree://<PUBKEY_HEX>@nodes.sphinx.network \
    --datadir=data --pbft

# Mix DNS trees with plain seeds
./sphinx node --role=validator \
    --tcp-addr=<PUBLIC_IP>:30303 \
    --seeds=enrtree://<PUBKEY_HEX>@nodes.sphinx.network,1.2.3.4:30303 \
    --datadir=data --pbft
```

### Comparison

| Feature | Plain IP Seeds | enrtree:// DNS |
|---------|---------------|----------------|
| Spoof resistance | ❌ DNS poisoning possible | ✅ SPHINCS+ signature verified |
| Peer quantity | 1–10 fixed addresses | Hundreds via Merkle tree |
| Freshness | Static/hardcoded | Dynamic (TTL-cached) |
| Decentralization | Manual updates | Anyone can run a crawler |
| Audit trail | None | Signed root with sequence numbers |

---

## 7. Validator Rewards

### How rewards work

When a validator proposes a block that reaches consensus, two types of
rewards are credited:

1. **Block reward** — A fixed amount of SPX minted per block (defined by
   `BaseBlockReward` in the chain parameters)
2. **Gas fees** — SPX paid by transaction senders, collected by the block
   proposer

Both rewards are credited to the validator's **SPIF address**, not the
node ID. This means the rewards are immediately visible in the state
database and queryable via JSON-RPC.

### Reward address mapping

The genesis allocation maps each validator node ID to a SPIF address:

```
Node-127.0.0.1:32307 → SPIF F6F6 66A0 F07B B9F1 ...
Node-127.0.0.1:32308 → SPIF 42D1 A449 30C6 1EE4 ...
Node-127.0.0.1:32309 → SPIF 929F C03E 6D4D D81B ...
```

For real-device mode, the reward address is the node ID itself until a
proper on-chain staking deposit mechanism is implemented (Stage D).

### Checking rewards

```bash
# Query block count (how many blocks have been minted)
curl -X POST http://127.0.0.1:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"spx_getBlockCount","params":[],"id":1}'

# Query supply status (shows rewards_minted_spx)
curl -X POST http://127.0.0.1:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"spx_getSupplyStatus","params":[],"id":1}'

# Query balance of a SPIF address
curl -X POST http://127.0.0.1:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"spx_getBalance","params":["SPIF F6F6 66A0 F07B B9F1 ..."],"id":1}'
```

### Log output

When a block is minted, the validator logs:

```
✅ REWARD: 10.000000 SPX → Node-127.0.0.1:30303 (block 5)
```

The reward is actually credited to the validator's SPIF address (not the
node ID displayed in the log message). The checkpoint shows the aggregate:

```
✅ CHECKPOINT: devnet at height=5
📊 SUPPLY BREAKDOWN:
   Genesis Allocation: 1,240,000,000 SPX
   Rewards Minted:     50.000000 SPX
   Total Minted:       1,240,000,050 SPX
   Remaining Supply:   3,759,999,950 SPX
```

---

## 8. CLI Reference

### Subcommands

| Command | Description |
|---------|-------------|
| `node` | Start a validator node |
| `send-tx` | Send a transaction |
| `get-balance` | Query an address balance |
| `watch-tx` | Wait for a transaction to confirm |
| `help` | Print usage information |

### Node flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--role` | Yes | `validator` | Node role: `validator`, `sender`, `receiver`, `none` |
| `--tcp-addr` | Yes | `127.0.0.1:30303` | P2P TCP address (use real IP for production) |
| `--udp-port` | No | `30304` | UDP port for Kademlia discovery |
| `--http-port` | No | `127.0.0.1:8545` | JSON-RPC HTTP address |
| `--ws-port` | No | `127.0.0.1:8600` | WebSocket address |
| `--seeds` | No | — | Comma-separated bootstrap addresses or `enrtree://` URLs |
| `--datadir` | No | `data` | Directory for LevelDB storage |
| `--pbft` | No | `false` | Enable PBFT consensus mode |
| `--nodes` | No | `1` | Total validators (same-box dev only; ignored in real-device) |
| `--node-index` | No | `0` | This node's index (same-box dev only; ignored in real-device) |
| `--network` | No | `devnet` | Network: `devnet`, `testnet`, `mainnet` |
| `--mode` | No | `development` | `development` or `production` |
| `--max-peers` | No | `50` | Max peer connections (production mode) |
| `--config` | No | — | Path to JSON config file |

### Transaction flags (`send-tx`)

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--rpc` | No | `http://127.0.0.1:8545` | JSON-RPC endpoint |
| `--from` | Yes | — | Sender SPIF address |
| `--to` | Yes | — | Receiver SPIF address |
| `--amount` | No | `0` | Amount in SPX |
| `--gas-limit` | No | `21000` | Gas limit |
| `--gas-price` | No | `1` | Gas price in gSPX |
| `--nonce` | No | `0` | Nonce (omit for auto-fetch) |
| `--key` | No | — | Path to private key file |
| `--wait` | No | `true` | Wait for confirmation |

### Example: send a transaction

```bash
./sphinx send-tx --rpc=http://127.0.0.1:8545 \
    --from="SPIF F6F6 66A0 F07B B9F1 C36C 0BC4 97DE F789 ACA6 B4A7 564F 88A6 277F CBBF D909 F8" \
    --to="SPIF 42D1 A449 30C6 1EE4 8B85 8E88 E393 BAA1 72D9 5DFF DE0D 5AE4 2B70 E60B 8C71 C2DB" \
    --amount=100 \
    --key=./mykey.pem
```

---

## 9. Troubleshooting

### "No elected leader found"

The consensus engine needs ≥ 3 connected validators to elect a leader.
Check that:
- All nodes use the same `--network` type (all devnet, all testnet, etc.)
- Firewalls allow inbound TCP on `--tcp-addr` and UDP on `--udp-port`
- The `--seeds` addresses are correct and reachable

Wait 30 seconds — the leader election retries automatically every 2 seconds.

### "Failed to exchange keys with peer"

The TCP connection to the seed failed. Verify:
- The seed node is running and its `--tcp-addr` is reachable
- No firewall is blocking the port
- IP addresses are correct (no typos)

### "Genesis hash mismatch"

This means one node is using different chain parameters than another.
Possible causes:
- Different `--network` values (devnet vs testnet vs mainnet)
- Corrupted data directory — delete `--datadir` and restart
- Different genesis code — ensure all nodes use the same binary

### "DNS discovery returned no peers"

The `enrtree://` domain is valid but no peers are published yet. This is
normal if no crawler has populated the DNS tree. Fall back to plain seeds
by adding `ip:port` addresses to `--seeds` alongside the enrtree URL.

### "Database is locked" / LevelDB errors

Only one process can open a LevelDB directory at a time. Ensure:
- Each node has a unique `--datadir`
- No other process is using the same data directory
- After a crash, delete the `LOCK` file in the data directory

### Checking logs

All log output goes to stdout. Key patterns to search for:

```bash
# Check if node found peers
./sphinx node ... 2>&1 | grep "Discovered new peer"

# Check if PBFT is active
./sphinx node ... 2>&1 | grep "PBFT CONSENSUS"

# Check if blocks are being minted
./sphinx node ... 2>&1 | grep "REWARD\|minted block"
```

---

## API Reference

### JSON-RPC Methods

| Method | Parameters | Returns |
|--------|------------|---------|
| `spx_getBlockCount` | none | Block height |
| `spx_getBalance` | `[address]` | Balance in nSPX |
| `spx_getSupplyStatus` | none | Supply breakdown |
| `spx_sendTransaction` | `[tx_json]` | Transaction ID |
| `spx_getTransaction` | `[txid]` | Transaction details |
| `spx_getChainInfo` | none | Chain parameters |
| `spx_getPeers` | none | Connected peers |

### Example: query chain info

```bash
curl -X POST http://127.0.0.1:8545 \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"spx_getChainInfo","params":[],"id":1}'
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│                    CLI (main.go)                 │
│  parse flags → dispatch to subcommand           │
└──────────────┬──────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────┐
│                 bind/nodes.go                    │
│  StartNode() → full production node startup     │
│  ├── LevelDB initialization                     │
│  ├── Blockchain + genesis creation              │
│  ├── SPHINCS+ key generation                    │
│  ├── Consensus engine (PBFT + VDF)              │
│  ├── TCP listener + peer exchange               │
│  ├── EIP-1459 DNS discovery                     │
│  └── Block production loop                      │
└─────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────┐
│              Core Components                     │
│                                                   │
│  src/core/     Blockchain, executor, state,      │
│                genesis, reward minting           │
│                                                   │
│  src/consensus/  PBFT consensus, VDF leader      │
│                  election, validator set          │
│                                                   │
│  src/dht/        Kademlia DHT, routing table     │
│                                                   │
│  src/p2p/        Peer discovery, UDP,           │
│                  seeds (DNS discovery)           │
│                                                   │
│  src/network/    Node manager, peer tracking     │
│                                                   │
│  src/rpc/        JSON-RPC server                 │
└─────────────────────────────────────────────────┘
```

---

## What's Not Yet Solved (Stage D)

### Dynamic validator set

Validators are currently seeded from the genesis allocation map
(`Node-127.0.0.1:32307` → SPIF address). True "join anytime, stake-derived
validator weight" requires a separate on-chain deposit mechanism — planned
but not yet implemented.

### Stake-weighted rewards

Block rewards are currently a fixed amount per block, distributed to the
proposer. Future versions will weight rewards by stake percentage, so a
validator with 10% of total stake earns ~10% of all rewards.

### Open validator registration

There is no mechanism for an operator to deposit SPX from their wallet
to declare stake. This is the mainnet blocker — once implemented, anyone
can become a validator by sending SPX to the deposit contract.

### NAT traversal

Reachability is currently the operator's responsibility. No STUN/TURN/UPnP
support.

---

*For the latest information, run `./sphinx help` or check the source
documentation in `src/p2p/seeds/` for EIP-1459 DNS discovery details.*