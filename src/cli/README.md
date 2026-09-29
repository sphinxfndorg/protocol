# Sphinx CLI — Running Nodes

How to build the CLI, author the genesis document, run validator nodes as
separate processes, and add nodes to a live network.

Every command below was executed against this tree.

---

## 1. Prerequisites and build

Go 1.25+ (`go version` — this tree is developed on go1.27.1).

```bash
git clone https://github.com/sphinxfndorg/protocol.git
cd protocol
go build ./...                 # compile everything
go build -o sphinx ./src/cli   # build the CLI binary
```

Check it:

```bash
./sphinx help
```

If you would rather not build a binary, every command in this document also
works as `go run src/cli/main.go <command>` — just slower on each invocation,
because the CLI is recompiled.

Run the tests (the Makefile targets exist because `src/core`'s SPHINCS+ suites
take ~12 min and exceed `go test`'s 10 min per-package default):

```bash
make test          # all suites, 40m timeout
make test-cli      # just the CLI
go test ./... -timeout 40m
```

---

## 2. The one genesis document

A node has **exactly one** genesis file: `<datadir>/config/genesis_state.json`.
It is the only source of the initial validator set; nothing else on the node
records membership. It carries:

| Section | Contents |
|---|---|
| `chain` | `chain_id`, `network`, `epoch_blocks`, `min_stake_nspx` |
| `validators` | `node_id`, `public_key`, `stake_nspx`, `reward_address` |
| `funded_accounts` | pre-funded reward addresses (`address`, `balance_nspx`, `label`) |
| `multisig` | the genesis vault M-of-N custody policy |
| `witnesses` | the pre-signed block-0 witness book |
| top-level | block-0 audit fields (identity, supply totals, CGE allocation rows) |

There is no `genesis.json`, no `genesis_multisig.json`, no
`devnet_genesis_witnesses.json`, and no fallback that reads any of them.

**How a node gets it:**

- **devnet** — `genesis create` writes one per node datadir. A node started with
  `--seeds` also fetches the missing public sections from its seeds
  automatically, retrying while the bootstrap node is still signing.
- **any other network** — there is **no automatic fetch**. Place the file at
  `<datadir>/config/genesis_state.json` out of band (copy/scp) before the node
  starts. A node started without it still runs, but it has no genesis validators
  and no funded accounts, so it stays a peer until it is staked.

**Block 0's hash does not depend on these sections.** It is built from the frozen
canonical parameters, so every node derives the same genesis hash.

**Identity is derived from `--tcp-addr`** as `Node-<host:port>`. That exact
string must appear as `node_id` in `genesis_state.json`, or the node is not in
the set. `--port-offset` never changes it.

---

## 3. Author the genesis document (`genesis create`)

`K` is a parameter you choose. It is **not** a constant of the system, and no
running node ever learns it from a flag — the value is written once into the
document and thereafter read from chain state like any other data.

```bash
./sphinx genesis create --validators=K     # K = 3, 4, 5, … 1000
```

The only rule is a floor: **`K >= 3`** (`consensus.MinValidators`), because a
smaller set can never be safe. What `K` you pick is a liveness choice, not a
correctness one — see §8. The node behaves identically whether `K` is 3 or 1000;
`K` only decides how many validators exist and how many must vote.

Flags:

| Flag | Default | Meaning |
|---|---|---|
| `--validators=K` | `0` | number of genesis validators. **Rejected if `K < 3`** (`consensus.MinValidators`). Pick for the fault tolerance you want, not for convenience |
| `--funded-accounts=M` | `0` | extra reward addresses pre-funded with a stake-sized balance, so validators added later can be staked |
| `--root` | `data` | root directory holding the per-validator `node<N>` datadirs |
| `--host` | `127.0.0.1` | host used to derive each node's `Node-<host:port>` identity |
| `--tcp-base` | `30303` | P2P TCP port of validator 0; validator `i` gets `tcp-base+i` |
| `--stake-spx` | `32` | initial stake per validator, in whole SPX (`denom.MinValidatorStakeSPX`) |
| `--epoch-blocks` | `10` | `epoch_blocks` chain parameter written into the document |
| `--chain-id` | `73310` | chain id written into the document |
| `--network` | `devnet` | network label written into the document |

This tool is the **only** place `K` exists. It is never written into any node's
flags, never inferred from a connected-peer count, and never re-read by a
running node — once the document is written, the count is just data.

It writes one entry per validator. For the `N = 3` case, i.e.
`--root=data --tcp-base=30303 --validators=3`:

```
data/node0/config/genesis_state.json      validator Node-127.0.0.1:30303
data/node1/config/genesis_state.json      validator Node-127.0.0.1:30304
data/node2/config/genesis_state.json      validator Node-127.0.0.1:30305
data/node0/Node-127.0.0.1:30303/          that node's generated SPHINCS+ identity key
data/node1/Node-127.0.0.1:30304/
data/node2/Node-127.0.0.1:30305/
data/custody/devnet-rewards/validator-0.key.json   … one per genesis validator
data/custody/devnet-rewards/funded-3.key.json      … M extra funded reward keys
```

Every node reads a **byte-identical** copy of the document.

`--validators` tells **only this tool** how many validators to write. The value
never reaches a running node, and no node flag carries a count.

Re-running `genesis create` against existing datadirs is **refused** if it would
rename, drop or re-key a validator identity the document already binds, and a
re-run with identical parameters rewrites the same bytes. Reward keys are loaded,
never regenerated, so addresses are stable across runs.

Both refusals, shown against the `N = 3` datadir above:

```bash
$ ./sphinx genesis create --validators=2
--validators=2 is below the BFT minimum (consensus.MinValidators=3): a genesis file listing fewer can never be safe

$ ./sphinx genesis create --validators=3 --tcp-base=41403
refusing to rewrite .../config/genesis_state.json: it already binds validator Node-127.0.0.1:30303, but this run does not include it (it would rename or drop a validator identity). ...
```

---

## 4. Starting a node

```bash
./sphinx node --role=validator --tcp-addr=127.0.0.1:30303 --datadir=data/node0 --pbft
```

### `node` flags

| Flag | Default | Meaning |
|---|---|---|
| `--role` | `validator` | `validator` \| `sender` \| `receiver` \| `none` |
| `--tcp-addr` | `127.0.0.1:30303` | P2P gossip listen address. **Also defines this node's `Node-<host:port>` identity** |
| `--http-port` | `127.0.0.1:8545` | HTTP JSON-RPC listen address |
| `--ws-port` | `127.0.0.1:8600` | wallet/JSON-RPC listen address. Left at the default it becomes **`8700 + --port-offset`** |
| `--udp-port` | `""` | DHT UDP port. Defaults to **this node's TCP port + 1000** |
| `--datadir` | `data` | LevelDB/storage directory. Left at the default it becomes **`data/node<offset>`** |
| `--port-offset` | `0` | **Local addressing only.** Shifts the *default* TCP/HTTP/WS/UDP ports and the *default* datadir. Never changes a node ID, a validator set, or membership |
| `--seeds` | `""` | comma-separated seed TCP addresses, and/or `enrtree://` DNS discovery URLs. Empty ⇒ the built-in default DNS discovery tree |
| `--network` | `devnet` | `devnet` \| `testnet` \| `mainnet` |
| `--reward-address` | `""` | SPIF wallet address that stakes this node and receives its block rewards |
| `--pbft` | `false` | tunes startup logging. Consensus itself is driven by the on-chain set, so this is not what turns PBFT on |
| `--config` | `""` | path to a JSON node-config file. Must describe **one** node |
| `--mode` | `development` | `development` \| `production` |

**Derived addressing.** With `--port-offset=N` and no explicit overrides:

| | value |
|---|---|
| P2P TCP | `127.0.0.1:(30303+N)` |
| HTTP JSON-RPC | `127.0.0.1:(8545+N)` |
| wallet RPC (`--ws-port`) | `127.0.0.1:(8700+N)` |
| DHT UDP | P2P TCP + 1000 = `31303+N` |
| datadir | `data/node<N>` |

An explicit `--tcp-addr` / `--http-port` / `--ws-port` / `--datadir` always wins
and is never shifted. If you pass an explicit `--tcp-addr`, you must also pass a
`--datadir` (the default would otherwise still be derived from the offset).

UDP discovery is always **TCP + 1000** for a given node, so the DHT port of
`127.0.0.1:30304` is `31304`.

### Consensus and quorum, in one paragraph

Membership comes from chain state only: the genesis document's `validators`, then
on-chain Stake transactions. A block commits only when validators holding
**strictly more than 2/3 of the staked set's total stake** have voted
(`voted*3 > total*2`). Peers are not validators: a node that is not in the set
still gossips, syncs and relays, but its vote weighs zero and it is never a
leader. Offline validators do not change the set size — they simply do not vote.

---

## 5. Single-machine devnet — running N nodes, one per terminal

The walkthrough below uses **N = 3** because that is the minimum legal set and
the smallest thing that produces blocks. It is an example, not a requirement.
For any `N` the commands are the same shape — see the general rule at the end of
this section.

Everything runs as separate processes on `127.0.0.1` with unique ports and
datadirs. There is **no node-count flag**.

All commands below are relative to the **repository root** (the directory holding
`go.mod`), and assume you built the binary in §1. Adjust the path if your clone
lives somewhere else.

**Step 0 — once, before any node starts:**

```bash
./sphinx genesis create --validators=N
```

Substitute your own `N` (`>= 3`). The three-terminal walkthrough below is the
`N = 3` case, expanded for each node:

This writes `data/node0`, `data/node1`, `data/node2` with validators
`Node-127.0.0.1:30303`, `:30304`, `:30305`.

**Terminal 1 — the bootstrap node** (holds the datadir `genesis create` wrote for validator 0):

```bash
./sphinx node --role=validator \
    --tcp-addr=127.0.0.1:30303 \
    --http-port=127.0.0.1:8545 \
    --datadir=data/node0 \
    --pbft
```

**Terminal 2** (`--port-offset=1` ⇒ TCP `30304`, wallet RPC `8701`, datadir `data/node1`):

```bash
./sphinx node --role=validator \
    --port-offset=1 \
    --seeds=127.0.0.1:30303 \
    --pbft
```

**Terminal 3** (`--port-offset=2` ⇒ TCP `30305`, wallet RPC `8702`, datadir `data/node2`):

```bash
./sphinx node --role=validator \
    --port-offset=2 \
    --seeds=127.0.0.1:30303 \
    --pbft
```

Terminals 2 and 3 derive the **same** `Node-<host:port>` identities that
`genesis create` wrote, because the offset shifts `--tcp-addr` and `--datadir`
together (`30304`↔`data/node1`, `30305`↔`data/node2`).

Start them in **any order**. Terminals 2/3 wait on their own and fetch the public
bundle from node 1.

### What you should see

Node 1 alone:

```
GENESIS FILE: seeded 3 validators into the consensus set (96 SPX total)
Block-production suspended (need ≥ 3 staked+ready validators for PBFT, have 1 — waiting for validators to become reachable)
```

Node 1 is **waiting**, not stalled or mining a solo chain. Once all three are up,
each node logs:

```
Quorum achieved: 96.00 / 96.00 SPX voted (100.0%)
committed block <same-hash> at height 1
```

96 SPX = 3 × 32. All three must report the **identical** block hash at each
height, and there must be **zero** `attestation quorum not met` errors.

### The general rule for N nodes

Nothing above is specific to 3. For a set of `N` validators, author it with
`--validators=N` and start node `i` (0-based) as:

```bash
./sphinx genesis create --validators=N          # once, for any N >= 3

# node 0 — the bootstrap
./sphinx node --role=validator --tcp-addr=127.0.0.1:30303 --http-port=127.0.0.1:8545 --datadir=data/node0 --pbft

# node i (i >= 1)
./sphinx node --role=validator --port-offset=i --seeds=127.0.0.1:30303 --pbft
```

| | value for node `i` |
|---|---|
| `--port-offset` | `i` |
| P2P TCP | `127.0.0.1:(30303+i)` |
| HTTP JSON-RPC | `127.0.0.1:(8545+i)` |
| wallet RPC | `127.0.0.1:(8700+i)` |
| DHT UDP | `(30303+i) + 1000` |
| `--datadir` | `data/node<i>` |
| identity | `Node-127.0.0.1:(30303+i)` |

Every validator except node 0 is started **identically** — same command, only
the offset differs. `genesis create` derives exactly these identities, so each
node finds itself in the set. A node with `i >= N` was never written into the
document, so it joins as a **peer** (see §6).

The staked total and the quorum threshold scale with `N` automatically:
`N × 32` SPX total, and each block needs strictly more than `2/3 × N × 32`
SPX voting. The nodes do not need to be told any of this.


---

## 6. Adding nodes to a live network

A later node needs **only `--seeds`** plus its own identity/ports. It does not
need the genesis document in advance: on devnet it fetches the public sections
from its seeds.

```bash
# Pick any offset i >= N — it is not in the document, so this node is a PEER.
# For an N=3 network the first such offset is 3 (a 4th, unlisted node):

./sphinx node --role=validator \
    --port-offset=3 \
    --seeds=127.0.0.1:30303 \
    --pbft
```

That node is `Node-127.0.0.1:30306` on datadir `data/node3`. Unless
`genesis create` listed it, it is **a peer only**:

```
Not listed in the genesis file — participating as a peer only until a Stake transaction admits this node
```

It syncs the full chain, relays gossip and can answer RPC — but it contributes
**0 SPX** to the quorum denominator and never becomes leader. You can verify the
denominator is unaffected: the three listed validators keep reporting
`96.00 / 96.00 SPX`, not `96.00 / 128.00`.

To add several at once, give each its own offset (they map to `data/node<N>`
and `30303+N`):

```bash
./sphinx node --role=validator --port-offset=3 --seeds=127.0.0.1:30303 --pbft
./sphinx node --role=validator --port-offset=4 --seeds=127.0.0.1:30303 --pbft
./sphinx node --role=validator --port-offset=5 --seeds=127.0.0.1:30303 --pbft
```

If the node's datadir is empty, the first thing it must do is obtain the genesis
document. On devnet that happens automatically over the network:

```
DEVNET BUNDLE: waiting for the bootstrap node to finish signing — retrying bundle fetch over the network (elapsed 15s)
DEVNET BUNDLE: fetched + verified the public bundle over the network in 21s
```

If it instead exits with `devnet late joiner has no custody bundle …`, the fetch
failed — the seeds were unreachable, or the bootstrap node was not running yet.
That refusal is deliberate: starting without the document would build a
*different* block 0, and every peer would reject it at key exchange.

> **Restarting a node with an existing datadir never refetches and never
> overwrites.** It logs `DEVNET BUNDLE: local bundle already complete — no
> fetch, no overwrite` and keeps the files byte-for-byte.

---

## 7. Becoming a validator: staking

**Current state of this build.** Unstaked nodes are peers only (§6). The
mechanism that turns a peer into a validator is a **Stake transaction**, which —
at the time of writing — is **not yet exposed as a CLI subcommand**. The
`funded-accounts` reward addresses and keys that `genesis create` produces are
the inputs it will consume:

```
data/custody/devnet-rewards/funded-3.key.json   private_key + public_key (hex)
data/custody/devnet-rewards/validator-0.key.json
```

Those keys are real spendable SPIF accounts, already funded with a stake-sized
balance, and their addresses are listed in the document's `funded_accounts`.
Until the Stake subcommand lands, a non-genesis node cannot be added to the set.

> **`--reward-address`** declares which address a node stakes from and receives
> rewards at. Admission from a reward address is **balance-verified**: the
> address must hold at least the minimum stake on-chain, and one reward address
> admits at most one node ID. There is no localhost trust path and no
> self-grant — an unlisted node can never award itself a seat by starting up.
>
> Keep `data/custody/` private. `devnet-rewards/*.key.json` contain private keys.

---

## 8. Liveness

Under strict 2/3 stake the chain proceeds only while more than two thirds of the
staked set votes. For a staked set of `K` validators at 32 SPX each, a block
needs strictly more than `2/3 × K × 32` SPX voting.

| Staked set `K` | Stop one validator | Why |
|---|---|---|
| `K = 3` (the minimum) | **chain halts** — 2 remaining hold 64 SPX, and `64*3 = 192` is not `> 192` | expected, not a bug |
| `K >= 4` | **chain continues** — 3 of 4 hold 96 SPX, and `96*3 = 288 > 256` | one offline validator tolerated |

So the floor of 3 buys you a working chain, not fault tolerance. Choose `K` for
the availability you actually need: `K = 3` has none, `K = 4` tolerates one
offline validator, `K = 5` tolerates two, and so on (`f = floor((K-1)/3)`).
The node computes this itself; you do not configure it.

Practical notes for a single machine:

- **View-change timeouts are generous on purpose.** A full PBFT round needs
  several SPHINCS+ signatures (block header, proposal, prepare, commit), and each
  costs seconds of CPU. Six signers on one laptop is slow; the leader waits up to
  ~90s for a round to commit before advancing the view. Give a loaded machine
  time before concluding something is wrong.
- **Offline validators do not change the set size.** They stop voting and the
  remaining stake simply may not clear 2/3 — which is exactly the halt above.
- **Keep the datadirs separate.** One terminal → one `--tcp-addr` → one matching
  `--datadir`. Two nodes sharing a datadir is the most common setup mistake.
- **Preserve `Node-<addr>/keys`.** That is the node's persistent identity. Peers
  pin `node_id`↔public key, so deleting it and regenerating makes the node a
  stranger under a familiar name.


---

## 9. Removed flags — and what replaced them

`--nodes`, `--node-index` and `--legacy-cluster` **no longer exist**. Use of any
of them fails immediately with `flag provided but not defined`.

| Removed | Was used for | Now |
|---|---|---|
| `--nodes=N` | told a node how many validators to expect, and sized its local validator set | **Nothing.** The set comes from `genesis_state.json`, then on-chain Stake transactions. No flag or peer count can influence it |
| `--node-index=<i>` | selected this node's slot in a pre-agreed roster (ports, identity, datadir, wallet-RPC port) | **`--port-offset=<i>`** — shifts *default* ports and *default* datadir only. It never selects an identity or a place in the validator set |
| `--legacy-cluster` | ran the deprecated same-process 3-node harness (`RunMultipleNodesInternal`) | **Nothing.** The harness, `bind/legacy.go`, and the flag are deleted. There is **no same-box mode** |
| `--test-nodes` | set a `TestConfig.NumNodes` field that nothing ever read | **Nothing.** Deleted |
| derived wallet RPC `8700 + --node-index` | per-node wallet-RPC port | **`8700 + --port-offset`**, or an explicit `--ws-port` |

Consequences to be aware of:

- **No "sized up front" requirement.** Earlier versions of this document told you
  to start every node with the same `--nodes=N` and warned that growing a running
  network was limited (3→4 worked, 4→5 did not). That limitation was an artefact
  of `--nodes` overriding the validator set. Membership is chain state now, so
  there is no up-front sizing and no growth limit.
- **No "synthetic / same-box addressing" fallback.** Previously, omitting
  `--tcp-addr` fell back to fixed ports starting at 32307 and ignored
  `--datadir`. That path is gone; `--tcp-addr` and `--datadir` are always honoured
  as given (or derived from `--port-offset`).
- **The `legacyExecute` function name is not legacy.** It is the normal
  flag-parsing path for flag-style invocation. Only its `--legacy-cluster` branch
  was legacy, and that branch is gone.

---

## 10. Inspecting a running node

Query **that node's** wallet-RPC port (`8700 + --port-offset`):

```bash
# node 1 (offset 0 → 8700)
./sphinx get-balance --rpc 127.0.0.1:8700 \
    --address <ADDRESS>

# node 2 (offset 1 → 8701)
./sphinx get-balance --rpc 127.0.0.1:8701 \
    --address <ADDRESS>
```

**The vault and escrow addresses are not fixed constants on a devnet.** Node 1
generates an M-of-N custody policy on first start and uses its derived address as
block 0's vault, so the address to query is whatever that node logged:

```
DEVNET AUTO-CUSTODY ACTIVE: vault=7A4399BF09033F3F9DB7D311A1949F3CEF938C2A escrow=B2B87E290E2D2EA57008DDF1CF684E259781FC6A
```

Query those and you get the expected shape — the escrow holds the time-locked
remainder, and the vault has already paid every allocation out of itself in block
0, so it reads `0`:

```bash
$ ./sphinx get-balance --rpc 127.0.0.1:8700 --address 7A4399BF09033F3F9DB7D311A1949F3CEF938C2A
Balance for 7A4399BF09033F3F9DB7D311A1949F3CEF938C2A: 0.000000 SPX (confirmed=0 nSPX, ...)

$ ./sphinx get-balance --rpc 127.0.0.1:8700 --address B2B87E290E2D2EA57008DDF1CF684E259781FC6A
Balance for B2B87E290E2D2EA57008DDF1CF684E259781FC6A: 424999981.513632 SPX (confirmed=424999981513631687242798355 nSPX, ...)
```

`0000000000000000000000000000000000000001` is only the **legacy** fallback vault
address, used when a network has no custody policy at all. On a devnet with
auto-custody it correctly reads `0` — it is not the address block 0 funded.

> Pointing `--rpc` at an `--http-port` value fails — that listener speaks HTTP,
> not the handshake-authenticated JSON-RPC wire format `get-balance` needs.

Useful log lines and what they mean:

| Line | Meaning |
|---|---|
| `GENESIS FILE: <K> initial validators, epoch_blocks=<E>, network=<N>` | the document was loaded |
| `seeded <K> validators into the consensus set (<S> SPX total)` | the staked set is exactly the document's, at its declared stakes |
| `Not listed in the genesis file — participating as a peer only …` | this node is not in the set; it is a peer |
| `No genesis file at … — validator membership will come from runtime stake admission only` | no document on disk |
| `Waiting for staked validators to be ready (<r>/<min> minimum)…` | the node is waiting for liveness, not misconfigured |
| `Quorum achieved: <voted> / <total> SPX voted` | a round reached > 2/3 |
| `committed block <hash> at height <h>` | the hash must match on every validator |
| `DEVNET BUNDLE: fetched + verified the public bundle over the network` | a joiner obtained the document itself |

Tear down and start over:

```bash
# Ctrl+C in each terminal, then:
rm -rf data/
```


---

## 11. Troubleshooting

| Symptom | Cause |
|---|---|
| `flag provided but not defined: …` | you used a flag this build no longer has — see §9 |
| `--validators=2 is below the BFT minimum …` | a genesis document needs ≥ 3 validators |
| `refusing to rewrite … it already binds validator …` | re-running `genesis create` with parameters that would rename/re-key existing identities. Re-run with the same `--host`/`--tcp-base`, or delete the old document deliberately |
| `address already in use` on bind | two processes on the same port. Give each a distinct `--port-offset`, or explicit `--tcp-addr`/`--http-port`/`--ws-port` |
| node runs but never produces a block; logs `Waiting for staked validators to be ready (r/min …)` | fewer than `consensus.MinValidators` (3) staked+ready validators are reachable. Start more of the listed validators |
| node logs `Not listed in the genesis file …` and never votes | it is not in the document's `validators`; see §7 |
| `attestation quorum not met` | some validators' votes are missing for that block — a liveness problem, not a config error. Check which validators are up |
| `devnet late joiner has no custody bundle …` | the network bundle fetch failed: seeds unreachable, or the bootstrap node was not yet running. Check `--seeds` |
| `genesis hash mismatch` at key exchange | the peer holds a different genesis document. All nodes in one network must read byte-identical documents |
| a node started with `--port-offset=0` next to an existing node fails to bind | offset 0 collides with node 1; use a distinct offset |

---

## 12. File reference

| File | Purpose |
|---|---|
| `src/cli/main.go` | CLI entry point |
| `src/cli/utils/cli.go` | subcommand routing, `node` flags, `--port-offset`, help text |
| `src/cli/utils/genesis.go` | `genesis create` — the only place the validator count exists |
| `src/core/genesis.go` | the one genesis document: struct, loader, writer, `Validate` |
| `src/bind/nodes.go` | `StartNode` — full node startup, listener binding, shutdown |
| `src/bind/helpers.go` | block sync, block production, peer handshake, genesis seeding |
| `src/bind/node_shutdown.go` | ordered teardown |
| `src/bind/devnet_bundle.go` | devnet joiner-side public-bundle fetch |
| `src/consensus/validators.go` | `MinValidators` |
| `src/consensus/consensus.go` | quorum (`meetsStakeQuorum` = `voted*3 > total*2`), leader selection |
| `src/bind/types.go` | `SyncState`, `GetBlocksRequest` / `GetBlocksResponse` |

