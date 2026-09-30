# Sphinx CLI — Running Nodes

How to build the CLI and run validator nodes as separate processes on one
machine.

**Every command and every log excerpt below was executed against this tree.**
Raw output is quoted verbatim; nothing here is aspirational.

> ## ⚠️ State of automatic joining — read this first
>
> After Phase 1, **the three-command flow below works, and the three nodes end
> up on the same chain at the same height and block hash — but only ONE of them
> is a validator.** The other two are **peers**.
>
> This is expected and temporary. Automatic joining is built in stages and only
> the first has landed:
>
> | Stage | Status | What it does |
> |---|---|---|
> | Auto-authored genesis | **Working** | The first node to start writes `genesis_state.json` naming only itself. |
> | Genesis fetch over the network | **Working** | Later nodes fetch that exact document from `--seeds`. |
> | Faucet payout | **Disabled** | Written, not yet enabled. Waits for the Phase 2 tests. |
> | Node submits its own Stake tx | **Disabled** | Waits for the Phase 2 tests. |
> | Activation at an epoch boundary | **Built, not yet wired to the live set** | Waits for the Phase 2 validator-set merge. |
>
> Consequence, stated plainly: **a joining node stays a peer** and contributes
> no vote weight. A one-validator devnet is a real, working chain — its single
> validator holds 100% of the stake, so it commits its own blocks — but a
> three-node devnet is a *one*-validator devnet with two spectators.
>
> Nothing here describes a 3-validator network as working, because it is not
> yet. §5 shows the log lines that prove the current state.

---

## 1. Prerequisites and build

Requires Go (built and tested on darwin/arm64).

```bash
cd /Users/kusuma/Desktop/protocol
go build ./...          # exit 0
go build -o sphinx ./src/cli
```

```
$ go build -o sphinx ./src/cli
35586240 sphinx
```

Run the tests the way the `Makefile` does (the SPHINCS+ suites in `src/core`
take about 3 minutes, which is why the default 10m `go test` timeout is too
tight on a loaded machine):

```bash
make test        # test-policy test-musig test-cli test-core
```

---

## 2. The zero-setup flow

Three terminals. Three commands. No `genesis create`, no `--datadir`, no
`--tcp-addr`, no key material, no addresses to paste.

```bash
# Terminal 1
./sphinx node --pbft

# Terminal 2
./sphinx node --pbft --port-offset=1 --seeds=127.0.0.1:30303

# Terminal 3
./sphinx node --pbft --port-offset=2 --seeds=127.0.0.1:30303
```

| Terminal | Command | P2P TCP | HTTP | Wallet RPC | Datadir |
|---|---|---|---|---|---|
| 1 | `--pbft` | `127.0.0.1:30303` | `127.0.0.1:8545` | `127.0.0.1:8700` | `data` |
| 2 | `--port-offset=1` | `127.0.0.1:30304` | `127.0.0.1:8546` | `127.0.0.1:8701` | `data/node1` |
| 3 | `--port-offset=2` | `127.0.0.1:30305` | `127.0.0.1:8547` | `127.0.0.1:8702` | `data/node2` |

- **`--port-offset N`** shifts only the *default* ports and the *default*
  datadir: TCP `30303+N`, HTTP `8545+N`, wallet RPC `8700+N`, datadir
  `data/node<N>`. It never changes a node's identity and never affects
  validator membership.
- **UDP = TCP + 1000** for peer discovery.
- **Node identity** is derived from the TCP address as `Node-<host:port>`.

Verified from the run:

```
$ grep 'Starting node role=' T1.log T2.log T3.log
T1.log: Starting node role=validator tcp=127.0.0.1:30303 udp= rpc=127.0.0.1:8545 seeds=""               data=data      pbft=true mode=development network=devnet
T2.log: Starting node role=validator tcp=127.0.0.1:30304 udp= rpc=127.0.0.1:8546 seeds="127.0.0.1:30303" data=data/node1 pbft=true mode=development network=devnet
T3.log: Starting node role=validator tcp=127.0.0.1:30305 udp= rpc=127.0.0.1:8547 seeds="127.0.0.1:30303" data=data/node2 pbft=true mode=development network=devnet

$ grep 'Wallet/JSON-RPC listener bound' T2.log
Wallet/JSON-RPC listener bound on 127.0.0.1:8701
```

**First startup is slow.** Terminal 1 spends roughly 1–2 minutes generating
SPHINCS+ keys and signing the 13 block-0 distribution witness sets (2-of-3 each,
26 signatures) before it can serve anything. Let Terminal 1 reach
`GENESIS AUTHORED` before launching the others, or they will wait (§4).


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

## 3. What Terminal 1 does: authors the genesis

There is no "bootstrap terminal" and no node count anywhere. The **first node to
start** writes the document, and it names only itself.

```
$ grep -E 'DEVNET REWARD KEY|GENESIS AUTHORED|DEVNET FAUCET|GENESIS FILE' T1.log
DEVNET REWARD KEY: auto-generated DA852F4FFDE0B7B89A3B5327271D2CEC1614F0DC34A91209EAE00C523E5E8627 (datadir data/custody/devnet-auto/reward) — no --reward-address needed
GENESIS AUTHORED: no document existed, so this node created it naming only itself (Node-127.0.0.1:30303)
DEVNET FAUCET: 55F1239553FC2E7B0A5910806CB9C04E57E47E6050AB9FE551D1E3498E1A734A holds 3200016800000000000000000 nSPX, paying 32000168000000000000 nSPX per joiner (min stake + fee reserve); any number of joiners, no fixed list
GENESIS FILE: 1 initial validator(s), epoch_blocks=10, network=devnet
GENESIS FILE: seeded 1 validators into the consensus set (32 SPX total)
```

Four things to notice:

1. **No reward address needed.** Each devnet node auto-generates one keypair in
   its own datadir on first start, so no address is ever pasted or copied.
2. **The document is marked `bootstrap: true`** and lists exactly one
   validator: itself. That is legitimate, and it is what makes the
   one-command flow possible at all.
3. **A faucet allocation is recorded** (§6) — *written*, but not yet paid out.
4. **`epoch_blocks=10`** is a chain parameter read from the document, not a
   flag.

Then it produces blocks:

```
$ grep -E 'SOLO MODE|Solo-mined and committed' T1.log | head -4
[Node-127.0.0.1:30303] SOLO MODE — bootstrap node, no peers detected yet, mining blocks independently
[Node-127.0.0.1:30303] Solo-mined and committed block height=1 txs=0
[Node-127.0.0.1:30303] Solo-mined and committed block height=2 txs=0
[Node-127.0.0.1:30303] Solo-mined and committed block height=3 txs=0
```

A single validator holds 100% of the staked stake, so it satisfies the strict
`> 2/3` rule on its own and does not need a second node to make progress.

### Where the document lives

```
data/config/genesis_state.json          # Terminal 1 (authored here)
data/node1/config/genesis_state.json    # Terminal 2 (fetched)
data/node2/config/genesis_state.json    # Terminal 3 (fetched)
```

Exactly **one** genesis file per node. It carries the chain parameters, the
initial validator set, the funded accounts, the custody policy and the block-0
witness book as sections of the same document.

---

## 4. What Terminals 2 and 3 do: fetch, never author

A node given `--seeds` is a **joiner**. It fetches the complete document over
the network from its seed and **never authors one of its own** — a joiner that
authored a document naming only itself would fork the chain at block 1.

```
$ grep -E 'DEVNET BUNDLE|GENESIS FILE|Not listed' T2.log
DEVNET BUNDLE: seed is reachable but still finishing block-0 witness signing (26 SPHINCS+ signatures) — retrying bundle fetch every 5s (elapsed 0s, ceiling 30m)
DEVNET BUNDLE: fetched + verified the public bundle over the network in 5s
DEVNET BUNDLE: joiner waited 5s for the bootstrap bundle
GENESIS FILE: 1 initial validator(s), epoch_blocks=10, network=devnet
GENESIS FILE: seeded 1 validators into the consensus set (32 SPX total)
[Node-127.0.0.1:30304] Not listed in the genesis file — participating as a peer only until a Stake transaction admits this node
```

The wait log distinguishes two very different problems, and says what to do:

| Log line | Meaning | Action |
|---|---|---|
| `no seed has answered yet ... ACTION: start the seed node` | Nothing is listening on the seed address | Start Terminal 1 |
| `seed is reachable but still finishing block-0 witness signing` | The seed is up and working; still signing | Wait (ceiling 30m) |

The 30-minute ceiling is deliberate: the seed cannot serve the bundle until it
has finished 26 SPHINCS+ signatures, which takes 1–3 minutes depending on core
count. A short deadline would fail legitimate cases where all three terminals
are launched at once.

**A node with `--seeds` never authors a genesis.** Verified:

```
$ grep -c 'GENESIS AUTHORED' T2.log T3.log

---

## 5. The three nodes converge — as one validator and two peers

Same height, same block hash, on all three terminals:

```
$ for f in T1 T2 T3; do printf "%s: " $f; grep -oE 'height=30, hash=[0-9a-f]{16}' $f.log | tail -1; done
T1: height=30, hash=e536f53f8db465ee
T2: height=30, hash=e536f53f8db465ee
T3: height=30, hash=e536f53f8db465ee

$ grep -c 'attestation quorum not met' T1.log T2.log T3.log
T1.log:0
T2.log:0
T3.log:0
```

The validator set is identical in every terminal — **one** validator, 32 SPX:

```
$ for f in T1 T2 T3; do echo "-- $f:"; grep 'seeded .* validators into the consensus set' $f.log | head -1; done
-- T1: GENESIS FILE: seeded 1 validators into the consensus set (32 SPX total)
-- T2: GENESIS FILE: seeded 1 validators into the consensus set (32 SPX total)
-- T3: GENESIS FILE: seeded 1 validators into the consensus set (32 SPX total)
```

So T2 and T3 reach consensus about block 30 without holding any weight: they
verify and follow the chain, they just do not vote. That is the intended
behaviour for an unstaked node, and it is what the warning at the top of this
document describes.

---

## 6. The devnet faucet (written, not yet paying out)

The bootstrap node's document carries a faucet account. The numbers are derived
from the real policy fee floor, not chosen:

| Quantity | Value |
|---|---|
| `BaseTransactionGas` | `21000` |
| `MinimumGasPrice` | `1000000000` nSPX/gas |
| Stake tx fee | `21000 × 1e9 = 21000000000000` nSPX = `0.000021` SPX |
| Fee reserve (2 fees × 4 margin) | `0.000168` SPX |
| **Payout per joiner** | **32.000168 SPX** = `32000168000000000000` nSPX |
| **Faucet pool** | `3200016800000000000000000` nSPX = 100,000 payouts |

The reserve exists because a joiner must be able to (a) lock the full minimum
stake **and** (b) still pay the gas fee for its own Stake transaction. Paying
exactly 32 SPX would leave zero minus the fee, so the Stake tx could never be
broadcast.

The pool is a **large fixed literal**, not `K × stake` and not a node count.
Nothing ever reads it as a network size; it is a treasury cap. If it were ever
exhausted, a joining node would simply not be funded and would remain a peer — a
liveness condition for that node, never a safety problem.

**It is not active yet.** Automatic joining is disabled pending the Phase 2
tests.

---

## 7. Validator math

A block commits when validators holding **strictly more than two thirds** of the
active staked set vote (`voted × 3 > total × 2`). For `K` validators at equal
stake that is `floor(2K/3) + 1` validators:

| `K` | Votes needed to commit | Offline tolerated |
|---|---|---|
| 1 | 1 | 0 |
| 2 | **2** (both) | 0 |
| 3 | **3** (all three) | 0 |
| 4 | 3 | **1** |
| 5 | 4 | 1 |

---

## 8. All flags

Run `./sphinx node --help` for the authoritative list. Defaults as of this tree:

| Flag | Default | Meaning |
|---|---|---|
| `--role` | `validator` | `validator \| sender \| receiver \| none` |
| `--tcp-addr` | `127.0.0.1:30303` | P2P gossip address; also the node identity |
| `--http-port` | `127.0.0.1:8545` | HTTP JSON-RPC |
| `--ws-port` | `127.0.0.1:8600` | WebSocket / wallet RPC base (`8700 + offset`) |
| `--datadir` | `data` | Storage root; becomes `data/node<N>` with an offset |
| `--seeds` | *(empty)* | Seed addresses. **Non-empty makes this node a joiner** |
| `--port-offset` | `0` | Shifts only the default ports and default datadir |
| `--udp-port` | TCP + 1000 | Peer discovery |
| `--pbft` | off | Enable PBFT consensus mode |
| `--network` | `devnet` | `devnet \| testnet \| mainnet` |
| `--reward-address` | *(empty)* | Optional on devnet; one is auto-generated |
| `--config` | *(empty)* | JSON file describing **one** node's addresses |
| `--mode` | `development` | `development \| production` |

**`--config` describes one node.** A single-entry file is used whatever
`--port-offset` is. A multi-entry file is **refused** with an explanatory error,
because indexing into it by `--port-offset` would turn it into a de-facto
pre-agreed node roster — exactly the knowledge this design removes.

---

## 9. Non-devnet networks

Auto-authoring genesis is **devnet only**. On `testnet` or `mainnet` a node with
no genesis document **refuses to start** and tells you where to put it:

```
no genesis document at <datadir>/config/genesis_state.json and --network="mainnet"
is not devnet: auto-authoring genesis is devnet-only, so this node cannot safely
guess the network's membership or chain parameters. Place the document at
<datadir>/config/genesis_state.json (copy it from a peer) and start again
```

You must place `genesis_state.json` at `<datadir>/config/genesis_state.json` out
of band, by copying it from a peer. The node will not create it for you.

---

## 10. Removed flags

These existed previously and are gone. They appear nowhere in this document
except here:

| Removed | Why |
|---|---|
| `--nodes` | A node count must never be configuration |
| `--node-index` | Ditto — identity comes from `--tcp-addr` |
| `-legacy-cluster` | Hardcoded a 3-node cluster on fixed ports |
| fixed `32307+` ports | Contradicted the real `30303` default; removed as dead code |

---

## 11. Optional: `genesis create`

**Not part of the main flow.** You do not need it to run a devnet, and nothing
above uses it.

`genesis create` authors a genesis document that names **several** validators
before any of them have started. Use it when you want a specific,
pre-declared set — for example to test fault tolerance with four validators.

```bash
./sphinx genesis create --validators=4
./sphinx genesis create --validators=3 --funded-accounts=2
```

| Flag | Default | Meaning |
|---|---|---|
| `--validators` | `3` (the BFT floor) | How many validators to name |
| `--funded-accounts` | `0` | Extra pre-funded reward addresses |
| `--root` | `data` | Root holding `node<N>` datadirs |
| `--host` | `127.0.0.1` | Host used to derive identities |
| `--tcp-base` | `30303` | Base TCP port |

It refuses fewer than the BFT floor of 3, because a multi-node network
provisioned below the floor can never tolerate a fault.

**Limitation — important.** `genesis create` does **not** support per-validator
reward addresses or public keys, and it cannot generate per-validator
identities for machines you do not control. It is therefore appropriate for a
single-machine devnet and for nothing else. Do not use it to author a
multi-machine production network.

---

## 12. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `refusing to author genesis: this node was given --seeds=...` | A joiner has no document | Start the seed node |
| `no seed has answered yet ... ACTION: start the seed node` | Nothing listening on the seed | Start Terminal 1 |
| `seed is reachable but still finishing block-0 witness signing` | Seed is working, just slow | Wait; ceiling is 30m |
| `... is not devnet: auto-authoring genesis is devnet-only` | Non-devnet with no document | Copy `genesis_state.json` into `<datadir>/config/` |
| A joiner never votes | Expected after Phase 1 | Automatic joining is disabled; see the warning at the top |
| `--config file holds N node entries` | Multi-entry config | Use one file per node, or explicit flags |

On one machine, SPHINCS+ signing is slow: a PBFT round needs several signatures
and each costs seconds of CPU. The generous timeouts are deliberate.

### Known limitation: the reported `default_port` does not match reality

The chain-info record reports `default_port: 32307` (it comes from
`params/commit/header.go` and is persisted in chain state), but the node
actually listens on `30303 + port-offset`. It is **display-only** — the value
is never used to dial anything — so it affects nothing functionally, but the
P2P chain handshake and the HTTP explorer both advertise a port the node is not
listening on. Left as-is deliberately: changing it would alter persisted chain
parameters.

| 7 | 5 | 2 |

**`K = 3` tolerates nothing.** Two of three is exactly 2/3, and the rule is
*strictly* more, so it does not commit. The smallest set that survives one
offline validator is **4**.

Offline validators do not change the set size — they simply stop voting.

Readiness uses the same arithmetic: block production waits until validators
holding more than 2/3 of the active snapshot's stake are ready. There is no
node count in that condition.

T2.log:0
T3.log:0
```

If the seed is unreachable and no document ever arrives, the joiner **waits and
then fails loudly**. It does not invent a genesis.

