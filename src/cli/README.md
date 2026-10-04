# Sphinx CLI — Running Nodes

How to build the CLI and run validator nodes as separate processes on one
machine.

The log excerpts below are from this tree. A fresh devnet starts with the
validator set in chain state; additional nodes join as peers and only gain
validator weight through chain-state admission.

> ## Checkpoint 2 implementation status
>
> | Item | Status |
> |---|---|
> | 0 — epoch-opening snapshot created before the opening block verifies | **Done, proven through the real `CommitBlock`** |
> | 0b — startup rebuilds a missing snapshot and gates participation | **Done, proven through the real `AttachSnapshotStore`** |
> | 1 — snapshot-based quorum everywhere; `getTotalNodes` deleted; float paths fixed | **Done, proven** |
> | 2 — proposed-height snapshot proposer selection; unstaked-peer neutrality; Debug logging | **Done** |
> | 3 — chain-queued Stake/Unstake, delayed activation, identity proof, CLI | **Done** |
> | 4 — evidence-only double-sign slashing from chain state | **Done** |
> | 5 — unequal-stake quorum and timeout quorum reports | **Done** |
> | 6 — block-hash commitments to active snapshot and canonical genesis data | **Done** |
> | 7 — SMR membership and quorum sourced from chain snapshots | **Done** |
> | 8 — README updated to match the implementation | **Done** |
>
> **`./sphinx node --pbft` by itself starts a one-validator devnet.** That
> validator is the whole active set and may produce every block. More nodes can
> join as peers without changing consensus behavior. They participate as
> validators only when chain state admits their stake. There is no command-line
> node-count or predeclared-roster setting. Stake takes effect at epoch `e+2`.
> A full unstake exits at its delayed boundary, but escrowed funds remain
> slashable for three more epochs before withdrawal; evidence is accepted for
> at most two epochs.
> Genesis validators with an on-chain stake owner have their genesis stake
> moved into the staking escrow during block 0; a valid double-sign proof
> reduces active stake and burns the matching escrowed penalty.

---

## 1. Prerequisites and build

Requires Go 1.25+ (this tree is developed on go1.27.1). Built and tested on
darwin/arm64.

```bash
git clone https://github.com/sphinxfndorg/protocol.git
cd protocol
go build ./...                 # compile everything
go build -o sphinx ./src/cli   # build the CLI binary
```

```
$ go build -o sphinx ./src/cli
35586240 sphinx
```

Check it:

```bash
./sphinx help
```

If you would rather not build a binary, every command in this document also
works as `go run src/cli/main.go <command>` — just slower on each invocation,
because the CLI is recompiled.

Run the tests the way the `Makefile` does (the SPHINCS+ suites in `src/core`
take about 3 minutes, which is why the default 10m `go test` timeout is too
tight on a loaded machine):

```bash
make test          # all suites, 40m timeout
make test-cli      # just the CLI
go test ./... -timeout 40m
```

### Verification

For this implementation, the selected package regression suite passed:

```text
go test ./src/consensus ./src/core ./src/core/transaction ./src/state ./src/cli/utils ./src/bind -count=1
```

After the final genesis-stake escrow change, the targeted stake/unstake and
real-commit-path tests passed, along with `go build ./...`, `go vet ./...`, and
`git diff --check`. These checks cover the chain-state membership logic, CLI
dispatch, real SPHINCS+ evidence/quorum paths, and the changed consensus
packages; they are not a claim that a separate-process multi-validator network
has been tested.

**Genesis commitment:** the block-0 header commits to the canonical
chain-defining projection of the genesis document and the epoch-0 validator
snapshot. On bootstrap, `Genesis block commitments: snapshot=... document=...`
prints both digests; they are also part of the block hash and are checked during
validation. There is intentionally no universal hard-coded digest: it is
derived from each chain's genesis parameters and initial validators. Tests
verify that changing chain-defining genesis data changes the commitment. The
canonical projection includes the version, chain ID and parameters, initial
validators, funded accounts, custody/witness policy, and bootstrap marker; it
excludes mutable audit totals and derived metadata.

---

## 2. Run a localnet (recommended)

For anything involving more than one validator, use `localnet`. It generates N
validator keypairs, writes **one genesis document naming all N**, and starts N
node processes with distinct port offsets:

```bash
./sphinx localnet --validators=4
```

Every process is a real genesis validator, so the network runs actual quorum —
unlike the hand-run flow in the next section, where only the first node holds
stake and the rest are unstaked peers.

| Flag | Default | Meaning |
|---|---|---|
| `--validators` | `4` | Number of validator processes. **Minimum 4.** |
| `--dir` | temp dir | Root for the per-node datadirs (`<dir>/node-<i>/`). Removed on exit unless `--dir` is given. |
| `--base-port-offset` | `0` | Offset of node 0; node *i* uses `base + i`. |
| `--keep` | off | Keep the data directory on exit. |

Node *i* listens on TCP `30303+base+i`, HTTP `8545+base+i`, wallet RPC
`8700+base+i`, and stores data under `<dir>/node-<i>/`. Node 0 authors genesis;
the others fetch that exact document over the devnet bundle, so all N derive
the identical validator set.

Why the minimum is 4: under strict `> 2/3`, `K=3` tolerates **no** offline
validator — two of three is exactly 2/3. Four is the smallest set that
demonstrates surviving a single failure (§7).

Startup is slow: each validator generates SPHINCS+ keys and node 0 signs the
block-0 witness book, which takes minutes. `Ctrl-C` stops every process.

**Cold start cost.** A localnet must generate SPHINCS+ keys and complete a
full peer mesh before it can commit, so startup scales with N. Measured on this
machine, to the first committed block:

| Phase | N=4 | N=7 |
|---|---|---|
| Supervisor identity keys | 0s | 0s |
| Custody provisioning (CGE escrow + 3 custodians) | 54s | 79s |
| Genesis + witness book | +17s | +28s |
| Node 0 boot | +97s | +136s |
| Peer discovery + first quorum round | +186s | +407s |
| **Total to first commit** | **186s** | **407s** |
| Directed peer handshakes logged | 22 | 79 |
| Full mesh required | 12 (4×3) | 42 (7×6) |
| Handshake window | 53s | 220s |

The dominant cost is **peer handshake**: a full mesh needs `N*(N-1)` directed
handshakes at roughly 2s each, so the handshake window alone grows from 53s at
N=4 to 220s at N=7 and accounts for most of the N-dependent growth. Note the
handshake count observed in the log exceeds `N*(N-1)` because peers retry.

**Known gaps.** Two failure scenarios are not covered by a passing test, and
both are left visible as skipped tests in
`src/cli/utils/localnet_integration_test.go`:

- *Leader failure is not survivable.* Killing the current leader stalls the
  chain: survivors keep their height indefinitely and **no view change is ever
  triggered**, so nobody is re-elected. Measured: survivors frozen for 6+
  minutes with 0 `View change triggered` lines, against 267 in a healthy run.
- *Validator rejoin is unverified.* A killed validator restarts cleanly on its
  existing datadir and keys and the chain keeps advancing, but the rejoined node
  emits no height+hash log line, so "it re-synced and all four agree on height
  and hash" cannot be asserted. Closing this needs either a best-height/hash RPC
  or a sync log line that carries both.
network commits blocks and tolerates a minority of failures. Under strict `> 2/3`
the quorum size is `(2N)/3 + 1`:

| N | Quorum | Live | Quorum met | Chain |
|---|---|---|---|---|
| 4 | 3 | 4 | yes | commits |
| 4 | 3 | 3 | yes | keeps committing |
| 4 | 3 | 2 | no (2/3 is not `> 2/3`) | halts |
| 7 | 5 | 7 | yes | commits |
| 7 | 5 | 5 | yes | keeps committing |
| 7 | 5 | 4 | no | halts |

That behaviour is covered end-to-end by `src/cli/utils/localnet_integration_test.go`,
which runs the real command against `N=4` and `N=7` validator processes. It is
build-tagged because each validator spends minutes on SPHINCS+ key generation and
block-0 witness signing before it can vote — a cold `N=4` localnet takes roughly
**3 minutes** to its first committed block, and `N=7` costs about twice that:

```bash
go test -tags localnet ./src/cli/utils/ -run TestLocalnet -timeout 90m
```

For each size the test asserts all three properties: every validator agrees on
height **and** hash; killing a tolerated minority keeps the chain committing; and
killing one more drops below quorum and halts it. The kill counts are derived from
the quorum formula rather than hardcoded, so the test follows the production rule
instead of restating it.

---

## 2a. Start a node by hand and add peers

A fresh devnet node authors its own genesis and starts with itself as the
initial validator. Start another process with a distinct local port/datadir and
the first node as its seed:

```bash
# Terminal 1 — authors devnet genesis and starts the first validator
./sphinx node --pbft

# Terminal 2 — joins as a peer and syncs from Terminal 1
./sphinx node --pbft --port-offset=1 --seeds=127.0.0.1:30303

# Terminal 3+ — same pattern, with a unique local port offset
./sphinx node --pbft --port-offset=2 --seeds=127.0.0.1:30303
```

Joining as a peer does not change validator membership or consensus readiness.
Active membership and proposer selection come from chain state; a peer only
votes after its stake has been admitted there. A one-validator chain cannot
rotate its proposer.

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
- **Wallet RPC is `8700+N`, not `8600+N`.** `--ws-port` is declared with the
  literal default `127.0.0.1:8600`, but that value is a *sentinel meaning
  "unset"* — the node never listens on 8600. Both the listener and the
  in-process custody watcher resolve the address through
  `network.ResolveWalletRPCAddr`, so they cannot disagree. Verified against a
  live node:

  ```
  offset 0 → Wallet/JSON-RPC listener bound on 127.0.0.1:8700
  offset 1 → Wallet/JSON-RPC listener bound on 127.0.0.1:8701
  ```
- **Node identity** is derived from the TCP address as `Node-<host:port>`.

Verified from the run:

```
$ grep 'Starting node role=' T1.log T2.log T3.log
T1.log: Starting node role=validator tcp=127.0.0.1:30303 udp=31303 rpc=127.0.0.1:8545 seeds=""               data=data      pbft=true mode=development network=devnet
T2.log: Starting node role=validator tcp=127.0.0.1:30304 udp=31304 rpc=127.0.0.1:8546 seeds="127.0.0.1:30303" data=data/node1 pbft=true mode=development network=devnet
T3.log: Starting node role=validator tcp=127.0.0.1:30305 udp=31305 rpc=127.0.0.1:8547 seeds="127.0.0.1:30303" data=data/node2 pbft=true mode=development network=devnet

$ grep 'Wallet/JSON-RPC listener bound' T2.log
Wallet/JSON-RPC listener bound on 127.0.0.1:8701
```

The startup line reports the **effective** discovery port (`udp=`), i.e. the
TCP+1000 value the node actually binds. `--udp-port` still defaults to empty so
the node derives it from its own listen address, but the log shows the resolved
number rather than the empty flag.

**First startup is slow.** Terminal 1 spends roughly 1–2 minutes generating
SPHINCS+ keys and signing the 13 block-0 distribution witness sets (2-of-3 each,
26 signatures) before it can serve anything. Let Terminal 1 reach
`GENESIS AUTHORED` before launching the others, or they will wait (§4).

---

## 3. Single-validator smoke test: what Terminal 1 does

In this smoke-test flow there is no pre-created validator roster. The **first
node to start** writes a genesis document that names only itself.

```
$ grep -E 'DEVNET REWARD KEY|GENESIS AUTHORED|DEVNET FAUCET|GENESIS FILE' T1.log
DEVNET REWARD KEY: auto-generated DA852F4FFDE0B7B89A3B5327271D2CEC1614F0DC34A91209EAE00C523E5E8627 (datadir data/custody/devnet-auto/reward) — no --reward-address needed
GENESIS AUTHORED: no document existed, so this node created it naming only itself (Node-127.0.0.1:30303)
DEVNET FAUCET ALLOCATION: 55F1239553FC2E7B0A5910806CB9C04E57E47E6050AB9FE551D1E3498E1A734A holds 3200016800000000000000000 nSPX; operators can manually fund joiners with up to 32000168000000000000 nSPX (min stake + fee reserve); no node list
GENESIS FILE: 1 initial validator(s), epoch_blocks=10, network=devnet
GENESIS FILE: seeded 1 validators into the consensus set (32 SPX total)
```

Four things to notice:

1. **No reward address needed.** Each devnet node auto-generates one keypair in
   its own datadir on first start, so no address is ever pasted or copied.
2. **The document is marked `bootstrap: true`** and lists exactly one
   validator: itself. That is legitimate, and it is what makes the
   one-command flow possible at all.
3. **A faucet allocation is recorded** (§6) — the node does not distribute
   payouts automatically; the operator must submit a transfer.
4. **`epoch_blocks=10`** is a chain parameter read from the document, not a
   flag.

Then it produces blocks:

```
$ grep -E 'SOLO MODE|Solo-mined and committed' T1.log | head -4
[Node-127.0.0.1:30303] SOLO MODE — this node is the sole active validator
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
T2.log:0
T3.log:0
```

A count of **zero** in both joiners is the proof that they never authored a
genesis. Any non-zero number means a joiner forked the chain at block 1.

If the seed is unreachable and no document ever arrives, the joiner **waits and
then fails loudly**. It does not invent a genesis.

---

## 5. The three nodes converge — as one validator and two peers

Same height, same block hash, on all three terminals:

```
$ for f in T1 T2 T3; do printf "%s: " $f; grep -oE 'Updated best block: height=[0-9]+, hash=[0-9a-f]{16}' $f.log | tail -1 | grep -oE 'height=[0-9]+, hash=[0-9a-f]{16}'; done
T1: height=75, hash=1ec95d81c1227724
T2: height=75, hash=1ec95d81c1227724
T3: height=75, hash=1ec95d81c1227724

$ grep -c 'attestation quorum not met' T1.log T2.log T3.log
T1.log:0
T2.log:0
T3.log:0
```

All three also agree on the genesis hash — the chain identity that §4's bundle
fetch is supposed to establish:

```
$ for f in T1 T2 T3; do printf "%s: " $f; grep -oE 'genesis hash: GENESIS_[0-9a-f]{16}' $f.log | tail -1; done
T1: genesis hash: GENESIS_94f47677da1b4c5a
T2: genesis hash: GENESIS_94f47677da1b4c5a
T3: genesis hash: GENESIS_94f47677da1b4c5a
```

The validator set is identical in every terminal — **one** validator, 32 SPX:

```
$ for f in T1 T2 T3; do echo "-- $f:"; grep 'seeded .* validators into the consensus set' $f.log | head -1; done
-- T1: GENESIS FILE: seeded 1 validators into the consensus set (32 SPX total)
-- T2: GENESIS FILE: seeded 1 validators into the consensus set (32 SPX total)
-- T3: GENESIS FILE: seeded 1 validators into the consensus set (32 SPX total)
```

So T2 and T3 reach consensus about block 75 without holding any weight: they
verify and follow the chain, they just do not vote. That is the intended
behaviour for an unstaked node, and it is what the warning at the top of this
document describes.

**What this section does not show.** Three terminals agreeing on a block hash is
**evidence of convergence, not of consensus**. The log line that would distinguish
them is the "seeded 1 validators" line above: one of the three processes holds
all 32 SPX. A single validator holding 100% of the stake commits its own blocks
uncontested — no quorum race ever happens here, so this run cannot fail in the
way a real multi-validator network would. §12 spells this out in full.

---

## 6. Devnet faucet and manual validator admission

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

The genesis document allocates this balance to the bootstrap faucet, but the
node does not automatically send payouts. The bootstrap operator can fund a
joiner's reward address with an ordinary signed transaction (the faucet key is
stored in the bootstrap datadir); for the default devnet, that key file is
`data/custody/devnet-auto/faucet/key.json`:

```bash
./sphinx send-tx \
  --rpc=http://127.0.0.1:8545 \
  --from="SPIF <faucet-address>" \
  --to="SPIF <joiner-reward-address>" \
  --amount=32.000168 \
  --key=data/custody/devnet-auto/faucet/key.json
```

After funds arrive, the joiner submits the signed `stake` transaction in §8a.
It includes proof-of-possession from the validator's consensus identity key;
the stake owner and validator operator must both authorize admission. Stake is
pending until the `e+2` epoch boundary, so connecting or receiving funds alone
never adds voting weight.

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
| 6 | 5 | 1 |
| 7 | 5 | 2 |

**`K = 3` tolerates nothing.** Two of three is exactly 2/3, and the rule is
*strictly* more, so it does not commit. The smallest set that survives one
offline validator is **4**.

Offline validators do not change the set size — they simply stop voting.

Readiness uses the same arithmetic: block production waits until validators
holding more than 2/3 of the active snapshot's stake are ready. There is no
node count in that condition.

**Where these numbers come from (Checkpoint 2 item 1).** Every quorum path now
reads a `ValidatorSnapshot` — an immutable, height-keyed record of the validator
set and its stake — rather than the live in-memory `ValidatorSet`. One function,
`quorumFromSnapshot`, applies the single rule everywhere:

- stake: `voted × 3 > total × 2` (strict; exactly 2/3 is **not** enough)
- distinct voters: `distinct >= StrictTwoThirdsCount(len(snapshot.Validators))`,
  i.e. `floor(2N/3) + 1`, in **integer** arithmetic

If the snapshot for the height is missing, every quorum path **fails closed**
rather than guessing from the live set. The old `getTotalNodes()` (which read
the live set) has been deleted, as has the old `int(N*0.67)` floor — which
returned `2` for `N=3`, permitting exactly the 2-of-3 the safety rule exists to
prevent.

---

## 7a. What the engine harness proves, and what it does not

**Read this before citing "the harness" as evidence of correctness.**

There are two harnesses. Both are real, and both are narrower than the word
"engine" suggests.

### `TestEngine_QuorumForN` (src/consensus/engine_harness_test.go)

This drives the **real production `hasQuorum`** — the same function the live
engine calls — for `N = 2, 3, 4`, stopping one validator in each case:

| N | running | commits? |
|---|---|---|
| 2 | 1 | halts (strict >2/3) |
| 3 | 2 | **halts** (2 of 3 is exactly 2/3 — not enough) |
| 4 | 3 | continues (smallest set tolerating one offline validator) |

It also asserts the vote-count floor and the stake rule always agree — which is
what caught the old `int(N*0.67)` bug.

**What it proves:** the production quorum *arithmetic and the vote-acceptance
decision* are correct for those N, against real snapshots.

**What it does NOT prove:** anything about the **full consensus engine**. It does
not start goroutines, does not run the view-change **timer**, does not perform
SPHINCS+ signing, does not exchange a single network message, and never calls
`Consensus.Start()`. It is a direct call into a pure function. A bug in the
engine's orchestration — timers, phase transitions, message plumbing, signing
latency — would not be caught here.

### `TestHarness_RealSPHINCS_QuorumForN` (src/bind/nvalidator_harness_test.go)

This runs **N real, independently generated SPHINCS+ keypairs** over the
production parameters, and asks whether a block signed by the required number of
them verifies, and whether one signed fewer is refused. It checks no key is
shared between validators, which would make the table meaningless.

**What it proves:** the quorum threshold and the real signing/verification path
agree — the arithmetic is not being satisfied by signatures the verifier would
reject.

**What it does NOT prove:** it is **in-process**, not three separate programs. No
P2P, no real socket, no separate datadir, no crash-and-restart, no Byzantine
node. It proves the signature arithmetic, not the network.

**Summary:** these tests pin the **production quorum functions** — the
arithmetic, the snapshot sourcing, and the signing threshold. They do **not**
exercise the orchestrated engine (goroutines + timers + VDF + messaging). Treat
them as "the maths is right", never as "the engine is right".

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

`--role=validator` describes the process role; it does **not** grant validator
membership or voting weight. Only the chain's active validator snapshot does.

### 8a. Stake, unstake, and submit double-sign evidence

Stake uses two separate signing authorities:

- `--key` is the SPIF account key that pays the stake and transaction fee.
- `--validator-key` is the validator's persistent node-identity key. Its
  proof-of-possession is bound to the chain ID, validator ID, owner, amount,
  and action and stored with the delayed on-chain admission.

`--validator-key` accepts the node's `keys/` directory (containing
`private.key` and `public.key`), the `private.key` path, or a JSON key file
with `private_key` / `public_key` (or `sk` / `pk`) hex fields. Keep the private
key secret; never use a peer-count or CLI node-count to establish membership.

```bash
# Lock 32 whole SPX. Use the exact Node-<tcp-address> identity for this node.
./sphinx stake --action=stake \
  --rpc=http://127.0.0.1:8545 \
  --from="SPIF <wallet-address>" \
  --validator-id="Node-127.0.0.1:30304" \
  --amount=32 \
  --key=wallet.json \
  --validator-key="<datadir>/Node-127.0.0.1:30304/keys"

# Request a full exit; withdrawal remains slashable for three more epochs
# after the e+2 exit boundary.
./sphinx stake --action=unstake \
  --rpc=http://127.0.0.1:8545 \
  --from="SPIF <wallet-address>" \
  --validator-id="Node-127.0.0.1:30304" \
  --key=wallet.json
```

An unstake is owner-only, has no partial amount, and cannot take effect
immediately. The queued state is replayable from committed blocks.

Double-sign slashing is accepted only for two valid, conflicting SPHINCS+
votes from the same chain-committed validator key at the same height and view.
Put the evidence in a JSON file with type `sphinx_double_sign` and submit it
with:

```bash
./sphinx slash \
  --rpc=http://127.0.0.1:8545 \
  --from="SPIF <fee-payer-address>" \
  --evidence=double-sign.json \
  --key=fee-payer.json
```

The executor checks historical snapshot membership, both signatures, and
evidence replay protection, then applies the policy's existing double-sign
penalty to active and pending-withdrawal stake and burns the matching escrow.
Evidence older than two epochs is rejected. Consensus vote signatures use the
v2 chain-ID and phase domain; this is a consensus-breaking change, so all
validators on a network must run compatible software before producing votes.
Local VDF misses, peer observations, or unsigned claims never slash.

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
Startup also requires a separately published 64-character canonical genesis
digest pin: set `SPHINX_MAINNET_GENESIS_DIGEST` or
`SPHINX_TESTNET_GENESIS_DIGEST` to that pin. The selected genesis must include
the agreed founder set and positive stakes. Do not calculate a pin from an
untrusted document and then trust that same document.

The protocol permits at most 100 active or pending validators. A new stake
admission is rejected while the set is full; an exiting validator stops
occupying a slot at its committed exit boundary.

---

## 10. Removed flags and membership-related commands

### Removed flags

These existed previously and are gone. They appear nowhere in this document
except here:

| Removed | Why |
|---|---|
| `--nodes` | A node count must never be configuration |
| `--node-index` | Ditto — identity comes from `--tcp-addr` |
| `-legacy-cluster` | Hardcoded a 3-node cluster on fixed ports |
| fixed `32307+` ports | Contradicted the real `30303` default; removed as dead code |

### Membership commands

`./sphinx help` includes these membership-related commands:

```
node  stake  slash  send-tx  get-balance  watch-tx  ipfs  wallet  multisig  help
```

`stake` queues an owner-authorized Stake or full Unstake action and requires
validator-key proof for new admission. `slash` submits signed double-vote
evidence for deterministic verification by the executor. Neither command
predeclares membership: activation and exit remain chain-state transitions at
the `e+2` epoch boundary, followed by the three-epoch unbonding delay before
withdrawal. The `wallet` and `multisig` families do not set a
validator count or roster.

### Removed from the engine (Checkpoint 2)

| Removed | Why |
|---|---|
| `getTotalNodes()` | Read the live `ValidatorSet`; every quorum path now reads a height-keyed `ValidatorSnapshot` |
| `Consensus.quorumFraction` field | Set to `0.67` and never read anywhere — a float named "quorum fraction" implied a 67% rule the engine never ran |
| `int(N*0.67)` quorum floor | Floored to `2` for `N=3`, permitting the very 2-of-3 the safety rule forbids |

---

## 11. Validator membership

There is no command-line option or helper that creates a validator roster or
sets a target validator count. The first devnet node writes genesis for itself.
Other nodes may connect and sync in any number; connectivity alone does not
change the active validator set. Validator admission and proposer selection
must follow chain state. A one-validator set has only one possible proposer;
rotation requires additional validators to be admitted through the delayed
Stake flow in §8a.

---

## 12. What the single-validator three-process smoke test proves, and what it does not

The single-validator smoke-test flow in §2 starts three real `sphinx node
--pbft` processes with separate datadirs and ports. That is a genuine
end-to-end run. Here is its exact scope.

### It DOES prove
- The first node auto-authors `genesis_state.json` naming only itself, and
  signs block 0.
- Joiners fetch that exact genesis document over the network and refuse to
  author their own.
- Nodes discover each other over real TCP and UDP sockets, on real ports.
- Blocks propagate, and the nodes converge on the same height and hash.
- Datadirs are genuinely isolated; `--port-offset` shifts ports without changing
  identity.
- Genesis-hash mismatch is rejected before admission.

### It does NOT prove
- **Multi-validator consensus.** In this smoke-test run only **one** node is a
  validator; the other two are peers with zero stake, so they vote nothing. The
  3-process run is a **1-validator chain with two spectators**, not a
  3-validator BFT network.
- **Quorum under partial failure.** Nothing here shows the chain halting when a
  validator is stopped, or surviving when one of four is. That is proven only by
  the in-process harnesses (§7a), not by this run.
- **The orchestrated engine under real conditions.** The run uses the real
  timers and goroutines, but with a single validator there is no prepare/commit
  quorum race to lose. It does not stress view change, leader rotation, or
  message loss.
- **Queued stake activation.** This run does not submit a Stake transaction; it
  therefore does not demonstrate a peer becoming a validator. See §8a for the
  manual chain-state admission flow.
- **Anything about mainnet/testnet.** Auto-authoring is devnet-only (§9).

**Bottom line:** the single-validator three-process run proves *plumbing* —
identity, discovery, genesis distribution, block propagation, convergence. The
quorum guarantees are proven by the in-process harnesses (§7a). This smoke test
does not prove a multi-validator BFT network. Submit Stake transactions using
§6 and §8a to admit additional validators; then test proposer rotation,
view-change, and multi-process quorum behavior separately.

---

## 13. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `refusing to author genesis: this node was given --seeds=...` | A joiner has no document | Start the seed node |
| `no seed has answered yet ... ACTION: start the seed node` | Nothing listening on the seed | Start Terminal 1 |
| `seed is reachable but still finishing block-0 witness signing` | Seed is working, just slow | Wait; ceiling is 30m |
| `... is not devnet: auto-authoring genesis is devnet-only` | Non-devnet with no document | Copy `genesis_state.json` into `<datadir>/config/` |
| A joiner never votes | It has not been admitted through chain state yet | Fund its stake owner, submit `stake`, and wait for the `e+2` activation boundary |
| `unknown subcommand "stake"` or `"slash"` | The executable is stale | Rebuild with `go build -o sphinx ./src/cli` |
| `--config file holds N node entries` | Multi-entry config | Use one file per node, or explicit flags |
| `Rejecting key exchange from <node>: genesis hash mismatch` | The two sides computed different genesis hashes, so neither will peer with the other | Compare `Genesis block commitments: snapshot=… document=…` in both logs — they must match. Delete the joiner's datadir (or `genesis_state.json`) and restart it so it refetches the bundle |
| `REFUSED peer genesis from <peer>: … digest/snapshot/hash mismatch` | The joiner holds a different genesis document than the peer | Same as above: refetch the bundle from the seed with a clean datadir |
| `REFUSED peer genesis … no local genesis block to verify` | The node has no genesis anchor at all | Check that `<datadir>/config/genesis_state.json` exists and names a validator; a joiner with no document must not adopt a peer's genesis |

On one machine, SPHINCS+ signing is slow: a PBFT round needs several signatures
and each costs seconds of CPU. The generous timeouts are deliberate.

### `default_port` is a chain parameter; `listen_addr` / `p2p_port` are what the node is on

The chain-info record carries two different things, and conflating them was the
old bug:

- **`default_port: 32307`** (devnet: `32309`) is the **chain parameter** from
  `params/commit/header.go`. It is persisted in chain state and is **display-only**
  — no code path ever dials it, and no chain-compatibility check compares a port
  (`network`'s checks `chain_id`; `consensus`'s checks `chain_id` + genesis hash).
  It is deliberately left alone: changing it would alter persisted chain parameters.
- **`listen_addr` and `p2p_port`** are the **runtime** address this process
  actually bound, read from the P2P listener's `Addr()` in `bind.StartNode`.
  They are never persisted and never enter a digest, so they are correct for
  `--port-offset` and for `--config`.

Both appear in the chain-info map served at `/api/explorer/stats` (and shown as
`P2P <addr>` on the explorer's Block Height card). They are omitted when no
address was registered. The explorer previously showed only the chain
parameter, so it advertised a port the node was not listening on.

**Scope, stated precisely:** the value never reached a running handshake. The
key-exchange handshake already carried the correct address (`bind/kex.go` sets
`Address` to this node's own `--tcp-addr`, and `derivePeerListenAddr` keeps the
claimed port), and the P2P `chaininfo` sync message carries no port at all. The
two places that still hardcode `32307` — `network/node.go`'s `GetChainInfo` and
`network/manager.go`'s `NodeManager.GetChainInfo` — are **unused helpers with no
callers**, so they reached no wire and no UI. They are left in place as dead code.
