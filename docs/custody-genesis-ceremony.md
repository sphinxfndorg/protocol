# Design note: genesis custody ceremony (M-of-N-authorised block 0)

Status: **design note only — not implemented.** Read this before building the
ceremony CLI or the node-side loader.

## Why this note exists

Genesis distributions are now M-of-N gated (`core.tx_auth.custodyPolicyOwns` +
`core.GenesisState.BuildBlockWithCustody` + the hard startup gate
`core.Blockchain.guardGenesisAuthorization`). That closed a real hole: a
custody-owned genesis vault could previously mint its entire block-0
distribution unsigned, because the block-0 "system transaction" exemption ran
before any policy check.

Closing it has a consequence that is easy to under-read, which is what this note
is for.

## The trust shift: recompute-and-verify → ceremony-artifact-and-trust

Today every node computes genesis independently and gets the identical block:

- Deterministic inputs only (fixed timestamp, difficulty, gas limit, extra data,
  canonical allocations) ⇒ identical hash on every machine, no coordination.
- The genesis hash is verified during peer key exchange, so a mismatch is
  rejected. Trust model: *recompute and verify*.

A custody-authorised genesis cannot work that way:

- Each distribution slice must carry a threshold SPHINCS+ witness.
- SPHINCS+ signing is randomised, and the witness is embedded in the
  transaction — therefore in block 0's `TxsRoot`, therefore in the block hash.
- So block 0 is **whatever the custodians signed**, not something a node can
  derive.

Trust model becomes *ceremony-artifact-and-trust*: nodes no longer recompute
block 0, they **verify a signed artifact**. The key-exchange genesis-hash check
still catches a wrong artifact, but "wrong" now means "signed by the wrong quorum
/ for the wrong parameters", not "computed differently".

This applies to **any environment with a custody vault** — devnet, testnet,
mainnet. Environments without a custody vault keep the recompute model
unchanged.

## Second consequence: the chain ID is a one-shot, unrecoverable ceremony input

The witness binds the chain ID into the signed message. Pinned by
`TestGenesisStartupGateIntegration` case (c):

> a block-0 witnessed for chain 7331 is **rejected** by a node whose active
> chain is devnet 73310 — even though every other field is correct.

That is correct, fail-closed behaviour. It also means:

- The chain ID must be a **confirmed, explicit input** to the ceremony, not a
  default read from a file at signing time.
- A wrong chain ID cannot be repaired after the fact. The witness is
  cryptographically bound to it, so recovery is **re-running the whole M-of-N
  ceremony**, not patching a config.
- `getCachedGenesisBlock()` currently builds from `DefaultGenesisState()`
  (ChainID 7331) precisely so the genesis hash is environment-free. That
  property **cannot survive** a custody-bound block 0: a witnessed block 0 is
  inherently per-chain.

## Required operator flow (not yet built)

1. **Confirm the environment first.** Print the target chain ID / chain name and
   require an explicit acknowledgement before any signing happens. The chain ID
   is bound into every witness, so this step is the guard against a wasted
   ceremony round.
2. **Confirm the distribution set.** The exact ordered slice list
   (`receiver, amount, nonce`) that will be signed — because the witness is
   per-slice and the set determines `TxsRoot`.
3. **Custodians sign each slice** with the vault policy (M-of-N).
4. **Emit one artifact** (the signed block 0, or the witness-per-slice set).
5. **Node loads the artifact** instead of calling `BuildBlock()`, then the
   existing startup gate verifies it before anything is stored or executed.

## What already exists (do not rebuild)

- `core.GenesisState.BuildBlockWithCustody(auth, chainID)` — builds a block 0
  with every slice witnessed and chain-bound.
- `core.Blockchain.guardGenesisAuthorization(block)` — the hard startup gate;
  run from `createGenesisBlock` before `ExecuteGenesisBlock`. Refuses to start
  on an unsigned/under-threshold/wrong-chain distribution.
- `core.tx_auth.custodyPolicyOwns` — the fail-closed switch keyed on the
  registered vault policy.
- Tests: `src/core/genesis_musig_test.go` (incl. the startup-gate integration
  test with the wrong-chain case).

## What is missing

- Ceremony CLI (extend `multisig devnet --role vault` or add a dedicated
  command) producing the artifact, with the chain-ID confirmation step above.
- Node-side artifact loader, plus a chain-aware replacement for the
  environment-free genesis cache.
- A decision on whether "no custody vault" remains a supported mode for
  production networks (see the escrow-enforcement question below — they share
  the same "silent soft-gating" shape).

## Related, separate, and arguably more urgent: CGE release enforcement

This note covers genesis only (path #1). The ongoing release path (path #2) is
untouched by this work and is currently soft-gated in the worst way:

- `SetEscrowMultisigEnforced(true)` has **no production caller**, so
  `escrowEnforced()` is always false, so `applyCGEReleases` escrow→recipient
  transfers are **never** witness-gated — even with
  `config/escrow_multisig.json` present.
- With no policy at all, the same is true silently (no warning).

Enabling enforcement is not a one-line flip: no production code stages
`SubmitCGEWitness` entries, so turning it on halts all time-based vesting until
a signing workflow exists. That trade-off is the decision to make next — genesis
being hardened does not make the vault secure overall while the release path
stays soft-gated by default.
