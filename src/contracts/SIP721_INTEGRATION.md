# SIP-721 Integration Guide — Royalties, Licensing & Marketplace

For wallet, marketplace, and tooling integrators calling the SIP-721 methods
(`mint`, `transfer_from`, `approve`, `owner_of`, `token_uri`,
`token_id_of_mint`, `list`, `buy`, `cancel`, `listing_of`,
`purchase_license`, `revoke_license`, `terms_of`, `info`).

This doc describes **behavior and invariants**, not implementation — it's the
contract you can build against. All method names, argument keys, return keys,
and error strings below are quoted verbatim from
`src/contracts/sip721_call.go` / `sip721_store.go` as of this writing.
Re-verify against source before shipping; if code and doc disagree, code wins
and the doc is a bug — file it.

Conventions: `token_id` is a positive decimal integer string (`"1"`, `"2"`,
…; `"0"` and non-numeric values are rejected with `missing token_id` /
`invalid token_id: <value>`). All nSPX amounts are positive decimal integer
strings. Amounts of zero or less are rejected everywhere a price or fee is
accepted.

---

## 0. Method index — args in, receipt out

All calls take `token_id` except `mint` (which allocates it), `info`
(collection-level), and `token_id_of_mint` (which takes `mint_id`).
`approve` takes `to` (alias: `approved`). `mint` takes `to`, `token_uri`
(alias: `uri`), optional `mint_id`, and optional economics
`royalty_bps` / `usage_fee` / `royalty_recipient` (see sections 4-5).

| Method | Key args | Success receipt (`Return`) |
|---|---|---|
| `mint` | `to`, `token_uri`, `mint_id?`, `royalty_bps?`, `usage_fee?`, `royalty_recipient?` | `method`, `to`, `token_id`, `token_uri`, `mint_id` (+ `royalty_bps`, `royalty_recipient?`, `usage_fee?` when terms set) |
| `transfer_from` | `from`, `to`, `token_id` | `method`, `from`, `to`, `token_id` (+ `sale_value`, `royalty_amount`, `proceeds_amount`, `royalty_recipient?` only when tx carried value `> 0`) |
| `approve` | `to`, `token_id` | `method`, `approved`, `token_id` |
| `owner_of` | `token_id` | `method`, `owner`, `token_id` |
| `token_uri` | `token_id` | `method`, `token_uri`, `token_id` |
| `token_id_of_mint` | `mint_id` | `method`, `mint_id`, `token_id` |
| `list` | `token_id`, `price` (alias: `price_nspx`) | `method`, `token_id`, `seller`, `price` |
| `buy` | `token_id` (+ tx carries exactly the ask) | `method`, `token_id`, `from`, `to`, `sale_value`, `royalty_amount`, `proceeds_amount` (+ `royalty_recipient` only when `royalty_amount > 0`) |
| `cancel` | `token_id` | `method`, `token_id` |
| `listing_of` | `token_id` | `method`, `token_id`, `seller`, `price` |
| `purchase_license` | `token_id`, `licensee?` (+ tx carries exactly the fee) | `method`, `token_id`, `licensee`, `fee`, `recipient` |
| `revoke_license` | `token_id` | `method`, `token_id` |
| `terms_of` | `token_id` | `method`, `token_id`, `creator`, `royalty_bps`, `royalty_recipient`, `usage_fee`, `licensee` |
| `info` | — | `method`, `name`, `symbol`, `owner`, `next_token_id` |

Notes integrators trip on:

- `purchase_license` defaults `licensee` to the **caller** when the arg is
  empty. The receipt always echoes the effective licensee — use it.
- `terms_of` **always** includes `royalty_recipient` (resolved: explicit
  recipient, else creator) and always includes `usage_fee` and `licensee`
  keys — empty string means "none set / unlicensed." Contrast `buy`, where
  `royalty_recipient` is **omitted** when `royalty_amount` is `"0"`.
- `transfer_from` only includes the sale block when the tx carried value
  `> 0`. A zero-value transfer receipt has no `sale_value` key at all.
- `mint` echoes `mint_id` verbatim even when empty. `mint_id` is optional;
  when supplied it must be unique per contract
  (`mint_id <id> already anchored as token <n>` on reuse).
- `info.next_token_id` is the **next ID to be allocated**, so the most
  recently minted token is `next_token_id − 1`.
- Authorization: `mint` requires the collection owner
  (`mint requires collection owner`); `approve` requires the token owner
  (`approve requires token owner`); `transfer_from` requires owner-or-approved
  (`transfer_from: caller <c> is neither owner nor approved`); `list`
  requires the token owner (`list requires the token owner`); `cancel`
  requires the listing seller or the collection owner
  (`cancel requires the listing seller or the collection owner`);
  `revoke_license` requires the collection owner or the token creator
  (`revoke_license requires the collection owner or the token creator`);
  `buy` requires the caller **not** be the current owner
  (`buy: seller cannot buy their own listing`).

---

## 1. Call shapes & the exact-value rule

Two methods are **strict-value gated**: the transaction's escrowed value must
equal the required amount exactly, or the call aborts and nothing moves.

| Method | Required value | On mismatch (verbatim) |
|---|---|---|
| `buy` | Exactly the current `list` price | `buy requires exactly <ask> nSPX, tx carried <got>`; listing untouched |
| `purchase_license` | Exactly the token's `usage_fee` | `purchase_license requires exactly <fee> nSPX, tx carried <got>`; no license issued |

`<got>` renders as the carried amount, or the literal string `none` when the
tx carried nothing. No overpay-and-refund, no partial payment. Read the
current price/fee immediately before submitting (see section 2). Both methods
additionally require an internal value-transfer hook; its absence is an
environment error (`buy requires a value transfer hook` /
`purchase_license requires a value transfer hook`).

---

## 2. `listing_of` semantics — read this before quoting a buy

**Never-listed and just-cleared are indistinguishable.** Only listed or not.
`listing_of` returns `token <id> is not listed` for a never-listed token, a
just-bought listing, a just-cancelled listing, a listing cleared by a
**direct** `transfer_from` (ownership changes silently clear any listing),
and a corrupt/empty stored record (missing seller or price decodes to "not
listed", never corrupt data).

**Wallet rule:** treat `token <id> is not listed` as "hide the buy button."
Any *other* error is a real failure — surface it distinctly. In particular,
`listing_of` on a **nonexistent token** returns `token <id> does not exist`,
a different condition from "exists but unlisted."

**Re-read before quoting.** A direct transfer silently clears a listing with
no separate event, so call `listing_of` immediately before displaying a buy
price or submitting `buy` — never cache a price from an earlier read.

**Stale-seller guard.** If the recorded seller no longer owns the token,
`buy` clears the record and aborts with
`token <id> listing is stale: seller <addr> no longer owns it`
rather than selling someone else's token. Treat like "not listed" and refresh.

---

## 3. Listings: `list` is the update path

No separate `update_price` — intentional. Re-`list` on an already-listed
token **overwrites the price in place, atomically, in one transaction.**

- Only the current token owner may `list` or overwrite.
- A relist takes effect immediately; a `buy` carrying the *old* price is
  rejected with `buy requires exactly <new> nSPX, tx carried <old>`.
- This avoids a `cancel`-then-`list` two-tx window where the old price stays
  buyable between calls.
- `list` accepts `price` (alias `price_nspx`), positive decimal nSPX only.
  Rejections: `invalid list price: "<raw>" (positive decimal nSPX required)`,
  `token <id> does not exist`, `list requires the token owner`.

`cancel` requires seller or collection owner, and clears to the unlisted
state in section 2.

---

## 4. Royalty settlement — rounding rule

On any value-carrying sale (`buy`, or paid `transfer_from`):

```
base     = max(sale_price, MinTokenSaleValue)   // policy floor, default 0.1 SPX = 1e17 nSPX; nil disables
royalty  = floor(royalty_bps × base / 10000)     // integer Div truncates; inputs non-negative so = floor
royalty  = min(royalty, sale_price)              // capped at escrow; seller never pays out of pocket
proceeds = sale_price − royalty                  // remainder, always to seller
```

- **Remainder floors to the seller** — not creator, not dropped.
- `royalty + proceeds == sale_price` exactly, always. Pure redistribution;
  no dust created/destroyed, total supply untouched.
- **Floor vs. cap, worked:** dust sale of 1 nSPX at 50% bps with the 1e17
  floor computes `royalty = 5e16` on the floor basis but **caps** at the 1
  nSPX escrow — creator takes the nSPX, seller gets nothing. Above the floor
  the cap never binds.
- Zero-value legs are **skipped, not paid as zero**: dust at small bps can
  round royalty to zero; 100% (`10000` bps) zeroes proceeds. Legs still sum
  to the price.
- `royalty_bps == 0` ≡ legacy no-terms token: full value to seller, single
  payee, `royalty_amount` reported as `"0"`.
- `royalty_bps` checked at mint (`invalid royalty_bps: "<raw>"
  (must be 0..10000)`) **and** fails closed at settlement on corrupt stored
  terms (`token <id> has invalid royalty_bps <n> (max 10000)`) — aborts,
  ownership unmoved.
- Recipient == seller collapses to a single payee for the full amount.
  Recipient defaults to creator at mint when unset; explicit recipients are
  SPIF-normalized at mint, so zero/burn addresses are rejected at admission.
- The floor prices royalties on `max(price, floor)` so dust-price settlement
  still yields a real royalty. Many small sales just above the floor each pay
  ≈ `bps × floor`, so splitting one sale into many does not reduce the
  aggregate royalty base.

---

## 5. Licensing — single-issue & ordering

- A token holds **at most one active licensee at a time, regardless of
  caller** — exclusivity is on the slot, not the requester. Any
  `purchase_license` while occupied reverts with
  `token <id> already licensed to <holder> (single-issue; revoke before
  re-licensing)`, even for a different requester. (There is no bare
  `already licensed` string in source; match on `already licensed to`.)
- No `usage_fee` set = not licensable:
  `token <id> has no license terms; the creator set no usage fee`.
  Corrupt stored fee:
  `token <id> has an invalid stored usage_fee: <detail>`.
- `revoke_license` needs an active license
  (`token <id> has no active license` otherwise — a different string from the
  purchase-side message). On a token with no terms at all it aborts earlier
  with `token <id> has no license terms`.
- Same-block revoke + purchase for one licensee/token is deterministic:
  block txs sort by `(sender, nonce, txid)` at proposal (executor mempool
  selection) and `applyTransactions` executes `TxsList` strictly
  sequentially, all writes buffered in `StateDB` until `Commit`. First wins
  the slot; second aborts and rolls back atomically — never partial.
- **`purchase_license` is a payment + entitlement receipt, not a bytes-gate.**
  The chain can't observe off-chain (e.g. IPFS) reads. The record is
  compliance/audit evidence of paid fee + issued license; real access control
  lives off-chain in the terms document / application layer. Don't assume the
  chain can revoke read access retroactively.

---

## Quick reference — error strings (verbatim)

| Error | Meaning |
|---|---|
| `buy requires exactly <ask> nSPX, tx carried <got>` | `buy` value ≠ ask (`none` when nothing carried) |
| `purchase_license requires exactly <fee> nSPX, tx carried <got>` | License payment ≠ fee |
| `token <id> already licensed to <holder> (single-issue; revoke before re-licensing)` | Slot occupied (any requester) |
| `token <id> has no active license` | Nothing to revoke |
| `token <id> has no license terms` | `revoke_license` on terms-less token |
| `token <id> has no license terms; the creator set no usage fee` | Not licensable |
| `token <id> has an invalid stored usage_fee: <detail>` | Corrupt stored fee |
| `token <id> has invalid royalty_bps <n> (max 10000)` | Corrupt terms; aborted, ownership unmoved |
| `token <id> has no royalty recipient` | No payout address in stored terms |
| `invalid royalty_bps: "<raw>" (must be 0..10000)` | Mint-time bps rejection |
| `invalid list price: "<raw>" (positive decimal nSPX required)` | Bad/zero/negative price |
| `token <id> has an invalid stored list price: <detail>` | Corrupt stored ask |
| `token <id> is not listed` | Not buyable: never/bought/cancelled/transferred/corrupt |
| `token <id> listing is stale: seller <addr> no longer owns it` | Seller lost token; record cleared |
| `token <id> does not exist` | Unknown token (≠ "unlisted") |
| `royalty: <detail>` | Creator-leg payout failed; whole call aborted |
| `proceeds: <detail>` | Seller-leg payout failed; whole call aborted |
| `license fee transfer: <detail>` | License-fee payout failed; no license issued |
| `buy: seller cannot buy their own listing` | Self-buy rejected |
| `list requires the token owner` | Non-owner list/relist |
| `cancel requires the listing seller or the collection owner` | Unauthorized cancel |
| `revoke_license requires the collection owner or the token creator` | Unauthorized revoke |
| `transfer_from: caller <c> is neither owner nor approved` | Unauthorized transfer |
| `approve requires token owner` | Non-owner approval |
| `mint requires collection owner` | Non-owner mint |
| `missing token_id` / `invalid token_id: <value>` | Bad token id arg |
| `mint_id <id> already anchored as token <n>` | `mint_id` reuse |
| `mint_id <id> not anchored on this contract` | Unknown `mint_id` lookup |
| `token <id> has no embedded terms` | `terms_of` on legacy no-terms token |

Settlement failures (`royalty:` / `proceeds:` / `license fee transfer:`) are
atomic: the call aborts, ownership/license state unmoved, the block's other
writes still commit — the failed call never partially applies.

## Open items not covered here

- GUI buy/sell flow (next up, built against this doc)
- Formal external security review of settlement/marketplace before mainnet

