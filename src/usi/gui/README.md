# USI GUI — Universal Sovereign Identity Desktop Application

`src/usi/gui` is the desktop front-end of USI Software (see
[`../README.md`](../README.md)): a Fyne-based application for creating a
sovereign SPIF identity, protecting data, proving ownership of data
("self-patenting"), and trading/licensing that data on-chain through the
native **SIP-721** smart-contract standard.

This document explains **what the technology is for** (the three core
utilities — self-patent, protect, rent) and **what developers can build
on top of the smart contracts** this package drives.

---

## 1. File map

| File | Role |
|---|---|
| `gui.go` | `Run()` entry point and every screen: Dashboard, Message (encrypt), Inbox (decrypt), Mint Data (sign/mint), Verify Data, My Keys, Wallet, Send/Receive, **Marketplace**, Register/Welcome. Sidebar navigation and session state live here. |
| `helper.go` | Background workers and dialogs: mint pipeline (`MintJob`, `showMintStatusDialog`), transfer status worker, `AnchorMintReceipt`, `MintNFTInCollection`, collection persistence (`SavedCollection`, `~/.sphinx/usi_collection.json`), passphrase dialogs, pin-outcome banners. |
| `rpc.go` | `WalletClient` — the JSON-RPC layer to a full node: balance, transfers, gas quoting/priority tiers, tx confirmation polling, **SIP-721 reads/writes** (`GetSIP721Owner/Listing/Terms`, `CallSIP721`, `DeploySIP721Collection`, `SearchSIP721Tokens`). |
| `provenance.go` | Pure formatters bridging backend records → UI: signature **assurance tri-state** (authenticated / integrity-only / invalid), **payload retrievability** (replicated / local-only / never uploaded), embedded-economics terms, SIP-721 token binding. |
| `onchain_verify.go` | The **on-chain half** of Verify Data: gathers anchor evidence over RPC (`gettransaction` + receipt + token owner), re-validates the payload with the node's own rules (`core.ValidateAnchorData`), and compares it field-by-field with the provenance the file records (mint id, CID, token binding, terms, minter key, confirming block). Pure `evaluateOnChain` → verified / pending / mismatch / not-anchored / unreachable. |
| `theme.go` | Colour palette and reusable UI components (`styledCard`, `infoPanel`, `alertBox`, `opLayout`), plus amount/gas formatting (`formatSPXAmount`, `formatGasPriceAmount` in gSPX). |
| `types.go` | `WalletClient` type, RPC response types, `BigInt` (JSON tolerant of scientific-notation nSPX amounts). |
| `*_test.go` | Contract tests: canonical SPIF collection addresses, SIP-721 deploy gas (base + contract quote), identity normalisation, pin-outcome honesty, provenance tri-state, **on-chain verification verdicts** (match / pending / mismatch / not-anchored / unreachable), transaction-history parsing, transfer fee tiers. |

Entry point: `gui.Run()` (wired from `src/usi/cmd`).

---

## 2. What this tech is for — the three core utilities

### 2.1 Self-patent your own data (prove you created it, first)

**Screen: Mint Data → Verify Data.**

A "data patent" here means a sovereign, timestamped, cryptographically
verifiable record that *you* created a specific piece of data at a specific
time — without asking any authority for permission. The mint pipeline
(`helper.go` → `mintStatusDialogWorker`) does exactly this:

1. **SPHINCS+ signature** — the file is hashed (SHAKE-256) and signed with
   your post-quantum identity key. A `.usimeta` sidecar records signer,
   timestamp, and metadata; the signature is also embedded in the file's own
   container (PDF/XMP/Office/PNG/JPEG/footer), so the proof travels with the
   document.
2. **IPFS pin** — the *clean, pre-signature* bytes are pinned to IPFS, and
   the mint refuses to proceed if nothing was actually uploaded (unless you
   explicitly opt into offline mode). The ERC-721 metadata JSON (name,
   description, image CID) is pinned too, producing an `ipfs://` token URI.
3. **On-chain anchor** — a signed mint receipt is anchored in a transaction's
   `ReturnData`. Every node re-validates the anchor's CID commitment, receipt
   hash, and minter key at both mempool admission **and consensus**
   (`core.ValidateAnchorData`), so the commitment cannot be forged or
   rewritten after the fact.
4. **Optional SIP-721 token** — minting inside a collection creates a
   marketplace token whose receipt carries `token_id`/`token_uri`/`contract`,
   binding the off-chain file to an on-chain asset.
5. **Provenance recorded in the file** — once the anchor confirms, the block
   height/hash, anchor tx, nonce, mint ID, mint price, token binding and
   embedded terms are stamped back into the file's metadata
   (`sign.RefreshOnChainProvenance`).

**Verify Data** then reports an honest tri-state:

- `AUTHENTICATED` — signature valid **and** the signer's key is registered
  and active in the key directory (proves *who* signed);
- `INTEGRITY ONLY` — self-consistent and untampered, but the signer could not
  be confirmed (tamper-evidence, *not* proof of authorship);
- `INVALID` — the file was tampered with or the key is not accepted.

It also shows payload retrievability (`REPLICATED` / `LOCAL ONLY` /
`NOT REACHABLE` / `NEVER UPLOADED`) and the full on-chain provenance block
exactly as recorded in the file.

Every Verify press additionally re-checks the file **against the node**
(`onchain_verify.go`) — the screen verifies *both* the offline artifact and
the on-chain record:

- the recorded anchor transaction is fetched and its payload re-validated
  with the same `core.ValidateAnchorData` rules every node runs at admission
  and at consensus;
- the recorded mint id, IPFS CID, SIP-721 binding, embedded terms, minter key
  and confirming block are compared one by one against that anchor, with a
  per-check ✓ / ✗ / – / ? row so a disagreement names the exact field;
- the verdict is honest in both directions: a node that cannot be reached is
  `NODE UNREACHABLE` (never a pass), a file claiming a block the chain does
  not have is `ANCHOR MISMATCH`, an anchor the chain has since confirmed while
  the file still records "pending" is a pass (the file made no false claim),
  and an offline-only file is `NOT ANCHORED — OFFLINE ONLY`.

The screen's headline combines both halves (e.g.
`✓ OFFLINE + ON-CHAIN VERIFIED`, `⚠ INTEGRITY ONLY — NODE UNREACHABLE`), so
neither assurance level can silently stand in for the other.

**Use case:** register a prior-art record for an invention draft, timestamp a
manuscript or dataset, or hand a client a document whose authorship and
integrity anyone can independently verify later.


### 2.2 Protect your data (confidentiality)

**Screens: Message (encrypt) → Inbox (decrypt).**

- Folders are locked into `.vault` files with **AES-256-GCM**, key derived
  via **Argon2id**; hybrid recipient encryption uses **Kyber768+X25519**.
- **Recipient fingerprints** share access: only listed recipients can
  decrypt; unauthorized attempts are rejected and the UI shows this before
  you even try.
- An optional **embedded message** travels inside the vault.
- Optional **peer delivery** (`usimail.SendVault`) sends the encrypted
  `.vault` unchanged to a recipient's USI mail peer — ciphertext only on the
  wire.
- The Inbox reads sender/organization info from the vault manifest *without*
  decrypting, so you can see who sent it and whether you're authorized first.

**Use case:** confidential document exchange (contracts, financial reports),
client deliverables, or an encrypted data room — protection is by identity,
not by trusting a platform.

### 2.3 Sell and **rent** your data (embedded economics)

**Screens: Mint Data (Embedded Economics) → Marketplace.**

Royalties and licensing are not UI conventions — they are **frozen into the
SIP-721 token at mint** and enforced by the native contract runtime on every
node at consensus. Terms are immutable per token: no post-mint rewrite is
possible.

| Term | Field | Meaning |
|---|---|---|
| Resale royalty | `royalty_bps` (0–10000) | On every value-carrying resale (`transfer_from`/`buy`), `max(sale price, policy.MinTokenSaleValue) × royalty_bps/10000` (capped at the escrowed price) is paid to the royalty recipient **forever**, remainder to the seller. The price floor stops dust-price sales from evading royalties. |
| License / rental fee | `usage_fee` (decimal nSPX) | Per-access fee enforced by `purchase_license`: the transaction must carry **exactly** the fee, which is paid to the royalty recipient and records the payer as the single active licensee. |
| Payout recipient | `royalty_recipient` | Optional override (default: the minter/creator) for both royalty and license-fee payouts. |

**Data rental flow (licensing):**

1. Creator mints with a `usage_fee` — the token becomes *licensable*.
2. A user runs `purchase_license` on the Marketplace screen, paying the exact
   fee; the contract pays the creator and records the licensee.
3. The creator (or collection owner) can `revoke_license` — clearing the
   single-issue license slot so the data can be licensed again.
4. `terms_of` reads back creator, royalty, fee and current licensee; the GUI
   shows all of it plus a live "Licensee: you / — no active license" state.

**Sale flow:** owner `list`s at a price → buyer `buy`s with the exact price
as tx value → contract splits proceeds/royalty atomically → seller is paid,
creator's royalty paid, ownership transfers. `cancel` withdraws a listing;
any direct transfer clears listings automatically. Exact-value escrow means
overpay/partial-pay paths do not exist — the node rejects any mismatch.

**Important honesty note (from the integration doc):** a license is a
**payment + entitlement receipt**, not a bytes-gate — the chain cannot see
off-chain IPFS reads. Real enforcement of *access* belongs in your
application layer (e.g. gate delivery of decryption keys or private gateways
on `licensee`); the chain provides the tamper-proof payment/entitlement
ledger. Also, a bare receipt anchor (no collection) records terms but has no
contract to honour them — only a token **inside a SIP-721 collection** is
discoverable, listable, buyable or rentable. The GUI warns before letting
you mint economics without a collection.

**Use case:** monetise a dataset by the drink (per-use licence fees) instead
of only selling it outright, while collecting a permanent royalty whenever
it is resold.

---

## 3. Screens at a glance

| Sidebar item | Screen | Purpose |
|---|---|---|
| Dashboard | `showDashboardScreen` | Balance, vault/signed-doc counts, network/key info, recent activity. |
| Message | `showEncryptScreen` | Lock a folder → `.vault` (recipients, embedded message, peer delivery). |
| Inbox | `showDecryptScreen` | Unlock a `.vault`, check sender/authorization, recover message. |
| Mint Data | `showSignScreen` | **Self-patent**: sign → pin → anchor; deploy/adopt a SIP-721 collection; set NFT metadata and embedded economics. |
| Verify Data | `showVerifyScreen` | **Offline + on-chain verification**: signature tri-state, retrievability, and a live re-check of the recorded anchor (mint id, CID, token, terms, minter key, block) against the node. |
| Wallet | `showWalletScreen` | Balance, chain tip (header-only sync), send/receive, transaction history. |
| Marketplace | `showMarketplaceScreen` | Discover/search minted data; list / buy / cancel; purchase / revoke licences; live listing + royalty/licence state. |
| My Keys | `showKeysScreen` | Public fingerprint, key parameters (SPHINCS+, SHAKE-256, AES-256-GCM, Argon2id, Kyber768+X25519), storage paths. |

---

## 4. For developers: what you can build with these smart contracts

The GUI is itself a reference client. Everything it does goes through two
layers you can reuse directly:

- **Typed ABI bindings** — `src/bind/abi`: `abi.NewSIP721DeployTx`,
  `abi.NewSIP721CallTx`, `abi.SIP721Contract` (typed `Mint`, `List`, `Buy`,
  `Cancel`, `PurchaseLicense`, `RevokeLicense`, `TransferFrom`, `Approve`,
  plus read-only `OwnerOf`, `TokenURI`, `ListingOf`, `TermsOf`, `Info`,
  `TokenIDOfMint`), all signing through the shared `abi.Transact`.
- **`WalletClient` (this package)** — `rpc.go`: `GetBalance`,
  `SendTransactionWithPriority`, `GetTransactionHistory`,
  `GetChainTipHeader`, `DeploySIP721Collection`, `GetSIP721CollectionInfo`,
  `GetSIP721Owner/Listing/Terms`, `CallSIP721`, `SearchSIP721Tokens`,
  `WaitForTxConfirmation`, `AnchorMintReceipt`, `MintNFTInCollection`.

Behavioural contract, error strings and invariants are specified in
**[`src/contracts/SIP721_INTEGRATION.md`](../../contracts/SIP721_INTEGRATION.md)**
— build against that doc; the platform overview is in
**[`src/contracts/README.md`](../../contracts/README.md)**.

### 4.1 The SIP-721 method surface

| Group | Methods | Notes |
|---|---|---|
| Core (ERC-721-like) | `mint`, `transfer_from`, `approve`, `owner_of`, `token_uri`, `token_id_of_mint` | Only the collection owner may mint. `mint_id` binds a token to an on-chain mint anchor. |
| Marketplace | `list`, `buy`, `cancel`, `listing_of` | `buy` must carry **exactly** the ask in `tx.Amount`. |
| Licensing (rental) | `purchase_license`, `revoke_license`, `terms_of` | `purchase_license` must carry **exactly** the fee; single-issue license; revoke by collection owner or token creator. |
| Collection | `info` | name, symbol, owner, `next_token_id`. |

Deployment: `deploycontract` with a `Runtime: "native"`, `Standard:
"sip721"` `DeploySpec` — or just call `WalletClient.DeploySIP721Collection`.
The address is deterministic (`ContractAddress(sender, nonce, code)`) and
must be canonical SPIF form (`SPIF ` + 16×4 uppercase hex).

### 4.2 Consensus rules your app can rely on

- **Ownership, approvals and terms are enforced by every node** at block
  execution — no indexer or marketplace UI is trusted to report them.
- **Exact-value escrow:** `buy` / `purchase_license` reject any `tx.Amount`
  mismatch (including zero); value-less calls (`list`/`cancel`/
  `revoke_license`) legitimately carry zero value.
- **Atomic settlement:** a failed royalty/proceeds/fee payout aborts the
  whole call — no partial transfers.
- **Immutable terms:** `royalty_bps` / `usage_fee` / `royalty_recipient`
  are frozen at mint (zero/empty = legacy no-terms token).
- **Royalty floor:** royalties price on `max(price, MinTokenSaleValue)`.
- **Anchors are consensus-verified** (`ValidateAnchorData` at admission and
  commit), so a mint commitment can't be forged after the fact.
- **Gas:** contract txs must offer *base transaction gas + contract gas*
  (see `rpc_gas_test.go`: deploy = 21000 + 100000 + codeBytes×50); the
  shared `abi` builders already quote this. Gas prices are denominated in
  **gSPX** (1 gSPX = 10⁹ nSPX); use `formatGasPriceAmount`, never SPX, to
  display them.

### 4.3 Concrete things you can build

1. **Data marketplace** — deploy a collection per publisher, mint data with
   royalty + licence terms, and browse/list/buy/rent via
   `SearchSIP721Tokens` + `CallSIP721`. (The GUI's Marketplace screen is a
   minimal version of this.)
2. **Data-rental / pay-per-use platform** — mint with `usage_fee`, gate a
   private gateway or key-distribution service on the `licensee` returned by
   `terms_of`, and let creators `revoke_license` between tenants.
3. **Royalty-enforced resale exchange** — secondary market where creators
   permanently collect `royalty_bps` on every sale; the floor blocks
   dust-price evasion, and settlement is atomic on-chain.
4. **Provenance / notarisation service** — wrap the mint pipeline
   (sign → pin → anchor) as a service; verification is the tri-state
   assurance + provenance block any third party can re-check from the file
   itself and the chain.
5. **Verified publisher / brand portal** — issue signed releases (reports,
   datasets, media) whose authenticity customers verify with Verify Data's
   `AUTHENTICATED` result against your published fingerprint.
6. **Encrypted data rooms** — combine vault encryption (recipient
   fingerprints) with on-chain licences: the contract holds entitlement, the
   vault holds ciphertext.
7. **Portfolio / analytics dashboards** — read-only consumers:
   `GetSIP721CollectionInfo`, `GetSIP721Owner/Listing/Terms`,
   `SearchSIP721Tokens`, `gettransactionhistory` power royalty-income views,
   licence-expiry trackers, and collection stats without ever signing.
8. **Composable token economics** — pair with **SIP-20**
   (`src/bind/abi.SIP20Contract`) for revenue shares, payout splitters, or
   prepaid credit consumed when paying `purchase_license` fees.

### 4.4 Practical integration checklist

1. Point `NewWalletClient` at the node's **wallet/JSON-RPC port**
   (default `127.0.0.1:8700`, or `SPHINX_RPC_ADDR`) — not the P2P gossip or
   HTTP ports.
2. Reserve nonces through one shared table (`mint.Nonces` / `abi.Transact`
   with `Reserver`) and **release them when the node terminally rejects a
   tx** — an async rejection otherwise poisons every later send.
3. For `buy` / `purchase_license`, **re-read the listing/terms immediately
   before submitting** and carry exactly that nSPX value.
4. Contract addresses must be in canonical SPIF form
   (`common.NormalizeSPIFAddress` / `FormatSPIFAddress`); compare identities
   with `sameIdentity` — storage holds raw uppercase hex, the UI holds
   `SPIF XXXX …` display form.
5. Quote gas with the `abi` builders (base + contract), price in gSPX, and
   poll confirmation via `GetTxConfirmation`/`WaitForTxConfirmation`
   (distinguish confirmed / rejected / still-pending — see
   `classifyTransferOutcome`).
6. Never treat a collection mint's token URI as real unless the pin outcome
   says the bytes were actually uploaded (`storage.PinOutcome.Uploaded()`).

---

## 5. Running & testing

```bash
# Run the GUI (from the module root)
go run ./src/usi

# Package tests (contract tests for addresses, gas, provenance, pinning, history)
go test ./src/usi/gui/
```

Startup prints two beacon lines before any key load or RPC call — the build
revision and the gas denomination (gSPX) — so UI-vs-binary issues are
diagnosable from the terminal alone.

Every GUI error pop-up is also mirrored to the terminal as a
`[USI-GUI][ERROR] <message>` line (see `showErrorDialog`): pop-ups are
transient and vanish on dismissal, while the log line survives the session,
so an "it showed an error" report can be diffed against the precise error
without re-running the click path.

## 6. License

Copyright (c) 2024-present Sphinx Core Dev — MIT License
<https://opensource.org/license/mit>.


