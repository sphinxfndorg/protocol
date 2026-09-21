# USI Software

USI Software (Universal Sovereign Identity) is a desktop identity, encryption, signature, and wallet application for the SPIF (Sphinx Fingerprint) identity system. It provides a graphical interface for creating a sovereign cryptographic identity, protecting folders as encrypted vaults, minting data with a cryptographic signature, verifying that data, and managing a SPIF wallet address.

The application is built in Go with the Fyne GUI toolkit.

## Features

- **Sovereign identity registration**
  - Creates a local USI identity for the SPIF organization.
  - Generates a passphrase-protected key pair.
  - Displays the user's public fingerprint for sharing and verification.

- **Secure login**
  - Loads an existing identity from the local key directory.
  - Unlocks the session using the user's passphrase.
  - Keeps the passphrase required for sensitive operations.

- **Folder encryption (Message)**
  - Encrypts folders into `.vault` files.
  - Uses AES-256-GCM for encryption.
  - Uses Argon2id for passphrase-based key derivation.
  - Supports optional embedded secure messages.
  - Supports recipient fingerprints for shared vault access.

- **Vault decryption (Inbox)**
  - Opens `.vault` files and restores the original folder.
  - Checks whether the current identity is authorized to decrypt shared vaults.
  - Recovers embedded messages when present.
  - Shows sender and organization information when available.

- **Document signing (Mint Data)**
  - Signs files using the user's cryptographic identity.
  - Uses SPHINCS+ signatures with SHAKE-256 hashing.
  - Stores signature metadata in a `.usimeta` sidecar file.
  - Auto-mints an on-chain NFT anchor for the signed data.
  - Prevents re-signing already signed documents to preserve integrity.
  - **Requires a minimum wallet balance of 100 SPX** — the node rejects the
    mint when the signed-in wallet holds less than the policy minimum.
  - **Costs SPX to perform** — every mint pays the policy-defined mint fee
    (default 1 SPX) on-chain through the anchor transaction's gas fee, which
    the executor deducts from the sender and distributes per the policy fee
    schedule. The GUI shows the current balance, the floor, and the mint fee
    before confirming.

- **Signature verification (Verify Data)**
  - Verifies whether a file is authentic and untampered.
  - Reads the `.usimeta` sidecar file from the same folder.
  - Displays signer, organization, timestamp, and verification status.

- **Key management**
  - Shows the user's public fingerprint.
  - Displays key parameters and storage paths.
  - Allows copying the public fingerprint to the clipboard.

- **Wallet interface**
  - Displays a SPIF wallet balance and address.
  - Provides send and receive dialogs.
  - Shows transaction history and wallet statistics.
  - **Node type determination:** USI is a **LIGHTWEIGHT wallet**, not a vault
    full node. It holds no blockchain and never downloads full block bodies —
    entire-block sync (`src/core/sync.go`) belongs exclusively to full nodes
    started via `bind.StartNode`. The wallet talks to a full node's JSON-RPC
    (`getbalance`, `getnonce`, `sendtransaction`, ...) and when it needs any
    chain data at all it downloads **block headers only** via the node's
    `getblockheader` / `getheaders` RPC (see `gui/rpc.go`
    `GetChainTipHeader` / `GetBlockHeader` / `GetHeaders`). The wallet screen
    shows the header-synced chain tip (height, hash, proposer).

## Cryptography Overview

USI Software is designed around post-quantum identity and file protection primitives:

| Purpose | Technology |
| --- | --- |
| Signature scheme | SPHINCS+ |
| Hash function | SHAKE-256 |
| Folder encryption | AES-256-GCM |
| Key derivation | Argon2id |
| Vault format | `.vault` |
| Signature metadata | `.usimeta` |
| Organization | SPIF |

Private keys are protected by the user's passphrase. If the passphrase is lost, encrypted data and identity access may be permanently unrecoverable.

## Application Screens

### Welcome

The first screen allows a user to register a new identity or log in with an existing passphrase.

### Register

Registration generates a master key pair and a passphrase. The application stores the local key material and displays:

- The generated passphrase
- The public fingerprint
- The SPIF organization label

If the key server is offline, registration still succeeds locally. The public bundle can be published later when the server is available.

### Dashboard

The dashboard summarizes:

- Total `.vault` files in the working directory
- Total signed documents with `.usimeta` metadata
- Last recorded activity
- Current key status
- Cryptographic identity parameters
- Recent activity history

### Message

The Message screen allows the user to select a folder and lock it into a `.vault` file. The user may optionally provide:

- Recipient fingerprints, comma-separated
- An embedded secure message

When recipients are provided, USI resolves their public keys from the key directory before encrypting the vault.

### Inbox

The Inbox screen allows the user to choose a `.vault` file, inspect vault information, confirm authorization, and restore the folder. If the vault contains an embedded message, the message is shown after successful decryption.

### Mint Data

The Mint Data screen allows the user to select any regular file and attach a cryptographic signature. The signature is stored as a `.usimeta` sidecar file, and the signed data is automatically minted as an on-chain NFT anchor.

Minting is a gated, paid operation governed by the consensus policy (`src/policy`): the wallet must hold at least the minimum mint balance (100 SPX) — enforced against the node's live `getbalance` — and each mint pays the policy mint fee (default 1 SPX) through the anchor transaction's gas fee. The screen shows the floor, the fee, and the user's current balance before confirming.

### IPFS dependency for minted data

Minting pins the signed data to **IPFS** so a verifier can fetch the payload by CID. IPFS is a **separate daemon** from the Sphinx node — running the chain nodes does not start IPFS. Start a Kubo daemon (or IPFS Desktop) and leave it listening on the default API port:

```bash
ipfs init        # once per machine
ipfs daemon      # serve the HTTP API on 127.0.0.1:5001, gateway on 127.0.0.1:8080
```

If your daemon runs on another host/port, override it before launching the wallet:

```bash
export SPHINX_IPFS_ADDR="http://127.0.0.1:5001"
export SPHINX_IPFS_GATEWAY="http://127.0.0.1:8080"
```

#### A local daemon is NOT durable storage

Your own daemon only serves content while it is online and reachable by peers. For minted data to stay retrievable independently of your machine, mirror every pin to a remote pinning service (currently **Pinata**):

```bash
export SPHINX_IPFS_PINNING_SERVICE="https://api.pinata.cloud"   # optional; assumed if a token is set
export SPHINX_IPFS_PINNING_TOKEN="<your-pinata-jwt>"
```

With a token set, each mint pins to the local daemon first, then mirrors to the service, and only reports **remote-pinned** when both agree on the same CID. Every backend is asked for **CIDv1** so one payload has exactly one canonical identifier — the CID is what gets committed on-chain, so a CIDv0/CIDv1 mismatch would leave the durable copy unreachable under the anchored identifier.

#### What happens when nothing can be uploaded

**The mint stops before signing.** If no IPFS backend accepts the file, the wallet aborts with a red banner naming the fix, and your file is left untouched — nothing is signed and nothing is anchored. This is deliberate: the anchor commits to a content hash, and signing first would leave a file that can never be re-minted.

To intentionally mint with **no upload at all**, opt in explicitly:

```bash
export SPHINX_IPFS_DISABLE="true"   # record a local content hash (spxhash-<hex>) instead of a CID
```

In that mode the mint proceeds, but `spxhash-<hex>` is a **local content hash, not a retrievable IPFS CID** — no node can serve it. The UI says so plainly, and `sphinx ipfs verify` reports `NEVER UPLOADED` rather than a generic fetch failure. This is an offline-only mode; anyone you share the token with will not be able to fetch the data.

#### Which file is pinned

The bytes pinned to IPFS (and committed by the on-chain anchor and the mint receipt's `PayloadHash`) are the **clean, pre-signature** file. The signature cannot be part of the bytes it signs, so the final on-disk file differs from the pinned copy by the signature container it gains. Both hashes are recorded in the document metadata so this expected difference is visible rather than looking like corruption:

- `ipfs_payload_hash` — the pinned bytes (= the receipt's `PayloadHash`)
- `file_hash` — the signed on-disk file (what Verify re-hashes)

### Verify Data

The Verify Data screen checks a file's embedded signature and reports what the file itself records about its mint.

**Signature assurance is a three-state result, not a boolean.** The screen never collapses the middle state into a plain "valid":

| Result | Meaning |
|---|---|
| `AUTHENTICATED` | The signature verifies **and** the signer's key is registered and active in the key directory. This is the only result that proves *who* signed. |
| `INTEGRITY ONLY` | The signature is self-consistent and the content is unchanged, but the signer's identity could **not** be confirmed against the directory (offline, or not registered). This is tamper-evidence, not proof of authorship. |
| `INVALID` | The signature does not verify, the file was modified, or the signer's key is not accepted. |

**Payload retrievability** is reported as a separate verdict (`REPLICATED` / `LOCAL ONLY` / `NOT REACHABLE` / `NEVER UPLOADED`), using the same vocabulary as `sphinx ipfs verify`. The check uses HTTP range requests, so it probes availability without downloading the payload.

**Backend-recorded provenance** is displayed from the document's own metadata — the same on-chain block the signer embedded into every container (PDF properties, XMP, PNG iTXt, JPEG APP1, Office custom.xml, or the binary footer) at mint time:

- Mint ID, anchor transaction, confirming block height and hash, transaction nonce
- Mint price (exact nSPX, as carried by the anchor transaction)
- Marketplace token binding, and the embedded economics (resale royalty, licence fee, payout recipient)
- IPFS CID, plus both payload hashes

These are shown exactly as recorded. Re-checking them against the chain is what `sphinx ipfs verify` does. Note the two hash rows differ by design: **Pinned Payload Hash** covers the clean bytes uploaded to IPFS, while **Signed File Hash** covers the signed file on disk.

### My Keys

The keys screen displays the user's public fingerprint, key parameters, and local key storage information.

### Wallet

The wallet screen shows a SPIF address, balance, send/receive actions, and transaction history. Send signs transactions locally with the canonical STHINCS manager bundle (`SignTransactionAuth`) and broadcasts them to a full node via `sendrawtransaction`; balance, history, and nonce are queried from the node's JSON-RPC.

## Local Key Storage

Read: https://github.com/sphinxfndorg/protocol/tree/main/src/core/wallet

The exact key directory is provided by the `keys.KeyDir` value in the core key package.

## Project Structure

The GUI entry point shown here is:

```text
go/src/usi/gui/gui.go
```

Main dependencies used by the GUI include:

- `fyne.io/fyne/v2` for the desktop interface
- `github.com/sphinxfndorg/protocol/src/accounts/phrase` for passphrase generation
- `github.com/sphinxfndorg/protocol/src/usi/core/key` for key generation and loading
- `github.com/sphinxfndorg/protocol/src/usi/core/crypter/vault` for vault encryption/decryption
- `github.com/sphinxfndorg/protocol/src/usi/core/sign` for signing and verification
- `github.com/sphinxfndorg/protocol/src/usi/server/server` for public fingerprint handling

## Running the Application

From the Go project root, run:

```bash
go run ./go/src/usi
```

Depending on the actual module layout, the entry command may differ. If the GUI package is wired into another `main` package, run that package instead.

## Development Notes

- The GUI uses `app.NewWithID("com.usi.UniversalSovereignIdentity")`.
- The window title is `Universal Sovereign Identity`.
- The default window size is `1100x680`.
- Dark theme is enabled by default and can be toggled from the welcome/register screens.
- Sensitive operations ask the user to confirm their passphrase.
- Activity is tracked in-memory and displayed on the dashboard.
- Wallet operations are connected to a real full-node backend: the wallet signs locally with the canonical SPHINCS auth bundle and broadcasts via `sendrawtransaction`, and reads balance/history/nonce over the node's JSON-RPC.
- The sidebar navigation labels are Dashboard, Message, Inbox, Mint Data, Verify Data, Wallet, and My Keys; internally these map to the encrypt, decrypt, sign, and verify screens/functions respectively.

## Security Notes

- Keep the generated passphrase private and backed up securely.
- Losing the passphrase can permanently lock encrypted vaults and private keys.
- Never share the private key files.
- Share only the public fingerprint or wallet address.
- Verify signatures using the original file and its matching `.usimeta` file.
- Confirm recipient fingerprints before encrypting shared vaults.

## License

Copyright (c) 2024-present Sphinx Core Dev

Released under the MIT License: <https://opensource.org/license/mit>