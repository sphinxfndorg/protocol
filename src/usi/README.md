# USI Software

USI Software (Universal Sovereign Identity) is a desktop identity, encryption, signature, and wallet application for the SPIF (Sphinx Fingerprint) identity system. It provides a graphical interface for creating a sovereign cryptographic identity, protecting folders as encrypted vaults, signing documents, verifying signatures, and managing a SPIF wallet address.

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

- **Folder encryption**
  - Encrypts folders into `.vault` files.
  - Uses AES-256-GCM for encryption.
  - Uses Argon2id for passphrase-based key derivation.
  - Supports optional embedded secure messages.
  - Supports recipient fingerprints for shared vault access.

- **Vault decryption**
  - Opens `.vault` files and restores the original folder.
  - Checks whether the current identity is authorized to decrypt shared vaults.
  - Recovers embedded messages when present.
  - Shows sender and organization information when available.

- **Document signing**
  - Signs files using the user's cryptographic identity.
  - Uses SPHINCS+ signatures with SHAKE-256 hashing.
  - Stores signature metadata in a `.usimeta` sidecar file.
  - Prevents re-signing already signed documents to preserve integrity.

- **Signature verification**
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
  - Current wallet values are UI stubs and should be connected to real wallet backend calls.

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

### Encrypt

The encrypt screen allows the user to select a folder and lock it into a `.vault` file. The user may optionally provide:

- Recipient fingerprints, comma-separated
- An embedded secure message

When recipients are provided, USI resolves their public keys from the key directory before encrypting the vault.

### Decrypt

The decrypt screen allows the user to choose a `.vault` file, inspect vault information, confirm authorization, and restore the folder. If the vault contains an embedded message, the message is shown after successful decryption.

### Sign

The sign screen allows the user to select any regular file and attach a cryptographic signature. The signature is stored as a `.usimeta` sidecar file.

### Verify

The verify screen checks a file against its `.usimeta` sidecar metadata. It reports whether the signature is valid and displays signer information when available.

### My Keys

The keys screen displays the user's public fingerprint, key parameters, and local key storage information.

### Wallet

The wallet screen shows a SPIF address, balance, send/receive actions, and transaction history. The current implementation contains placeholder wallet data and TODO markers for real wallet package integration.

## Local Key Storage

USI stores key material locally under the configured key directory. The GUI displays paths such as:

```text
~/.usi/keys/private.key
~/.usi/keys/public.key
```

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
- Wallet operations are currently placeholders and should be connected to a real wallet backend.

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
