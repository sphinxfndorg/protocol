```markdown
# Sphinx Wallet Key Management

How SPHINCS+ key pairs are generated, encrypted, stored on disk, backed up to USB, and how to locate and inspect the files created by the wallet.

## Overview

Running the wallet demo:

```bash
cd src/core/wallet
go run .
```

Performs the following:

1. Generates a SPHINCS+ key pair.
2. Generates a 12-word recovery mnemonic and Base32 passkey.
3. Prompts for an encryption passphrase.
4. Encrypts the private key using AES-256-GCM.
5. Stores the encrypted key in the disk keystore.
6. Generates a SPIF wallet address.

Example:

```text
Mnemonic: elder hip symbol cloth give midnight emerge picture reveal razor farm pepper
Base32Passkey: I6O4FHE5RY

SPIF Address:
SPIFDB8B8D5CC081D0949C3268AF4D788D51D2FC66EBF1416ABF08111628CAF6EE47
```

---

## Key Storage

### Disk Keystore

Location:

```text
~/.sphinx/disk-keystore/keys/
```

List stored keys:

```bash
ls -la ~/.sphinx/disk-keystore/keys/
```

Example file:

```text
disk_key_1782058713033516000_66c0ea62150a9f2c.json
```

Example keystore record:

```json
{
  "id": "disk_key_1782058713033516000_66c0ea62150a9f2c",
  "encrypted_sk": "<ciphertext>",
  "public_key": "<public-key>",
  "address": "SPIF...",
  "key_type": "sphincs+",
  "wallet_type": "DiskWallet",
  "chain_id": 7331
}
```

---

## USB Backup

Backup keys to removable storage:

```bash
cd src/accounts/usbdemo
go run .
```

Directory layout:

```text
<usb>/sphinx-usb-keystore/
├── usb-info.json
├── keys/
│   └── <key-id>.json
└── backup/
    └── <timestamp>/
        ├── backup-manifest.json
        └── <key-id>.json
```

Notes:

- `keys/` contains active restorable backups.
- `backup/` contains historical snapshots.
- This is not a hardware wallet.
- Private keys remain encrypted blobs.

---

## SPHINCS+ Key Format

### Private Key

```text
64 bytes total

SKseed  = 16 bytes
SKprf   = 16 bytes
PKseed  = 16 bytes
PKroot  = 16 bytes
```

Stored encrypted using:

```text
AES-256-GCM
Argon2id
SHA3-512
```

### Public Key

```text
32 bytes total

PKseed = 16 bytes
PKroot = 16 bytes
```

---

## SPIF Address Format

```text
SPIF + HEX(SHA3-256(public_key))
```

Example:

```text
SPIFDB8B8D5CC081D0949C3268AF4D788D51D2FC66EBF1416ABF08111628CAF6EE47
```

---

## Inspecting Wallet Files

Pretty-print a keystore:

```bash
cat ~/.sphinx/disk-keystore/keys/<key-id>.json | jq .
```

Count wallets:

```bash
ls ~/.sphinx/disk-keystore/keys/ | wc -l
```

Find all keystore files:

```bash
find ~ -iname "disk_key_*" 2>/dev/null
```

Search for addresses:

```bash
grep -r "SPIF" ~/.sphinx/ 2>/dev/null
```

Most recent key:

```bash
ls -t ~/.sphinx/disk-keystore/keys/ | head -1
```

Keystore path:

```bash
realpath ~/.sphinx/disk-keystore/keys/
```

---

## macOS Finder Access

Open keystore directly:

```bash
open ~/.sphinx/disk-keystore/keys/
```

Open parent folder:

```bash
open ~/.sphinx/disk-keystore/
```

Open hidden wallet directory:

```bash
open ~/.sphinx/
```

Open wallet source:

```bash
open ~/go/src/core/wallet/
```

Finder shortcuts:

| Shortcut | Action |
|-----------|---------|
| Cmd+Shift+G | Go to Folder |
| Cmd+Shift+H | Home Folder |
| Cmd+Shift+. | Toggle Hidden Files |
| Cmd+Shift+C | Computer |
| Cmd+Shift+D | Desktop |
| Cmd+Shift+A | Applications |

---

## Vault Files

Find vault files:

```bash
find ~ -name "*.vault" 2>/dev/null
```

List local vaults:

```bash
ls -la *.vault
```

Open vault source directory:

```bash
open ~/go/src/core/wallet/vault/
```

---

## Running Wallet Demo

Generate wallet:

```bash
cd src/core/wallet
go run .
```

Expected output:

```text
GenerateKey: Generated keys
SerializeSK: Serialized private key: length=64

Mnemonic: ...
Base32Passkey: ...

SPIF Address: ...
Stored key pair with ID: ...

Verified: decrypted secret key matches stored public key.
```

---

## Troubleshooting

### Keystore Missing

```bash
cd src/core/wallet
go run .
```

### Permission Denied

```bash
sudo cat ~/.sphinx/disk-keystore/keys/disk_key_*.json
```

### Locate USB Backup

macOS:

```bash
ls /Volumes/
```

Linux:

```bash
ls /media/$(whoami)/
```

Search system-wide:

```bash
sudo find / -name "sphinx-usb-keystore" -type d 2>/dev/null
```

---

## Current Limitations

- No HD wallet derivation.
- No Ledger or hardware-wallet integration.
- USB backup is encrypted file storage only.
- Duplicate `getDefaultDiskStoragePath()` implementations exist.
- Mnemonic word list is fetched from GitHub at runtime.
- Trust-store delete operations are incomplete.
- ListTrustedSenders is partially implemented.

---

## Recommended Workflow

1. Generate wallet.
2. Save mnemonic securely.
3. Save passphrase in a password manager.
4. Record SPIF address.
5. Create USB backup.
6. Test restore process.
7. Verify wallet integrity.

The SPIF address format is standardized and ready for wallet integration.
```