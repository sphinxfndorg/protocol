# Hybrid KEM + SPHINCS+ Key Storage Architecture

## 📂 Locating Your Keys on Disk

The encrypted wallet key files are stored locally under:

```text
~/.sphinx/disk-keystore/keys/
```

Each wallet is stored as a JSON file with a unique filename, for example:

```text
disk_key_1782684199459254000_7499f7c653526e1e.json
```

Example full path:

```text
/Users/username/.sphinx/disk-keystore/keys/disk_key_1782684199459254000_7499f7c653526e1e.json
```

> **Note**
>
> This default storage location is defined in:
>
> `accounts/key/disk/local.go`
>
> via the `getDefaultDiskStoragePath()` function.
>
> Both the USI GUI and CLI automatically use this directory.

---

## Viewing Your Wallet Keys

### Open the keystore in Finder (macOS)

```bash
open ~/.sphinx/disk-keystore/keys/
```

### List every wallet

```bash
ls -la ~/.sphinx/disk-keystore/keys/
```

### Pretty-print a wallet JSON

```bash
cat ~/.sphinx/disk-keystore/keys/disk_key_1782684199459254000_7499f7c653526e1e.json | jq '.'
```

If `jq` is unavailable:

```bash
cat ~/.sphinx/disk-keystore/keys/disk_key_1782684199459254000_7499f7c653526e1e.json | python3 -m json.tool
```

### View using a pager

```bash
less ~/.sphinx/disk-keystore/keys/disk_key_1782684199459254000_7499f7c653526e1e.json
```

Press **q** to exit.

### Open the entire keystore directory

```bash
open ~/.sphinx/disk-keystore/
```

---

## Key Storage Summary

| Key Type | Location | Format |
|----------|----------|--------|
| USI Wallet Keys | `~/.sphinx/disk-keystore/keys/` | JSON (`disk_key_*.json`) |
| Node Validator Keys | `./data/Node-*/keys/` | Raw binary (`private.key`, `public.key`) |

---

# The Encrypted Keystore JSON

A common question is where the KEM private key is stored, since the keystore only exposes the following fields:

```json
{
  "encrypted_sk": "...",
  "public_key": "...",
  "metadata": {
    "kem_public": "..."
  }
}
```

The KEM private key is **not** stored as a standalone JSON field.

Instead, the wallet combines both the SPHINCS+ private key and the KEM private key into a single secret blob before encryption.

---

# Combined Secret Key Layout

Before encryption, the wallet creates:

```text
combined_secret_key =
    SPHINCS+_private_key ||
    KEM_private_key
```

The combined blob is then encrypted using **AES-256-GCM**, with an encryption key derived from the user's passphrase using **Argon2id** followed by **SHA3-512** key stretching.

```text
encrypted_sk =
    Encrypt(
        SPHINCS+_private_key ||
        KEM_private_key
    )
```

Therefore, the `encrypted_sk` field contains **both private keys**.

---

# Decrypted Layout

After decrypting `encrypted_sk`, the resulting memory layout becomes:

```text
┌─────────────────────┬──────────────────────────────┐
│ SPHINCS+ Private    │ KEM Private                  │
│ Key                 │ Key                          │
├─────────────────────┼──────────────────────────────┤
│ 64 bytes            │ 2434 bytes                   │
└─────────────────────┴──────────────────────────────┘
```

Total size:

```text
64 + 2434 = 2498 bytes
```

---

# KEM Private Key Composition

The KEM private key itself contains two cryptographic keys:

```text
┌───────────────────────┬───────────────────────────┐
│ X25519 Private Key    │ Kyber768 Private Key      │
├───────────────────────┼───────────────────────────┤
│ 32 bytes              │ 2402 bytes                │
└───────────────────────┴───────────────────────────┘
```

Total:

```text
2434 bytes
```

---

# Extracting the KEM Private Key

During wallet loading (`LoadKeyFromDisk`), the decrypted blob is split back into its original components.

```go
combinedSK, err := diskStorage.DecryptKey(
    loadedKeyPair,
    passphrase,
)

const sphincsPrivateKeySize = 64

// SPHINCS+ private key
skBytes := combinedSK[:sphincsPrivateKeySize]

// KEM private key
kemPrivBytes := combinedSK[sphincsPrivateKeySize:]
```

After slicing:

```text
skBytes      → SPHINCS+ private key
kemPrivBytes → KEM private key
```

---

# Why Store Both Private Keys Together?

The wallet intentionally encrypts both private keys together.

Advantages include:

- One passphrase protects all secret material.
- Only one encrypted object needs to be backed up.
- Backup and restore remain atomic.
- Prevents accidentally losing one private key while keeping the other.
- Simplifies the keystore structure.

This guarantees that a wallet either possesses its complete cryptographic identity or none of it.

---

# Public Keys Remain Separate

Public keys are not confidential and therefore remain accessible outside the encrypted blob.

| Component | Storage Location | Encrypted |
|-----------|------------------|-----------|
| SPHINCS+ Public Key | `public_key` | No |
| SPHINCS+ Private Key | First 64 bytes of `encrypted_sk` | Yes |
| KEM Public Key | `metadata.kem_public` | No |
| KEM Private Key | Remaining 2434 bytes of `encrypted_sk` | Yes |

---

# Visual Overview

```text
┌───────────────────────────────────────────────────────┐
│                   encrypted_sk                        │
│                                                       │
│      AES-256-GCM encrypted with user passphrase       │
└───────────────────────────────────────────────────────┘
                         │
                         ▼
┌───────────────────────────────────────────────────────┐
│                  Decrypted Blob                       │
├───────────────────┬───────────────────────────────────┤
│ SPHINCS+ Private  │ KEM Private                       │
│ Key               │ Key                               │
│ (64 bytes)        │ (2434 bytes)                      │
├───────────────────┼───────────────────────────────────┤
│                   │ X25519  (32 bytes)               │
│                   │ Kyber768 (2402 bytes)            │
└───────────────────┴───────────────────────────────────┘
```

---

# Summary

| Key | Storage Location | Encrypted |
|------|------------------|-----------|
| SPHINCS+ Public Key | `public_key` | No |
| SPHINCS+ Private Key | First 64 bytes of `encrypted_sk` | Yes |
| KEM Public Key | `metadata.kem_public` | No |
| KEM Private Key | Remaining 2434 bytes of `encrypted_sk` | Yes |

The KEM private key is always present in every wallet. Rather than being stored as a separate JSON field, it is embedded inside the encrypted `encrypted_sk` blob alongside the SPHINCS+ private key. This design simplifies wallet management while ensuring that all secret cryptographic material is protected by a single passphrase.