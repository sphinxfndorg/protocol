## Hybrid KEM + SPHINCS+ Key Storage Architecture

A common question is where the KEM private key is stored, since only the
following fields appear in the keystore:

```json
{
  "encrypted_sk": "...",
  "public_key": "...",
  "metadata": {
    "kem_public": "..."
  }
}
```

The KEM private key is not stored as a separate JSON field. Instead, it is
combined with the SPHINCS+ private key and encrypted as a single secret blob.

---

### Combined Secret Key Layout

Before encryption, the wallet constructs a combined private key:

```text
combined_secret_key =
    SPHINCS+_private_key ||
    KEM_private_key
```

The resulting blob is then encrypted using AES-256-GCM with a key derived
from the user passphrase via Argon2id and SHA3-512 stretching:

```text
encrypted_sk =
    Encrypt(
        SPHINCS+_private_key ||
        KEM_private_key
    )
```

This means the `encrypted_sk` field contains both private keys.

---

### Decrypted Layout

After decrypting `encrypted_sk`, the resulting byte layout is:

```text
┌─────────────────────┬──────────────────────────────┐
│ SPHINCS+ Private    │ KEM Private                  │
│ Key                 │ Key                          │
├─────────────────────┼──────────────────────────────┤
│ 64 bytes            │ 2434 bytes                   │
└─────────────────────┴──────────────────────────────┘
```

Total decrypted size:

```text
64 + 2434 = 2498 bytes
```

---

### KEM Private Key Composition

The KEM private key itself is composed of two parts:

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

### Extracting the KEM Private Key

The wallet separates the keys after decryption.

Example from `LoadKeyFromDisk`:

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
skBytes      -> SPHINCS+ private key
kemPrivBytes -> KEM private key
```

---

### Why Store Both Private Keys Together?

The wallet intentionally combines both private keys before encryption.

Benefits:

- Single passphrase protects all secret material.
- Only one encrypted object must be backed up.
- Wallet backup and restore remain atomic.
- Reduced risk of losing one private key while retaining the other.
- Simpler keystore structure.

The design guarantees that a wallet either possesses the complete
cryptographic identity or none of it.

---

### Public Keys Remain Separate

Public keys are not secret and therefore remain accessible outside the
encrypted blob.

| Component | Storage Location | Encrypted |
|------------|-----------------|-----------|
| SPHINCS+ Public Key | `public_key` | No |
| SPHINCS+ Private Key | `encrypted_sk` (first 64 bytes) | Yes |
| KEM Public Key | `metadata.kem_public` | No |
| KEM Private Key | `encrypted_sk` (remaining bytes) | Yes |

---

### Visual Overview

```text
┌───────────────────────────────────────────────────────┐
│                   encrypted_sk                        │
│                                                       │
│  AES-256-GCM encrypted using user passphrase          │
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

### Summary

| Key | Storage Location | Encrypted |
|------|-----------------|-----------|
| SPHINCS+ Public Key | `public_key` | No |
| SPHINCS+ Private Key | Inside `encrypted_sk` (first 64 bytes) | Yes |
| KEM Public Key | `metadata.kem_public` | No |
| KEM Private Key | Inside `encrypted_sk` (remaining 2434 bytes) | Yes |

In summary, the KEM private key is present in every wallet, but it is
intentionally embedded inside the encrypted secret-key blob rather than
exposed as a standalone field. This provides a simpler and more secure
keystore design while ensuring that all secret cryptographic material is
protected by the same passphrase.