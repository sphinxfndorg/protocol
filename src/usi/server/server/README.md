# USI Public Key Directory

This package stores and serves public registrar/user bundles:

```json
{
  "fingerprint": "sha3-256(signature public key)",
  "signature_public_key": "...",
  "kem_public_key": "...",
  "kem_public_key_signature": "SPHINCS+ signature over fingerprint + kem public key"
}
```

Private keys stay on the registrar's local device. The server/database stores only public lookup data.

## Encryption lookup flow

1. Alice enters Bob's fingerprint.
2. Alice's app calls `Client.Lookup(fingerprint)`.
3. The client verifies:
   - `SHA3-256(signature_public_key) == fingerprint`
   - `kem_public_key_signature` is valid for the KEM binding message.
4. Alice encrypts/wraps the vault session key with `bundle.KEMPublicKey`.

## Signature adapter

Plug in your existing SPHINCS+ verifier:

```go
verifier := publickeydir.VerifierFunc(func(pub, msg, sig []byte) bool {
    return sign.VerifyWithPublicKey(msg, &sign.Signature{Signature: sig, PublicKey: pub}, pub)
})
```

Use the exact same message for signing and verifying:

```go
msg := publickeydir.BindingMessage(fingerprint, kemPublicKey)
kemSignature := sign.Sign(msg, passphrase)
```
