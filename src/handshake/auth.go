// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/handshake/auth.go
package security

import (
	"encoding/binary"
	"errors"
	"fmt"

	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	"golang.org/x/crypto/sha3"
)

// SphincsAuthenticator authenticates handshake peers with SPHINCS+ signatures.
//
// Proof wire format: pkLen (4, big-endian) || publicKey || signature.
//
// SECURITY: a valid signature only proves the peer owns *some* key. The
// Trusted callback is what makes it an identity check, so it is mandatory: it
// must return nil only for public keys you accept (validator set, configured
// peers, on-chain registry...).
//
// NOTE: each handshake consumes one signature from the key's signing capacity
// (2^30 for the H=30 parameter set). Use a dedicated node-identity key rather
// than a wallet key.
type SphincsAuthenticator struct {
	km      *key.KeyManager
	sk      *sthincs.SPHINCS_SK
	pkBytes []byte
	trusted func(peerPK []byte) error
}

// NewSphincsAuthenticator builds an Authenticator from this node's serialized
// secret/public key and a trust callback.
func NewSphincsAuthenticator(km *key.KeyManager, skBytes, pkBytes []byte, trusted func(peerPK []byte) error) (*SphincsAuthenticator, error) {
	if km == nil || km.Params == nil || km.Params.Params == nil {
		return nil, errors.New("key manager with SPHINCS+ parameters is required")
	}
	if trusted == nil {
		return nil, errors.New("a trust callback is required: without it any key would be accepted")
	}
	sk, _, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		return nil, fmt.Errorf("load node identity key: %w", err)
	}
	pk := make([]byte, len(pkBytes))
	copy(pk, pkBytes)
	return &SphincsAuthenticator{km: km, sk: sk, pkBytes: pk, trusted: trusted}, nil
}

// Prove signs the handshake digest.
func (a *SphincsAuthenticator) Prove(digest []byte) ([]byte, error) {
	sig, err := sthincs.Spx_sign(a.km.Params.Params, digest, a.sk)
	if err != nil {
		return nil, fmt.Errorf("sign handshake digest: %w", err)
	}
	if sig == nil {
		return nil, errors.New("sign handshake digest: nil signature")
	}
	sigBytes, err := sig.SerializeSignature()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 4, 4+len(a.pkBytes)+len(sigBytes))
	binary.BigEndian.PutUint32(out, uint32(len(a.pkBytes)))
	out = append(out, a.pkBytes...)
	out = append(out, sigBytes...)
	return out, nil
}

// Verify checks the peer's proof and that its key is trusted. It never panics
// on malformed peer input.
func (a *SphincsAuthenticator) Verify(digest, proof []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("malformed proof: %v", r)
		}
	}()
	if len(proof) < 4 {
		return errors.New("proof too short")
	}
	pkLen := binary.BigEndian.Uint32(proof[:4])
	if pkLen == 0 || uint64(pkLen) > uint64(len(proof)-4) {
		return errors.New("invalid public key length in proof")
	}
	pkBytes := proof[4 : 4+pkLen]
	sigBytes := proof[4+pkLen:]
	if len(sigBytes) == 0 {
		return errors.New("missing signature")
	}

	// Cheap check first: reject untrusted keys before any signature work.
	if err := a.trusted(pkBytes); err != nil {
		return fmt.Errorf("peer key not trusted: %w", err)
	}

	pk, err := a.km.DeserializePublicKey(pkBytes)
	if err != nil {
		return err
	}
	sig, err := sthincs.DeserializeSignature(a.km.Params.Params, sigBytes)
	if err != nil {
		return err
	}
	if !sthincs.Spx_verify(a.km.Params.Params, digest, sig, pk) {
		return errors.New("invalid handshake signature")
	}
	return nil
}

// NewAllowList returns a trust callback accepting exactly the given serialized
// public keys.
func NewAllowList(publicKeys ...[]byte) func([]byte) error {
	set := make(map[[32]byte]struct{}, len(publicKeys))
	for _, pk := range publicKeys {
		set[sha3.Sum256(pk)] = struct{}{}
	}
	return func(pk []byte) error {
		if _, ok := set[sha3.Sum256(pk)]; !ok {
			return errors.New("public key is not in the allow-list")
		}
		return nil
	}
}
