// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package key

import "testing"

// TestVerifyPubKey_MatchingPair generates a real SPHINCS+ key pair and
// confirms VerifyPubKey accepts the genuinely matching (secret, pubkey)
// combination. This requires your actual sthincs.Spx_keygen / parameters
// packages to build — I can't fabricate SPHINCS+ key material by hand, so
// this test exercises the real code path rather than a mock.
func TestVerifyPubKey_MatchingPair(t *testing.T) {
	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}

	sk, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	skBytes, err := sk.SerializeSK()
	if err != nil {
		t.Fatalf("SerializeSK failed: %v", err)
	}

	pkBytes, err := pk.SerializePK()
	if err != nil {
		t.Fatalf("SerializePK failed: %v", err)
	}

	ok, err := km.VerifyPubKey(skBytes, pkBytes)
	if err != nil {
		t.Fatalf("VerifyPubKey returned error for a genuinely matching pair: %v", err)
	}
	if !ok {
		t.Fatal("VerifyPubKey rejected a genuinely matching SK/PK pair")
	}
}

// TestVerifyPubKey_MismatchedPair confirms VerifyPubKey rejects a public
// key from a DIFFERENT key pair than the one the secret belongs to — this
// is the actual security property the function exists to enforce.
func TestVerifyPubKey_MismatchedPair(t *testing.T) {
	km, err := NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}

	sk1, _, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey (pair 1) failed: %v", err)
	}
	_, pk2, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey (pair 2) failed: %v", err)
	}

	sk1Bytes, err := sk1.SerializeSK()
	if err != nil {
		t.Fatalf("SerializeSK failed: %v", err)
	}
	pk2Bytes, err := pk2.SerializePK()
	if err != nil {
		t.Fatalf("SerializePK failed: %v", err)
	}

	ok, err := km.VerifyPubKey(sk1Bytes, pk2Bytes)
	if err != nil {
		// Either a clean "false, nil" or a deserialize-level error is
		// acceptable here — both correctly refuse to treat this as a
		// verified pair. Log rather than fail so either behavior passes.
		t.Logf("VerifyPubKey returned error for mismatched pair (acceptable): %v", err)
		return
	}
	if ok {
		t.Fatal("VerifyPubKey accepted a public key from a DIFFERENT key pair — this is a real security bug, not a test artifact")
	}
}
