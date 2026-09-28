// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/bind/identity_test.go
//
// Tests for the single-persistent-identity contract: the node's consensus
// keypair (handshake key, PBFT verification key, genesis header signature)
// IS the keypair persisted under Node-<address>/keys, loaded fail-closed and
// never regenerated per start.
package bind

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/consensus"
	"github.com/sphinxfndorg/protocol/src/core"
	database "github.com/sphinxfndorg/protocol/src/core/state"
	config "github.com/sphinxfndorg/protocol/src/core/sthincs/config"
	key "github.com/sphinxfndorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxfndorg/protocol/src/core/sthincs/sign/backend"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/parameters"
	"github.com/sphinxfndorg/protocol/src/crypto/STHINCS/sthincs"
	"github.com/sphinxfndorg/protocol/src/network"
)

// withTempDataDir points the global data dir at a fresh temp dir for the
// duration of the test and restores it afterwards, so key files never land in
// the repository's data/ tree.
func withTempDataDir(t *testing.T) {
	t.Helper()
	prev := common.GetDataDir()
	common.SetDataDir(t.TempDir())
	t.Cleanup(func() { common.SetDataDir(prev) })
}

// generateTestIdentity generates a fresh keypair (test-only generation — the
// production constructor never generates) in the same serialized format
// GetOrCreateKeys persists.
func generateTestIdentity(t *testing.T) (skBytes, pkBytes []byte) {
	t.Helper()
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	sk, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	skBytes, pkBytes, err = km.SerializeKeyPair(sk, pk)
	if err != nil {
		t.Fatalf("SerializeKeyPair: %v", err)
	}
	return skBytes, pkBytes
}

// serviceFromIdentity builds a SigningService exactly the way the production
// call site does: key material loaded/injected, constructor never generates.
func serviceFromIdentity(t *testing.T, nodeID string, skBytes, pkBytes []byte) *consensus.SigningService {
	t.Helper()
	cfg, err := config.NewSTHINCSParameters()
	if err != nil {
		t.Fatalf("NewSTHINCSParameters: %v", err)
	}
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	mgr := sign.NewSTHINCSManager(nil, km, cfg)
	ss, err := consensus.NewSigningService(mgr, km, nodeID, skBytes, pkBytes)
	if err != nil {
		t.Fatalf("NewSigningService: %v", err)
	}
	return ss
}

// TestSigningIdentityStableAcrossRestarts is the regression test for the
// redundant per-start keypair generation: constructing the service twice from
// the same persisted identity ("restart") must yield the SAME public key.
//
// This test FAILED on the original code, where NewSigningService called
// initializeKeys -> GenerateKey on every construction (two constructions →
// two unrelated keypairs: pk1=f6f892df… pk2=a642e9d8…).
func TestSigningIdentityStableAcrossRestarts(t *testing.T) {
	skBytes, pkBytes := generateTestIdentity(t)

	ss1 := serviceFromIdentity(t, "Node-127.0.0.1:30303", skBytes, pkBytes)
	ss2 := serviceFromIdentity(t, "Node-127.0.0.1:30303", skBytes, pkBytes)

	pk1, err := ss1.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey #1: %v", err)
	}
	pk2, err := ss2.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey #2: %v", err)
	}
	if !bytes.Equal(pk1, pk2) {
		t.Fatalf("consensus identity changed across constructions: pk1=%x pk2=%x", pk1[:8], pk2[:8])
	}
	// The service must advertise exactly the persisted public key bytes.
	if !bytes.Equal(pk1, pkBytes) {
		t.Fatalf("service public key does not match injected identity: svc=%x disk=%x", pk1, pkBytes)
	}
}

// TestLoadIdentityKeysPersistsAcrossRestarts drives the real production path
// for a datadir through network.NodeIdentityKeys: first call creates and
// persists the pair (created=true), the "restart" call loads the identical
// pair (created=false) — no second keygen anywhere.
func TestLoadIdentityKeysPersistsAcrossRestarts(t *testing.T) {
	withTempDataDir(t)
	const addr = "127.0.0.1:30303"

	sk1, pk1, created, err := network.NodeIdentityKeys(nil, addr)
	if err != nil {
		t.Fatalf("NodeIdentityKeys (first start): %v", err)
	}
	if !created {
		t.Fatalf("first start with no key files must report created=true")
	}
	if !common.KeysExist(addr) {
		t.Fatalf("first start did not persist key files under %s", common.GetKeysDataDir(addr))
	}

	sk2, pk2, created2, err := network.NodeIdentityKeys(nil, addr)
	if err != nil {
		t.Fatalf("NodeIdentityKeys (restart): %v", err)
	}
	if created2 {
		t.Fatalf("restart must not regenerate keys (created=true)")
	}
	if !bytes.Equal(sk1, sk2) || !bytes.Equal(pk1, pk2) {
		t.Fatalf("identity bytes changed across restarts")
	}

	ss1 := serviceFromIdentity(t, "Node-"+addr, sk1, pk1)
	ss2 := serviceFromIdentity(t, "Node-"+addr, sk2, pk2)
	pks1, err := ss1.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey #1: %v", err)
	}
	pks2, err := ss2.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey #2: %v", err)
	}
	if !bytes.Equal(pks1, pks2) || !bytes.Equal(pks1, pk1) {
		t.Fatalf("service identity differs from persisted identity across restarts")
	}
}

// TestLoadIdentityKeysFailsClosed covers the two damage modes:
//  1. corrupt key file -> error, and the file is NOT replaced with fresh keys
//  2. missing half of the pair -> error, nothing generated
//
// On the original GetOrCreateKeys path a corrupt file silently fell through
// to regeneration; LoadIdentityKeys must never do that.
func TestLoadIdentityKeysFailsClosed(t *testing.T) {
	withTempDataDir(t)
	const addr = "127.0.0.1:30304"

	if _, _, _, err := network.NodeIdentityKeys(nil, addr); err != nil {
		t.Fatalf("NodeIdentityKeys (first start): %v", err)
	}
	privPath := common.GetPrivateKeyPath(addr)
	goodPriv, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}

	// 1. Corrupt the private key file with garbage of a plausible length.
	if err := os.WriteFile(privPath, []byte("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"), 0o600); err != nil {
		t.Fatalf("corrupt private key: %v", err)
	}
	if _, _, _, err := network.NodeIdentityKeys(nil, addr); err == nil {
		t.Fatalf("corrupt key file must fail closed, got no error")
	} else if !bytes.Contains([]byte(err.Error()), []byte("refusing to regenerate")) {
		t.Fatalf("corrupt-key error must say it refuses to regenerate, got: %v", err)
	}
	// The damaged file must be untouched — no silent regeneration happened.
	nowPriv, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("re-read private key: %v", err)
	}
	if bytes.Equal(nowPriv, goodPriv) {
		t.Fatalf("expected corrupted content to remain (no regeneration), but file was rewritten")
	}

	// The corrupt state must keep failing (stays failed, not self-healing).
	if _, _, _, err := network.NodeIdentityKeys(nil, addr); err == nil {
		t.Fatalf("expected continued failure while private key is corrupt")
	}

	// Restore the good pair, then delete the public half.
	if err := os.WriteFile(privPath, goodPriv, 0o600); err != nil {
		t.Fatalf("restore private key: %v", err)
	}
	pubPath := common.GetPublicKeyPath(addr)
	if err := os.Remove(pubPath); err != nil {
		t.Fatalf("remove public key: %v", err)
	}
	_, _, _, err = network.NodeIdentityKeys(nil, addr)
	if err == nil {
		t.Fatalf("missing public.key must fail closed, got no error")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("refusing to regenerate")) {
		t.Fatalf("missing-file error must say it refuses to regenerate, got: %v", err)
	}
	if common.KeysExist(addr) {
		t.Fatalf("missing public key must not be silently regenerated")
	}
}

// TestNewSigningServiceFailsClosed verifies the constructor itself never
// accepts (let alone generates around) bad key material.
func TestNewSigningServiceFailsClosed(t *testing.T) {
	cfg, err := config.NewSTHINCSParameters()
	if err != nil {
		t.Fatalf("NewSTHINCSParameters: %v", err)
	}
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	mgr := sign.NewSTHINCSManager(nil, km, cfg)

	// Empty material -> error, no generation.
	if _, err := consensus.NewSigningService(mgr, km, "Node-x", nil, nil); err == nil {
		t.Fatalf("empty identity must be rejected")
	}

	// Mismatched pair (sk from one keygen, pk from another) -> error.
	sk1, pk1 := generateTestIdentity(t)
	sk2, pk2 := generateTestIdentity(t)
	if _, err := consensus.NewSigningService(mgr, km, "Node-x", sk1, pk2); err == nil {
		t.Fatalf("mismatched keypair must be rejected")
	}
	// Sanity: the matched pairs are accepted.
	if _, err := consensus.NewSigningService(mgr, km, "Node-x", sk1, pk1); err != nil {
		t.Fatalf("valid keypair rejected: %v", err)
	}
	if _, err := consensus.NewSigningService(mgr, km, "Node-x", sk2, pk2); err != nil {
		t.Fatalf("valid keypair rejected: %v", err)
	}
	// Corrupting the PUBLIC part embedded in the secret must fail the
	// pair-consistency check (fail closed), not regenerate. Note: flipping a
	// byte inside SKseed/SKprf alone is structurally undetectable (SPHINCS+
	// has no cheap re-derivation), so corrupt byte 50, which sits in the
	// PKroot region of the secret blob (SKseed||SKprf||PKseed||PKroot,
	// n=16 bytes per field).
	garbage := make([]byte, len(sk1))
	copy(garbage, sk1)
	garbage[50] ^= 0xFF
	if _, err := consensus.NewSigningService(mgr, km, "Node-x", garbage, pk1); err == nil {
		t.Fatalf("corrupted identity bytes must be rejected")
	}
	// Truncated key material must fail deserialization outright.
	if _, err := consensus.NewSigningService(mgr, km, "Node-x", sk1[:16], pk1); err == nil {
		t.Fatalf("truncated identity bytes must be rejected")
	}
}

// TestHandshakeAndGenesisUsePersistedIdentity proves the two identity-critical
// consumers use the injected (persisted) key:
//
//  1. handshake: the auth_proof a peer verifies is signed with the persisted
//     key — verification under the persisted PUBLIC key must succeed, and the
//     service's advertised GetPublicKey must equal the persisted bytes
//  2. genesis: the block-0 header signature produced via SetGenesisSigner ->
//     BuildBlock must verify under the persisted public key
func TestHandshakeAndGenesisUsePersistedIdentity(t *testing.T) {
	withTempDataDir(t)
	const addr = "127.0.0.1:30305"
	const nodeID = "Node-" + addr

	// Persist an identity exactly like production first start does.
	skBytes, pkBytes, _, err := network.NodeIdentityKeys(nil, addr)
	if err != nil {
		t.Fatalf("NodeIdentityKeys: %v", err)
	}
	ss := serviceFromIdentity(t, nodeID, skBytes, pkBytes)

	params := newIdentityTestParams(t)

	// ── 1. Handshake path (unchanged — keeps passing, shown for context) ──
	// Advertised key == persisted key.
	advPK, err := ss.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if !bytes.Equal(advPK, pkBytes) {
		t.Fatalf("handshake advertises a key different from the persisted identity: adv=%x disk=%x", advPK, pkBytes)
	}
	// auth_proof signature made by this service verifies under the persisted key.
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	persistedPK, err := sthincs.DeserializePK(params, pkBytes)
	if err != nil {
		t.Fatalf("DeserializePK: %v", err)
	}
	// Peer side: verifyAndRegisterPeerKey under a FRESH registry service
	// (simulates a peer that has never seen this node before).
	peerSS, _, _ := newPeerSigningService(t, "peer")
	proof, err := signChallenge(ss, nonce, nodeID, "genesis-hash", "SPIF-reward")
	if err != nil {
		t.Fatalf("signChallenge: %v", err)
	}
	if err := verifyAndRegisterPeerKey(params, peerSS, persistedPK, nonce, nodeID, "genesis-hash", "SPIF-reward", proof); err != nil {
		t.Fatalf("handshake proof from the persisted identity key rejected: %v", err)
	}

	// ── 2. Genesis path (direct, without the VM layer) ──
	// In production the VM gate passes because SECTION 10 of StartNode
	// registers the real SPHINCS+ verifier (SetSphincsVerifier); the test
	// process never boots a node, so instead we prove the same property the
	// gate depends on by checking the raw signature bytes that the gate would
	// feed the VM: they verify under the persisted public key.
	core.SetGenesisSigner(ss, nodeID)
	t.Cleanup(func() { core.SetGenesisSigner(nil, "") })
	gs := core.DefaultGenesisState()
	block := gs.BuildBlock()
	if len(block.Header.ProposerSignature) == 0 {
		t.Fatalf("genesis block was not signed")
	}
	if block.Header.ProposerID != nodeID {
		t.Fatalf("genesis ProposerID = %q, want %q", block.Header.ProposerID, nodeID)
	}
	genesisSigMsg, err := consensus.DeserializeSignedMessage(block.Header.ProposerSignature)
	if err != nil {
		t.Fatalf("deserialize genesis signature: %v", err)
	}
	genSig, err := sthincs.DeserializeSignature(params, genesisSigMsg.Signature)
	if err != nil {
		t.Fatalf("deserialize genesis SPHINCS+ signature: %v", err)
	}
	if !sthincs.Spx_verify(params, append(append(genesisSigMsg.Timestamp, genesisSigMsg.Nonce...), genesisSigMsg.Data...), genSig, persistedPK) {
		t.Fatalf("genesis signature does not verify under the persisted identity key")
	}
}

// newPeerSigningService builds a second, independent service for the "peer
// side" of the handshake test, with its own unrelated key.
func newPeerSigningService(t *testing.T, nodeID string) (*consensus.SigningService, *key.KeyManager, *parameters.Parameters) {
	t.Helper()
	cfg, err := config.NewSTHINCSParameters()
	if err != nil {
		t.Fatalf("NewSTHINCSParameters: %v", err)
	}
	km, err := key.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	sk, pk, err := km.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		t.Fatalf("SerializeKeyPair: %v", err)
	}
	mgr := sign.NewSTHINCSManager(nil, km, cfg)
	ss, err := consensus.NewSigningService(mgr, km, nodeID, skBytes, pkBytes)
	if err != nil {
		t.Fatalf("NewSigningService: %v", err)
	}
	return ss, km, cfg.Params
}

// newIdentityTestParams returns the production SPHINCS+ parameter set for tests.
func newIdentityTestParams(t *testing.T) *parameters.Parameters {
	t.Helper()
	cfg, err := config.NewSTHINCSParameters()
	if err != nil {
		t.Fatalf("NewSTHINCSParameters: %v", err)
	}
	return cfg.Params
}

// TestNodeIdentityKeysFileOnlyPathCreatesAndLoads covers the SECOND creation
// path in NodeIdentityKeys: when no DB handle is available (nil db) the keypair
// is minted and persisted by generateIdentityKeysFileOnly. The test asserts
//
//  1. the on-disk format is exactly what the strict loader accepts
//     (a drift between the two creation paths would otherwise appear only on
//     the no-DB path, i.e. never in the DB-backed production flow), and
//  2. the file modes are the documented 0600 (private) / 0644 (public) —
//     the same modes WriteKeysToFile gives the DB-backed path.
func TestNodeIdentityKeysFileOnlyPathCreatesAndLoads(t *testing.T) {
	withTempDataDir(t)
	const addr = "127.0.0.1:30306"

	// db == nil forces the file-only creation path.
	sk, pk, created, err := network.NodeIdentityKeys(nil, addr)
	if err != nil {
		t.Fatalf("NodeIdentityKeys (file-only, nil db): %v", err)
	}
	if !created {
		t.Fatalf("first start with no key files must report created=true")
	}
	if len(pk) != 32 || len(sk) != 2*len(pk) {
		t.Fatalf("unexpected serialized sizes: sk=%d pk=%d (want pk=32, sk=2*pk)", len(sk), len(pk))
	}

	// Permissions: private 0600, public 0644 (WriteKeysToFile contract).
	privInfo, err := os.Stat(common.GetPrivateKeyPath(addr))
	if err != nil {
		t.Fatalf("stat private.key: %v", err)
	}
	if got := privInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("private.key mode = %o, want 600", got)
	}
	pubInfo, err := os.Stat(common.GetPublicKeyPath(addr))
	if err != nil {
		t.Fatalf("stat public.key: %v", err)
	}
	if got := pubInfo.Mode().Perm(); got != 0o644 {
		t.Fatalf("public.key mode = %o, want 644", got)
	}

	// The strict loader must accept exactly what the file-only path wrote.
	lsk, lpk, err := network.LoadIdentityKeys(addr)
	if err != nil {
		t.Fatalf("LoadIdentityKeys rejected file-only output: %v", err)
	}
	if !bytes.Equal(lsk, sk) || !bytes.Equal(lpk, pk) {
		t.Fatalf("file-only path output does not round-trip through LoadIdentityKeys")
	}

	// A second call must load, not regenerate.
	sk2, pk2, created2, err := network.NodeIdentityKeys(nil, addr)
	if err != nil {
		t.Fatalf("NodeIdentityKeys (file-only, restart): %v", err)
	}
	if created2 || !bytes.Equal(sk2, sk) || !bytes.Equal(pk2, pk) {
		t.Fatalf("file-only path regenerated on the second call")
	}

	// And the identity is usable as a SigningService identity.
	ss := serviceFromIdentity(t, "Node-"+addr, sk, pk)
	got, err := ss.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if !bytes.Equal(got, pk) {
		t.Fatalf("SigningService built from file-only identity advertises a different key")
	}
}

// TestBindOrderingLaterGetOrCreateKeysLoadsSamePair pins the exact ordering
// of bind/nodes.go:
//
//	~line 541  network.NodeIdentityKeys(mainDatabase, currentAddress)  (creation)
//	~line 787  nodeMgr.CreateLocalNode(...) -> network.NewNode(isLocal)
//	           -> NetworkKeyManager.GetOrCreateKeys(currentAddress)
//
// The second call must LOAD the pair the first call persisted — if it
// regenerated, first start would mint two competing identities and the
// handshake key would differ from the network-layer key. This is the
// production DB-backed path (GetOrCreateKeys with a real *database.DB).
func TestBindOrderingLaterGetOrCreateKeysLoadsSamePair(t *testing.T) {
	withTempDataDir(t)
	const addr = "127.0.0.1:30307"

	db, err := database.NewLevelDB(filepath.Join(t.TempDir(), "maindb"))
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Step 1: what bind/nodes.go does at ~line 541 (before NewBlockchain).
	sk, pk, created, err := network.NodeIdentityKeys(db, addr)
	if err != nil {
		t.Fatalf("NodeIdentityKeys: %v", err)
	}
	if !created {
		t.Fatalf("first start must report created=true")
	}

	// Step 2: what CreateLocalNode does later at ~line 787 — same DB handle,
	// same address. It must load, not regenerate.
	nkm, err := network.NewNetworkKeyManager(db)
	if err != nil {
		t.Fatalf("NewNetworkKeyManager: %v", err)
	}
	sk2, pk2, err := nkm.GetOrCreateKeys(addr)
	if err != nil {
		t.Fatalf("GetOrCreateKeys (later call): %v", err)
	}
	if !bytes.Equal(sk, sk2) || !bytes.Equal(pk, pk2) {
		t.Fatalf("later GetOrCreateKeys minted a DIFFERENT identity: this start would carry two competing keypairs")
	}
}
