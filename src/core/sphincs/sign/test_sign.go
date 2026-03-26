// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,q
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// go/src/core/sphincs/sign/test_sign.go
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/holiman/uint256"
	"github.com/sphinxorg/protocol/src/core/hashtree"
	sigproof "github.com/sphinxorg/protocol/src/core/proof"
	key "github.com/sphinxorg/protocol/src/core/sphincs/key/backend"
	sign "github.com/sphinxorg/protocol/src/core/sphincs/sign/backend"

	"github.com/syndtr/goleveldb/leveldb"
)

// =============================================================================
// SPHINCS+ Transaction Protocol — Alice sends to Charlie
// =============================================================================
//
// ROLES:
//   Alice  = the signer. Holds the secret key. Signs transactions.
//   Charlie = the verifier. Receives transactions. Validates them.
//
// WHAT ALICE TRANSMITS (wire payload — bytes only, no Go objects):
//   senderID        string    identity claim ("alice")
//   pkBytes         ~64 B     Alice's public key
//   sigBytes        35 KB     SPHINCS+ signature — Charlie runs Spx_verify on this
//   message         variable  the transaction content
//   timestamp       8 B       Unix timestamp — binds sig to a point in time
//   nonce           16 B      random — ensures uniqueness even for same message
//   merkleRootHash  32 B      compact receipt — Charlie stores this permanently
//   commitment      32 B      unique tx fingerprint — Charlie stores this permanently
//
// WHAT CHARLIE STORES PERMANENTLY (after Spx_verify passes):
//   merkleRootHash  32 B      receipt: "I verified a tx with this root"
//   commitment      32 B      identity: "this is which tx it was"
//   timestamp+nonce 24 B      replay guard: "I have seen this session"
//   sigBytes        DISCARDED immediately after Spx_verify — never stored
//
// WHAT ALICE STORES PERMANENTLY:
//   NOTHING — Alice stores no transaction data after transmitting.
//   Her secret key lives in memory or an HSM only, never written to disk
//   as part of the transaction flow.
//
// WHY COMMITMENT EXISTS:
//   commitment = SpxHash(sigBytes || pkBytes || timestamp || nonce || message)
//   It is the unique identity card of this specific signing event.
//   Charlie uses it to answer: "which transaction does this receipt belong to?"
//   Without commitment, merkleRootHash is 32 anonymous bytes with no context.
//   With commitment, Charlie can look up any past transaction by its fingerprint
//   and confirm he verified it — message, key, time, and nonce all bound in.
//
// WHY MERKLE ROOT EXISTS:
//   It is a 32-byte compact receipt that proves a valid sig was verified.
//   Charlie rebuilds the Merkle tree from sigBytes during VerifySignature and
//   confirms the received root matches — this proves merkleRootHash was honestly
//   derived from the real sigBytes, not invented by an attacker.
//   After Spx_verify passes, Charlie keeps the root and discards sigBytes.
//
// SECURITY LAYERS (Charlie's 4 steps):
//   Step 1 — Identity:   registry.VerifyIdentity stops identity spoofing
//   Step 2 — Freshness:  timestamp window stops old-signature reuse
//   Step 3 — Replay:     nonce store stops resubmission of valid past txs
//   Step 4 — Spx_verify: the ONLY check that forces a valid SPHINCS+ signature
//                        Eve cannot produce sigBytes that passes this without Alice's SK
//
// WIRE BOUNDARY RULE:
//   Everything in wirePayload is BYTES. Charlie deserializes each field himself.
//   Charlie never touches Alice's in-memory sig, pk, or merkleRoot objects.
//   This ensures Spx_verify runs on bytes that actually came from the network.

// copyBytes returns an independent copy of b. Use this whenever a []byte will
// be placed into a struct that outlives the source slice, or when the source
// slice will be zeroed after the copy.
//
// Go struct assignment copies the slice header (pointer, length, capacity) but
// NOT the underlying array. Without this helper, zeroing the source after
// assignment silently corrupts the destination — they share the same memory.
func copyBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// printTiming prints a labeled timing line in milliseconds.
func printTiming(label string, d time.Duration) {
	ms := float64(d.Microseconds()) / 1000.0
	fmt.Printf("  %-44s %8.3f ms\n", label, ms)
}

// printSize prints a labeled size line, auto-scaling to B/KB/MB.
func printSize(label string, bytes int) {
	switch {
	case bytes >= 1024*1024:
		fmt.Printf("  %-44s %8.2f MB  (%d bytes)\n", label, float64(bytes)/1024/1024, bytes)
	case bytes >= 1024:
		fmt.Printf("  %-44s %8.2f KB  (%d bytes)\n", label, float64(bytes)/1024, bytes)
	default:
		fmt.Printf("  %-44s %8d B\n", label, bytes)
	}
}

func main() {
	// =========================================================================
	// SETUP
	// =========================================================================

	// PRODUCTION NOTE: Do not clear LevelDB on startup in production.
	// This demo clears it to avoid stale nonce pairs from previous test runs.
	// In production, LevelDB persists across restarts — that is what makes
	// the replay prevention durable.
	err := os.RemoveAll("src/core/sphincs/hashtree/leaves_db")
	if err != nil {
		log.Fatal("Failed to clear LevelDB directory:", err)
	}
	err = os.MkdirAll("src/core/sphincs/hashtree", os.ModePerm)
	if err != nil {
		log.Fatal("Failed to create hashtree directory:", err)
	}

	// Open LevelDB — Charlie uses this to store:
	//   (1) timestamp+nonce pairs for replay prevention
	//   (2) commitment → merkleRootHash receipts for dispute resolution
	// PRODUCTION NOTE: This should be a persistent, backed-up database.
	// Loss of this DB means loss of replay protection and receipt history.
	db, err := leveldb.OpenFile("src/core/sphincs/hashtree/leaves_db", nil)
	if err != nil {
		log.Fatal("Failed to open LevelDB:", err)
	}
	defer db.Close()

	km, err := key.NewKeyManager()
	if err != nil {
		log.Fatalf("Error initializing KeyManager: %v", err)
	}
	parameters := km.GetSPHINCSParameters()
	manager := sign.NewSphincsManager(db, km, parameters)

	// =========================================================================
	// ALICE — Key generation
	// =========================================================================
	//
	// PRODUCTION NOTE: Alice generates her keypair once during account creation.
	// skBytes must NEVER be transmitted, stored in plaintext on disk, or logged.
	// In production use a hardware security module (HSM) or encrypted key store.
	// pkBytes is public — Alice registers it in Charlie's registry out-of-band
	// before any transactions happen (on-chain, PKI cert, or bootstrap handshake).

	fmt.Println("=================================================================")
	fmt.Println(" ALICE — Key generation")
	fmt.Println("=================================================================")

	tKeyGen := time.Now()
	sk, pk, err := km.GenerateKey()
	dKeyGen := time.Since(tKeyGen)
	if err != nil {
		log.Fatalf("Error generating keys: %v", err)
	}

	tSerializeKP := time.Now()
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	dSerializeKP := time.Since(tSerializeKP)
	if err != nil {
		log.Fatalf("Error serializing key pair: %v", err)
	}

	tDeserializeKP := time.Now()
	deserializedSK, deserializedPK, err := km.DeserializeKeyPair(skBytes, pkBytes)
	dDeserializeKP := time.Since(tDeserializeKP)
	if err != nil {
		log.Fatalf("Error deserializing key pair: %v", err)
	}

	fmt.Println()
	fmt.Println("  Timing:")
	printTiming("GenerateKey()", dKeyGen)
	printTiming("SerializeKeyPair()", dSerializeKP)
	printTiming("DeserializeKeyPair()", dDeserializeKP)
	fmt.Println()
	fmt.Println("  Sizes:")
	printSize("Secret key (skBytes) — NEVER transmitted", len(skBytes))
	printSize("Public key (pkBytes) — registered out-of-band", len(pkBytes))

	// =========================================================================
	// CHARLIE'S TRUSTED PUBLIC KEY REGISTRY
	// =========================================================================
	//
	// The registry maps identity strings to trusted public key bytes.
	// Charlie checks this BEFORE any cryptographic verification — it stops
	// identity spoofing attacks where Eve uses her own valid keypair but
	// claims to be Alice.
	//
	// PRODUCTION NOTE: The registry must be populated through a trusted
	// out-of-band channel BEFORE any transactions arrive. Options:
	//   (a) On-chain registration: Alice posts pkBytes to a smart contract
	//       under her address. Charlie reads the contract — cannot be faked.
	//   (b) PKI certificate: a trusted CA signs Alice's pkBytes.
	//   (c) TOFU (Trust On First Use): Charlie stores the first pkBytes he
	//       sees from Alice during the initial PING/PONG handshake.
	//       TOFU is only safe if Eve cannot reach Charlie before Alice does.
	//
	// CRITICAL: Register() is NEVER called with data from an incoming transaction.
	// Populating the registry from receivedPKBytes would defeat its purpose —
	// Eve could simply send her own pkBytes and claim to be Alice.
	// The first registration wins (TOFU) — subsequent attempts are rejected.
	registry := sign.NewPublicKeyRegistry()
	registry.Register("alice", pkBytes) // out-of-band, trusted registration

	// =========================================================================
	// ALICE — Signing tx1
	// =========================================================================
	//
	// What happens inside SignMessage:
	//   1. Generates timestamp (8 bytes, Unix seconds) and nonce (16 bytes, random)
	//   2. Calls Spx_sign(params, timestamp||nonce||message, SK) → 35 KB sigBytes
	//   3. Computes commitment = SpxHash(sigBytes||pkBytes||timestamp||nonce||message)
	//      commitment is the unique fingerprint of this exact signing event
	//   4. Builds 5-leaf Merkle tree:
	//        leaf[0] = commitment || sigBytes[0:chunk]   (commitment prepended)
	//        leaf[1] = sigBytes[chunk:2*chunk]
	//        leaf[2] = sigBytes[2*chunk:3*chunk]
	//        leaf[3] = sigBytes[3*chunk:]
	//        leaf[4] = SpxHash(commitment)               (independently verifiable)
	//   5. Returns sig, merkleRoot, timestamp, nonce, commitment

	fmt.Println()
	fmt.Println("=================================================================")
	fmt.Println(" ALICE — Signing tx1")
	fmt.Println("=================================================================")

	message := []byte("Hello, world!")

	// PRODUCTION NOTE: Alice calls SignMessage only when she wants to send a tx.
	// The sig object and sigBytes exist only in memory during this transaction.
	// Alice does NOT store sigBytes to disk — she only keeps her SK (in HSM).
	tSign := time.Now()
	sig, merkleRoot, timestamp, nonce, commitment, err := manager.SignMessage(
		message, deserializedSK, deserializedPK,
	)
	dSign := time.Since(tSign)
	if err != nil {
		log.Fatal("Failed to sign message:", err)
	}

	// Serialize sigBytes — this is what goes on the wire to Charlie.
	// PRODUCTION NOTE (parameter choice):
	//   Current params SHAKE-256-256f: sigBytes = 35,664 bytes (fast signing)
	//   Alternative SHAKE-256-256s:    sigBytes =  7,856 bytes (same 256-bit security)
	//   Switching to 256s reduces wire cost by ~4.5x with no security tradeoff.
	tSigSer := time.Now()
	sigBytes, err := manager.SerializeSignature(sig)
	dSigSer := time.Since(tSigSer)
	if err != nil {
		log.Fatal("Failed to serialize signature:", err)
	}

	merkleRootHash := merkleRoot.Hash.Bytes()

	// Alice's LOCAL sanity check — runs BEFORE transmission, using her own
	// in-memory objects. This is NOT Charlie's verification.
	//
	// Purpose: Alice confirms her own signing operation produced consistent
	// results before spending network bandwidth transmitting to Charlie.
	// If this fails, something is wrong with Alice's node — she does not transmit.
	//
	// PRODUCTION NOTE: This call uses Alice's local sig and merkleRoot objects —
	// objects that were never serialized or deserialized. It is a pre-flight check
	// only. Charlie's verification (Step 4 below) operates on wire bytes, not these.
	tLocalVerify := time.Now()
	isValidLocal := manager.VerifySignature(
		message, timestamp, nonce, sig, deserializedPK, merkleRoot, commitment,
	)
	dLocalVerify := time.Since(tLocalVerify)
	if !isValidLocal {
		log.Fatal("Alice local check failed — not transmitting")
	}

	// Build proof — for downstream light clients only.
	//
	// What the proof is:
	//   proof = SpxHash(timestamp||nonce||message || merkleRootHash ||
	//                   CommitmentLeaf(commitment) || pkBytes)
	//
	// What it does:
	//   A light client (Dave) who cannot afford to run Spx_verify can receive
	//   this proof from Charlie (a full node who already ran Spx_verify) and
	//   verify that the transaction he received is the same one Charlie verified.
	//   Dave regenerates the proof from the received values and compares.
	//
	// What it does NOT do:
	//   It does not replace Spx_verify. It does not prove the sig is valid.
	//   It only proves consistency — the values are the same ones Charlie verified.
	//   Dave must trust that Charlie ran Spx_verify honestly.
	//
	// PRODUCTION NOTE: The proof is optional infrastructure for relay nodes
	// and light clients. Charlie (a full node) ignores it — he runs Spx_verify.
	tProofGen := time.Now()
	commitmentLeaf := sign.CommitmentLeaf(commitment)
	proofLeaves := [][]byte{merkleRootHash, commitmentLeaf}
	// FIX: use buildMessageWithTimestampAndNonce-style safe concatenation here
	// instead of the nested append that risks aliasing nonce's backing array.
	proofMsg := make([]byte, 0, len(timestamp)+len(nonce)+len(message))
	proofMsg = append(proofMsg, timestamp...)
	proofMsg = append(proofMsg, nonce...)
	proofMsg = append(proofMsg, message...)
	proof, err := sigproof.GenerateSigProof(
		[][]byte{proofMsg},
		proofLeaves,
		pkBytes,
	)
	dProofGen := time.Since(tProofGen)
	if err != nil {
		log.Fatalf("Failed to generate proof: %v", err)
	}
	sigproof.SetStoredProof(proof)

	fmt.Println()
	fmt.Println("  Timing:")
	printTiming("SignMessage() — Spx_sign + merkle + commitment", dSign)
	printTiming("SerializeSignature()", dSigSer)
	printTiming("VerifySignature() — local sanity check", dLocalVerify)
	printTiming("GenerateSigProof() — for light clients only", dProofGen)

	fmt.Println()
	fmt.Println("  Sizes (wire payload):")
	printSize("sigBytes — Charlie verifies then discards", len(sigBytes))
	printSize("pkBytes", len(pkBytes))
	printSize("merkleRootHash — Charlie stores permanently", len(merkleRootHash))
	printSize("commitment — Charlie stores permanently", len(commitment))
	printSize("timestamp", len(timestamp))
	printSize("nonce", len(nonce))
	printSize("proof — light clients only", len(proof))
	printSize("message", len(message))
	wireTotal := len(pkBytes) + len(sigBytes) + len(message) + len(timestamp) +
		len(nonce) + len(merkleRootHash) + len(commitment) + len(proof)
	fmt.Println()
	printSize("TOTAL wire payload", wireTotal)
	printSize("  of which: sigBytes (transient)", len(sigBytes))
	printSize("  of which: everything else (persistent)", wireTotal-len(sigBytes))
	fmt.Println()
	fmt.Printf("  Alice stores permanently:  0 bytes\n")
	fmt.Printf("  Alice discards after tx:   sigBytes + all in-memory objects\n")

	// =========================================================================
	// WIRE PAYLOAD — bytes only, no Go objects
	// =========================================================================
	//
	// This struct represents what travels over the network.
	// Every field is a raw byte slice — no deserialized Go objects.
	// Charlie will deserialize each field himself from scratch.
	// Charlie never has access to Alice's in-memory sig, pk, or merkleRoot.
	//
	// PRODUCTION NOTE: In a real P2P network, this would be serialized into
	// a protobuf or RLP-encoded message and sent over TCP/UDP.
	// The wire boundary is enforced by the serialization layer —
	// Go objects cannot cross process boundaries, only bytes can.
	//
	// FIX: every field that will be zeroed after this point must be copied
	// with copyBytes() before being placed here. Go slice assignment copies
	// only the header (pointer+len+cap), NOT the underlying array. Without
	// the copy, zeroing sigBytes below would also zero wirePayload.SigBytes
	// because both slice headers point at the same backing array.
	wirePayload := struct {
		SenderID       string
		PKBytes        []byte
		SigBytes       []byte
		Message        []byte
		Timestamp      []byte
		Nonce          []byte
		MerkleRootHash []byte
		Commitment     []byte
		Proof          []byte
	}{
		SenderID:       "alice",
		PKBytes:        pkBytes,
		SigBytes:       copyBytes(sigBytes), // independent copy — safe to zero sigBytes below
		Message:        message,
		Timestamp:      timestamp,
		Nonce:          nonce,
		MerkleRootHash: merkleRootHash,
		Commitment:     commitment,
		Proof:          proof,
	}

	// Zero Alice's local sigBytes now that wirePayload has its own independent copy.
	// This prevents the 7–35 KB signature from lingering in Alice's heap memory.
	// Safe because wirePayload.SigBytes points to a different backing array.
	for i := range sigBytes {
		sigBytes[i] = 0
	}

	// =========================================================================
	// CHARLIE — Verifying tx1
	// =========================================================================
	//
	// Charlie receives wirePayload as raw bytes from the network.
	// He deserializes each field himself — he never touches Alice's objects.
	// His verification has 4 steps in strict order.

	fmt.Println()
	fmt.Println("=================================================================")
	fmt.Println(" CHARLIE — Verifying tx1")
	fmt.Println("=================================================================")

	receivedSenderID := wirePayload.SenderID
	receivedPKBytes := wirePayload.PKBytes
	receivedSigBytes := wirePayload.SigBytes
	receivedMessage := wirePayload.Message
	receivedTimestamp := wirePayload.Timestamp
	receivedNonce := wirePayload.Nonce
	receivedMerkleRootHash := wirePayload.MerkleRootHash
	receivedCommitment := wirePayload.Commitment
	fmt.Println()

	// STEP 1 — IDENTITY CHECK
	//
	// Charlie checks receivedPKBytes against his trusted registry BEFORE
	// doing any cryptographic work. This stops identity spoofing:
	//   Eve can generate a valid SPHINCS+ keypair and produce a genuine sig.
	//   All crypto checks (Spx_verify, commitment, Merkle) would pass for Eve's key.
	//   But Eve's pkBytes != Alice's registered pkBytes → rejected here immediately.
	//
	// ORDER MATTERS: identity check must come before Spx_verify.
	// If Spx_verify ran first, Eve's tx would waste Charlie's compute before
	// the identity check fires. Running identity first is free (one bytes.Equal call)
	// and eliminates the attacker's material before any crypto runs.
	//
	// PRODUCTION NOTE: The registry is Charlie's source of truth for identity.
	// It must be populated at node startup from a trusted source (on-chain,
	// PKI, or bootstrap handshake) — never from incoming transaction data.
	tStep1 := time.Now()
	identityPass := registry.VerifyIdentity(receivedSenderID, receivedPKBytes)
	dStep1 := time.Since(tStep1)
	if !identityPass {
		log.Fatalf("Step 1 — Identity: FAIL (%q not in registry)", receivedSenderID)
	}
	printTiming("Step 1 VerifyIdentity() — one bytes.Equal call", dStep1)
	fmt.Printf("         result: PASS (%q matches registry)\n\n", receivedSenderID)

	// STEP 2 — FRESHNESS CHECK
	//
	// The timestamp must be within a 5-minute window of Charlie's current time.
	// This prevents an attacker from replaying an old valid signature that was
	// captured before its nonce was stored (e.g. captured before Charlie came online).
	//
	// PRODUCTION NOTE: The 5-minute window is a tradeoff between security
	// (smaller = harder to replay) and network tolerance (larger = handles
	// clock skew and slow nodes). For a blockchain, the block timestamp
	// provides a stronger bound — reject any tx whose timestamp is older
	// than the previous block's timestamp by more than the allowed drift.
	tStep2 := time.Now()
	receivedTimestampInt := binary.BigEndian.Uint64(receivedTimestamp)
	currentTimestamp := uint64(time.Now().Unix())
	age := currentTimestamp - receivedTimestampInt
	dStep2 := time.Since(tStep2)
	if age > 300 {
		log.Fatal("Step 2 — Freshness: FAIL (timestamp too old)")
	}
	printTiming("Step 2 Freshness() — BigEndian.Uint64 + subtract", dStep2)
	fmt.Printf("         result: PASS (age=%ds, window=300s)\n\n", age)

	// STEP 3 — REPLAY CHECK
	//
	// The timestamp+nonce pair must not have been seen before.
	// This prevents replaying a valid tx that passed Steps 1-2.
	// Even if Eve intercepts Alice's complete wire payload and retransmits it
	// immediately, Charlie finds the pair in LevelDB and rejects it.
	//
	// PRODUCTION NOTE: In a distributed network, the nonce store must be
	// shared across all nodes — otherwise Eve can replay Alice's tx to a node
	// that has not seen it yet. The correct solution is an on-chain nullifier
	// set: after Charlie accepts a tx, the commitment is posted on-chain.
	// Any node can check the on-chain set before accepting a tx.
	// Per-node LevelDB is sufficient for single-node or demo deployments.
	tStep3 := time.Now()
	exists, err := manager.CheckTimestampNonce(receivedTimestamp, receivedNonce)
	dStep3 := time.Since(tStep3)
	if err != nil {
		log.Fatalf("Failed to check timestamp-nonce: %v", err)
	}
	if exists {
		log.Fatal("Step 3 — Replay: FAIL (pair already seen)")
	}
	printTiming("Step 3 CheckTimestampNonce() — LevelDB GET", dStep3)
	fmt.Printf("         result: PASS (pair not seen before)\n\n")

	// STEP 4 — SPX_VERIFY
	//
	// Charlie deserializes sigBytes and pkBytes from the wire himself.
	// He reconstructs a HashTreeNode shell from the received merkleRootHash bytes.
	// Then he calls manager.VerifySignature on HIS OWN deserialized objects —
	// not Alice's in-memory objects.
	//
	// Inside manager.VerifySignature:
	//   (a) sphincs.Spx_verify(params, timestamp||nonce||message, sig, pk)
	//       Walks the complete SPHINCS+ hypertree:
	//         - Recomputes FORS tree signatures
	//         - Verifies every authentication path from leaf to root
	//         - Checks the hypertree chain up to the public key root
	//       Returns false for ANY bytes not produced by Spx_sign with Alice's SK.
	//       This is the ONLY step that cryptographically forces a valid SPHINCS+ sig.
	//       Eve using random bytes, or Eve's own SK → both fail here.
	//   (b) Re-derives commitment from verified sigBytes
	//       Confirms receivedCommitment = SpxHash(sigBytes||pk||ts||nonce||msg)
	//       Meaning: the commitment field was honestly computed from the real sig.
	//   (c) Rebuilds 5-leaf Merkle tree from sigBytes
	//       Confirms receivedMerkleRootHash matches the rebuilt root.
	//       Meaning: merkleRootHash was honestly derived from the real sigBytes.
	//
	// WHY THIS IS THE WIRE BOUNDARY:
	//   charlieDeserializedSig came from receivedSigBytes (network bytes)
	//   charlieDeserializedPK  came from receivedPKBytes  (network bytes)
	//   charlieReceivedMerkleRoot was built from receivedMerkleRootHash (network bytes)
	//   Charlie never accesses Alice's local sig, pk, or merkleRoot objects.
	//   This guarantees Spx_verify runs on data that actually traveled the wire.
	//
	// PRODUCTION NOTE: After this call returns true, sigBytes is no longer needed.
	// Charlie MUST discard sigBytes immediately — do not write it to LevelDB.
	// The permanent record is merkleRootHash (32 bytes) and commitment (32 bytes).
	// Storing 35 KB per tx in a database would make the node unscalable.

	// Deserialize sig from wire bytes — Charlie does this himself.
	tDeserSig := time.Now()
	charlieDeserializedSig, err := manager.DeserializeSignature(receivedSigBytes)
	dDeserSig := time.Since(tDeserSig)
	if err != nil {
		log.Fatalf("Step 4 — FAIL (cannot deserialize sig: %v)", err)
	}

	// Deserialize pk from wire bytes — Charlie does this himself.
	tDeserPK := time.Now()
	charlieDeserializedPK, err := km.DeserializePublicKey(receivedPKBytes)
	dDeserPK := time.Since(tDeserPK)
	if err != nil {
		log.Fatalf("Step 4 — FAIL (cannot deserialize pk: %v)", err)
	}

	// Reconstruct HashTreeNode shell from received hash bytes.
	// Charlie receives merkleRootHash as bytes — he cannot receive a Go object.
	// VerifySignature will internally rebuild the full Merkle tree from sigBytes
	// and compare the rebuilt root against this shell's hash field.
	charlieReceivedMerkleRoot := &hashtree.HashTreeNode{
		Hash: uint256.NewInt(0).SetBytes(receivedMerkleRootHash),
	}

	// Run full verification on Charlie's own deserialized objects.
	tStep4 := time.Now()
	isValidFromWire := manager.VerifySignature(
		receivedMessage,
		receivedTimestamp,
		receivedNonce,
		charlieDeserializedSig,    // deserialized by Charlie from wire bytes
		charlieDeserializedPK,     // deserialized by Charlie from wire bytes
		charlieReceivedMerkleRoot, // reconstructed by Charlie from wire bytes
		receivedCommitment,
	)
	dStep4 := time.Since(tStep4)
	if !isValidFromWire {
		log.Fatal("Step 4 — Spx_verify: FAIL")
	}
	printTiming("Step 4 DeserializeSignature() — from wire bytes", dDeserSig)
	printTiming("       DeserializePublicKey()  — from wire bytes", dDeserPK)
	printTiming("       VerifySignature() — Spx_verify + commitment + merkle", dStep4)
	fmt.Printf("         result: PASS (full SPHINCS+ hypertree verified)\n\n")

	// Zero Charlie's copy of receivedSigBytes immediately after verification.
	// The 7–35 KB signature is no longer needed — the permanent record is the
	// 32-byte merkleRootHash and 32-byte commitment stored below.
	for i := range receivedSigBytes {
		receivedSigBytes[i] = 0
	}

	// POST-VERIFICATION: store receipt, discard sigBytes
	//
	// PRODUCTION NOTE — what Charlie stores permanently (88 bytes total):
	//   (1) timestamp+nonce → "seen"          for replay prevention
	//   (2) commitment → merkleRootHash        for dispute resolution

	// Store timestamp+nonce pair — blocks replay of this exact tx.
	// PRODUCTION NOTE: Store AFTER verification succeeds, not before.
	// Storing before verification would let an attacker permanently block
	// a valid tx by submitting a fake tx with the same timestamp+nonce first.
	tStoreNonce := time.Now()
	err = manager.StoreTimestampNonce(receivedTimestamp, receivedNonce)
	dStoreNonce := time.Since(tStoreNonce)
	if err != nil {
		log.Fatal("Failed to store timestamp-nonce:", err)
	}

	// Store commitment → merkleRootHash receipt.
	tStoreReceipt := time.Now()
	err = db.Put(receivedCommitment, receivedMerkleRootHash, nil)
	dStoreReceipt := time.Since(tStoreReceipt)
	if err != nil {
		log.Fatal("Failed to store receipt:", err)
	}

	printTiming("StoreTimestampNonce() — LevelDB PUT nonce guard", dStoreNonce)
	printTiming("StoreReceipt() — LevelDB PUT commitment→root", dStoreReceipt)
	fmt.Println()
	charlieStored := len(receivedCommitment) + len(receivedMerkleRootHash) +
		len(receivedTimestamp) + len(receivedNonce)
	fmt.Println("  Storage:")
	printSize("sigBytes — DISCARDED (never written to DB)", len(receivedSigBytes))
	printSize("Charlie stores permanently", charlieStored)
	printSize("  commitment (receipt lookup key)", len(receivedCommitment))
	printSize("  merkleRootHash (receipt value)", len(receivedMerkleRootHash))
	printSize("  timestamp+nonce (replay guard)", len(receivedTimestamp)+len(receivedNonce))
	fmt.Printf("\n  Charlie accepts tx1! sender=%s message=%q\n",
		receivedSenderID, receivedMessage)

	// =========================================================================
	// EVE — tx2: own SK, substitutes Alice's pkBytes
	// =========================================================================
	//
	// Eve's strategy:
	//   1. Generate her own real SPHINCS+ keypair
	//   2. Sign the message with her own SK → eveSigBytes (genuinely valid sig)
	//   3. Put Alice's pkBytes in the wire payload instead of her own
	//   4. Hope Charlie's Spx_verify passes
	//
	// Why it fails at Step 4:
	//   eveSigBytes was produced by Spx_sign(message, eveSK)
	//   Charlie calls Spx_verify(eveSigBytes, alicePK)
	//   The SPHINCS+ hypertree root embedded in eveSig corresponds to evePK,
	//   not alicePK. The authentication path check fails → Spx_verify = false.
	//
	// Note: Steps 1-3 all PASS for Eve's tx — she used fresh timestamp+nonce
	// and Alice's real pkBytes. Only Step 4 stops her.
	// This demonstrates why Spx_verify is mandatory — it is the only check
	// that requires Alice's SK to produce the sigBytes.

	fmt.Println()
	fmt.Println("=================================================================")
	fmt.Println(" EVE — tx2: own SK, substitutes Alice's pkBytes")
	fmt.Println("=================================================================")
	fmt.Println()

	tEveKG := time.Now()
	eveSK, evePKObj, err := km.GenerateKey()
	dEveKG := time.Since(tEveKG)
	if err != nil {
		log.Fatalf("Eve failed to generate keypair: %v", err)
	}
	eveSKBytes, _, err := km.SerializeKeyPair(eveSK, evePKObj)
	if err != nil {
		log.Fatalf("Eve failed to serialize keypair: %v", err)
	}
	_, evePKBytesTemp, _ := km.SerializeKeyPair(eveSK, evePKObj)
	eveDeserializedSK, eveDeserializedPK, err := km.DeserializeKeyPair(eveSKBytes, evePKBytesTemp)
	if err != nil {
		log.Fatalf("Eve failed to deserialize keypair: %v", err)
	}

	// Eve signs with her own SK — produces a genuinely valid SPHINCS+ sig,
	// but under eveSK, not aliceSK.
	tEveSign := time.Now()
	eveSig, eveMerkleRoot, eveTimestamp, eveNonce, eveCommitment, err :=
		manager.SignMessage(message, eveDeserializedSK, eveDeserializedPK)
	dEveSign := time.Since(tEveSign)
	if err != nil {
		log.Fatalf("Eve failed to sign: %v", err)
	}
	eveSigBytes, err := manager.SerializeSignature(eveSig)
	if err != nil {
		log.Fatalf("Eve failed to serialize sig: %v", err)
	}
	eveMerkleRootHash := eveMerkleRoot.Hash.Bytes()
	printTiming("Eve GenerateKey()", dEveKG)
	printTiming("Eve SignMessage() with her own SK", dEveSign)
	fmt.Println()

	eveWire := struct {
		SenderID       string
		PKBytes        []byte
		SigBytes       []byte
		Message        []byte
		Timestamp      []byte
		Nonce          []byte
		MerkleRootHash []byte
		Commitment     []byte
	}{
		SenderID:       "alice",     // claims Alice's identity
		PKBytes:        pkBytes,     // Alice's real pkBytes — Eve knows it (it's public)
		SigBytes:       eveSigBytes, // produced by eveSK — mismatch with alicePK
		Message:        message,
		Timestamp:      eveTimestamp,
		Nonce:          eveNonce,
		MerkleRootHash: eveMerkleRootHash,
		Commitment:     eveCommitment,
	}

	// Step 1: PASSES — Eve used alicePKBytes (public knowledge)
	tES1 := time.Now()
	s1 := registry.VerifyIdentity(eveWire.SenderID, eveWire.PKBytes)
	dES1 := time.Since(tES1)
	printTiming("Step 1 VerifyIdentity()", dES1)
	if s1 {
		fmt.Printf("         result: PASS ← Eve used alicePKBytes, passes registry\n\n")
	} else {
		fmt.Printf("         result: FAIL\n\n")
	}

	// Step 2: PASSES — Eve used a fresh timestamp
	tES2 := time.Now()
	eveAge := currentTimestamp - binary.BigEndian.Uint64(eveWire.Timestamp)
	dES2 := time.Since(tES2)
	printTiming("Step 2 Freshness()", dES2)
	if eveAge <= 300 {
		fmt.Printf("         result: PASS ← fresh timestamp\n\n")
	} else {
		fmt.Printf("         result: FAIL\n\n")
	}

	// Step 3: PASSES — Eve used a new nonce
	tES3 := time.Now()
	eveExists, _ := manager.CheckTimestampNonce(eveWire.Timestamp, eveWire.Nonce)
	dES3 := time.Since(tES3)
	printTiming("Step 3 CheckTimestampNonce()", dES3)
	if !eveExists {
		fmt.Printf("         result: PASS ← new nonce, not in store\n\n")
	} else {
		fmt.Printf("         result: FAIL\n\n")
	}

	// Step 4: FAILS — Spx_verify(eveSig, alicePK) → false
	// eveSigBytes was produced by Spx_sign with eveSK.
	// The hypertree root embedded in eveSig corresponds to evePK, not alicePK.
	// The authentication paths do not match alicePK's root → verification fails.
	eveDeserSig, err := manager.DeserializeSignature(eveWire.SigBytes)
	if err != nil {
		fmt.Printf("Step 4 Spx_verify: FAIL (deserialization: %v)\n", err)
	} else {
		alicePKForVerify, _ := km.DeserializePublicKey(eveWire.PKBytes)
		eveMerkleNode := &hashtree.HashTreeNode{
			Hash: uint256.NewInt(0).SetBytes(eveWire.MerkleRootHash),
		}
		tES4 := time.Now()
		eveValid := manager.VerifySignature(
			eveWire.Message, eveWire.Timestamp, eveWire.Nonce,
			eveDeserSig,      // Eve's sig — produced by eveSK
			alicePKForVerify, // Alice's pk — does not match eveSK
			eveMerkleNode,
			eveWire.Commitment,
		)
		dES4 := time.Since(tES4)
		printTiming("Step 4 VerifySignature() — Spx_verify(eveSig, alicePK)", dES4)
		if !eveValid {
			fmt.Printf("         result: FAIL ← eveSig + alicePK → hypertree mismatch\n")
			fmt.Printf("  Eve's attack rejected. Alice's funds are safe.\n")
		} else {
			fmt.Printf("  CRITICAL: Eve's attack passed — implementation error\n")
		}
	}

	// =========================================================================
	// EVE — tx3: replay of Alice's valid tx1
	// =========================================================================
	//
	// Eve captured Alice's complete wire payload from tx1 and retransmits it.
	// The sig is genuinely valid — it was produced by Alice's SK.
	// Steps 1 and 2 would pass. Step 3 catches it.
	//
	// Why it fails at Step 3:
	//   Charlie stored receivedTimestamp+receivedNonce after tx1 was accepted.
	//   The same pair appears in the replay → CheckTimestampNonce returns true → rejected.

	fmt.Println()
	fmt.Println("=================================================================")
	fmt.Println(" EVE — tx3: replay of Alice's valid tx1")
	fmt.Println("=================================================================")
	fmt.Println()

	tTx3 := time.Now()
	exists, err = manager.CheckTimestampNonce(receivedTimestamp, receivedNonce)
	dTx3 := time.Since(tTx3)
	if err != nil {
		log.Fatalf("Failed to check timestamp-nonce for tx3: %v", err)
	}
	printTiming("Step 3 CheckTimestampNonce()", dTx3)
	if exists {
		fmt.Printf("         result: FAIL ← pair already in store. tx3 rejected.\n")
	} else {
		fmt.Printf("WARNING: replay not caught.\n")
	}

	// =========================================================================
	// EVE — tx4: identity spoofing, own keypair claims Alice's identity
	// =========================================================================
	//
	// Eve's strategy:
	//   1. Generate her own real SPHINCS+ keypair
	//   2. Sign with her own SK — everything is cryptographically valid for evePK
	//   3. Send her own pkBytes but claim senderID = "alice"
	//
	// Why it fails at Step 1:
	//   registry.VerifyIdentity("alice", attackerPKBytes)
	//   attackerPKBytes != alice's registered pkBytes → rejected immediately.
	//   Spx_verify never runs — no compute wasted on attacker's material.

	fmt.Println()
	fmt.Println("=================================================================")
	fmt.Println(" EVE — tx4: identity spoofing, own keypair, claims Alice's identity")
	fmt.Println("=================================================================")
	fmt.Println()

	attackerSK, attackerPK, err := km.GenerateKey()
	if err != nil {
		log.Fatalf("Attacker failed to generate keypair: %v", err)
	}
	attackerSKBytes, attackerPKBytes, err := km.SerializeKeyPair(attackerSK, attackerPK)
	if err != nil {
		log.Fatalf("Attacker failed to serialize keypair: %v", err)
	}
	attackerDSK, attackerDPK, err := km.DeserializeKeyPair(attackerSKBytes, attackerPKBytes)
	if err != nil {
		log.Fatalf("Attacker failed to deserialize keypair: %v", err)
	}

	// Eve produces a genuinely valid SPHINCS+ sig under her own key.
	// The sig is valid — just not under Alice's identity.
	_, attackerMerkleRoot, attackerTimestamp, attackerNonce, attackerCommitment, err :=
		manager.SignMessage(message, attackerDSK, attackerDPK)
	if err != nil {
		log.Fatalf("Attacker failed to sign: %v", err)
	}
	attackerMerkleRootHash := attackerMerkleRoot.Hash.Bytes()
	attackerCommitmentLeaf := sign.CommitmentLeaf(attackerCommitment)
	// FIX: safe concatenation for attacker proof message too.
	attackerProofMsg := make([]byte, 0, len(attackerTimestamp)+len(attackerNonce)+len(message))
	attackerProofMsg = append(attackerProofMsg, attackerTimestamp...)
	attackerProofMsg = append(attackerProofMsg, attackerNonce...)
	attackerProofMsg = append(attackerProofMsg, message...)
	attackerProof, err := sigproof.GenerateSigProof(
		[][]byte{attackerProofMsg},
		[][]byte{attackerMerkleRootHash, attackerCommitmentLeaf},
		attackerPKBytes,
	)
	if err != nil {
		log.Fatalf("Attacker failed to generate proof: %v", err)
	}

	// Step 1 rejects immediately — attackerPKBytes != alice's registered pkBytes.
	// No crypto runs. No compute wasted.
	tTx4S1 := time.Now()
	identityOK := registry.VerifyIdentity("alice", attackerPKBytes)
	dTx4S1 := time.Since(tTx4S1)
	printTiming("Step 1 VerifyIdentity()", dTx4S1)
	fmt.Printf("         result: %v (expected: false)\n", identityOK)
	if !identityOK {
		fmt.Printf("  Identity spoofing rejected at Step 1.\n")
		fmt.Printf("  Spx_verify never ran — zero compute wasted on attacker's material.\n")
	}
	_ = attackerProof

	// =========================================================================
	// FINAL SUMMARY
	// =========================================================================

	fmt.Println()
	fmt.Println("=================================================================")
	fmt.Println(" SUMMARY")
	fmt.Println("=================================================================")

	fmt.Println()
	fmt.Println("  ALICE — timing:")
	printTiming("GenerateKey() — once at account creation", dKeyGen)
	printTiming("SignMessage() — per transaction", dSign)
	printTiming("SerializeSignature() — per transaction", dSigSer)
	printTiming("VerifySignature() — local sanity check only", dLocalVerify)
	printTiming("GenerateSigProof() — for light clients only", dProofGen)

	fmt.Println()
	fmt.Println("  ALICE — storage:")
	printSize("Stores permanently", 0)
	printSize("Discards after tx (sigBytes + objects)", len(sigBytes))

	fmt.Println()
	fmt.Println("  CHARLIE — timing (per transaction):")
	printTiming("Step 1 VerifyIdentity()", dStep1)
	printTiming("Step 2 Freshness()", dStep2)
	printTiming("Step 3 CheckTimestampNonce()", dStep3)
	printTiming("Step 4 DeserializeSignature()", dDeserSig)
	printTiming("       DeserializePublicKey()", dDeserPK)
	printTiming("       VerifySignature() — Spx_verify", dStep4)
	printTiming("StoreTimestampNonce()", dStoreNonce)
	printTiming("StoreReceipt()", dStoreReceipt)
	totalCharlie := dStep1 + dStep2 + dStep3 + dDeserSig + dDeserPK + dStep4 + dStoreNonce + dStoreReceipt
	printTiming("TOTAL verification time", totalCharlie)

	fmt.Println()
	fmt.Println("  CHARLIE — storage (per transaction):")
	printSize("sigBytes — DISCARDED after Spx_verify", len(sigBytes))
	printSize("Stores permanently", charlieStored)
	printSize("  commitment (lookup key)", len(receivedCommitment))
	printSize("  merkleRootHash (receipt value)", len(receivedMerkleRootHash))
	printSize("  timestamp+nonce (replay guard)", len(receivedTimestamp)+len(receivedNonce))

	fmt.Println()
	fmt.Println("  WIRE payload:")
	printSize("Total", wireTotal)
	printSize("  sigBytes (transient — discarded by Charlie)", len(sigBytes))
	printSize("  everything else (persistent)", wireTotal-len(sigBytes))

	fmt.Println()
	fmt.Println("  PARAMETER recommendation:")
	fmt.Printf("  %-44s %8d bytes\n", "Current SHAKE-256-256f sigBytes", len(sigBytes))
	fmt.Printf("  %-44s %8d bytes  (same 256-bit security)\n", "Consider SHAKE-256-256s sigBytes", 7856)
	fmt.Printf("  Size reduction: %.1fx\n", float64(len(sigBytes))/7856.0)

	_ = dES1
	_ = dES2
	_ = dES3
	_ = dTx3
	_ = dTx4S1
}
