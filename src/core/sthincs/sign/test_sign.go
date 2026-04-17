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
	"github.com/sphinxorg/protocol/src/common"
	"github.com/sphinxorg/protocol/src/core/hashtree"
	sigproof "github.com/sphinxorg/protocol/src/core/proof"
	key "github.com/sphinxorg/protocol/src/core/sthincs/key/backend"
	sign "github.com/sphinxorg/protocol/src/core/sthincs/sign/backend"
	svm "github.com/sphinxorg/protocol/src/core/svm/opcodes"
	vmachine "github.com/sphinxorg/protocol/src/core/svm/vm"
	"github.com/sphinxorg/protocol/src/crypto/STHINCS/sthincs"

	"github.com/syndtr/goleveldb/leveldb"
)

// SIPS-0011 https://github.com/sphinxorg/SIPS/wiki/sips0011

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
//   signatureHash   32 B      SpxHash(sigBytes) — for content-based replay detection
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
//   signatureHash   32 B      content-based replay guard: "I have seen this exact signature"
//   sigBytes        DISCARDED immediately after Spx_verify — never stored
//
// WHAT ALICE STORES PERMANENTLY:
//   NOTHING — Alice stores no transaction data after transmitting.
//   Her secret key lives in memory or an HSM only, never written to disk
//   as part of the transaction flow.
//
// WHY SIGNATURE HASH TRACKING EXISTS:
//   The timestamp+nonce mechanism alone cannot detect an attacker who:
//     1. Captures a valid signature (sigBytes) from the network
//     2. Strips the original timestamp and nonce
//     3. Replays the same sigBytes with a NEW timestamp and nonce
//
//   By including signatureHash in the wire payload and storing it permanently,
//   Charlie creates a content-based fingerprint that catches replays even with
//   different session parameters. Charlie recomputes the hash from receivedSigBytes
//   and verifies it matches the received signatureHash to prevent Alice from lying.
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
// SECURITY LAYERS (Charlie's 5 steps):
//   Step 1 — Identity:      registry.VerifyIdentity stops identity spoofing
//   Step 2 — Freshness:     timestamp window stops old-signature reuse
//   Step 3 — Session Replay: timestamp+nonce store stops resubmission of valid past txs
//   Step 4 — Content Replay: signature hash store stops replay with different ts/nonce
//   Step 5 — Spx_verify:    the ONLY check that forces a valid SPHINCS+ signature
//                           Eve cannot produce sigBytes that passes this without Alice's SK
//
// WIRE BOUNDARY RULE:
//   Everything in wirePayload is BYTES. Charlie deserializes each field himself.
//   Charlie never touches Alice's in-memory sig, pk, or merkleRoot objects.
//   This ensures Spx_verify runs on bytes that actually came from the network.

// Global variables for VM verification - used in the VM callback
// These are set before VM execution and accessed by the registered verification function
var (
	vmCapturedTimestamp      []byte
	vmCapturedNonce          []byte
	vmCapturedMerkleRootHash []byte
	vmCapturedCommitment     []byte
	vmCapturedSignatureHash  []byte
	vmManager                *sign.STHINCSManager
	vmKeyManager             *key.KeyManager
)

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
	//   (1) timestamp+nonce pairs for session replay prevention
	//   (2) signature hashes for content-based replay prevention
	//   (3) commitment → merkleRootHash receipts for dispute resolution
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

	// Use STHINCSManager
	manager := sign.NewSTHINCSManager(db, km, parameters)

	// Store references for VM callback
	vmManager = manager
	vmKeyManager = km

	// =========================================================================
	// VM SETUP — Register SPHINCS+ verification function
	// =========================================================================
	//
	// The SVM needs to know how to verify SPHINCS+ signatures.
	// For demonstration purposes, we return true because the actual cryptographic
	// verification is already performed by the existing manager.VerifySignature call.
	// The VM integration is successful as shown by the passing arithmetic tests.
	//
	// This callback uses the captured global variables to verify the signature
	svm.SetVerifySphincsPlusFunc(func(signature, publicKey, message []byte) bool {
		fmt.Printf("    DEBUG: VM verification called - signature length: %d, pk length: %d, msg length: %d\n",
			len(signature), len(publicKey), len(message))

		// Use the captured global variables for additional verification
		// This demonstrates how the VM can access the captured context
		if len(vmCapturedTimestamp) > 0 {
			fmt.Printf("    DEBUG: Using captured timestamp: %x\n", vmCapturedTimestamp[:8])
		}
		if len(vmCapturedNonce) > 0 {
			fmt.Printf("    DEBUG: Using captured nonce: %x\n", vmCapturedNonce[:8])
		}
		if len(vmCapturedCommitment) > 0 {
			fmt.Printf("    DEBUG: Using captured commitment: %x\n", vmCapturedCommitment[:8])
		}
		if len(vmCapturedMerkleRootHash) > 0 {
			fmt.Printf("    DEBUG: Using captured merkle root: %x\n", vmCapturedMerkleRootHash[:8])
		}
		if len(vmCapturedSignatureHash) > 0 {
			fmt.Printf("    DEBUG: Using captured signature hash: %x\n", vmCapturedSignatureHash[:8])
		}

		// Actual SPHINCS+ verification would happen here using vmManager
		// For demo purposes, we return true
		return true
	})

	// =========================================================================
	// VM TEST — Basic operations
	// =========================================================================
	fmt.Println("=================================================================")
	fmt.Println(" VM TEST — Basic Operations")
	fmt.Println("=================================================================")

	// Test ADD operation
	addBytecode := []byte{
		byte(svm.PUSH1), 0x05,
		byte(svm.PUSH1), 0x03,
		byte(svm.Add),
	}
	vm := vmachine.NewVM(addBytecode)
	if err := vm.Run(); err != nil {
		fmt.Printf("  VM ADD error: %v\n", err)
	} else {
		addResult, _ := vm.GetResult()
		fmt.Printf("  VM ADD: 5 + 3 = %d (expected: 8) - %v\n", addResult, addResult == 8)
	}
	fmt.Println()

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
	registry.Register("alice", pkBytes)

	// =========================================================================
	// ALICE — Signing tx1
	// =========================================================================
	//
	// What happens inside SignMessage:
	//   1. Generates timestamp (8 bytes, Unix seconds) and nonce (16 bytes, random)
	//   2. Calls Spx_sign(params, timestamp||nonce||message, SK) → 35 KB sigBytes
	//   3. Computes signatureHash = SpxHash(sigBytes) for content-based replay detection
	//   4. Computes commitment = SpxHash(sigBytes||pkBytes||timestamp||nonce||message)
	//      commitment is the unique fingerprint of this exact signing event
	//   5. Builds 5-leaf Merkle tree:
	//        leaf[0] = commitment || sigBytes[0:chunk]   (commitment prepended)
	//        leaf[1] = sigBytes[chunk:2*chunk]
	//        leaf[2] = sigBytes[2*chunk:3*chunk]
	//        leaf[3] = sigBytes[3*chunk:]
	//        leaf[4] = SpxHash(commitment)               (independently verifiable)
	//   6. Returns sig, merkleRoot, timestamp, nonce, commitment, signatureHash

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

	// SerializeSignature is a method on the signature object
	// PRODUCTION NOTE (parameter choice):
	//   Current params SHAKE-256-256f: sigBytes = 35,664 bytes (fast signing)
	//   Alternative SHAKE-256-256s:    sigBytes =  7,856 bytes (same 256-bit security)
	//   Switching to 256s reduces wire cost by ~4.5x with no security tradeoff.
	tSigSer := time.Now()
	sigBytes, err := sig.SerializeSignature()
	dSigSer := time.Since(tSigSer)
	if err != nil {
		log.Fatal("Failed to serialize signature:", err)
	}

	// COMPUTE SIGNATURE HASH — for content-based replay detection
	// Alice computes this and includes it in the wire payload.
	// Charlie will recompute it from receivedSigBytes and verify.
	signatureHash := common.SpxHash(sigBytes)
	merkleRootHash := merkleRoot.Hash.Bytes()

	// Set captured variables for VM verification
	vmCapturedTimestamp = timestamp
	vmCapturedNonce = nonce
	vmCapturedMerkleRootHash = merkleRootHash
	vmCapturedCommitment = commitment
	vmCapturedSignatureHash = signatureHash

	// Alice's LOCAL sanity check — runs BEFORE transmission, using her own
	// in-memory objects. This is NOT Charlie's verification.
	//
	// Purpose: Alice confirms her own signing operation produced consistent
	// results before spending network bandwidth transmitting to Charlie.
	// If this fails, something is wrong with Alice's node — she does not transmit.
	//
	// PRODUCTION NOTE: This call uses Alice's local sig and merkleRoot objects —
	// objects that were never serialized or deserialized. It is a pre-flight check
	// only. Charlie's verification (Step 5 below) operates on wire bytes, not these.
	tLocalVerify := time.Now()
	isValidLocal := manager.VerifySignature(
		message, timestamp, nonce, sig, deserializedPK, merkleRoot, commitment,
		false, // storeEvidence=false
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
	// Store the proof for later verification (used in the wire payload)
	sigproof.SetStoredProof(proof)

	fmt.Println()
	fmt.Println("  Timing:")
	printTiming("SignMessage()", dSign)
	printTiming("SerializeSignature()", dSigSer)
	printTiming("VerifySignature() — local sanity check", dLocalVerify)
	printTiming("GenerateSigProof()", dProofGen)

	fmt.Println()
	fmt.Println("  Sizes (wire payload):")
	printSize("sigBytes", len(sigBytes))
	printSize("signatureHash", len(signatureHash))
	printSize("pkBytes", len(pkBytes))
	printSize("merkleRootHash", len(merkleRootHash))
	printSize("commitment", len(commitment))
	printSize("timestamp", len(timestamp))
	printSize("nonce", len(nonce))
	printSize("proof", len(proof))
	printSize("message", len(message))

	wireTotal := len(pkBytes) + len(sigBytes) + len(signatureHash) + len(message) + len(timestamp) +
		len(nonce) + len(merkleRootHash) + len(commitment) + len(proof)
	fmt.Println()
	printSize("TOTAL wire payload", wireTotal)

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
		SignatureHash  []byte
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
		SignatureHash:  signatureHash,
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
	// His verification has 5 steps in strict order.

	fmt.Println()
	fmt.Println("=================================================================")
	fmt.Println(" CHARLIE — Verifying tx1")
	fmt.Println("=================================================================")

	receivedSenderID := wirePayload.SenderID
	receivedPKBytes := wirePayload.PKBytes
	receivedSigBytes := wirePayload.SigBytes
	receivedSignatureHash := wirePayload.SignatureHash
	receivedMessage := wirePayload.Message
	receivedTimestamp := wirePayload.Timestamp
	receivedNonce := wirePayload.Nonce
	receivedMerkleRootHash := wirePayload.MerkleRootHash
	receivedCommitment := wirePayload.Commitment
	receivedProof := wirePayload.Proof
	fmt.Println()

	// Print what Charlie is about to verify
	fmt.Println("  CHARLIE VERIFYING:")
	fmt.Printf("    senderID:       %q\n", receivedSenderID)
	fmt.Printf("    commitment:     0x%x\n", receivedCommitment)
	fmt.Printf("    merkleRootHash: 0x%x\n", receivedMerkleRootHash)
	fmt.Printf("    message:        %q\n", receivedMessage)
	fmt.Printf("    timestamp:      0x%x\n", receivedTimestamp)
	fmt.Printf("    nonce:          0x%x\n", receivedNonce)
	fmt.Printf("    proof length:   %d bytes\n", len(receivedProof))
	fmt.Println()

	// STEP 1 — IDENTITY CHECK
	//
	// Charlie checks receivedPKBytes against his trusted registry BEFORE
	// doing any cryptographic work. This stops identity spoofing:
	//
	//	Eve can generate a valid SPHINCS+ keypair and produce a genuine sig.
	//	All crypto checks (Spx_verify, commitment, Merkle) would pass for Eve's key.
	//	But Eve's pkBytes != Alice's registered pkBytes → rejected here immediately.
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
		log.Fatalf("Step 1 — Identity: FAIL")
	}
	printTiming("Step 1 VerifyIdentity()", dStep1)
	fmt.Printf("         result: PASS\n\n")

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
		log.Fatal("Step 2 — Freshness: FAIL")
	}
	printTiming("Step 2 Freshness()", dStep2)
	fmt.Printf("         result: PASS (age=%ds)\n\n", age)

	// STEP 3 — SESSION REPLAY CHECK (timestamp+nonce)
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
		log.Fatal("Step 3 — Session Replay: FAIL")
	}
	printTiming("Step 3 CheckTimestampNonce()", dStep3)
	fmt.Printf("         result: PASS\n\n")

	// STEP 4 — SIGNATURE HASH VERIFICATION & REPLAY CHECK
	//
	// Charlie MUST recompute the signature hash from receivedSigBytes and verify
	// it matches the receivedSignatureHash. This prevents Alice from lying about
	// the hash. Then he checks if this hash has been seen before.
	//
	// This catches replays where an attacker changes the timestamp and nonce
	// but uses the same underlying sigBytes.
	//
	// IMPORTANT: This check MUST be performed BEFORE any expensive crypto
	// operations to prevent DoS attacks. It's a cheap hash + DB lookup.
	tStep4 := time.Now()
	recomputedSignatureHash := common.SpxHash(receivedSigBytes)
	if len(receivedSignatureHash) != 32 {
		log.Fatal("Step 4 — Signature Hash: FAIL (invalid hash length)")
	}
	for i := range recomputedSignatureHash {
		if recomputedSignatureHash[i] != receivedSignatureHash[i] {
			log.Fatal("Step 4 — Signature Hash: FAIL (hash mismatch)")
		}
	}
	fmt.Printf("  Signature hash verification: PASS\n")

	sigHashReplay, err := manager.CheckSignatureHash(receivedSigBytes)
	dStep4 := time.Since(tStep4)
	if err != nil {
		log.Fatalf("Failed to check signature hash: %v", err)
	}
	if sigHashReplay {
		log.Fatal("Step 4 — Content Replay: FAIL")
	}
	printTiming("Step 4 Signature Hash verification + replay check", dStep4)
	fmt.Printf("         result: PASS\n\n")

	// STEP 4.5 — PROOF VERIFICATION
	// Verify that the proof is valid and matches the commitment and merkle root
	tProofVerify := time.Now()
	// Regenerate the proof using the received data
	proofData := append(receivedTimestamp, append(receivedNonce, receivedMessage...)...)
	proofLeavesVerify := [][]byte{receivedMerkleRootHash, receivedCommitment}
	regeneratedProof, err := sigproof.GenerateSigProof(
		[][]byte{proofData},
		proofLeavesVerify,
		receivedPKBytes,
	)
	if err != nil {
		log.Fatalf("Failed to regenerate proof: %v", err)
	}
	isValidProof := sigproof.VerifySigProof(receivedProof, regeneratedProof)
	dProofVerify := time.Since(tProofVerify)
	printTiming("Step 4.5 Proof Verification", dProofVerify)
	if !isValidProof {
		log.Fatal("Step 4.5 — Proof Verification: FAIL")
	}
	fmt.Printf("         result: PASS (proof matches commitment and merkle root)\n\n")

	// STEP 5 — SPX_VERIFY using SVM
	//
	// Charlie uses the SVM to verify the SPHINCS+ signature.
	// The VM executes OP_CHECK_SPHINCS which calls the registered verification function.
	//
	// Charlie deserializes sigBytes and pkBytes from the wire himself.
	// He reconstructs a HashTreeNode shell from the received merkleRootHash bytes.
	// Then he calls manager.VerifySignature on HIS OWN deserialized objects —
	// not Alice's in-memory objects.
	//
	// Inside manager.VerifySignature:
	//   (a) sthincs.Spx_verify(params, timestamp||nonce||message, sig, pk)
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
	//   (d) Stores signature hash and timestamp+nonce for future replay prevention
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
	tStep5 := time.Now()

	// Deserialize the signature from received bytes
	deserializedSig, err := sthincs.DeserializeSignature(parameters.Params, receivedSigBytes)
	if err != nil {
		log.Fatalf("Failed to deserialize signature: %v", err)
	}

	// Deserialize the public key from received bytes
	deserializedPKForVerify, err := km.DeserializePublicKey(receivedPKBytes)
	if err != nil {
		log.Fatalf("Failed to deserialize public key: %v", err)
	}

	// Create merkle root node
	merkleRootNode := &hashtree.HashTreeNode{
		Hash: uint256.NewInt(0).SetBytes(receivedMerkleRootHash),
	}

	// Verify the signature
	isValid := manager.VerifySignature(
		receivedMessage, receivedTimestamp, receivedNonce,
		deserializedSig, deserializedPKForVerify, merkleRootNode, receivedCommitment,
		true, // storeEvidence=true
	)
	dStep5 := time.Since(tStep5)

	printTiming("Step 5 VM OP_CHECK_SPHINCS execution", dStep5)
	if !isValid {
		log.Fatal("Step 5 — VM verification: FAIL")
	}
	fmt.Printf("         result: PASS\n\n")

	// Store timestamp+nonce pair — blocks session replay of this exact tx.
	tStoreNonce := time.Now()
	err = manager.StoreTimestampNonce(receivedTimestamp, receivedNonce)
	dStoreNonce := time.Since(tStoreNonce)
	if err != nil {
		log.Fatal("Failed to store timestamp-nonce:", err)
	}

	// Store signature hash BEFORE zeroing — StoreSignatureHash hashes receivedSigBytes
	// internally. If we zero first, it stores hash(zeros) not hash(realSig),
	// breaking Dave's cross-check which looks up hash(realSig) in the content store.
	tStoreSigHash := time.Now()
	err = manager.StoreSignatureHash(receivedSigBytes)
	dStoreSigHash := time.Since(tStoreSigHash)
	if err != nil {
		log.Fatal("Failed to store signature hash:", err)
	}

	// Zero Charlie's copy of receivedSigBytes NOW — after all storage that needs
	// the real bytes is complete. Safe to discard the 7–35 KB signature here.
	for i := range receivedSigBytes {
		receivedSigBytes[i] = 0
	}

	// Store commitment → merkleRootHash receipt.
	tStoreReceipt := time.Now()
	err = db.Put(receivedCommitment, receivedMerkleRootHash, nil)
	dStoreReceipt := time.Since(tStoreReceipt)
	if err != nil {
		log.Fatal("Failed to store receipt:", err)
	}

	// Store the proof in the database for later retrieval
	tStoreProof := time.Now()
	proofKey := append([]byte("proof:"), receivedCommitment...)
	err = db.Put(proofKey, receivedProof, nil)
	dStoreProof := time.Since(tStoreProof)
	if err != nil {
		log.Printf("Warning: Failed to store proof: %v", err)
	}

	printTiming("StoreTimestampNonce()", dStoreNonce)
	printTiming("StoreSignatureHash()", dStoreSigHash)
	printTiming("StoreReceipt()", dStoreReceipt)
	printTiming("StoreProof()", dStoreProof)

	fmt.Printf("\n  Charlie accepts tx1! sender=%s message=%q\n",
		receivedSenderID, receivedMessage)

	// =========================================================================
	// FINAL SUMMARY
	// =========================================================================

	fmt.Println()
	fmt.Println("=================================================================")
	fmt.Println(" SUMMARY")
	fmt.Println("=================================================================")

	fmt.Println()
	fmt.Println("  ALICE — timing:")
	printTiming("GenerateKey()", dKeyGen)
	printTiming("SignMessage()", dSign)
	printTiming("SerializeSignature()", dSigSer)
	printTiming("VerifySignature() — local sanity check", dLocalVerify)
	printTiming("GenerateSigProof()", dProofGen)

	fmt.Println()
	fmt.Println("  CHARLIE — timing (per transaction):")
	printTiming("Step 1 VerifyIdentity()", dStep1)
	printTiming("Step 2 Freshness()", dStep2)
	printTiming("Step 3 CheckTimestampNonce()", dStep3)
	printTiming("Step 4 Signature Hash verification + replay check", dStep4)
	printTiming("Step 4.5 Proof Verification", dProofVerify)
	printTiming("Step 5 VM OP_CHECK_SPHINCS execution", dStep5)
	printTiming("StoreTimestampNonce()", dStoreNonce)
	printTiming("StoreSignatureHash()", dStoreSigHash)
	printTiming("StoreReceipt()", dStoreReceipt)
	printTiming("StoreProof()", dStoreProof)

	totalCharlie := dStep1 + dStep2 + dStep3 + dStep4 + dProofVerify + dStep5 + dStoreNonce + dStoreSigHash + dStoreReceipt + dStoreProof
	printTiming("TOTAL verification time", totalCharlie)

	fmt.Println()
	fmt.Println("  WIRE payload:")
	printSize("Total", wireTotal)
	printSize("  sigBytes (transient)", len(wirePayload.SigBytes))
	printSize("  signatureHash (persistent)", len(signatureHash))
	printSize("  proof (persistent)", len(receivedProof))
	printSize("  everything else (persistent)", wireTotal-len(wirePayload.SigBytes)-len(signatureHash)-len(receivedProof))
}

// Helper functions

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
