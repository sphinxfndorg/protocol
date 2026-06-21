// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package main

import (
	"fmt"
	"log"

	multisig "github.com/sphinxorg/protocol/src/core/multisig/mps"
)

// REMOVED DEPENDENCY: this file imported
//
//	"github.com/sphinxorg/protocol/src/core/wallet/utils"
//
// solely to call utils.NewWalletConfig() / walletConfig.Close(). Tracing
// the rest of the file: walletConfig was never read from or written to
// again after creation — every operation below (NewMultiSig, SignMessage,
// AddSig, VerifySignatures, AddSigFromPubKey) goes through `manager`, not
// `walletConfig`. So this wasn't a partial dependency to replace, it was
// dead initialization to delete. If your multisig manager is SUPPOSED to
// be backed by wallet config storage (e.g. for persistence), that wiring
// was never actually present here either — `manager.GetStoredSK()` /
// `GetStoredPK()` already imply multisig has its own storage internally.
//
// NOT REVIEWED: github.com/sphinxorg/protocol/src/core/multisig/mps was
// not shared with me — NewMultiSig/SignMessage/AddSig/VerifySignatures/
// AddSigFromPubKey/GetStoredSK/GetStoredPK are all assumed unchanged from
// your original file. If that package also imports the deleted
// wallet/auth or wallet/utils internally, this file will still fail to
// build until that's fixed too — that's outside what I can see from here.
func main() {
	// Set quorum for multisignature (e.g., 3 participants required)
	quorum := 3
	manager, err := multisig.NewMultiSig(quorum)
	if err != nil {
		log.Fatalf("Error initializing MultisigManager: %v", err)
	}

	// Retrieve participant private keys from the MultisigManager
	privKeys := make([][]byte, quorum)
	for i := 0; i < quorum; i++ {
		privKeys[i] = manager.GetStoredSK()[i] // Get stored private keys
	}

	// Sign a message using each participant's private key
	message := []byte("This is a test message.")
	for i := 0; i < quorum; i++ {
		partyID := fmt.Sprintf("Participant%d", i+1)
		// SignMessage returns signature, Merkle root, timestamp, and nonce
		// Timestamp ensures signatures are temporally bound, preventing reuse of old signatures
		// Nonce ensures each signature is unique, even for identical messages
		sig, merkleRoot, timestamp, nonce, err := manager.SignMessage(message, privKeys[i], partyID)
		if err != nil {
			log.Fatalf("Error signing message for %s: %v", partyID, err)
		}
		fmt.Printf("%s signed the message. Signature: %x, Merkle Root: %x, Timestamp: %x, Nonce: %x\n", partyID, sig, merkleRoot, timestamp, nonce)

		// Add the signature, timestamp, nonce, and Merkle root to the multisig
		// Timestamp and nonce are checked for freshness and uniqueness to prevent reuse
		// Merkle root ensures signature integrity
		err = manager.AddSig(i, sig, timestamp, nonce, merkleRoot)
		if err != nil {
			log.Fatalf("Error adding signature for %s: %v", partyID, err)
		}
	}

	// Verify all signatures to ensure quorum is met
	// Verification checks timestamp freshness, nonce uniqueness, SPHINCS+ cryptographic validity,
	// and Merkle root integrity, preventing Alice from reusing signatures
	isValid, err := manager.VerifySignatures(message)
	if err != nil {
		log.Fatalf("Error verifying signatures: %v", err)
	}
	if isValid {
		fmt.Println("All signatures are valid, and quorum has been met.")
	} else {
		fmt.Println("Signatures are not valid, or quorum has not been met.")
	}

	// Example of using AddSigFromPubKey
	// Use the first participant's public key, signature, timestamp, nonce, and Merkle root
	pubKey := manager.GetStoredPK()[0]
	// For demonstration, reuse the first signature (in practice, generate a new valid signature)
	sig, merkleRoot, timestamp, nonce, err := manager.SignMessage(message, privKeys[0], "Participant1")
	if err != nil {
		log.Fatalf("Error signing message for AddSigFromPubKey: %v", err)
	}
	// AddSigFromPubKey includes timestamp and nonce checks to prevent reuse
	// Alice cannot lie about reusing a signature due to timestamp-nonce storage in LevelDB
	err = manager.AddSigFromPubKey(pubKey, sig, timestamp, nonce, merkleRoot)
	if err != nil {
		log.Fatalf("Error adding signature from pubKey: %v", err)
	}
	fmt.Println("Signature added successfully using AddSigFromPubKey.")
}
