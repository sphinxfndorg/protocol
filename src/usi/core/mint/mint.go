// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"

	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
	"github.com/sphinxfndorg/protocol/src/usi/core/sign"
)

// Mint creates a signed MintReceipt for arbitrary payload bytes.
//
// Subject is a user-defined token/asset identifier.
// payload can be any bytes.
// cid is the IPFS content hash (optional, can be "").
// metadataURI is an ERC-721 style metadata URI (optional, can be "").
//
// NOTE: This function ONLY creates a local signed receipt.
// It does NOT upload to IPFS or create a blockchain transaction.
// For the full automatic flow (IPFS upload + blockchain anchor),
// use MintAndAnchor() instead.
func Mint(payload []byte, subject string, passphrase string, orgCode string, cid string, metadataURI string) (*MintResult, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase required")
	}
	if subject == "" {
		return nil, errors.New("subject required")
	}

	// Load key to embed fingerprint and public key.
	kp, _, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}
	minterPKHex := hex.EncodeToString(kp.PublicKey)

	if orgCode == "" {
		orgCode = "SPIF"
	}
	payloadHashWithOrg := keys.SHAKE256HashWithOrg(payload, keys.OrgCode(orgCode))
	payloadHashHex := hex.EncodeToString(payloadHashWithOrg)

	// Deterministic mint id: SHA3-256(minterPKHex || subject || payloadHashHex)
	// This ensures globally unique, deterministic mint IDs.
	mintIDInput := []byte(minterPKHex + ":" + subject + ":" + payloadHashHex)
	mintIDHash := sha3.Sum256(mintIDInput)
	mintID := hex.EncodeToString(mintIDHash[:])

	rec := &MintReceipt{
		Version:                ReceiptVersion,
		MintID:                 mintID,
		Subject:                subject,
		PayloadHash:            payloadHashHex,
		CID:                    cid,
		MetadataURI:            metadataURI,
		OrgCode:                orgCode,
		Timestamp:              time.Now().Unix(),
		MinterPublicKey:        minterPKHex,
		MinterFingerprint:      "",
		SignatureHex:           "",
		Metadata:               map[string]string{},
		RequireExternalPayload: true,
	}

	// Canonical bytes to sign.
	canon, err := canonicalReceiptBytes(rec)
	if err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}

	// Sign canonical receipt bytes.
	sig, err := sign.Sign(canon, passphrase)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// Verify quickly that embedded pk matches loaded kp.
	if subtle.ConstantTimeCompare(sig.PublicKey, kp.PublicKey) != 1 {
		return nil, errors.New("mint: signing public key mismatch")
	}

	rec.SignatureHex = hex.EncodeToString(sig.Signature)

	res := &MintResult{Receipt: rec}
	return res, nil
}

// MintAndAnchorOptions configures the full automatic mint flow.
type MintAndAnchorOptions struct {
	Payload     []byte // The content to mint
	Subject     string // Asset/token identifier
	Passphrase  string // Local key passphrase
	OrgCode     string // Organization code (default "SPIF")
	MetadataURI string // ERC-721 style metadata URI (optional)

	// IPFS configuration
	IPFSAddr       string // IPFS API address (e.g. "http://127.0.0.1:5001")
	GatewayBaseURL string // IPFS gateway base URL (e.g. "http://127.0.0.1:8080")
	DisableIPFS    bool   // Skip real IPFS upload

	// Blockchain configuration
	NodeAddr string // Sphinx node TCP address (e.g. "127.0.0.1:30303")
	From     string // Sender address for the on-chain transaction
	KeyFile  string // Path to private key file for signing the transaction
}

// MintAndAnchorResult contains the complete result of a mint + anchor operation.
type MintAndAnchorResult struct {
	Receipt     *MintReceipt  `json:"receipt"`
	CID         string        `json:"cid,omitempty"`          // IPFS content identifier
	CIDHashHex  string        `json:"cid_hash_hex,omitempty"` // sha256(CID) as hex
	TxID        string        `json:"tx_id,omitempty"`        // On-chain transaction ID
	GatewayURL  string        `json:"gateway_url,omitempty"`  // IPFS gateway URL
	ReceiptPath string        `json:"receipt_path,omitempty"` // Path to saved receipt file
	AnchorPath  string        `json:"anchor_path,omitempty"`  // Path to saved anchor tag file
	Elapsed     time.Duration `json:"elapsed"`
}

// MintAndAnchor performs the COMPLETE automatic flow:
// 1. Create a signed MintReceipt (local)
// 2. Upload the payload to IPFS → get CID
// 3. Build an anchor tag with the CID
// 4. Create a REAL blockchain transaction with the anchor in ReturnData
// 5. Broadcast the transaction → included in a confirmed block
// 6. Save the receipt and anchor tag to disk
//
// This is the equivalent of Ethereum ERC-721 minting:
//   - IPFS stores the content (like tokenURI)
//   - The blockchain transaction permanently records the commitment
//   - Anyone can verify by looking up the TX and fetching from IPFS
func MintAndAnchor(opts *MintAndAnchorOptions) (*MintAndAnchorResult, error) {
	start := time.Now()

	if opts == nil {
		return nil, errors.New("nil options")
	}
	if len(opts.Payload) == 0 {
		return nil, errors.New("payload required")
	}
	if opts.Subject == "" {
		return nil, errors.New("subject required")
	}
	if opts.Passphrase == "" {
		return nil, errors.New("passphrase required")
	}

	// Step 1: Create the signed receipt (local)
	fmt.Printf("\n Step 1/5: Creating signed MintReceipt...\n")
	mintResult, err := Mint(opts.Payload, opts.Subject, opts.Passphrase, opts.OrgCode, "", opts.MetadataURI)
	if err != nil {
		return nil, fmt.Errorf("create receipt: %w", err)
	}
	receipt := mintResult.Receipt
	fmt.Printf("   SUCCESS Receipt signed! MintID: %s\n", receipt.MintID[:16]+"...")

	// Step 2: Upload payload to IPFS
	fmt.Printf("📤 Step 2/5: Uploading to IPFS...\n")
	var cid string
	var cidHashHex string
	var gatewayURL string

	if !opts.DisableIPFS {
		ipfsClient := newIPFSClient(opts.IPFSAddr, opts.GatewayBaseURL)
		cid, err = ipfsClient.AddBytesToIPFS(opts.Payload, "payload.bin")
		if err != nil {
			fmt.Printf("   WARNING  IPFS upload failed: %v (continuing without CID)\n", err)
		} else {
			cidHashHex = computeCIDHash(cid)
			gatewayURL = ipfsClient.GetGatewayURL(cid)
			receipt.CID = cid
			fmt.Printf("   SUCCESS Uploaded to IPFS! CID: %s\n", cid)
			fmt.Printf("   🌐 Gateway: %s\n", gatewayURL)
		}
	} else {
		fmt.Printf("   ⏭️  IPFS disabled (--disable-ipfs)\n")
	}

	// Step 3: Build the anchor tag with CID
	fmt.Printf("🔗 Step 3/5: Building on-chain anchor...\n")
	anchorTag := &AnchorTag{
		Type:            AnchorTagType,
		MintID:          receipt.MintID,
		Subject:         receipt.Subject,
		CID:             cid,
		MinterPublicKey: receipt.MinterPublicKey,
	}
	anchorHash, err := ReceiptCommitmentHash(receipt)
	if err != nil {
		return nil, fmt.Errorf("compute receipt hash: %w", err)
	}
	anchorTag.ReceiptHash = hex.EncodeToString(anchorHash)
	fmt.Printf("   SUCCESS Anchor built! ReceiptHash: %s\n", anchorTag.ReceiptHash[:16]+"...")

	// Step 4: Create and broadcast blockchain transaction
	fmt.Printf("⛓️  Step 4/5: Broadcasting on-chain transaction...\n")
	var txID string
	if opts.NodeAddr != "" && opts.From != "" && opts.KeyFile != "" {
		anchorData, err := SerializeAnchorTag(anchorTag)
		if err != nil {
			return nil, fmt.Errorf("serialize anchor: %w", err)
		}

		txID, err = broadcastAnchorTransaction(opts.NodeAddr, opts.From, opts.KeyFile, anchorData)
		if err != nil {
			fmt.Printf("   WARNING  Blockchain tx failed: %v (anchor saved to disk)\n", err)
		} else {
			fmt.Printf("   SUCCESS Transaction broadcast! TX ID: %s\n", txID)
			fmt.Printf("   🔗 This TX will be included in a confirmed block (permanent anchor)\n")
		}
	} else {
		fmt.Printf("   ⏭️  Blockchain anchor skipped (need --node-addr, --from, --key)\n")
	}

	// Step 5: Save receipt and anchor to disk
	fmt.Printf("💾 Step 5/5: Saving to disk...\n")
	receiptPath, err := SaveReceipt(receipt, "")
	if err != nil {
		return nil, fmt.Errorf("save receipt: %w", err)
	}
	fmt.Printf("   SUCCESS Receipt saved: %s\n", receiptPath)

	anchorPath, err := SaveAnchorTag(anchorTag, "")
	if err != nil {
		return nil, fmt.Errorf("save anchor: %w", err)
	}
	fmt.Printf("   SUCCESS Anchor saved: %s\n", anchorPath)

	elapsed := time.Since(start)

	result := &MintAndAnchorResult{
		Receipt:     receipt,
		CID:         cid,
		CIDHashHex:  cidHashHex,
		TxID:        txID,
		GatewayURL:  gatewayURL,
		ReceiptPath: receiptPath,
		AnchorPath:  anchorPath,
		Elapsed:     elapsed,
	}

	// Print complete summary
	fmt.Printf("\n══════════════════ MINT COMPLETE ══════════════════\n")
	fmt.Printf("SUCCESS Local receipt:     %s\n", receiptPath)
	fmt.Printf("SUCCESS Anchor tag:        %s\n", anchorPath)
	if cid != "" {
		fmt.Printf("SUCCESS IPFS upload:       %s\n", cid)
		fmt.Printf("   Gateway:           %s\n", gatewayURL)
	}
	if txID != "" {
		fmt.Printf("SUCCESS On-chain anchor:   %s\n", txID)
	}
	fmt.Printf(" Mint ID:          %s\n", receipt.MintID)
	fmt.Printf(" Subject:          %s\n", receipt.Subject)
	fmt.Printf("⏱️  Elapsed:          %v\n", elapsed)
	fmt.Printf("══════════════════════════════════════════════════\n")

	return result, nil
}

// computeCIDHash computes sha256(CID) as hex — the on-chain commitment.
func computeCIDHash(cid string) string {
	sum := sha3.Sum256([]byte(cid))
	return hex.EncodeToString(sum[:])
}
