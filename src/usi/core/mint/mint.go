// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

package mint

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/sphinxfndorg/protocol/src/core"
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

	// NFT metadata (ERC-721 compatible)
	NFTName        string          // NFT name/title
	NFTDescription string          // NFT description
	NFTAttributes  []NFTAttribute  // ERC-721 trait attributes

	// Ethereum-close SIP-721 collection mint. When Collection is set, the
	// media+metadata IPFS uploads MUST succeed (the mint aborts otherwise)
	// and the tokenURI is bound on-chain as contract storage tokenURI[tokenId]
	// with a per-collection tokenId counter, alongside the legacy
	// ReturnData mint_anchor commitment (which then carries the same
	// token_id/token_uri/contract so the whole mint verifies atomically).
	Collection string // SIP-721 collection contract address (sc...); "" = legacy anchor only
	To         string // token recipient for contract mint; defaults to From

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
	CID         string        `json:"cid,omitempty"`          // IPFS content identifier (media)
	MetadataCID string        `json:"metadata_cid,omitempty"` // IPFS CID of metadata JSON
	TokenURI    string        `json:"token_uri,omitempty"`    // ipfs://<metadataCID>
	TokenID     uint64        `json:"token_id,omitempty"`     // SIP-721 tokenId counter value (0 = legacy anchor)
	Collection  string        `json:"collection,omitempty"`   // SIP-721 collection that allocated TokenID
	TxID        string        `json:"tx_id,omitempty"`        // On-chain transaction ID
	GatewayURL  string        `json:"gateway_url,omitempty"`  // IPFS gateway URL
	ReceiptPath string        `json:"receipt_path,omitempty"` // Path to saved receipt file
	AnchorPath  string        `json:"anchor_path,omitempty"`  // Path to saved anchor tag file
	Elapsed     time.Duration `json:"elapsed"`
}

// MintAndAnchor performs the COMPLETE automatic flow:
// 1. Create a signed MintReceipt (local)
// 2. Upload the media/payload to IPFS → get media CID
// 3. Build ERC-721 metadata JSON (name, description, image=mediaCID)
// 4. Upload metadata JSON to IPFS → get metadata CID → tokenURI
// 5. When opts.Collection is set, mint the token in the SIP-721 collection
//    on-chain (tokenId counter + tokenURI[tokenId] contract storage) — this
//    ABORTS if IPFS is unreachable because a tokenURI-less NFT pins nothing
// 6. Create a REAL blockchain transaction with the anchor in ReturnData
// 7. Save the receipt and anchor tag to disk
//
// This is the equivalent of Ethereum ERC-721 minting:
//   - IPFS stores the media (like tokenURI)
//   - IPFS stores the metadata JSON (like ERC-721 metadata)
//   - the SIP-721 collection contract stores tokenURI[tokenId] + ownerOf
//   - the blockchain transaction permanently records the commitment
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
	fmt.Printf("\n Step 1/6: Creating signed MintReceipt...\n")
	mintResult, err := Mint(opts.Payload, opts.Subject, opts.Passphrase, opts.OrgCode, "", opts.MetadataURI)
	if err != nil {
		return nil, fmt.Errorf("create receipt: %w", err)
	}
	receipt := mintResult.Receipt
	fmt.Printf("   SUCCESS Receipt signed! MintID: %s\n", receipt.MintID[:16]+"...")

	// Step 2: Upload media/payload to IPFS
	fmt.Printf("📤 Step 2/6: Uploading media to IPFS...\n")
	var mediaCID string
	var mediaGatewayURL string
	var tokenID uint64
	var collectionMintTxID string

	if !opts.DisableIPFS {
		ipfsClient := newIPFSClient(opts.IPFSAddr, opts.GatewayBaseURL)
		mediaCID, mediaGatewayURL, err = UploadMedia(opts.Payload, "payload.bin", ipfsClient)
		if err != nil {
			// Ethereum-close rule: when this mint is bound to a SIP-721
			// collection, the media upload is REQUIRED — a collection token
			// must resolve to real content. Mint aborts instead of pinning
			// nothing.
			if strings.TrimSpace(opts.Collection) != "" {
				return nil, fmt.Errorf("collection mint aborted: media upload to IPFS failed: %w", err)
			}
			fmt.Printf("   WARNING  IPFS upload failed: %v (continuing without CID)\n", err)
		} else {
			receipt.MediaCID = mediaCID
			receipt.CID = mediaCID // backward compat
			fmt.Printf("   SUCCESS Uploaded media to IPFS! CID: %s\n", mediaCID)
			fmt.Printf("   🌐 Gateway: %s\n", mediaGatewayURL)
		}
	} else {
		if strings.TrimSpace(opts.Collection) != "" {
			// A collection mint is an NFT: it ALWAYS requires a real IPFS
			// upload, so --disable-ipfs is rejected for this path.
			return nil, fmt.Errorf("collection mint aborted: IPFS is disabled but tokenURI requires a real IPFS CID")
		}
		fmt.Printf("   ⏭️  IPFS disabled (--disable-ipfs)\n")
	}

	// Step 3: Build and upload ERC-721 metadata JSON to IPFS
	fmt.Printf("📋 Step 3/6: Building NFT metadata JSON...\n")
	var metadataCID string
	var tokenURI string

	if !opts.DisableIPFS && mediaCID != "" {
		ipfsClient := newIPFSClient(opts.IPFSAddr, opts.GatewayBaseURL)

		// Build ERC-721 metadata with image pointing to media CID
		nftMeta := BuildNFTMetadata(
			opts.NFTName,
			opts.NFTDescription,
			mediaCID,
			opts.NFTAttributes,
			receipt.MinterPublicKey,
			opts.OrgCode,
			opts.Subject,
			receipt.MintID,
			0, // blockHeight not known yet
		)

		metadataCID, tokenURI, err = UploadNFTMetadata(nftMeta, ipfsClient)
		if err != nil {
			// Metadata JSON is the tokenURI document: without it there is no
			// ERC-721 metadata to resolve. Abort when binding to a collection.
			if strings.TrimSpace(opts.Collection) != "" {
				return nil, fmt.Errorf("collection mint aborted: metadata upload to IPFS failed: %w", err)
			}
			fmt.Printf("   WARNING  Metadata upload failed: %v (continuing without tokenURI)\n", err)
		} else {
			receipt.MetadataCID = metadataCID
			receipt.TokenURI = tokenURI
			receipt.MetadataURI = tokenURI // backward compat
			fmt.Printf("   SUCCESS Metadata uploaded! CID: %s\n", metadataCID)
			fmt.Printf("   🔗 TokenURI: %s\n", tokenURI)
		}
	} else {
		if strings.TrimSpace(opts.Collection) != "" && tokenURI == "" {
			return nil, fmt.Errorf("collection mint aborted: tokenURI is empty and required for contract storage tokenURI[tokenId]")
		}
		fmt.Printf("   ⏭️  NFT metadata skipped (IPFS disabled or no media CID)\n")
	}

	// Step 4: Mint the token in the SIP-721 collection (Ethereum tokenId counter
	//         + contract storage tokenURI[tokenId]), then build the anchor tag.
	fmt.Printf("🔗 Step 4/6: Building on-chain anchor...\n")

	if strings.TrimSpace(opts.Collection) != "" {
		fmt.Printf("   🐉  Minting in SIP-721 collection %s...\n", opts.Collection)
		if opts.NodeAddr == "" || opts.From == "" || opts.KeyFile == "" {
			return nil, fmt.Errorf("collection mint requires --node-addr, --from and --key-file")
		}
		recipientTo := strings.TrimSpace(opts.To)
		if recipientTo == "" {
			recipientTo = opts.From
		}
		// The collection call executes inside core.executeContractTransaction at
		// consensus time: the node enforces ownerOf (only the collection owner may
		// mint), allocates next_token_id from sip721:info, and stores
		// tokenURI[tokenId] + owner and the sip721:mint reverse index. The tokenId
		// is read back from contract storage and trusted as the single counter value.
		tokenID, collectionMintTxID, err = BroadcastSIP721CollectionMint(
			opts.NodeAddr, opts.Collection, opts.From, opts.KeyFile, recipientTo, tokenURI, receipt.MintID)
		if err != nil {
			return nil, fmt.Errorf("collection mint aborted: %w", err)
		}
		receipt.TokenID = tokenID
		receipt.ContractAddress = strings.TrimSpace(opts.Collection)
		fmt.Printf("   SUCCESS Token #%d minted in %s (tx=%s)\n", tokenID, opts.Collection, collectionMintTxID)
	}

	anchorTag := &AnchorTag{
		Type:            AnchorTagType,
		MintID:          receipt.MintID,
		Subject:         receipt.Subject,
		CID:             mediaCID,
		MinterPublicKey: receipt.MinterPublicKey,
		TokenID:         receipt.TokenID,
		TokenURI:        receipt.TokenURI,
		Contract:        receipt.ContractAddress,
	}
	// Node-side mint verification (src/core.ValidateTransactionPolicy) checks
	// the tag's CID commitment — emit it whenever a real CID was pinned so the
	// anchor is verifiable. A tag with no CID (IPFS disabled / upload failed)
	// is rejected by the node's policy: an anchor without a CID pins nothing
	// and cannot be verified by anyone.
	if mediaCID != "" {
		anchorTag.CIDHashHex = core.CIDHashHexFor(mediaCID)
	}
	anchorHash, err := ReceiptCommitmentHash(receipt)
	if err != nil {
		return nil, fmt.Errorf("compute receipt hash: %w", err)
	}
	anchorTag.ReceiptHash = hex.EncodeToString(anchorHash)
	fmt.Printf("   SUCCESS Anchor built! ReceiptHash: %s\n", anchorTag.ReceiptHash[:16]+"...")

	// Step 5: Create and broadcast blockchain transaction
	fmt.Printf("⛓️  Step 5/6: Broadcasting on-chain transaction...\n")
	txID := collectionMintTxID // a collection mint already anchored on-chain in step 4
	if opts.NodeAddr != "" && opts.From != "" && opts.KeyFile != "" {
		anchorData, err := SerializeAnchorTag(anchorTag)
		if err != nil {
			return nil, fmt.Errorf("serialize anchor: %w", err)
		}

		if collectionMintTxID != "" {
			// A collection mint already consumed the account's current nonce,
			// so the receipt commitment must be anchored with the NEXT nonce
			// (the mempool enforces an exact nonce match). broadcastReceiptAnchor
			// fetches it from the node like step 4 did for the collection call.
			txID, err = broadcastReceiptAnchor(opts.NodeAddr, opts.From, opts.KeyFile, anchorData)
			if err != nil {
				fmt.Printf("   WARNING  Receipt anchor tx failed: %v (collection mint tx %s remains the on-chain proof)\n", err, collectionMintTxID)
			} else {
				fmt.Printf("   SUCCESS Receipt anchor broadcast! TX ID: %s\n", txID)
			}
		} else {
			txID, err = broadcastAnchorTransaction(opts.NodeAddr, opts.From, opts.KeyFile, anchorData)
			if err != nil {
				fmt.Printf("   WARNING  Blockchain tx failed: %v (anchor saved to disk)\n", err)
			} else {
				fmt.Printf("   SUCCESS Transaction broadcast! TX ID: %s\n", txID)
				fmt.Printf("   🔗 This TX will be included in a confirmed block (permanent anchor)\n")
			}
		}
	} else {
		fmt.Printf("   ⏭️  Blockchain anchor skipped (need --node-addr, --from, --key)\n")
	}

	// Step 6: Save receipt and anchor tag to disk
	fmt.Printf("💾 Step 6/6: Saving receipt and anchor to disk...\n")
	receiptPath, err := SaveReceipt(receipt, "")
	if err != nil {
		fmt.Printf("   WARNING  Failed to save receipt: %v\n", err)
	} else {
		fmt.Printf("   SUCCESS Receipt saved to: %s\n", receiptPath)
	}

	anchorPath, err := SaveAnchorTag(anchorTag, "")
	if err != nil {
		fmt.Printf("   WARNING  Failed to save anchor: %v\n", err)
	} else {
		fmt.Printf("   SUCCESS Anchor saved to: %s\n", anchorPath)
	}

	elapsed := time.Since(start)
	fmt.Printf("\n MintAndAnchor complete in %v\n", elapsed)

	return &MintAndAnchorResult{
		Receipt:     receipt,
		CID:         mediaCID,
		MetadataCID: metadataCID,
		TokenURI:    tokenURI,
		TokenID:     receipt.TokenID,
		Collection:  receipt.ContractAddress,
		TxID:        txID,
		GatewayURL:  mediaGatewayURL,
		ReceiptPath: receiptPath,
		AnchorPath:  anchorPath,
		Elapsed:     elapsed,
	}, nil
}
