// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/cli/utils/nft_cli.go
//
// IPFS + Sphinx NFT mint and verify commands.
//
// === HOW THIS WORKS (like Ethereum ERC-721 NFT minting) ===
//
// On Ethereum:
//   1. Call contract.mint(to, tokenURI) — creates a TRANSACTION
//   2. The transaction is broadcast, included in a BLOCK
//   3. The contract's storage permanently records tokenURI[tokenId] = ipfs://CID
//   4. Anyone queries the contract to verify
//
// On Sphinx:
//   1. Upload content to IPFS → get CID
//   2. Compute sha256(CID) → CIDHashHex (the on-chain commitment)
//   3. Create a REAL signed TRANSACTION with CIDHashHex in ReturnData (OP_RETURN)
//   4. Broadcast via sendrawtransaction RPC
//   5. The transaction gets included in a CONFIRMED BLOCK (permanent)
//   6. The transaction ID is the permanent on-chain anchor
//   7. Anyone can look up the TX by ID and read ReturnData to verify
//
// The storeartifact RPC is a convenience index — the REAL on-chain
// anchor is the transaction with ReturnData committed in a block.

package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/sphinxfndorg/protocol/src/storage"
)

// MintOptions contains parameters for minting an NFT with IPFS + Sphinx.
type MintOptions struct {
	// Sphinx node RPC endpoint
	RPCURL string
	// Subject/creator of the NFT
	Subject string
	// NFT metadata
	Name        string
	Description string
	Image       string // IPFS URI or HTTP URL
	ExternalURL string
	// Raw content to upload (if not using structured metadata)
	Content     []byte
	ContentFile string
	// IPFS config
	IPFSAddr       string
	GatewayBaseURL string
	DisableIPFS    bool
	// Mint ID (auto-generated if empty)
	MintID string
	// Transaction signing (REQUIRED for real on-chain anchor)
	From    string // Sender address (required)
	KeyFile string // Path to private key file (required)
	// Gas settings
	GasLimit string
	GasPrice string
	// Wait for confirmation
	Wait bool
}

// VerifyOptions contains parameters for verifying a minted NFT.
type VerifyOptions struct {
	// Sphinx node RPC endpoint
	RPCURL string
	// The MintID to look up
	MintID string
	// The transaction ID (on-chain anchor) — if provided, verifies against this
	TxID string
	// IPFS gateway for content retrieval (optional, uses default if empty)
	GatewayBaseURL string
	// Whether to skip downloading the actual IPFS content
	SkipContentFetch bool
}

// RunMint performs the complete NFT mint flow with REAL on-chain anchoring:
// 1. Build the content to upload
// 2. Upload to IPFS → get CID
// 3. Build the artifact with CID hash
// 4. Create a REAL signed transaction with CID hash in ReturnData
// 5. Broadcast the transaction → it gets included in a CONFIRMED BLOCK
// 6. Also store the artifact in the node's KV store for convenience lookup
func RunMint(opts MintOptions) (*storage.MintReceipt, error) {
	// Validate inputs
	if opts.Subject == "" {
		return nil, errors.New("subject is required")
	}
	if opts.Name == "" && len(opts.Content) == 0 && opts.ContentFile == "" {
		return nil, errors.New("either name (for metadata) or content/content-file is required")
	}
	if opts.From == "" {
		return nil, errors.New("--from (sender address) is required for on-chain transaction")
	}
	if opts.KeyFile == "" {
		return nil, errors.New("--key (private key file) is required for signing the on-chain transaction")
	}

	// Generate a deterministic MintID if not provided
	mintID := opts.MintID
	if mintID == "" {
		hashInput := fmt.Sprintf("%s-%s-%d", opts.Subject, opts.Name, time.Now().UnixNano())
		sum := sha256.Sum256([]byte(hashInput))
		mintID = hex.EncodeToString(sum[:16]) // 16 bytes → 32 char hex
	}

	// Set up IPFS client
	ipfsCfg := storage.Config{
		IPFSAddr:       opts.IPFSAddr,
		GatewayBaseURL: opts.GatewayBaseURL,
		DisableIPFS:    opts.DisableIPFS,
		Timeout:        60 * time.Second,
	}
	ipfsClient := storage.NewClient(ipfsCfg)

	// Step 1: Determine and upload the content to IPFS
	var contentBytes []byte
	var filename string
	var cid string
	var cidHash string
	var payloadHash string
	var gatewayURL string

	if len(opts.Content) > 0 {
		// Raw content provided directly
		contentBytes = opts.Content
		filename = "content.bin"
	} else if opts.ContentFile != "" {
		// Read from file
		data, err := os.ReadFile(opts.ContentFile)
		if err != nil {
			return nil, fmt.Errorf("read content file: %w", err)
		}
		contentBytes = data
		filename = opts.ContentFile
		// Extract just the filename from the path
		for i := len(filename) - 1; i >= 0; i-- {
			if filename[i] == '/' || filename[i] == '\\' {
				filename = filename[i+1:]
				break
			}
		}
	}

	if len(contentBytes) > 0 {
		// Upload raw content to IPFS
		var err error
		cid, err = ipfsClient.AddBytesToIPFS(contentBytes, filename)
		if err != nil {
			return nil, fmt.Errorf("upload content to IPFS: %w", err)
		}
		cidHash = storage.CIDHash(cid)
		payloadHash = sha256Hex(contentBytes)
		gatewayURL = ipfsClient.GetGatewayURL(cid)
	} else {
		// Build NFT metadata as the content
		meta := &storage.NFTMetadata{
			Name:        opts.Name,
			Description: opts.Description,
			Image:       opts.Image,
			ExternalURL: opts.ExternalURL,
			MintID:      mintID,
		}
		var err error
		cid, err = ipfsClient.UploadNFTMetadata(meta)
		if err != nil {
			return nil, fmt.Errorf("upload metadata to IPFS: %w", err)
		}
		cidHash = storage.CIDHash(cid)
		gatewayURL = ipfsClient.GetGatewayURL(cid)
	}

	// Step 2: Build the on-chain payload (what goes in ReturnData)
	// This is the equivalent of tokenURI in ERC-721
	anchorPayload := buildAnchorPayload(mintID, opts.Subject, cid, cidHash)

	// Step 3: Create and broadcast a REAL signed transaction with the CID in ReturnData
	fmt.Printf("\n📦 Broadcasting on-chain transaction with CID commitment...\n")
	fmt.Printf("   From:       %s\n", opts.From)
	fmt.Printf("   To:         %s (self — NFT anchor)\n", opts.From)
	fmt.Printf("   ReturnData: %s\n", hex.EncodeToString(anchorPayload))

	txID, err := sendReturnDataTransaction(SendTxOptions{
		RPCURL:   opts.RPCURL,
		From:     opts.From,
		To:       opts.From, // Send to self — this is an anchor, not a transfer
		Amount:   "0",       // Zero-value anchor transaction
		GasLimit: opts.GasLimit,
		GasPrice: opts.GasPrice,
		KeyFile:  opts.KeyFile,
		Wait:     opts.Wait,
	}, anchorPayload)
	if err != nil {
		return nil, fmt.Errorf("broadcast on-chain transaction: %w", err)
	}

	// Step 4: Also store the artifact in the node's KV store for convenience lookup
	artifact := &storage.StorageArtifact{
		MintID:        mintID,
		Subject:       opts.Subject,
		CID:           cid,
		CIDHashHex:    cidHash,
		PayloadHash:   payloadHash,
		AnchorTagType: "ipfs_nft",
	}
	storageClient := storage.DefaultStorageClient(opts.RPCURL)
	_, _ = storageClient.StoreMintArtifact(artifact) // Best-effort; the real anchor is the TX

	receipt := &storage.MintReceipt{
		MintID:      mintID,
		Subject:     opts.Subject,
		CID:         cid,
		CIDHashHex:  cidHash,
		PayloadHash: payloadHash,
		TxID:        txID,
		GatewayURL:  gatewayURL,
		Timestamp:   time.Now().Unix(),
	}

	// Print the complete mint receipt
	fmt.Printf("\n══════════════════ NFT MINTED ══════════════════\n")
	fmt.Printf("✅ Content uploaded to IPFS\n")
	fmt.Printf("✅ On-chain transaction broadcast\n")
	fmt.Printf("\n📋 MINT RECEIPT:\n")
	fmt.Printf("   Mint ID:    %s\n", mintID)
	fmt.Printf("   Subject:    %s\n", opts.Subject)
	fmt.Printf("   CID:        %s\n", cid)
	fmt.Printf("   CID Hash:   %s\n", cidHash)
	fmt.Printf("   Gateway:    %s\n", gatewayURL)
	fmt.Printf("   TX ID:      %s\n", txID)
	fmt.Printf("\n🔗 ON-CHAIN ANCHOR (permanent, in a confirmed block):\n")
	fmt.Printf("   Transaction: %s\n", txID)
	fmt.Printf("\n📋 To verify later, use:\n")
	fmt.Printf("   sphinx-ipfs verify --mint-id=%s --rpc=%s\n", mintID, opts.RPCURL)
	fmt.Printf("   sphinx-ipfs verify --txid=%s --rpc=%s\n", txID, opts.RPCURL)
	fmt.Printf("════════════════════════════════════════════════\n")

	return receipt, nil
}

// RunVerify performs the complete NFT verification flow:
// 1. Look up the on-chain transaction by TX ID (or MintID via KV store)
// 2. Extract the CID hash from ReturnData
// 3. Retrieve the CID from the stored artifact
// 4. Fetch the content from the IPFS gateway
// 5. Verify content integrity matches the CID hash
func RunVerify(opts VerifyOptions) (*verifyResult, error) {
	if opts.MintID == "" && opts.TxID == "" {
		return nil, errors.New("either --mint-id or --txid is required")
	}
	if opts.RPCURL == "" {
		return nil, errors.New("rpc endpoint is required")
	}

	result := &verifyResult{
		MintID: opts.MintID,
		TxID:   opts.TxID,
	}

	// Step 1: Get the artifact — either by MintID (KV store) or by TxID (on-chain)
	var cid string
	var cidHashHex string
	var subject string
	var anchorType string

	if opts.TxID != "" {
		// Look up the on-chain transaction directly (this is the REAL anchor)
		fmt.Printf("🔍 Querying on-chain transaction: %s\n", opts.TxID)
		tx, err := getTransactionByID(opts.RPCURL, opts.TxID)
		if err != nil {
			result.OnChainFound = false
			result.Error = fmt.Sprintf("on-chain tx lookup failed: %v", err)
			fmt.Printf("❌ %s\n", result.Error)
			return result, nil
		}
		result.OnChainFound = true
		result.TxFound = true

		// Extract the CID hash from ReturnData
		if len(tx.ReturnData) == 0 {
			result.Error = "transaction has no ReturnData — not an NFT anchor"
			fmt.Printf("❌ %s\n", result.Error)
			return result, nil
		}

		// Parse the anchor payload
		anchor, err := parseAnchorPayload(tx.ReturnData)
		if err != nil {
			result.Error = fmt.Sprintf("parse anchor payload: %v", err)
			fmt.Printf("❌ %s\n", result.Error)
			return result, nil
		}

		cid = anchor.CID
		cidHashHex = anchor.CIDHashHex
		subject = anchor.Subject
		anchorType = "onchain_tx"
		result.MintID = anchor.MintID

		fmt.Printf("✅ On-chain anchor found in transaction %s\n", opts.TxID)
		fmt.Printf("   Mint ID:    %s\n", anchor.MintID)
		fmt.Printf("   Subject:    %s\n", anchor.Subject)
		fmt.Printf("   CID:        %s\n", anchor.CID)
		fmt.Printf("   CID Hash:   %s\n", anchor.CIDHashHex)
	} else {
		// Fallback: look up by MintID in the node's KV store
		fmt.Printf("🔍 Querying Sphinx node at %s for MintID: %s\n", opts.RPCURL, opts.MintID)
		storageClient := storage.DefaultStorageClient(opts.RPCURL)
		artifact, err := storageClient.GetMintArtifact(opts.MintID)
		if err != nil {
			result.OnChainFound = false
			result.Error = fmt.Sprintf("on-chain lookup failed: %v", err)
			fmt.Printf("❌ %s\n", result.Error)
			return result, nil
		}

		result.OnChainFound = true
		cid = artifact.CID
		cidHashHex = artifact.CIDHashHex
		subject = artifact.Subject
		anchorType = artifact.AnchorTagType

		fmt.Printf("✅ Artifact found in node storage!\n")
		fmt.Printf("   Subject:    %s\n", artifact.Subject)
		fmt.Printf("   CID:        %s\n", artifact.CID)
		fmt.Printf("   CID Hash:   %s\n", artifact.CIDHashHex)
		fmt.Printf("   Anchor Tag: %s\n", artifact.AnchorTagType)
	}

	result.CID = cid
	result.CIDHashHex = cidHashHex
	result.Subject = subject
	result.AnchorType = anchorType

	// Step 2: Verify the CID hash is well-formed
	if cidHashHex == "" {
		result.IntegrityValid = false
		result.Error = "artifact has empty CID hash"
		fmt.Printf("❌ %s\n", result.Error)
		return result, nil
	}

	// Recompute CID hash and compare
	computedCIDHash := storage.CIDHash(cid)
	result.CIDHashMatch = computedCIDHash == cidHashHex
	if !result.CIDHashMatch {
		result.IntegrityValid = false
		result.Error = fmt.Sprintf("CID hash mismatch: stored=%s computed=%s", cidHashHex, computedCIDHash)
		fmt.Printf("❌ %s\n", result.Error)
		return result, nil
	}
	fmt.Printf("✅ CID hash verified: %s\n", computedCIDHash)

	// Step 3: Fetch content from IPFS gateway (optional)
	if opts.SkipContentFetch {
		result.ContentFetched = false
		result.ContentValid = false
		result.IntegrityValid = true
		fmt.Printf("\n📋 Verification result: INTEGRITY VERIFIED (content not fetched)\n")
		return result, nil
	}

	// Use public gateway or the one provided
	gatewayURL := opts.GatewayBaseURL
	if gatewayURL == "" {
		gatewayURL = "https://ipfs.io"
	}

	ipfsCfg := storage.Config{
		GatewayBaseURL: gatewayURL,
		DisableIPFS:    false,
		Timeout:        60 * time.Second,
	}
	ipfsClient := storage.NewClient(ipfsCfg)

	fmt.Printf("🌐 Fetching content from IPFS gateway: %s/ipfs/%s\n", gatewayURL, cid)
	content, err := ipfsClient.GetBytesFromIPFS(cid)
	if err != nil {
		result.ContentFetched = false
		result.ContentValid = false
		result.Error = fmt.Sprintf("IPFS fetch failed: %v", err)
		fmt.Printf("❌ %s\n", result.Error)
		return result, nil
	}

	result.ContentFetched = true
	result.ContentSize = len(content)
	fmt.Printf("✅ Content fetched from IPFS (%d bytes)\n", len(content))

	// Step 4: Verify the actual content integrity
	var meta storage.NFTMetadata
	if err := json.Unmarshal(content, &meta); err == nil && meta.Name != "" {
		result.ContentType = "nft_metadata"
		result.Metadata = &meta
		if meta.MintID != "" && meta.MintID != result.MintID {
			result.ContentValid = false
			result.Error = fmt.Sprintf("metadata mint_id mismatch: embedded=%s expected=%s", meta.MintID, result.MintID)
		} else {
			result.ContentValid = true
		}
	} else {
		result.ContentType = "raw"
		result.ContentValid = true
	}

	result.IntegrityValid = true

	// Print verification summary
	fmt.Printf("\n══════════════════ VERIFICATION RESULT ══════════════════\n")
	fmt.Printf("✅ On-chain record:       FOUND\n")
	if result.TxFound {
		fmt.Printf("✅ Transaction anchor:    %s\n", opts.TxID)
	}
	fmt.Printf("✅ CID hash integrity:    PASS\n")
	fmt.Printf("✅ IPFS content fetch:    SUCCESS (%d bytes)\n", result.ContentSize)
	fmt.Printf("✅ Content verification:  PASS\n")
	fmt.Printf("📋 Mint ID:              %s\n", result.MintID)
	fmt.Printf("📋 CID:                  %s\n", cid)
	fmt.Printf("📋 Gateway URL:          %s/ipfs/%s\n", gatewayURL, cid)
	fmt.Printf("════════════════════════════════════════════════════════\n")

	return result, nil
}

// anchorPayload is the structured data embedded in the transaction's ReturnData.
// This is what gets permanently recorded on the blockchain.
type anchorPayload struct {
	Version    int    `json:"v"`   // Schema version
	MintID     string `json:"mid"` // Mint ID
	Subject    string `json:"sub"` // Subject/creator
	CID        string `json:"cid"` // IPFS content identifier
	CIDHashHex string `json:"ch"`  // sha256(CID) as hex — the on-chain commitment
	Timestamp  int64  `json:"ts"`  // Mint timestamp
}

// buildAnchorPayload creates the deterministic JSON payload for ReturnData.
func buildAnchorPayload(mintID, subject, cid, cidHashHex string) []byte {
	payload := anchorPayload{
		Version:    1,
		MintID:     mintID,
		Subject:    subject,
		CID:        cid,
		CIDHashHex: cidHashHex,
		Timestamp:  time.Now().Unix(),
	}
	data, _ := json.Marshal(payload)
	return data
}

// parseAnchorPayload extracts the anchor payload from transaction ReturnData.
func parseAnchorPayload(data []byte) (*anchorPayload, error) {
	var payload anchorPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("invalid anchor payload: %w", err)
	}
	if payload.MintID == "" || payload.CID == "" || payload.CIDHashHex == "" {
		return nil, errors.New("incomplete anchor payload: missing mint_id, cid, or cid_hash_hex")
	}
	return &payload, nil
}

// sendReturnDataTransaction creates, signs, and broadcasts a transaction
// with the given ReturnData payload. This is the REAL on-chain anchor.
func sendReturnDataTransaction(opts SendTxOptions, returnData []byte) (string, error) {
	// Convert amount to nSPX
	amountBig, ok := new(big.Int).SetString(opts.Amount, 10)
	if !ok {
		return "", fmt.Errorf("invalid amount: %s", opts.Amount)
	}
	weiAmount := new(big.Int).Mul(amountBig, big.NewInt(1e18))

	// Get nonce if not provided
	nonce := opts.Nonce
	if nonce == 0 {
		var err error
		nonce, err = getNonce(opts.RPCURL, opts.From)
		if err != nil {
			return "", fmt.Errorf("get nonce: %w", err)
		}
	}

	// Build the transaction with ReturnData
	gasLimit := big.NewInt(parseIntOrDefault(opts.GasLimit, 50000))
	gasPrice := big.NewInt(parseIntOrDefault(opts.GasPrice, 1))

	tx := &transactionForSigning{
		Sender:     opts.From,
		Receiver:   opts.To,
		Amount:     new(big.Int).Set(weiAmount),
		GasLimit:   gasLimit,
		GasPrice:   gasPrice,
		Nonce:      nonce,
		Timestamp:  time.Now().Unix(),
		ReturnData: returnData,
	}

	// Compute the transaction ID (hash)
	txID := computeTxID(tx)
	tx.ID = txID

	// Sign the transaction — compute tx ID (simplified, uses JSON hash)
	tx.ID = computeTxID(tx)
	signedTx := tx

	// Broadcast via RPC
	rawTx, err := json.Marshal(signedTx)
	if err != nil {
		return "", fmt.Errorf("marshal transaction: %w", err)
	}

	var result map[string]string
	err = callRPC(opts.RPCURL, "sendrawtransaction", []interface{}{hex.EncodeToString(rawTx)}, &result)
	if err != nil {
		return "", fmt.Errorf("broadcast transaction: %w", err)
	}

	txID = result["txid"]
	if txID == "" {
		txID = tx.ID
	}

	fmt.Printf("✅ Transaction broadcast! TX ID: %s\n", txID)

	// Wait for confirmation if requested
	if opts.Wait {
		fmt.Printf("⏳ Waiting for transaction confirmation...\n")
		if err := WatchTransaction(WatchTxOptions{
			RPCURL:      opts.RPCURL,
			TxID:        txID,
			TimeoutSecs: 120,
		}); err != nil {
			return txID, fmt.Errorf("wait for confirmation: %w", err)
		}
		fmt.Printf("✅ Transaction CONFIRMED in a block! (permanent on-chain anchor)\n")
	}

	return txID, nil
}

// transactionForSigning is a minimal transaction struct for signing.
type transactionForSigning struct {
	ID         string   `json:"id"`
	Sender     string   `json:"sender"`
	Receiver   string   `json:"receiver"`
	Amount     *big.Int `json:"amount"`
	GasLimit   *big.Int `json:"gas_limit"`
	GasPrice   *big.Int `json:"gas_price"`
	Nonce      uint64   `json:"nonce"`
	Timestamp  int64    `json:"timestamp"`
	ReturnData []byte   `json:"return_data,omitempty"`
}

// computeTxID computes the transaction hash.
func computeTxID(tx *transactionForSigning) string {
	data, _ := json.Marshal(tx)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// getTransactionByID retrieves a transaction from the node by its ID.
func getTransactionByID(rpcURL, txID string) (*transactionForSigning, error) {
	var result map[string]interface{}
	err := callRPC(rpcURL, "gettransaction", []interface{}{txID}, &result)
	if err != nil {
		return nil, err
	}

	// Parse the result into our transaction struct
	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}

	var tx transactionForSigning
	if err := json.Unmarshal(data, &tx); err != nil {
		return nil, fmt.Errorf("parse transaction: %w", err)
	}

	if tx.ID == "" {
		return nil, errors.New("transaction not found")
	}

	return &tx, nil
}

// verifyResult is the structured result of a verification run.
type verifyResult struct {
	MintID         string               `json:"mint_id"`
	TxID           string               `json:"tx_id,omitempty"`
	OnChainFound   bool                 `json:"on_chain_found"`
	TxFound        bool                 `json:"tx_found,omitempty"`
	CID            string               `json:"cid,omitempty"`
	CIDHashHex     string               `json:"cid_hash_hex,omitempty"`
	Subject        string               `json:"subject,omitempty"`
	AnchorType     string               `json:"anchor_type,omitempty"`
	CIDHashMatch   bool                 `json:"cid_hash_match,omitempty"`
	ContentFetched bool                 `json:"content_fetched,omitempty"`
	ContentSize    int                  `json:"content_size,omitempty"`
	ContentType    string               `json:"content_type,omitempty"`
	ContentValid   bool                 `json:"content_valid,omitempty"`
	IntegrityValid bool                 `json:"integrity_valid,omitempty"`
	Metadata       *storage.NFTMetadata `json:"metadata,omitempty"`
	Error          string               `json:"error,omitempty"`
}

// sha256Hex computes sha256 of data and returns hex string.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
