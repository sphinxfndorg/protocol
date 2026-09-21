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
//   2. Compute CIDHashHex = storage.CIDHash(CID) (common.SpxHash — the
//      canonical Sphinx hash) → the on-chain commitment
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
	"path/filepath"
	"strings"
	"time"

	"github.com/sphinxfndorg/protocol/src/bind/abi"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
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

	// Set up IPFS client. Start from DefaultConfig so the remote-pinning
	// environment (SPHINX_IPFS_PINNING_SERVICE/_TOKEN) applies to the CLI too —
	// building a bare Config here would silently drop the durable tier and
	// leave mints local-only even when the operator configured a service.
	ipfsCfg := storage.DefaultConfig()
	if opts.IPFSAddr != "" {
		ipfsCfg.IPFSAddr = opts.IPFSAddr
	}
	if opts.GatewayBaseURL != "" {
		ipfsCfg.GatewayBaseURL = opts.GatewayBaseURL
	}
	ipfsCfg.DisableIPFS = opts.DisableIPFS
	ipfsCfg.Timeout = 60 * time.Second
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

	// Upload the content with the durability-aware pin helper, so the CLI
	// reports honestly where the bytes actually are. Minting used to accept a
	// local content hash (spxhash-…) in place of a real CID and anchor it
	// on-chain, which produced permanent commitments to data that no IPFS node
	// could ever serve.
	var pin storage.PinOutcome
	if len(contentBytes) > 0 {
		pin = ipfsClient.PinPayload(contentBytes, filename)
		payloadHash = sha256Hex(contentBytes)
	} else {
		// Build NFT metadata as the content
		meta := &storage.NFTMetadata{
			Name:        opts.Name,
			Description: opts.Description,
			Image:       opts.Image,
			ExternalURL: opts.ExternalURL,
			MintID:      mintID,
		}
		metaJSON, mErr := json.Marshal(meta)
		if mErr != nil {
			return nil, fmt.Errorf("marshal metadata: %w", mErr)
		}
		pin = ipfsClient.PinPayload(metaJSON, "metadata.json")
	}

	// --disable-ipfs is an explicit operator opt-in to an offline commitment;
	// anything else that fails to upload must stop the mint, because there is
	// no retrievable object for the anchor to commit to.
	if !pin.Uploaded() && !pin.OptIn {
		return nil, fmt.Errorf("nothing was uploaded to IPFS: %w", pin.Warn)
	}
	if pin.Warn != nil {
		fmt.Printf("WARNING %v\n", pin.Warn)
	}
	if pin.Uploaded() {
		if pin.Durable() {
			fmt.Printf("SUCCESS Content pinned durably via %s\n", pin.Source)
		} else {
			fmt.Printf("WARNING Content pinned to the LOCAL daemon only — it becomes unreachable when this machine's daemon goes offline.\n")
		}
	} else {
		fmt.Printf("WARNING OFFLINE MODE: %s is a local content hash, NOT a retrievable IPFS CID — nobody else can fetch this data.\n", pin.CID)
	}

	cid = pin.CID
	cidHash = storage.CIDHash(cid)
	gatewayURL = ipfsClient.GetGatewayURL(cid)

	// Step 2: Build the on-chain payload (what goes in ReturnData)
	// This is the equivalent of tokenURI in ERC-721
	anchorPayload := buildAnchorPayload(mintID, opts.Subject, cid, cidHash)

	// Step 3: Create and broadcast a REAL signed transaction with the CID in ReturnData
	fmt.Printf("\nINFO Broadcasting on-chain transaction with CID commitment...\n")
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
	fmt.Printf("SUCCESS Content uploaded to IPFS\n")
	fmt.Printf("SUCCESS On-chain transaction broadcast\n")
	fmt.Printf("\n MINT RECEIPT:\n")
	fmt.Printf("   Mint ID:    %s\n", mintID)
	fmt.Printf("   Subject:    %s\n", opts.Subject)
	fmt.Printf("   CID:        %s\n", cid)
	fmt.Printf("   CID Hash:   %s\n", cidHash)
	fmt.Printf("   Gateway:    %s\n", gatewayURL)
	fmt.Printf("   TX ID:      %s\n", txID)
	fmt.Printf("\n🔗 ON-CHAIN ANCHOR (permanent, in a confirmed block):\n")
	fmt.Printf("   Transaction: %s\n", txID)
	fmt.Printf("\n To verify later, use:\n")
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
	// recordedPayloadHash is the payload digest the mint recorded, when one is
	// available. The on-chain anchor tag commits only to the CID/receipt, so
	// only the node-side artifact (the --mint-id path) carries it.
	var recordedPayloadHash string

	if opts.TxID != "" {
		// Look up the on-chain transaction directly (this is the REAL anchor)
		fmt.Printf("INFO Querying on-chain transaction: %s\n", opts.TxID)
		tx, err := getTransactionByID(opts.RPCURL, opts.TxID)
		if err != nil {
			result.OnChainFound = false
			result.Error = fmt.Sprintf("on-chain tx lookup failed: %v", err)
			fmt.Printf("ERROR %s\n", result.Error)
			return result, nil
		}
		result.OnChainFound = true
		result.TxFound = true

		// Extract the CID hash from ReturnData
		if len(tx.ReturnData) == 0 {
			result.Error = "transaction has no ReturnData — not an NFT anchor"
			fmt.Printf("ERROR %s\n", result.Error)
			return result, nil
		}

		// Parse the anchor payload
		anchor, err := parseAnchorPayload(tx.ReturnData)
		if err != nil {
			result.Error = fmt.Sprintf("parse anchor payload: %v", err)
			fmt.Printf("ERROR %s\n", result.Error)
			return result, nil
		}

		cid = anchor.CID
		cidHashHex = anchor.CIDHashHex
		subject = anchor.Subject
		anchorType = "onchain_tx"
		result.MintID = anchor.MintID

		fmt.Printf("SUCCESS On-chain anchor found in transaction %s\n", opts.TxID)
		fmt.Printf("   Mint ID:    %s\n", anchor.MintID)
		fmt.Printf("   Subject:    %s\n", anchor.Subject)
		fmt.Printf("   CID:        %s\n", anchor.CID)
		fmt.Printf("   CID Hash:   %s\n", anchor.CIDHashHex)
	} else {
		// Fallback: look up by MintID in the node's KV store
		fmt.Printf("INFO Querying Sphinx node at %s for MintID: %s\n", opts.RPCURL, opts.MintID)
		storageClient := storage.DefaultStorageClient(opts.RPCURL)
		artifact, err := storageClient.GetMintArtifact(opts.MintID)
		if err != nil {
			result.OnChainFound = false
			result.Error = fmt.Sprintf("on-chain lookup failed: %v", err)
			fmt.Printf("ERROR %s\n", result.Error)
			return result, nil
		}

		result.OnChainFound = true
		cid = artifact.CID
		cidHashHex = artifact.CIDHashHex
		subject = artifact.Subject
		anchorType = artifact.AnchorTagType
		recordedPayloadHash = artifact.PayloadHash

		fmt.Printf("SUCCESS Artifact found in node storage!\n")
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
		fmt.Printf("ERROR %s\n", result.Error)
		return result, nil
	}

	// Recompute CID hash and compare
	computedCIDHash := storage.CIDHash(cid)
	result.CIDHashMatch = computedCIDHash == cidHashHex
	if !result.CIDHashMatch {
		result.IntegrityValid = false
		result.Error = fmt.Sprintf("CID hash mismatch: stored=%s computed=%s", cidHashHex, computedCIDHash)
		fmt.Printf("ERROR %s\n", result.Error)
		return result, nil
	}
	fmt.Printf("SUCCESS CID hash verified: %s\n", computedCIDHash)

	// Step 3: a spxhash- "CID" is NOT an IPFS identifier. It is the local
	// content hash the wallet records when nothing was uploaded (IPFS
	// disabled, or no backend reachable). Reporting this explicitly is the
	// whole point: previously it was indistinguishable from a gateway outage,
	// and the only way to notice was spotting the prefix by eye.
	if storage.IsLocalOnlyCommitment(cid) {
		result.NotUploaded = true
		result.Durability = storage.DurabilityNotUploaded.String()
		result.ContentFetched = false
		result.ContentValid = false
		result.IntegrityValid = true
		result.Error = fmt.Sprintf(
			"NOT UPLOADED: the recorded CID %q is a local content hash, not an IPFS identifier — the mint ran without a reachable IPFS backend, so nothing was ever uploaded and no gateway can serve this data",
			cid)
		fmt.Printf("\n══════════════════ VERIFICATION RESULT ══════════════════\n")
		fmt.Printf("WARNING Commitment verified:   YES (the on-chain CID hash matches)\n")
		fmt.Printf("ERROR   IPFS availability:     NEVER UPLOADED\n")
		fmt.Printf("        CID %s is a local content hash, not a retrievable IPFS CID.\n", cid)
		fmt.Printf("        Nothing to fetch — there is no IPFS copy anywhere.\n")
		fmt.Printf("        Mint ID: %s\n", result.MintID)
		fmt.Printf("════════════════════════════════════════════════════════\n")
		return result, nil
	}

	// Step 3: Fetch content from IPFS gateway (optional)
	if opts.SkipContentFetch {
		result.ContentFetched = false
		result.ContentValid = false
		result.IntegrityValid = true
		fmt.Printf("\n Verification result: INTEGRITY VERIFIED (content not fetched)\n")
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

	configuredIsLocal := storage.IsLocalGatewayURL(gatewayURL)
	fmt.Printf("🌐 Fetching content from IPFS gateway: %s/ipfs/%s\n", gatewayURL, cid)
	content, pubErr := ipfsClient.GetBytesFromIPFS(cid)
	configuredOK := pubErr == nil
	localDaemonOK := false
	if !configuredOK {
		// The gateway could not serve it. Before calling it unreachable, check
		// whether the LOCAL daemon still has it: "only your own node can serve
		// this" is a materially different answer from "nobody can", and it is
		// the expected state for a local-daemon-only pin whose machine is
		// still online.
		localCfg := storage.DefaultConfig()
		localClient := storage.NewClient(localCfg)
		if local, lerr := localClient.FetchFromDaemon(cid); lerr == nil {
			content, pubErr = local, nil
			localDaemonOK = true
			fmt.Printf("WARNING Gateway %s could not serve %s; the local daemon at %s still has it — retrievable only while that machine stays online.\n", gatewayURL, cid, localCfg.IPFSAddr)
		}
	}
	// storage.ClassifyRetrievability owns this decision, so the CLI and the
	// wallet GUI can never disagree about the same state: only a NON-LOCAL
	// gateway counts as durable, and a localhost gateway is local
	// infrastructure however it is spelled.
	result.Durability = storage.ClassifyRetrievability(
		configuredOK && !configuredIsLocal,
		localDaemonOK || (configuredOK && configuredIsLocal),
	).String()

	if pubErr != nil {
		result.ContentFetched = false
		result.ContentValid = false
		result.Error = fmt.Sprintf("IPFS fetch failed: %v", pubErr)
		fmt.Printf("ERROR %s\n", result.Error)
		return result, nil
	}

	result.ContentFetched = true
	result.ContentSize = len(content)
	result.ContentSHA256 = sha256Hex(content)
	fmt.Printf("SUCCESS Content fetched from IPFS (%d bytes)\n", len(content))

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

	// When the mint recorded a payload digest, the fetched bytes must match it.
	// Without this check "Content verification: PASS" only meant "we fetched
	// something" — any bytes at all counted. (The on-chain anchor tag carries
	// no payload hash, so this binds on the --mint-id/artifact path.)
	if strings.TrimSpace(recordedPayloadHash) != "" {
		match := strings.EqualFold(result.ContentSHA256, strings.TrimSpace(recordedPayloadHash))
		result.PayloadHashMatch = &match
		if !match {
			result.ContentValid = false
			result.Error = fmt.Sprintf("payload hash mismatch: fetched content sha256=%s but the mint recorded %s", result.ContentSHA256, recordedPayloadHash)
			fmt.Printf("ERROR %s\n", result.Error)
		}
	}

	result.IntegrityValid = true

	// Print verification summary
	fmt.Printf("\n══════════════════ VERIFICATION RESULT ══════════════════\n")
	fmt.Printf("SUCCESS On-chain record:       FOUND\n")
	if result.TxFound {
		fmt.Printf("SUCCESS Transaction anchor:    %s\n", opts.TxID)
	}
	fmt.Printf("SUCCESS CID hash integrity:    PASS\n")
	fmt.Printf("SUCCESS IPFS content fetch:    SUCCESS (%d bytes)\n", result.ContentSize)
	fmt.Printf("SUCCESS Content verification:  PASS\n")
	if result.PayloadHashMatch != nil {
		fmt.Printf("SUCCESS Payload hash binding:  %s\n", map[bool]string{true: "MATCH", false: "MISMATCH"}[*result.PayloadHashMatch])
	}
	switch result.Durability {
	case storage.DurabilityRemotePinned.String():
		fmt.Printf("SUCCESS IPFS durability:       REMOTE-PINNED (a public gateway served it)\n")
	case storage.DurabilityLocalOnly.String():
		fmt.Printf("WARNING IPFS durability:       LOCAL-ONLY (only this machine's infrastructure has it)\n")
	case storage.DurabilityNotReachable.String():
		fmt.Printf("WARNING IPFS durability:       NOT REACHABLE (no public gateway or local daemon had it)\n")
	default:
		fmt.Printf("WARNING IPFS durability:       %s\n", result.Durability)
	}
	fmt.Printf(" Mint ID:              %s\n", result.MintID)
	fmt.Printf(" CID:                  %s\n", cid)
	fmt.Printf(" Gateway URL:          %s/ipfs/%s\n", gatewayURL, cid)
	fmt.Printf("════════════════════════════════════════════════════════\n")

	return result, nil
}

// RepinOptions configures "ipfs repin".
type RepinOptions struct {
	// RPCURL is the Sphinx node JSON-RPC endpoint used to read the anchor.
	RPCURL string
	// MintID or TxID selects the recorded commitment to re-pin (one required).
	MintID string
	TxID   string
	// File is the original payload the mint committed to. It is required
	// because a re-pin must push the SAME bytes the anchor describes — pinning
	// anything else would create a retrievable object that does not match the
	// on-chain commitment.
	File string
	// IPFS config; empty values fall back to DefaultConfig()/environment, so
	// the remote-pinning env vars apply here too.
	IPFSAddr       string
	GatewayBaseURL string
}

// RepinResult is the outcome of a re-pin. It doubles as per-anchor AUDIT data:
// WasLocalOnlyCommitment identifies an anchor whose media was never uploaded,
// which is exactly the population a chain-wide audit needs to size before any
// node-side rule change can be considered.
type RepinResult struct {
	MintID     string `json:"mint_id,omitempty"`
	Subject    string `json:"subject,omitempty"`
	AnchorType string `json:"anchor_type,omitempty"`

	// OldCID is what the mint recorded (unchanged by a re-pin).
	OldCID string `json:"old_cid,omitempty"`
	// NewCID is the identifier the payload is now retrievable under. For a
	// local-only commitment this necessarily DIFFERS from OldCID, because the
	// old value was a content hash rather than a CID.
	NewCID string `json:"new_cid,omitempty"`

	WasLocalOnlyCommitment bool `json:"was_local_only_commitment,omitempty"`
	// FileVerifiedAgainstAnchor is true only when the supplied file was proven
	// byte-identical to what the anchor committed to.
	FileVerifiedAgainstAnchor bool   `json:"file_verified_against_anchor,omitempty"`
	Durability                string `json:"durability,omitempty"`

	// OnChainAnchorUnchanged is always true and is stated explicitly so nobody
	// mistakes a re-pin for a repair of the on-chain record: it commits to
	// OldCID and cannot be rewritten.
	OnChainAnchorUnchanged bool `json:"on_chain_anchor_unchanged"`

	Error string `json:"error,omitempty"`
}

// anchorResolution is the commitment a mint recorded, however it was looked up.
type anchorResolution struct {
	MintID      string
	CID         string
	CIDHashHex  string
	Subject     string
	AnchorType  string
	PayloadHash string // artifact path only: the on-chain tag carries no payload hash
}

// resolveAnchor finds the commitment a mint recorded — preferring the on-chain
// anchor when a txid is supplied (it is the real, permanent record) and falling
// back to the node's artifact store for a mint-id lookup.
//
// NOTE: "ipfs verify" resolves the same information inline, because its
// per-step progress printing is interleaved with the lookups and it is a
// shipped, user-facing path. This helper exists for "ipfs repin" so the new
// command does not also inline it; unifying the two is a follow-up.
func resolveAnchor(opts RepinOptions) (*anchorResolution, error) {
	if opts.TxID != "" {
		tx, err := getTransactionByID(opts.RPCURL, opts.TxID)
		if err != nil {
			return nil, fmt.Errorf("on-chain tx lookup failed: %w", err)
		}
		if len(tx.ReturnData) == 0 {
			return nil, errors.New("transaction has no ReturnData — not an NFT anchor")
		}
		anchor, err := parseAnchorPayload(tx.ReturnData)
		if err != nil {
			return nil, fmt.Errorf("parse anchor payload: %w", err)
		}
		return &anchorResolution{
			MintID:     anchor.MintID,
			CID:        anchor.CID,
			CIDHashHex: anchor.CIDHashHex,
			Subject:    anchor.Subject,
			AnchorType: "onchain_tx",
		}, nil
	}
	artifact, err := storage.DefaultStorageClient(opts.RPCURL).GetMintArtifact(opts.MintID)
	if err != nil {
		return nil, fmt.Errorf("artifact lookup failed (try --txid, which reads the permanent on-chain record): %w", err)
	}
	return &anchorResolution{
		MintID:      artifact.MintID,
		CID:         artifact.CID,
		CIDHashHex:  artifact.CIDHashHex,
		Subject:     artifact.Subject,
		AnchorType:  artifact.AnchorTagType,
		PayloadHash: artifact.PayloadHash,
	}, nil
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
	if opts.KeyFile == "" {
		return "", fmt.Errorf("--key is required: NFT anchor transactions must be locally signed with a full SPHINCS auth bundle before broadcast")
	}

	// Convert amount to nSPX (zero-value anchors are allowed: 0 nSPX)
	amountBig, ok := new(big.Int).SetString(opts.Amount, 10)
	if !ok {
		return "", fmt.Errorf("invalid amount: %s", opts.Amount)
	}
	weiAmount := new(big.Int).Mul(amountBig, big.NewInt(1e18))

	// A caller-supplied --nonce wins. Otherwise leave it nil so abi.Transact
	// resolves it from the node's getnonce — the registered method — instead of
	// this package's removed spx_getTransactionCount path, which always failed
	// and sent nonce 0.
	var nonce *uint64
	if opts.Nonce != 0 {
		nonce = &opts.Nonce
	}

	// Build the canonical transaction with ReturnData
	gasLimit := big.NewInt(parseIntOrDefault(opts.GasLimit, 50000))
	gasPrice := big.NewInt(parseIntOrDefault(opts.GasPrice, 1))

	tx := &types.Transaction{
		Sender:     opts.From,
		Receiver:   opts.To,
		Amount:     weiAmount,
		GasLimit:   gasLimit,
		GasPrice:   gasPrice,
		Nonce:      opts.Nonce,
		Timestamp:  time.Now().Unix(),
		ChainID:    7331, // Sphinx Mainnet chain ID (EIP-155 replay protection)
		ReturnData: returnData,
	}

	// Sign → encode → broadcast through the shared path, using this package's
	// canonical signer: tx.ID = tx.Hash() (common.SpxHash over the full struct
	// JSON) + a full SPHINCS auth bundle (also common.SpxHash).
	txID, err := abi.Transact(&abi.TransactOpts{
		Client:   abiRPC{},
		Signer:   abiSigner{keyFile: opts.KeyFile},
		NodeAddr: opts.RPCURL,
		ChainID:  tx.ChainID,
		Nonce:    nonce,
	}, tx)
	if err != nil {
		return "", fmt.Errorf("broadcast transaction: %w", err)
	}

	fmt.Printf("SUCCESS Transaction broadcast! TX ID: %s\n", txID)

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
		fmt.Printf("SUCCESS Transaction CONFIRMED in a block! (permanent on-chain anchor)\n")
	}

	return txID, nil
}

// transactionForSigning is a read-model used by the verify path to load an
// anchored transaction from the node. It is NOT used for signing — all
// signing goes through signTransactionCanonical (types.Transaction +
// common.SpxHash auth bundle).
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

// computeTxID was removed: the canonical transaction ID is derived by
// types.Transaction.Hash() (common.SpxHash over the full struct JSON) inside
// signTransactionCanonical. A bare sha256 over a partial struct produced IDs
// the node's SVM verifier would reject ("error executing op code 0x69 at
// pc=21: VERIFY failed").

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

	// NotUploaded reports that the recorded CID is a LOCAL CONTENT HASH
	// (spxhash-…), not an IPFS identifier: the mint ran with IPFS disabled or
	// without any reachable backend, so nothing was ever uploaded and no
	// gateway can serve it. Reporting this distinctly matters because it used
	// to be indistinguishable from a transient gateway outage — both just
	// failed to fetch.
	NotUploaded bool `json:"not_uploaded,omitempty"`
	// Durability classifies retrievability: DurabilityRemotePinned when a
	// public gateway served the content (so it does not depend on the
	// minter's machine), DurabilityLocalOnly when only the local daemon could,
	// DurabilityNotReachable when no backend could, or DurabilityNotUploaded.
	Durability string `json:"durability,omitempty"`
	// ContentSHA256 is the digest of the fetched content, and PayloadHashMatch
	// records whether it matched the payload hash the mint recorded (only
	// available on the artifact path, since the on-chain anchor tag carries
	// commitments but not the payload hash).
	ContentSHA256    string `json:"content_sha256,omitempty"`
	PayloadHashMatch *bool  `json:"payload_hash_match,omitempty"`
	Error            string `json:"error,omitempty"`
}

// Durability verdicts now live in the storage package (storage.Durability), so
// the "ipfs verify" output and the wallet GUI cannot describe the same
// underlying state two different ways. Scripts can compare against those
// stable strings: "remote-pinned" / "local-only" / "not-reachable" /
// "not-uploaded" (see storage.Durability.String).

// fileMatchesRecordedCID reports whether data is the payload a recorded
// commitment describes.
//
// For a local-only commitment (spxhash-<hex>) this is a STRONG check: the
// identifier is derived from the bytes, so recomputing it proves the file is
// byte-identical to the original. That is what makes "ipfs repin" safe — it
// cannot be used to attach an arbitrary (or someone else's) file to an anchor.
//
// For a real IPFS CID the check is not locally possible: a CID depends on the
// multihash and chunking strategy the backend used, which this command cannot
// reproduce. The second return value reports which case applied, so callers
// state "unknown" rather than implying the file was verified. The checkable
// path returns the expected identifier too, so a failure can say what the file
// actually is.
func fileMatchesRecordedCID(recordedCID string, data []byte) (matches bool, checkable bool, expected string) {
	if !storage.IsLocalOnlyCommitment(recordedCID) {
		return false, false, ""
	}
	expected = storage.FallbackCIDFor(data)
	return expected == strings.TrimSpace(recordedCID), true, expected
}

// RunRepin re-pins the payload behind an already-minted anchor, so media that
// only ever lived on the minter's disk can become retrievable going forward.
//
// It deliberately does NOT (and cannot) change the anchor: the on-chain tag
// commits to the CID recorded at mint time, and that commitment is immutable.
// What it gives you is a durable copy under a REAL CID, plus the per-anchor
// evidence an audit needs.
func RunRepin(opts RepinOptions) (*RepinResult, error) {
	if opts.RPCURL == "" {
		return nil, errors.New("rpc endpoint is required")
	}
	if opts.MintID == "" && opts.TxID == "" {
		return nil, errors.New("either --mint-id or --txid is required")
	}
	if opts.File == "" {
		return nil, errors.New("--file is required: a re-pin must push the same bytes the anchor committed to")
	}

	result := &RepinResult{OnChainAnchorUnchanged: true}

	resolved, err := resolveAnchor(opts)
	if err != nil {
		result.Error = err.Error()
		fmt.Printf("ERROR %s\n", result.Error)
		return result, nil
	}
	result.MintID = resolved.MintID
	result.Subject = resolved.Subject
	result.AnchorType = resolved.AnchorType
	result.OldCID = resolved.CID
	result.WasLocalOnlyCommitment = storage.IsLocalOnlyCommitment(resolved.CID)

	data, err := os.ReadFile(opts.File)
	if err != nil {
		result.Error = fmt.Sprintf("read file: %v", err)
		fmt.Printf("ERROR %s\n", result.Error)
		return result, nil
	}

	// Prove the file is the original before pushing it anywhere. Getting this
	// wrong would publish bytes under a commitment that does not describe them.
	matches, checkable, expected := fileMatchesRecordedCID(resolved.CID, data)
	switch {
	case checkable && !matches:
		result.Error = fmt.Sprintf(
			"refusing to re-pin: %s does not match the anchor's recorded commitment (anchor=%s, file=%s). Re-pinning different bytes would create a retrievable object that contradicts the on-chain anchor.",
			opts.File, resolved.CID, expected)
		fmt.Printf("ERROR %s\n", result.Error)
		return result, nil
	case checkable:
		result.FileVerifiedAgainstAnchor = true
		fmt.Printf("SUCCESS File proven identical to the anchor's commitment (spxhash recomputed and matched)\n")
	default:
		// A real CID cannot be recomputed locally. Fall back to the recorded
		// payload digest when the artifact supplied one, and say plainly when
		// nothing could be checked.
		if strings.TrimSpace(resolved.PayloadHash) != "" {
			if strings.EqualFold(sha256Hex(data), strings.TrimSpace(resolved.PayloadHash)) {
				result.FileVerifiedAgainstAnchor = true
				fmt.Printf("SUCCESS File matches the mint's recorded payload hash\n")
			} else {
				result.Error = fmt.Sprintf("refusing to re-pin: %s does not match the mint's recorded payload hash", opts.File)
				fmt.Printf("ERROR %s\n", result.Error)
				return result, nil
			}
		} else {
			fmt.Printf("WARNING Could not verify %s against the recorded CID (%s): a real CID is not locally recomputable and the anchor carries no payload hash. Re-pinning anyway, on the assumption you supplied the original.\n",
				opts.File, resolved.CID)
		}
	}

	ipfsCfg := storage.DefaultConfig()
	if opts.IPFSAddr != "" {
		ipfsCfg.IPFSAddr = opts.IPFSAddr
	}
	if opts.GatewayBaseURL != "" {
		ipfsCfg.GatewayBaseURL = opts.GatewayBaseURL
	}
	client := storage.NewClient(ipfsCfg)

	pin := client.PinPayload(data, filepath.Base(opts.File))
	if !pin.Uploaded() {
		result.Error = fmt.Sprintf("re-pin failed: %v", pin.Warn)
		fmt.Printf("ERROR %s\n", result.Error)
		return result, nil
	}
	result.NewCID = pin.CID
	result.Durability = pin.Durability.String()
	if pin.Warn != nil {
		fmt.Printf("WARNING %v\n", pin.Warn)
	}

	fmt.Printf("\n══════════════════ RE-PIN RESULT ══════════════════\n")
	fmt.Printf(" Mint ID:            %s\n", result.MintID)
	fmt.Printf(" Recorded CID:       %s%s\n", result.OldCID, localOnlyNote(result.WasLocalOnlyCommitment))
	fmt.Printf(" Re-pinned CID:      %s\n", result.NewCID)
	fmt.Printf(" Durability:         %s\n", result.Durability)
	fmt.Printf(" File verified:      %v\n", result.FileVerifiedAgainstAnchor)
	fmt.Printf("\nNOTE The on-chain anchor is UNCHANGED: it still commits to %s.\n", result.OldCID)
	if result.NewCID != result.OldCID {
		fmt.Printf("     The newly retrievable copy is addressed by %s, which differs\n", result.NewCID)
		fmt.Printf("     from the anchored value because the original was a content hash,\n")
		fmt.Printf("     not a CID. Verifiers reading the chain will still see %s.\n", result.OldCID)
	}
	fmt.Printf("═══════════════════════════════════════════════════\n")
	return result, nil
}

// localOnlyNote annotates an audit result so a scan output is self-explanatory.
func localOnlyNote(wasLocalOnly bool) string {
	if wasLocalOnly {
		return "   <-- NEVER UPLOADED (local content hash)"
	}
	return ""
}

// sha256Hex computes sha256 of data and returns hex string.
// NOTE: this is an OFF-CHAIN content-integrity digest only (like an IPFS-style
// content hash for payloadHash). It is never re-derived by the node's SVM
// verifier, so it does not participate in transaction signature verification —
// all on-chain auth hashes use common.SpxHash.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
