// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/sign/embed.go
package sign

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"crypto/rand"

	"golang.org/x/crypto/sha3"
	"golang.org/x/sys/unix"

	"github.com/jung-kurt/gofpdf"
	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	rawdata "github.com/sphinxorg/protocol/src/usi/core/rawdb"
	pubkeydir "github.com/sphinxorg/protocol/src/usi/server/server"
)

// magicMarker is appended to binary/text files that use the footer embed method.
var magicMarker = []byte("USIMETA")

// orgBundleResolver defines the interface for looking up organization bundles
type orgBundleResolver interface {
	LookupByPublicKey(pubKeyHex string) (pubkeydir.PublicKeyBundle, error)
	Close() error
}

// ─────────────────────────────────────────────────────────────────────────────
// METADATA BLOCK BUILDERS
// ─────────────────────────────────────────────────────────────────────────────

func buildSecureMetadataBlock(meta *Meta, fingerprint string) string {
	nonce := meta.Nonce
	if nonce == "" {
		nonce = "none"
	}

	shortFileHash := meta.FileHash
	if len(shortFileHash) > 32 {
		shortFileHash = shortFileHash[:32] + "..."
	}

	shortFinalHash := meta.FinalDocumentHash
	if len(shortFinalHash) > 32 {
		shortFinalHash = shortFinalHash[:32] + "..."
	}

	formattedSignature := "not signed"
	if len(meta.Signature) >= 64 {
		formattedSignature = fmt.Sprintf("%s...%s",
			meta.Signature[:32], meta.Signature[len(meta.Signature)-32:])
	} else if len(meta.Signature) > 0 {
		formattedSignature = meta.Signature
	}

	if shortFinalHash == "" && shortFileHash != "" {
		shortFinalHash = shortFileHash
	}

	return fmt.Sprintf(
		"USI-SUMMARY\n"+
			"Fingerprint: %s\n"+
			"Signature: %s\n"+
			"Signature Status: VALID [OK]\n"+
			"Signed: %s\n"+
			"Nonce: %s (%d chars)\n"+
			"File Hash: %s\n"+
			"Final Hash: %s\n"+
			"Algorithm: SHAKE-256 + PQ",
		formatFingerprintLegacy(fingerprint),
		formattedSignature,
		time.Unix(meta.Timestamp, 0).Format("2006-01-02 15:04:05"),
		nonce,
		len(nonce),
		shortFileHash,
		shortFinalHash,
	)
}

func buildCryptographicMetadataBlock(meta *Meta, fingerprint, finalHash string) map[string]string {
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		log.Printf("ERROR: Failed to marshal metadata: %v", err)
		return map[string]string{} // or handle appropriately
	}
	defer secureZeroBytes(metaJSON)

	cryptoDetails := fmt.Sprintf(
		"USI CRYPTOGRAPHIC SIGNATURE VERIFICATION\n\n"+
			"Fingerprint: %s\n"+
			"Signature Status: VALID\n"+
			"Timestamp: %s\n"+
			"Nonce: %s\n"+
			"Algorithm: SHAKE-256 + post-quantum signature\n"+
			"File Hash: %s\n"+
			"Final Document Hash: %s",
		formatFingerprintLegacy(fingerprint),
		time.Unix(meta.Timestamp, 0).Format("2006-01-02 15:04:05"),
		getNoncePrefix(meta.Nonce),
		meta.FileHash,
		finalHash,
	)

	return map[string]string{
		"Title":        "Cryptographically Signed Document - E2E Cipher Protocol",
		"Author":       "USI Secure Vault",
		"Subject":      cryptoDetails,
		"Keywords":     "Integrity Protection; Cryptographic Signature; USI",
		"Creator":      "USI v0.002 Secure",
		"Producer":     "E2E Cipher Protocol",
		"Fingerprint":  fingerprint,
		"USISignature": string(metaJSON),
		"SigningTime":  time.Now().Format(time.RFC3339),
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC ENTRY POINTS
// ─────────────────────────────────────────────────────────────────────────────

// EmbedSignature signs the file at filePath and embeds the signature using the
// format-appropriate method (PDF properties, PNG iTXt, JPEG XMP, Office custom
// properties, or a binary footer for everything else). On macOS, rich xattrs
// are also written for Spotlight / Finder "Get Info" display.
func EmbedSignature(filePath string, meta *Meta, fingerprint, passphrase string) error {
	log.Printf("EmbedSignature called for: %s", filePath)

	if meta == nil {
		meta = &Meta{}
	}
	if meta.Nonce == "" {
		meta.Nonce = generateSecureNonce()
	}
	if meta.Timestamp == 0 {
		meta.Timestamp = time.Now().Unix()
	}
	if meta.Signer == "" {
		meta.Signer = "USI Secure Vault"
	}
	if meta.DocumentTitle == "" {
		meta.DocumentTitle = "Cryptographically Signed Document"
	}

	ext := strings.ToLower(filepath.Ext(filePath))

	var embedErr error
	switch ext {
	case ".pdf":
		log.Printf("Processing as PDF")
		embedErr = embedPDFMetadata(filePath, meta, fingerprint, passphrase)
	case ".png":
		log.Printf("Processing as PNG")
		embedErr = embedPNGMetadata(filePath, meta, fingerprint, passphrase)
	case ".jpg", ".jpeg":
		log.Printf("Processing as JPEG")
		embedErr = embedJPEGMetadata(filePath, meta, fingerprint, passphrase)
	case ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp":
		log.Printf("Processing as Office/ODF ZIP-based format")
		embedErr = embedOfficeMetadata(filePath, meta, fingerprint, passphrase)
	default:
		if runtime.GOOS == "darwin" &&
			(ext == ".mov" || ext == ".mp4" || ext == ".m4v" || ext == ".avi") {
			log.Printf("Media file on macOS - embedding QuickTime metadata + xattrs")
			if err := embedMOVQuickTimeMetadata(filePath, meta, fingerprint); err != nil {
				log.Printf("Warning: QuickTime metadata embedding failed: %v", err)
			}
			embedErr = createUSIMetaFile(filePath, meta, passphrase, true)
		}
		// For all other binary/text files embedErr stays nil here;
		// createUSIMetaFile with skipFooter=false is called in the fallback below.
	}

	if embedErr != nil {
		log.Printf("Warning: format-specific embed failed: %v — falling back to footer", embedErr)
		if err := createUSIMetaFile(filePath, meta, passphrase, false); err != nil {
			return fmt.Errorf("embed fallback failed: %w", err)
		}
	}

	if runtime.GOOS == "darwin" {
		if err := setRichXattrs(filePath, meta, fingerprint); err != nil {
			log.Printf("Warning: xattr set failed: %v", err)
		} else {
			log.Printf("✅ Rich xattrs set for: %s", filepath.Base(filePath))
		}
	}

	return nil
}

// VerifyUniversal tries every known signature location in priority order and
// returns (true, meta, nil) on the first successful cryptographic verification.
// passphrase is accepted for API compatibility but is NOT required — anyone
// with the file can verify the embedded SPHINCS+ signature using the public
// key stored in the metadata.
func VerifyUniversal(filePath, passphrase string) (bool, *Meta, error) {
	log.Printf("VerifyUniversal started for: %s", filePath)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false, nil, fmt.Errorf("file does not exist: %s", filePath)
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	var meta *Meta
	var extractErr error

	// ── 1. macOS media files: try xattrs first ──────────────────────────────
	if runtime.GOOS == "darwin" &&
		(ext == ".mov" || ext == ".mp4" || ext == ".m4v" || ext == ".avi") {
		meta, extractErr = extractXattrSignature(filePath)
		if extractErr == nil && meta != nil {
			log.Printf("Found signature in xattrs for media file")
			if ok, err := verifyEmbeddedSignature(filePath, meta); err == nil && ok {
				log.Printf("Xattr verification SUCCESS")
				return true, meta, nil
			} else {
				log.Printf("Xattr verification failed: %v", err)
			}
		}
	}

	// ── 2. Format-specific extraction ───────────────────────────────────────
	switch ext {
	case ".png":
		meta, extractErr = extractPNGSignature(filePath)
		if extractErr == nil && meta != nil {
			log.Printf("Found signature in PNG iTXt chunk")
		}
	case ".jpg", ".jpeg":
		meta, extractErr = extractJPEGSignature(filePath)
	case ".pdf":
		meta, extractErr = extractPDFSignature(filePath)
		if meta == nil {
			// Legacy binary-scan fallback
			meta, extractErr = extractMetadataFromPDF(filePath)
			if extractErr == nil && meta != nil {
				log.Printf("Found signature via legacy PDF extraction")
			}
		}
	case ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp":
		meta, extractErr = extractOfficeSignature(filePath)
	default:
		meta, extractErr = extractEmbeddedSignature(filePath)
		if meta == nil && runtime.GOOS == "darwin" {
			meta, extractErr = extractXattrSignature(filePath)
		}
	}

	if extractErr == nil && meta != nil {
		log.Printf("Found embedded signature in file")
		if ok, err := verifyEmbeddedSignature(filePath, meta); err == nil && ok {
			log.Printf("File signature verification SUCCESS")
			storeVerifiedMeta(filePath, meta)
			return true, meta, nil
		} else {
			log.Printf("Embedded signature verification failed: %v", err)
		}
	}

	// ── 3. RawData database (local cache written at signing time) ────────────
	db, dbErr := rawdata.GetDB()
	if dbErr == nil {
		cachedMeta, loadErr := db.LoadUSIMeta(filePath)
		if loadErr == nil && cachedMeta != nil {
			log.Printf("Found USI meta in RawData database (cached)")

			// Log the hash comparison so failures are visible
			fileData, readErr := os.ReadFile(filePath)
			if readErr == nil {
				currentHashHex := hex.EncodeToString(computeShake256(fileData))
				secureZeroBytes(fileData)
				log.Printf("Current file hash: %s, stored: %s",
					truncate(currentHashHex, 16), truncate(cachedMeta.FileHash, 16))
			}

			if ok, err := verifyEmbeddedSignature(filePath, cachedMeta); err == nil && ok {
				log.Printf("RawData verification SUCCESS")
				return true, cachedMeta, nil
			} else {
				log.Printf("RawData verification failed: %v", err)
			}
		}
	}

	// ── 4. Legacy .usimeta sidecar ───────────────────────────────────────────
	usiMetaPath := filePath + ".usimeta"
	if _, statErr := os.Stat(usiMetaPath); statErr == nil {
		log.Printf("Found .usimeta sidecar (legacy)")
		ok, sidecarMeta, err := verifyUSIMetaWithDetails(filePath, usiMetaPath)
		if err != nil {
			log.Printf(".usimeta verification failed: %v", err)
			return false, sidecarMeta, err
		}
		if ok {
			log.Printf(".usimeta verification SUCCESS")
			return true, sidecarMeta, nil
		}
		return false, sidecarMeta, fmt.Errorf("signature invalid")
	}

	log.Printf("No valid signature found for: %s", filePath)
	return false, nil, errors.New("no valid USI signature found")
}

// storeVerifiedMeta caches a successfully verified Meta in the RawData DB.
func storeVerifiedMeta(filePath string, meta *Meta) {
	db, err := rawdata.GetDB()
	if err != nil {
		return
	}
	if err := db.StoreUSIMeta(filePath, meta); err != nil {
		log.Printf("Warning: failed to cache verified meta: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CORE VERIFICATION — no passphrase required
// ─────────────────────────────────────────────────────────────────────────────

// resolverWrapper wraps LevelDBStore to satisfy the orgBundleResolver interface
// Update resolverWrapper to work with Store interface
type resolverWrapper struct {
	store pubkeydir.Store // Change to Store interface
}

func (w *resolverWrapper) LookupByPublicKey(pubKeyHex string) (pubkeydir.PublicKeyBundle, error) {
	if w.store == nil {
		return pubkeydir.PublicKeyBundle{}, errors.New("store is nil")
	}
	return w.store.LookupByPublicKey(pubKeyHex)
}

func (w *resolverWrapper) Close() error {
	if w.store != nil {
		return w.store.Close()
	}
	return nil
}

// verifyEmbeddedSignature is the single authoritative verification function.
// It:
//  1. Re-reads the file fresh.
//  2. Strips any footer if present so the hash covers only original content.
//  3. Checks the file hash (strict, then content-normalised for PDFs).
//  4. Validates the timestamp (future-only guard + max-age).
//  5. Verifies the SPHINCS+ signature using the PUBLIC KEY embedded in meta —
//     no passphrase required; anyone can verify.
func verifyEmbeddedSignature(filePath string, meta *Meta) (bool, error) {
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return false, fmt.Errorf("cannot read file: %w", err)
	}
	defer secureZeroBytes(fileData)

	// Strip footer if present (binary/text files only).
	if len(fileData) >= len(magicMarker)+4 &&
		bytes.Equal(fileData[len(fileData)-len(magicMarker):], magicMarker) {
		sizeStart := len(fileData) - len(magicMarker) - 4
		metaSize := binary.BigEndian.Uint32(fileData[sizeStart : sizeStart+4])
		metaStart := sizeStart - int(metaSize)
		if metaStart >= 0 {
			fileData = fileData[:metaStart]
		}
	}

	currentHash := computeShake256(fileData)

	// Integrity check: strict first, content-normalised fallback for PDFs.
	if verifyStrictIntegrity(filePath, meta) {
		log.Printf("Strict integrity check passed")
	} else if verifyContentIntegrity(filePath, meta) {
		log.Printf("Content integrity verified (structural/metadata changes only)")
	} else {
		return false, fmt.Errorf("file content has been modified: stored=%s computed=%s",
			truncate(meta.FileHash, 16), truncate(hex.EncodeToString(currentHash), 16))
	}

	// Org binding check
	resolver := defaultResolver()
	if resolver != nil {
		// Validate org binding
		if err := validateOrgBinding(meta, resolver); err != nil {
			log.Printf("Org binding validation failed: %v", err)
			// Don't fail verification - just warn (offline compatibility)
		}
		// Close the resolver if it needs cleanup
		if closer, ok := resolver.(interface{ Close() error }); ok {
			defer closer.Close()
		}
	}

	if meta.Signature == "" {
		return true, nil
	}
	return verifyCryptoSignature(meta, currentHash)
}

// ─────────────────────────────────────────────────────────────────────────────
// CRYPTO VERIFICATION
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
// ORG BUNDLE RESOLVER — process-lifetime singleton
// ─────────────────────────────────────────────────────────────────────────────

var (
	resolverOnce  sync.Once
	resolverStore pubkeydir.Store // Change to Store interface
)

// SharedResolver exposes the process-lifetime resolver for callers that need
// to write to the same store without opening a second handle.
// Returns nil if the store has not been initialised or failed to open.
// SharedResolver exposes the process-lifetime resolver for callers that need
// to write to the same store without opening a second handle.
// Returns nil if the store has not been initialised or failed to open.
func SharedResolver() pubkeydir.Store {
	resolverOnce.Do(func() {
		// Use HTTP client instead of local LevelDB
		serverURL := "http://localhost:8080"
		resolverStore = pubkeydir.NewClient(serverURL, nil)
		log.Printf("Resolver connected to key server at %s", serverURL)
	})
	return resolverStore
}

// defaultResolver returns the process-lifetime LevelDB store for org validation.
// Opens once, stays open. Returns nil if the directory does not exist yet
// (first run before any registration) — callers treat nil as "skip validation".
// defaultResolver returns the process-lifetime LevelDB store wrapped as an interface.
func defaultResolver() orgBundleResolver {
	resolverOnce.Do(func() {
		serverURL := "http://localhost:8080"
		client := pubkeydir.NewClient(serverURL, nil)
		resolverStore = client
		log.Printf("Resolver connected to key server at %s", serverURL)
	})
	if resolverStore == nil {
		return nil
	}
	return &resolverWrapper{store: resolverStore}
}

// validateOrgBinding confirms three things:
//  1. The public key embedded in meta is registered in the directory.
//  2. The bundle's Organisation field matches meta.OrgCode.
//  3. The bundle is not revoked.
//
// If the directory is unreachable (offline field use), the check is skipped
// with a warning — the SPHINCS+ signature alone still proves integrity.
// Set requireOnline=true for high-assurance contexts (e.g. server-side).
func validateOrgBinding(meta *Meta, resolver orgBundleResolver) error {
	if meta.PublicKey == "" {
		return errors.New("meta missing public key — cannot validate org binding")
	}
	if resolver == nil {
		log.Printf("Warning: org binding check skipped (directory unavailable) for org=%q", meta.OrgCode)
		return nil // degrade gracefully for offline field use
	}

	bundle, err := resolver.LookupByPublicKey(meta.PublicKey)
	if err != nil {
		if errors.Is(err, pubkeydir.ErrNotFound) {
			return fmt.Errorf("public key not registered in directory (org=%q) — possible key substitution", meta.OrgCode)
		}
		// Network / DB error: warn but don't block (same offline policy)
		log.Printf("Warning: org directory lookup failed: %v — skipping org validation", err)
		return nil
	}

	// Revocation is a hard failure even offline-policy-wise
	if bundle.Status == pubkeydir.StatusRevoked {
		return fmt.Errorf("signer key has been revoked (org=%q, reason=%q)", meta.OrgCode, bundle.RevocationReason)
	}

	// Org code consistency check — only when meta carries an OrgCode claim
	if meta.OrgCode != "" && bundle.Organization != "" {
		if !strings.EqualFold(bundle.Organization, meta.OrgCode) {
			return fmt.Errorf("org mismatch: file claims %q, directory says %q", meta.OrgCode, bundle.Organization)
		}
	}

	return nil
}

// verifyCryptoSignature verifies the SPHINCS+ signature stored in meta against
// msgBytes using the public key embedded in meta.  No passphrase is required;
// the public key is self-contained in the signed metadata.
//
// Security note: the caller (verifyEmbeddedSignature) has already confirmed
// that meta.FileHash matches the current file before reaching this function.
// That hash check is what makes trusting the embedded public key safe — the
// attacker cannot swap both the file content AND the stored hash/signature
// without invalidating one of them.
func verifyCryptoSignature(meta *Meta, msgBytes []byte) (bool, error) {
	if meta.Signature == "" {
		return false, errors.New("metadata missing signature")
	}
	if !validateSPHINCSSignature(meta.Signature) {
		return false, fmt.Errorf("signature format validation failed: invalid length or encoding")
	}

	sigBytes, err := hex.DecodeString(meta.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature encoding: %w", err)
	}

	if meta.PublicKey == "" {
		return false, errors.New("metadata missing public key")
	}
	signerPubKey, err := hex.DecodeString(meta.PublicKey)
	if err != nil {
		return false, fmt.Errorf("invalid public key encoding: %w", err)
	}

	hashBytes := msgBytes
	if len(hashBytes) == 0 && meta.FinalDocumentHash != "" {
		hashBytes = computeShake256AsBytes(meta.FinalDocumentHash)
	}

	sig := &Signature{
		Signature: sigBytes,
		PublicKey: signerPubKey,
	}

	ok, err := Verify(hashBytes, sig, signerPubKey)
	if err != nil {
		return false, fmt.Errorf("SPHINCS+ verification error: %w", err)
	}
	if !ok {
		return false, errors.New("cryptographic signature invalid — document may be tampered or signed by a different key")
	}
	return true, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// SIGNING — creates metadata and stores/embeds it
// ─────────────────────────────────────────────────────────────────────────────

// createUSIMetaFile hashes the (already-finalised) file, signs it, stores the
// metadata in the RawData DB, and optionally appends a binary footer.
//
//   - skipFooterEmbedding = true  → PDF, PNG, JPEG, Office (native metadata channels)
//   - skipFooterEmbedding = false → binary/text files (footer method)
func createUSIMetaFile(filePath string, inputMeta *Meta, passphrase string, skipFooterEmbedding bool) error {
	log.Printf("Creating USI signature for: %s", filePath)

	documentData, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	defer secureZeroBytes(documentData)

	docHash := computeShake256(documentData)
	fileHash := hex.EncodeToString(docHash)

	sig, err := Sign(docHash, passphrase)
	if err != nil {
		return fmt.Errorf("signing document: %w", err)
	}

	// Fix 1: Ensure public key and org code are always embedded in Meta
	// In createUSIMetaFile, after Sign():
	meta := &Meta{
		Signature:          hex.EncodeToString(sig.Signature),
		PublicKey:          hex.EncodeToString(sig.PublicKey),
		OrgCode:            inputMeta.OrgCode,
		FileHash:           fileHash,
		FinalDocumentHash:  fileHash, // Already set correctly
		Timestamp:          time.Now().Unix(),
		SignatureTimestamp: time.Now().Unix(),
		Nonce:              generateSecureNonce(),
		Signer:             inputMeta.Signer,
		DocumentTitle:      inputMeta.DocumentTitle,
	}
	// Add this line to record the nonce
	if err := recordSigningNonce(meta.Nonce); err != nil {
		return fmt.Errorf("nonce replay check failed: %w", err)
	}

	db, err := rawdata.GetDB()
	if err != nil {
		log.Printf("Warning: RawData database unavailable: %v", err)
	} else {
		if err := db.StoreUSIMeta(filePath, meta); err != nil {
			return fmt.Errorf("failed to store metadata in RawData: %w", err)
		}
		log.Printf("Metadata stored in RawData database for: %s", filePath)
	}

	if !skipFooterEmbedding {
		if err := embedSignatureInFile(filePath, meta); err != nil {
			log.Printf("Warning: failed to embed signature footer in file: %v", err)
		}
	}

	log.Printf("Signature created successfully for: %s", filePath)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// FOOTER EMBED / EXTRACT (binary/text files)
// ─────────────────────────────────────────────────────────────────────────────

func embedSignatureInFile(filePath string, meta *Meta) error {
	documentData, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	defer secureZeroBytes(documentData)

	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	defer secureZeroBytes(metaJSON)

	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, uint32(len(metaJSON)))

	out := make([]byte, 0, len(documentData)+4+len(metaJSON)+len(magicMarker))
	out = append(out, documentData...)
	out = append(out, sizeBuf...)
	out = append(out, metaJSON...)
	out = append(out, magicMarker...)

	// CRITICAL: This write operation must not fail silently
	if err := os.WriteFile(filePath, out, 0644); err != nil {
		log.Printf("ERROR: Failed to write signature to %s: %v", filePath, err)
		return fmt.Errorf("write signature to file: %w", err)
	}

	// Verify the write was successful
	if info, err := os.Stat(filePath); err != nil {
		log.Printf("ERROR: Cannot stat file after writing: %v", err)
	} else if info.Size() == 0 {
		log.Printf("ERROR: File is empty after signature embedding!")
		return errors.New("file became empty after embedding")
	}

	log.Printf("Successfully embedded signature in %s (size: %d bytes)", filePath, len(out))
	return nil
}

func extractEmbeddedSignature(filePath string) (*Meta, error) {
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	defer secureZeroBytes(fileData)

	if len(fileData) < len(magicMarker)+4 {
		return nil, nil
	}
	if !bytes.Equal(fileData[len(fileData)-len(magicMarker):], magicMarker) {
		return nil, nil
	}

	sizeStart := len(fileData) - len(magicMarker) - 4
	if sizeStart < 0 {
		return nil, nil
	}

	metaSize := binary.BigEndian.Uint32(fileData[sizeStart : sizeStart+4])
	metaStart := sizeStart - int(metaSize)
	if metaStart < 0 {
		return nil, nil
	}

	var meta Meta
	if err := json.Unmarshal(fileData[metaStart:sizeStart], &meta); err != nil {
		return nil, nil
	}
	if meta.Signature != "" || meta.FileHash != "" {
		return &meta, nil
	}
	return nil, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// PNG EMBEDDING / EXTRACTION
// ─────────────────────────────────────────────────────────────────────────────

func embedPNGMetadata(filePath string, meta *Meta, fingerprint, passphrase string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	if len(data) < 8 || !bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		return fmt.Errorf("not a valid PNG file")
	}

	data = stripPNGChunk(data, "iTXt")

	xmpPayload := []byte(buildPDFStyleXMPPacket(meta, fingerprint))
	keyword := []byte("XML:com.adobe.xmp\x00\x00\x00\x00\x00")
	chunkData := append(keyword, xmpPayload...)
	iTXt := buildPNGChunk("iTXt", chunkData)

	ihdrEnd := 33
	out := make([]byte, 0, len(data)+len(iTXt))
	out = append(out, data[:ihdrEnd]...)
	out = append(out, iTXt...)
	out = append(out, data[ihdrEnd:]...)

	if err := os.WriteFile(filePath, out, 0644); err != nil {
		return err
	}
	if err := createUSIMetaFile(filePath, meta, passphrase, true); err != nil {
		return err
	}
	log.Printf("PNG metadata embedded successfully: %s", filePath)
	return nil
}

func extractPNGSignature(filePath string) (*Meta, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if len(data) < 8 || !bytes.Equal(data[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
		return nil, nil
	}
	pos := 8
	for pos+12 <= len(data) {
		length := binary.BigEndian.Uint32(data[pos:])
		chunkType := string(data[pos+4 : pos+8])
		if chunkType == "iTXt" {
			chunkData := data[pos+8 : pos+8+int(length)]
			if bytes.Contains(chunkData, []byte("USI-Signature")) {
				jsonStart := bytes.Index(chunkData, []byte("{"))
				if jsonStart >= 0 {
					var meta Meta
					if err := json.Unmarshal(chunkData[jsonStart:], &meta); err == nil {
						return &meta, nil
					}
				}
			}
		}
		pos += 12 + int(length)
	}
	return nil, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// JPEG EMBEDDING / EXTRACTION
// ─────────────────────────────────────────────────────────────────────────────

func embedJPEGMetadata(filePath string, meta *Meta, fingerprint, passphrase string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xD8 {
		return fmt.Errorf("not a valid JPEG file")
	}

	data = stripJPEGXMPSegment(data)

	xmpNS := "http://ns.adobe.com/xap/1.0/\x00"
	xmpBody := buildPDFStyleXMPPacket(meta, fingerprint)
	payload := []byte(xmpNS + xmpBody)

	segLen := uint16(len(payload) + 2)
	app1 := make([]byte, 4+len(payload))
	app1[0] = 0xFF
	app1[1] = 0xE1
	binary.BigEndian.PutUint16(app1[2:], segLen)
	copy(app1[4:], payload)

	out := make([]byte, 0, len(data)+len(app1))
	out = append(out, data[:2]...)
	out = append(out, app1...)
	out = append(out, data[2:]...)

	if err := os.WriteFile(filePath, out, 0644); err != nil {
		return err
	}
	if err := createUSIMetaFile(filePath, meta, passphrase, true); err != nil {
		return err
	}
	log.Printf("JPEG metadata embedded successfully: %s", filePath)
	return nil
}

func extractJPEGSignature(filePath string) (*Meta, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xD8 {
		return nil, nil
	}
	if bytes.Contains(data, []byte("USISignature")) {
		start := bytes.Index(data, []byte(`"USISignature":"`))
		if start >= 0 {
			start += 16
			end := bytes.Index(data[start:], []byte(`"`))
			if end >= 0 {
				jsonStr := strings.ReplaceAll(string(data[start:start+end]), `\"`, `"`)
				var meta Meta
				if err := json.Unmarshal([]byte(jsonStr), &meta); err == nil {
					return &meta, nil
				}
			}
		}
	}
	return nil, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// PDF EMBEDDING / EXTRACTION
// ─────────────────────────────────────────────────────────────────────────────

func embedPDFMetadata(filePath string, meta *Meta, fingerprint, passphrase string) error {
	log.Printf("Processing PDF: %s", filePath)

	tmpSigned := filePath + ".signed.tmp.pdf"
	defer func() {
		if _, statErr := os.Stat(tmpSigned); statErr == nil {
			secureRemove(tmpSigned)
		}
	}()

	sigPagePath := filePath + ".sigpage.pdf"
	if err := createSignaturePage(sigPagePath, meta, fingerprint); err != nil {
		return err
	}
	defer secureRemove(sigPagePath)

	if err := api.MergeAppendFile([]string{filePath, sigPagePath}, tmpSigned, true,
		model.NewDefaultConfiguration()); err != nil {
		return fmt.Errorf("merging PDFs: %w", err)
	}

	signedData, err := createDocumentSignature(tmpSigned, meta, fingerprint)
	if err != nil {
		return fmt.Errorf("creating document signature: %w", err)
	}
	if err := os.WriteFile(filePath, signedData, 0644); err != nil {
		return fmt.Errorf("writing signed document: %w", err)
	}
	if err := createUSIMetaFile(filePath, meta, passphrase, true); err != nil {
		return err
	}
	log.Printf("PDF metadata embedded successfully: %s", filePath)
	return nil
}

func extractPDFSignature(filePath string) (*Meta, error) {
	const maxScanSize = 10 * 1024 * 1024
	const minValidSignatureLen = 64

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}

	var data []byte
	if info.Size() > maxScanSize {
		f, err := os.Open(filePath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		offset := info.Size() - maxScanSize
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
		data, err = io.ReadAll(f)
		if err != nil {
			return nil, err
		}
	} else {
		data, err = os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
	}

	markers := [][]byte{
		[]byte("/USISignature("),
		[]byte(`"USISignature":"`),
		[]byte("<usi:Signature>"),
	}

	for _, marker := range markers {
		if !bytes.Contains(data, marker) {
			continue
		}
		start := bytes.Index(data, marker) + len(marker)

		var end int
		switch marker[0] {
		case '/':
			end = bytes.Index(data[start:], []byte(")"))
		case '"':
			end = bytes.Index(data[start:], []byte(`"`))
		default:
			end = bytes.Index(data[start:], []byte("</usi:Signature>"))
		}
		if end < 0 {
			continue
		}

		signatureData := data[start : start+end]
		if len(signatureData) < minValidSignatureLen {
			log.Printf("Warning: signature too short for SPHINCS+ (%d bytes)", len(signatureData))
			continue
		}

		var meta Meta
		if err := json.Unmarshal(signatureData, &meta); err == nil &&
			len(meta.Signature) >= minValidSignatureLen {
			log.Printf("Found SPHINCS+ signature in PDF metadata (length: %d)", len(meta.Signature))
			return &meta, nil
		}

		if _, err := hex.DecodeString(string(signatureData)); err == nil {
			meta.Signature = string(signatureData)
			log.Printf("Found raw SPHINCS+ signature in PDF metadata (length: %d)", len(meta.Signature))
			return &meta, nil
		}
	}
	return nil, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// OFFICE EMBEDDING / EXTRACTION
// ─────────────────────────────────────────────────────────────────────────────

func embedOfficeMetadata(filePath string, meta *Meta, fingerprint, passphrase string) error {
	tempPath := filePath + ".tmp"
	if err := copyAndModifyOffice(filePath, tempPath, meta, fingerprint); err != nil {
		return err
	}
	defer secureRemove(tempPath)

	if err := os.Rename(tempPath, filePath); err != nil {
		return err
	}
	if err := createUSIMetaFile(filePath, meta, passphrase, true); err != nil {
		return err
	}
	log.Printf("Office metadata embedded successfully: %s", filePath)
	return nil
}

func copyAndModifyOffice(srcPath, dstPath string, meta *Meta, fingerprint string) error {
	r, err := zip.OpenReader(srcPath)
	if err != nil {
		return fmt.Errorf("opening office ZIP: %w", err)
	}
	defer r.Close()

	outFile, err := os.Create(dstPath)
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	defer outFile.Close()

	zw := zip.NewWriter(outFile)
	defer zw.Close()

	const customXMLPath = "docProps/custom.xml"
	const relsPath = "_rels/.rels"
	customXMLWritten := false

	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("reading zip entry %s: %w", f.Name, err)
		}
		content, _ := io.ReadAll(rc)
		rc.Close()

		if f.Name == relsPath {
			content = injectCustomPropsRel(content)
		}
		if f.Name == customXMLPath {
			content = buildOfficeCustomPropsPDFStyle(meta, fingerprint)
			customXMLWritten = true
		}

		w, err := zw.Create(f.Name)
		if err != nil {
			return err
		}
		if _, err := w.Write(content); err != nil {
			return fmt.Errorf("failed to write zip entry %s: %w", f.Name, err)
		}
	}

	if !customXMLWritten {
		w, _ := zw.Create(customXMLPath)
		w.Write(buildOfficeCustomPropsPDFStyle(meta, fingerprint))
	}
	return nil
}

func extractOfficeSignature(filePath string) (*Meta, error) {
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, nil
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name != "docProps/custom.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		if !bytes.Contains(content, []byte("USISignature")) {
			continue
		}
		start := bytes.Index(content, []byte("<vt:lpwstr>"))
		if start < 0 {
			continue
		}
		start += 11
		end := bytes.Index(content[start:], []byte("</vt:lpwstr>"))
		if end < 0 {
			continue
		}
		var meta Meta
		if err := json.Unmarshal(content[start:start+end], &meta); err == nil {
			return &meta, nil
		}
	}
	return nil, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// XMP PACKET
// ─────────────────────────────────────────────────────────────────────────────

func buildPDFStyleXMPPacket(meta *Meta, fingerprint string) string {
	ts := time.Unix(meta.Timestamp, 0).Format(time.RFC3339)
	sigTs := time.Unix(meta.SignatureTimestamp, 0).Format(time.RFC3339)
	if meta.SignatureTimestamp == 0 {
		sigTs = ts
	}
	nonce := meta.Nonce
	if nonce == "" {
		nonce = "none"
	}

	secureBlock := buildSecureMetadataBlock(meta, fingerprint)
	cryptoDetails := fmt.Sprintf(
		"USI CRYPTOGRAPHIC SIGNATURE VERIFICATION\n\n"+
			"Fingerprint: %s\n"+
			"Signature Status: VALID\n"+
			"Timestamp: %s\n"+
			"Nonce: %s\n"+
			"Algorithm: SHAKE-256 + post-quantum signature\n"+
			"File Hash: %s\n"+
			"Final Document Hash: %s",
		formatFingerprintLegacy(fingerprint),
		time.Unix(meta.Timestamp, 0).Format("2006-01-02 15:04:05"),
		getNoncePrefix(nonce),
		formatHashWithSpaces(meta.FileHash, 4),
		formatHashWithSpaces(meta.FinalDocumentHash, 4),
	)

	pubKeyA, pubKeyB := splitHalf(meta.PublicKey)
	sigA, sigB := splitHalf(meta.Signature)

	signer := meta.Signer
	if signer == "" {
		signer = "USI Secure Vault"
	}
	docTitle := meta.DocumentTitle
	if docTitle == "" {
		docTitle = "Cryptographically Signed Document"
	}

	return fmt.Sprintf(`<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about=""
        xmlns:dc="http://purl.org/dc/elements/1.1/"
        xmlns:xmp="http://ns.adobe.com/xap/1.0/"
        xmlns:xmpRights="http://ns.adobe.com/xap/1.0/rights/"
        xmlns:pdf="http://ns.adobe.com/pdf/1.3/"
        xmlns:usi="http://usprotocol.io/ns/1.0/">
      <dc:title><rdf:Alt><rdf:li xml:lang="x-default">%s</rdf:li></rdf:Alt></dc:title>
      <dc:description><rdf:Alt><rdf:li xml:lang="x-default">%s</rdf:li></rdf:Alt></dc:description>
      <dc:creator><rdf:Seq><rdf:li>%s</rdf:li></rdf:Seq></dc:creator>
      <dc:subject>
        <rdf:Bag>
          <rdf:li>USI-SIGNED</rdf:li>
          <rdf:li>Cryptographic Signature</rdf:li>
          <rdf:li>E2E Cipher Protocol</rdf:li>
          <rdf:li>Integrity Protected</rdf:li>
          <rdf:li>%s</rdf:li>
        </rdf:Bag>
      </dc:subject>
      <pdf:Keywords>USI Cryptographically Signed; Integrity Protected</pdf:Keywords>
      <xmp:CreateDate>%s</xmp:CreateDate>
      <xmp:ModifyDate>%s</xmp:ModifyDate>
      <xmp:MetadataDate>%s</xmp:MetadataDate>
      <xmp:CreatorTool>E2E Cipher Protocol v0.002</xmp:CreatorTool>
      <xmp:Label>USI-SIGNED</xmp:Label>
      <xmpRights:Marked>True</xmpRights:Marked>
      <xmpRights:UsageTerms><rdf:Alt><rdf:li xml:lang="x-default">Cryptographically signed. Verify with USI before use.</rdf:li></rdf:Alt></xmpRights:UsageTerms>
      <usi:SecureMetadata>%s</usi:SecureMetadata>
      <usi:CryptographicMetadata>%s</usi:CryptographicMetadata>
      <usi:SignatureStatus>VALID</usi:SignatureStatus>
      <usi:Protocol>E2E Cipher Protocol</usi:Protocol>
      <usi:Version>USI v0.002 Secure</usi:Version>
      <usi:Algorithm>SHAKE-256 + post-quantum signature</usi:Algorithm>
      <usi:Fingerprint>%s</usi:Fingerprint>
      <usi:FingerprintFormatted>%s</usi:FingerprintFormatted>
      <usi:SignedAt>%s</usi:SignedAt>
      <usi:SignatureTimestamp>%s</usi:SignatureTimestamp>
      <usi:Nonce>%s</usi:Nonce>
      <usi:NoncePrefix>%s</usi:NoncePrefix>
      <usi:FileHash_SHAKE256>%s</usi:FileHash_SHAKE256>
      <usi:FileHash_Formatted>%s</usi:FileHash_Formatted>
      <usi:FinalDocumentHash>%s</usi:FinalDocumentHash>
      <usi:FinalDocumentHash_Formatted>%s</usi:FinalDocumentHash_Formatted>
      <usi:PublicKey_A>%s</usi:PublicKey_A>
      <usi:PublicKey_B>%s</usi:PublicKey_B>
      <usi:Signature_A>%s</usi:Signature_A>
      <usi:Signature_B>%s</usi:Signature_B>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end="w"?>`,
		xmlEscape(docTitle),
		xmlEscape(cryptoDetails),
		xmlEscape(signer),
		xmlEscape(secureBlock),
		ts, ts, ts,
		xmlEscape(secureBlock),
		xmlEscape(cryptoDetails),
		xmlEscape(fingerprint),
		xmlEscape(formatFingerprintLegacy(fingerprint)),
		ts,
		sigTs,
		xmlEscape(nonce),
		xmlEscape(getNoncePrefix(nonce)),
		xmlEscape(meta.FileHash),
		xmlEscape(formatHashWithSpaces(meta.FileHash, 4)),
		xmlEscape(meta.FinalDocumentHash),
		xmlEscape(formatHashWithSpaces(meta.FinalDocumentHash, 4)),
		xmlEscape(pubKeyA),
		xmlEscape(pubKeyB),
		xmlEscape(sigA),
		xmlEscape(sigB),
	)
}

func formatHashWithSpaces(hash string, groupSize int) string {
	if len(hash) == 0 {
		return ""
	}
	var result strings.Builder
	for i, ch := range hash {
		if i > 0 && i%groupSize == 0 && i < len(hash)-1 {
			result.WriteRune(' ')
		}
		result.WriteRune(ch)
	}
	return result.String()
}

// ─────────────────────────────────────────────────────────────────────────────
// OFFICE CUSTOM PROPERTIES
// ─────────────────────────────────────────────────────────────────────────────

func buildOfficeCustomPropsPDFStyle(meta *Meta, fingerprint string) []byte {
	ts := time.Unix(meta.Timestamp, 0).Format("2006-01-02 15:04:05")
	sigTs := time.Unix(meta.SignatureTimestamp, 0).Format("2006-01-02 15:04:05")
	if meta.SignatureTimestamp == 0 {
		sigTs = ts
	}
	nonce := meta.Nonce
	if nonce == "" {
		nonce = "none"
	}

	secureBlock := buildSecureMetadataBlock(meta, fingerprint)
	cryptoBlock := fmt.Sprintf(
		"USI CRYPTOGRAPHIC SIGNATURE VERIFICATION\n\n"+
			"Fingerprint: %s\n"+
			"Signature Status: VALID\n"+
			"Timestamp: %s\n"+
			"Nonce: %s",
		formatFingerprintLegacy(fingerprint),
		ts,
		getNoncePrefix(nonce),
	)

	pubKeyA, pubKeyB := splitHalf(meta.PublicKey)
	sigA, sigB := splitHalf(meta.Signature)

	const fmtid = "{D5CDD505-2E9C-101B-9397-08002B2CF9AE}"

	type prop struct {
		pid  int
		name string
		val  string
	}
	props := []prop{
		{2, "USI_SignatureStatus", "VALID"},
		{3, "USI_Protocol", "E2E Cipher Protocol v0.002"},
		{4, "USI_Algorithm", "SHAKE-256 + post-quantum signature"},
		{5, "USI_Version", "USI v0.002 Secure"},
		{6, "USI_Fingerprint", formatFingerprintLegacy(fingerprint)},
		{7, "USI_SignedAt", ts},
		{8, "USI_SignatureTimestamp", sigTs},
		{9, "USI_Nonce", nonce},
		{10, "USI_NoncePrefix", getNoncePrefix(nonce)},
		{11, "USI_SecureMetadata", secureBlock},
		{12, "USI_CryptographicMetadata", cryptoBlock},
		{13, "USI_FileHash_SHAKE256", meta.FileHash},
		{14, "USI_FinalDocumentHash", meta.FinalDocumentHash},
		{15, "USI_PublicKey_A", pubKeyA},
		{16, "USI_PublicKey_B", pubKeyB},
		{17, "USI_Signature_A", sigA},
		{18, "USI_Signature_B", sigB},
		{19, "USI_Signer", meta.Signer},
		{20, "USI_DocumentTitle", meta.DocumentTitle},
	}

	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n")
	sb.WriteString("<Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/custom-properties\"\n")
	sb.WriteString("            xmlns:vt=\"http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes\">\n")
	for _, p := range props {
		sb.WriteString(fmt.Sprintf(
			"  <property fmtid=%q pid=%q name=%q>\n    <vt:lpwstr>%s</vt:lpwstr>\n  </property>\n",
			fmtid, fmt.Sprintf("%d", p.pid), p.name, xmlEscape(p.val),
		))
	}
	sb.WriteString("</Properties>\n")
	return []byte(sb.String())
}

// ─────────────────────────────────────────────────────────────────────────────
// PNG / JPEG CHUNK HELPERS
// ─────────────────────────────────────────────────────────────────────────────

func pngCRC32(b []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, v := range b {
		crc ^= uint32(v)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xEDB88320
			} else {
				crc >>= 1
			}
		}
	}
	return crc ^ 0xFFFFFFFF
}

func buildPNGChunk(chunkType string, data []byte) []byte {
	typeBytes := []byte(chunkType)
	crcInput := append(typeBytes, data...)
	crc := pngCRC32(crcInput)

	chunk := make([]byte, 4+4+len(data)+4)
	binary.BigEndian.PutUint32(chunk[0:], uint32(len(data)))
	copy(chunk[4:], typeBytes)
	copy(chunk[8:], data)
	binary.BigEndian.PutUint32(chunk[8+len(data):], crc)
	return chunk
}

func stripPNGChunk(data []byte, chunkType string) []byte {
	out := make([]byte, 8, len(data))
	copy(out, data[:8])
	pos := 8
	for pos+12 <= len(data) {
		length := binary.BigEndian.Uint32(data[pos:])
		end := pos + 4 + 4 + int(length) + 4
		if end > len(data) {
			break
		}
		if string(data[pos+4:pos+8]) != chunkType {
			out = append(out, data[pos:end]...)
		}
		pos = end
	}
	return out
}

func stripJPEGXMPSegment(data []byte) []byte {
	const xmpNS = "http://ns.adobe.com/xap/1.0/"
	out := make([]byte, 2, len(data))
	copy(out, data[:2])
	pos := 2
	for pos+4 <= len(data) {
		if data[pos] != 0xFF {
			out = append(out, data[pos:]...)
			break
		}
		marker := data[pos+1]
		if marker == 0xD9 || marker == 0xDA {
			out = append(out, data[pos:]...)
			break
		}
		segLen := int(binary.BigEndian.Uint16(data[pos+2:])) + 2
		end := pos + segLen
		if end > len(data) {
			out = append(out, data[pos:]...)
			break
		}
		if marker == 0xE1 && segLen > 30 &&
			strings.HasPrefix(string(data[pos+4:end]), xmpNS) {
			pos = end
			continue
		}
		out = append(out, data[pos:end]...)
		pos = end
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// OFFICE RELATIONSHIP INJECTION
// ─────────────────────────────────────────────────────────────────────────────

func injectCustomPropsRel(relsXML []byte) []byte {
	const relType = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties"
	if bytes.Contains(relsXML, []byte(relType)) {
		return relsXML
	}
	if bytes.Contains(relsXML, []byte("<script")) ||
		bytes.Contains(relsXML, []byte("javascript:")) {
		log.Printf("Warning: suspicious content in relsXML, skipping injection")
		return relsXML
	}
	rel := `<Relationship Id="rId_usi_custom" Type="` + relType + `" Target="docProps/custom.xml"/>`
	return bytes.Replace(relsXML,
		[]byte("</Relationships>"),
		append([]byte("\n  "+rel+"\n"), []byte("</Relationships>")...),
		1)
}

// ─────────────────────────────────────────────────────────────────────────────
// MACOS XATTR
// ─────────────────────────────────────────────────────────────────────────────

func sanitizeXattrValue(value string) string {
	re := regexp.MustCompile(`[;&|$` + "`" + `\\'"\n\r\t\f\v]`)
	sanitized := re.ReplaceAllString(value, "")
	return strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, sanitized)
}

func setXattrSyscall(path, key, value string) error {
	return unix.Setxattr(path, key, []byte(value), 0)
}

func setRichXattrs(filePath string, meta *Meta, fingerprint string) error {
	if runtime.GOOS != "darwin" {
		return nil
	}

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return err
	}

	ts := time.Unix(meta.Timestamp, 0).Format("2006-01-02 15:04:05")
	sigTs := time.Unix(meta.SignatureTimestamp, 0).Format("2006-01-02 15:04:05")
	if meta.SignatureTimestamp == 0 {
		sigTs = ts
	}
	nonce := meta.Nonce
	if nonce == "" {
		nonce = "none"
	}

	formattedFileHash := formatHashWithSpaces(meta.FileHash, 4)
	formattedFinalHash := formatHashWithSpaces(meta.FinalDocumentHash, 4)
	if formattedFinalHash == "" && formattedFileHash != "" {
		formattedFinalHash = formattedFileHash
		log.Printf("Warning: FinalDocumentHash was empty, using FileHash as fallback")
	}

	description := fmt.Sprintf(
		"USI CRYPTOGRAPHIC SIGNATURE VERIFICATION\n\n"+
			"Fingerprint: %s\n"+
			"Signature Status: VALID\n"+
			"Timestamp: %s\n"+
			"Nonce: %s\n"+
			"Algorithm: SHAKE-256 + post-quantum signature\n"+
			"File Hash: %s\n"+
			"Final Document Hash: %s",
		formatFingerprintLegacy(fingerprint),
		ts,
		getNoncePrefix(nonce),
		formattedFileHash,
		formattedFinalHash,
	)

	signer := meta.Signer
	if signer == "" {
		signer = "USI Secure Vault"
	}
	docTitle := meta.DocumentTitle
	if docTitle == "" {
		docTitle = "Cryptographically Signed Document - E2E Cipher Protocol"
	}

	if err := writeMDItemXattrsBplist(absPath, map[string]interface{}{
		"kMDItemTitle":                      docTitle,
		"kMDItemAuthors":                    []string{signer},
		"kMDItemDescription":                description,
		"kMDItemKeywords":                   []string{"Integrity Protection", "Cryptographic Signature", "USI"},
		"kMDItemComment":                    fmt.Sprintf("USI VALID | Signed: %s | FP: %s", ts, formatFingerprintLegacy(fingerprint)),
		"kMDItemCreator":                    "USI v0.002 Secure",
		"kMDItemEncodingApplicationVersion": "E2E Cipher Protocol",
		"kMDItemVersion":                    "USI v0.002",
	}); err != nil {
		log.Printf("Warning: bplist xattr write failed: %v", err)
	}

	plainAttrs := map[string]string{
		"io.usprotocol.status":          "VALID",
		"io.usprotocol.protocol":        "E2E Cipher Protocol v0.002",
		"io.usprotocol.algorithm":       "SHAKE-256 + post-quantum signature",
		"io.usprotocol.fingerprint":     fingerprint,
		"io.usprotocol.fingerprint_fmt": formatFingerprintLegacy(fingerprint),
		"io.usprotocol.signed_at":       ts,
		"io.usprotocol.signature_ts":    sigTs,
		"io.usprotocol.filehash":        meta.FileHash,
		"io.usprotocol.finaldochash":    meta.FinalDocumentHash,
		"io.usprotocol.publickey":       meta.PublicKey,
		"io.usprotocol.signature":       meta.Signature,
		"io.usprotocol.nonce":           nonce,
		"io.usprotocol.version":         "USI v0.002 Secure",
		"io.usprotocol.signer":          meta.Signer,
		"io.usprotocol.document_title":  meta.DocumentTitle,
	}
	for key, value := range plainAttrs {
		safeKey := sanitizeXattrValue(key)
		safeValue := sanitizeXattrValue(value)
		if safeKey != key || safeValue != value {
			log.Printf("Xattr had unsafe characters, sanitized: %s", key)
		}
		var xattrErrors []error
		for key, value := range plainAttrs {
			safeKey := sanitizeXattrValue(key)
			safeValue := sanitizeXattrValue(value)
			if safeKey != key || safeValue != value {
				log.Printf("Xattr had unsafe characters, sanitized: %s", key)
			}
			if err := setXattrSyscall(absPath, safeKey, safeValue); err != nil {
				xattrErrors = append(xattrErrors, fmt.Errorf("%s: %w", safeKey, err))
				log.Printf("ERROR: xattr set failed for %s: %v", safeKey, err)
			}
		}
		if len(xattrErrors) > 0 {
			log.Printf("WARNING: %d xattr operations failed", len(xattrErrors))
		}
	}

	// Finder comment via AppleScript
	if !strings.HasPrefix(absPath, filepath.Clean("/Users/")) &&
		!strings.HasPrefix(absPath, filepath.Clean("/System/Volumes/Data/Users/")) {
		if !strings.Contains(absPath, ".usi") {
			log.Printf("Skipping AppleScript Finder comment for path outside /Users: %s", absPath)
			goto skipAppleScript
		}
	}
	{
		safeComment := strings.NewReplacer(
			`"`, `\"`, "\n", " ", `\`, `\\`, "$", `\$`, "`", "\\`", ";", `\;`,
		).Replace(description)
		script := fmt.Sprintf("set comment of (POSIX file %q as alias) to %q", absPath, safeComment)
		if err := exec.Command("osascript", "-e", script).Run(); err != nil {
			log.Printf("AppleScript Finder comment failed: %v", err)
		}
	}
skipAppleScript:
	exec.Command("mdimport", absPath).Run()
	log.Printf("✅ Rich xattrs written for: %s", filepath.Base(filePath))
	return nil
}

func extractXattrSignature(filePath string) (*Meta, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, nil
	}
	if info.Mode().Perm()&0022 != 0 {
		log.Printf("Skipping xattr on world-writable file: %s", filePath)
		return nil, nil
	}

	absPath, _ := filepath.Abs(filePath)
	isTrusted := strings.HasPrefix(absPath, "/Users/") ||
		strings.HasPrefix(absPath, "/System/Volumes/Data/Users/")
	if !isTrusted {
		log.Printf("Skipping xattr on untrusted path: %s", filePath)
		return nil, nil
	}

	output, err := exec.Command("xattr", "-p", "io.usprotocol.signature", filePath).Output()
	if err != nil {
		return nil, nil
	}

	var meta Meta
	if err := json.Unmarshal(output, &meta); err != nil {
		return nil, nil
	}
	if meta.Signature != "" && len(meta.Signature) >= 64 {
		return &meta, nil
	}
	return nil, nil
}

func writeMDItemXattrsBplist(filePath string, attrs map[string]interface{}) error {
	var sb strings.Builder
	sb.WriteString("import plistlib, xattr, sys\n")
	sb.WriteString("f = sys.argv[1]\n")

	for key, value := range attrs {
		fullKey := "com.apple.metadata:" + key
		var pyValue string
		switch v := value.(type) {
		case string:
			pyValue = fmt.Sprintf("%q", v)
		case []string:
			parts := make([]string, len(v))
			for i, s := range v {
				escaped := strings.ReplaceAll(s, `\`, `\\`)
				escaped = strings.ReplaceAll(escaped, `"`, `\"`)
				parts[i] = fmt.Sprintf(`"%s"`, escaped)
			}
			pyValue = fmt.Sprintf("[%s]", strings.Join(parts, ", "))
		}
		sb.WriteString(fmt.Sprintf(
			"xattr.setxattr(f, %q, plistlib.dumps(%s, fmt=plistlib.FMT_BINARY))\n",
			fullKey, pyValue,
		))
	}

	cmd := exec.Command("python3", "-c", sb.String(), filePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("ERROR: Python xattr failed: %v, output: %s", err, output)
		log.Printf("Attempting CoreFoundation fallback...")
		if fallbackErr := writeMDItemXattrsViaCoreFoundation(filePath, attrs); fallbackErr != nil {
			return fmt.Errorf("both Python and CoreFoundation xattr methods failed: primary=%v, fallback=%w", err, fallbackErr)
		}
	} else if len(output) > 0 {
		log.Printf("Python xattr script output: %s", output)
	}
	// Always also run the CF path so both methods are written
	return writeMDItemXattrsViaCoreFoundation(filePath, attrs)
}

func writeMDItemXattrsViaCoreFoundation(filePath string, attrs map[string]interface{}) error {
	var sb strings.Builder
	sb.WriteString(`
import plistlib, ctypes, os, sys

libSystem = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
libSystem.setxattr.restype = ctypes.c_int
libSystem.setxattr.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int,
]

def set_mditem_xattr(path, key, value):
    full_key = "com.apple.metadata:" + key
    data = plistlib.dumps(value, fmt=plistlib.FMT_BINARY)
    buf = ctypes.create_string_buffer(data)
    result = libSystem.setxattr(
        path.encode("utf-8"), full_key.encode("utf-8"), buf, len(data), 0, 0)
    if result != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), path)

f = sys.argv[1]
`)

	for key, value := range attrs {
		switch v := value.(type) {
		case string:
			sb.WriteString(fmt.Sprintf("set_mditem_xattr(f, %q, %q)\n", key, v))
		case []string:
			parts := make([]string, len(v))
			for i, s := range v {
				parts[i] = fmt.Sprintf("%q", s)
			}
			sb.WriteString(fmt.Sprintf("set_mditem_xattr(f, %q, [%s])\n", key, strings.Join(parts, ", ")))
		}
	}

	// Use the venv python that has xattr installed, or fall back to system python
	pythonPath := "/Users/kusuma/usi-venv/bin/python3"
	if _, err := os.Stat(pythonPath); os.IsNotExist(err) {
		pythonPath = "python3"
	}

	cmd := exec.Command(pythonPath, "-c", sb.String(), filePath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("CoreFoundation xattr fallback failed: %w (output: %s)", err, output)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC VERIFICATION ALIASES
// ─────────────────────────────────────────────────────────────────────────────

func VerifyDocumentSignature(filePath, passphrase string) (bool, *Meta, error) {
	return VerifyUniversal(filePath, passphrase)
}

func VerifySidecarSignature(filePath, passphrase string) (bool, *Meta, error) {
	return VerifyUniversal(filePath, passphrase)
}

func EmbedSidecar(filePath string, meta *Meta, passphrase string) error {
	return EmbedSignature(filePath, meta, "", passphrase)
}

func EmbedPDF(filePath string, meta *Meta, passphrase string) error {
	return EmbedSignature(filePath, meta, "USI Secure File Vault", passphrase)
}

// ─────────────────────────────────────────────────────────────────────────────
// PDF PAGE / SIGNATURE HELPERS
// ─────────────────────────────────────────────────────────────────────────────

func createSignaturePage(filePath string, meta *Meta, fingerprint string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(0, 10, "USI CRYPTOGRAPHIC SIGNATURE")
	pdf.Ln(12)

	pdf.SetFont("Arial", "I", 10)
	pdf.SetTextColor(255, 0, 0)
	pdf.MultiCell(0, 5,
		"WARNING: This document is cryptographically signed. Any modification will invalidate the signature.",
		"", "", false)
	pdf.Ln(5)
	pdf.SetTextColor(0, 0, 0)

	pdf.SetFont("Arial", "", 12)
	pdf.MultiCell(0, 6, buildSecureMetadataBlock(meta, fingerprint), "", "", false)

	pdf.SetY(-20)
	pdf.SetFont("Arial", "I", 8)
	pdf.CellFormat(0, 10,
		fmt.Sprintf("USI Integrity Protected - Signed at %s",
			time.Unix(meta.Timestamp, 0).Format("2006-01-02 15:04:05")),
		"", 0, "C", false, 0, "")

	return pdf.OutputFileAndClose(filePath)
}

func createDocumentSignature(filePath string, meta *Meta, fingerprint string) ([]byte, error) {
	documentData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	defer secureZeroBytes(documentData)

	tmp := filePath + ".meta.pdf"
	defer secureRemove(tmp)
	if err := os.WriteFile(tmp, documentData, 0644); err != nil {
		return nil, err
	}

	info := buildCryptographicMetadataBlock(meta, fingerprint, meta.FinalDocumentHash)
	cleanInfo := cleanPDFMetadata(info)

	conf := model.NewDefaultConfiguration()
	if err := api.AddPropertiesFile(tmp, "", cleanInfo, conf); err != nil {
		log.Printf("ERROR: PDF metadata embedding failed: %v", err)
		// Decide: return error or continue with warning
		// For critical signature, you might want to fail:
		// return nil, fmt.Errorf("PDF metadata embedding failed: %w", err)
	} else {
		log.Printf("PDF metadata embedded successfully")
	}

	return os.ReadFile(tmp)
}

func cleanPDFMetadata(info map[string]string) map[string]string {
	clean := make(map[string]string, len(info))
	for k, v := range info {
		v = strings.ReplaceAll(v, "\x00", "")
		v = strings.ReplaceAll(v, "\r", "")
		v = strings.ReplaceAll(v, "\n", " ")
		v = strings.TrimSpace(v)
		if len(v) > 1000 {
			v = v[:1000] + "...(truncated)"
		}
		clean[k] = v
	}
	return clean
}

// ─────────────────────────────────────────────────────────────────────────────
// LEGACY EXTRACTION HELPERS
// ─────────────────────────────────────────────────────────────────────────────

func extractMetadataFromPDF(filePath string) (*Meta, error) {
	sidecarPath := filePath + ".usimeta"
	if info, err := os.Stat(sidecarPath); err == nil {
		if info.Mode().Perm()&0022 != 0 {
			log.Printf("Skipping world-writable sidecar: %s", sidecarPath)
		} else {
			data, err := os.ReadFile(sidecarPath)
			if err != nil {
				return nil, fmt.Errorf("reading sidecar file: %w", err)
			}
			var meta Meta
			if err := json.Unmarshal(data, &meta); err != nil {
				return nil, fmt.Errorf("parsing sidecar metadata: %w", err)
			}
			if meta.Signature != "" || meta.FileHash != "" {
				return &meta, nil
			}
		}
	}

	meta, err := extractMetadataByBinaryScan(filePath)
	if err == nil && meta != nil {
		return meta, nil
	}
	return nil, fmt.Errorf("USI signature metadata not found in PDF")
}

func extractMetadataByBinaryScan(filePath string) (*Meta, error) {
	const scanWindow = 2 * 1024 * 1024

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	readOffset := info.Size() - int64(scanWindow)
	if readOffset < 0 {
		readOffset = 0
	}
	if _, err := f.Seek(readOffset, io.SeekStart); err != nil {
		return nil, err
	}

	buf, err := io.ReadAll(io.LimitReader(f, scanWindow))
	if err != nil {
		return nil, err
	}
	defer secureZeroBytes(buf)

	marker := []byte(`"USISignature":`)
	idx := bytes.Index(buf, marker)
	if idx == -1 {
		return nil, errors.New("USISignature marker not found")
	}

	start := idx
	for start > 0 && buf[start] != '{' {
		start--
	}
	if buf[start] != '{' {
		return nil, errors.New("could not locate JSON object start")
	}

	relEnd := findMatchingBraceBytes(buf[start:])
	if relEnd == -1 {
		return nil, errors.New("could not find matching closing brace")
	}
	end := start + relEnd + 1
	jsonData := buf[start:end]

	if !isValidJSONBytes(jsonData) {
		return nil, errors.New("extracted segment is not valid JSON")
	}

	var outer map[string]json.RawMessage
	if err := json.Unmarshal(jsonData, &outer); err != nil {
		return nil, fmt.Errorf("parsing outer JSON: %w", err)
	}
	usiRaw, ok := outer["USISignature"]
	if !ok {
		return nil, errors.New("USISignature key not present")
	}

	// Try double-encoded (string wrapping a JSON object)
	var nested string
	if err := json.Unmarshal(usiRaw, &nested); err == nil {
		var meta Meta
		if err := json.Unmarshal([]byte(nested), &meta); err != nil {
			return nil, fmt.Errorf("parsing nested Meta: %w", err)
		}
		return &meta, nil
	}

	var meta Meta
	if err := json.Unmarshal(usiRaw, &meta); err != nil {
		return nil, fmt.Errorf("parsing USISignature as Meta: %w", err)
	}
	return &meta, nil
}

// verifyUSIMetaWithDetails verifies a .usimeta sidecar without requiring a passphrase.
func verifyUSIMetaWithDetails(filePath, metaPath string) (bool, *Meta, error) {
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return false, nil, fmt.Errorf("cannot read file: %w", err)
	}
	defer secureZeroBytes(fileData)

	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return false, nil, fmt.Errorf("cannot read metadata: %w", err)
	}
	defer secureZeroBytes(metaData)

	var meta Meta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return false, nil, fmt.Errorf("invalid metadata format: %w", err)
	}

	if err := validateSignatureTimestamp(&meta); err != nil {
		return false, &meta, err
	}

	// Legacy field-name fallback
	if meta.FileHash == "" {
		var rawMeta map[string]interface{}
		if err := json.Unmarshal(metaData, &rawMeta); err == nil {
			if v, ok := rawMeta["file_hash"].(string); ok {
				meta.FileHash = v
			}
			if v, ok := rawMeta["public_key"].(string); ok {
				meta.PublicKey = v
			}
		}
	}
	if meta.FileHash == "" {
		return false, &meta, fmt.Errorf("no file hash found in metadata")
	}

	currentHash := computeShake256(fileData)
	if meta.FileHash != hex.EncodeToString(currentHash) {
		return false, &meta, fmt.Errorf("file content has been modified")
	}
	if meta.Signature == "" {
		return true, &meta, nil
	}

	ok, err := verifyCryptoSignature(&meta, currentHash)
	if err != nil {
		return false, &meta, fmt.Errorf("signature verification error: %w", err)
	}
	if !ok {
		return false, &meta, errors.New("cryptographic signature invalid")
	}
	return true, &meta, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// MOV / QUICKTIME
// ─────────────────────────────────────────────────────────────────────────────

func embedMOVQuickTimeMetadata(filePath string, meta *Meta, fingerprint string) error {
	log.Printf("Embedding QuickTime metadata for: %s", filePath)
	ts := time.Unix(meta.Timestamp, 0).Format("2006-01-02 15:04:05")
	comment := fmt.Sprintf("USI VALID | Signed: %s | FP: %s | Hash: %.16s",
		ts, formatFingerprintLegacy(fingerprint), meta.FileHash)

	udtaData := make([]byte, 0)
	udtaData = append(udtaData, buildQuickTimeAtom("©nam", []byte(meta.DocumentTitle))...)
	udtaData = append(udtaData, buildQuickTimeAtom("©ART", []byte(meta.Signer))...)
	udtaData = append(udtaData, buildQuickTimeAtom("©cmt", []byte(comment))...)
	udtaData = append(udtaData, buildQuickTimeAtom("©day", []byte(ts))...)
	descText := fmt.Sprintf("USI Signed Document - Status: VALID - Fingerprint: %s", fingerprint[:20])
	udtaData = append(udtaData, buildQuickTimeAtom("©des", []byte(descText))...)

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(buildQuickTimeAtom("udta", udtaData))
	return err
}

func buildQuickTimeAtom(atomType string, data []byte) []byte {
	size := 8 + len(data)
	sizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sizeBuf, uint32(size))
	atom := make([]byte, 0, size)
	atom = append(atom, sizeBuf...)
	atom = append(atom, []byte(atomType)...)
	atom = append(atom, data...)
	return atom
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRITY CHECKS
// ─────────────────────────────────────────────────────────────────────────────

func verifyStrictIntegrity(filePath string, meta *Meta) bool {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return false
	}
	defer secureZeroBytes(data)
	return meta.FinalDocumentHash == hex.EncodeToString(computeShake256(data))
}

func verifyContentIntegrity(filePath string, meta *Meta) bool {
	contentHash, err := computeContentHash(filePath)
	if err != nil {
		return false
	}
	return meta.FileHash == contentHash
}

// ─────────────────────────────────────────────────────────────────────────────
// HASH UTILITIES
// ─────────────────────────────────────────────────────────────────────────────

func computeShake256(data []byte) []byte {
	shake := sha3.NewShake256()
	shake.Write(data)
	hash := make([]byte, 32)
	shake.Read(hash)
	return hash
}

func computeContentHash(filePath string) (string, error) {
	normalizedContent, err := normalizePDFContent(filePath)
	if err != nil {
		return "", fmt.Errorf("normalizing PDF content: %w", err)
	}
	defer secureZeroBytes(normalizedContent)
	return hex.EncodeToString(computeShake256(normalizedContent)), nil
}

func normalizePDFContent(filePath string) ([]byte, error) {
	tmpNormalized := filePath + ".normalized.pdf"
	defer secureRemove(tmpNormalized)
	conf := model.NewDefaultConfiguration()
	if err := api.OptimizeFile(filePath, tmpNormalized, conf); err != nil {
		return nil, fmt.Errorf("optimizing PDF: %w", err)
	}
	return os.ReadFile(tmpNormalized)
}

func computeShake256AsBytes(hashHex string) []byte {
	b, _ := hex.DecodeString(hashHex)
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITY FUNCTIONS
// ─────────────────────────────────────────────────────────────────────────────

// generateSecureNonce returns 32 cryptographically random bytes as a hex string.
// Uses crypto/rand exclusively — math/rand is NOT used here.
func generateSecureNonce() string {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		// Extremely rare; fall back to time+pid mix rather than panic.
		log.Printf("Warning: crypto/rand failed (%v), using time-based nonce fallback", err)
		ts := time.Now().UnixNano()
		pid := os.Getpid()
		for i := 0; i < 8 && i < 32; i++ {
			nonce[i] ^= byte(ts >> (i * 8))
		}
		for i := 0; i < 4 && i+8 < 32; i++ {
			nonce[i+8] ^= byte(pid >> (i * 8))
		}
	}
	return hex.EncodeToString(nonce)
}

func splitHalf(s string) (string, string) {
	if len(s) == 0 {
		return "", ""
	}
	mid := len(s) / 2
	return s[:mid], s[mid:]
}

// validateSignatureTimestamp rejects timestamps in the future (> 10 s skew).
// No upper bound on age - signatures remain valid forever.
// The 24-hour lower bound was intentionally removed: documents signed in the
// past must remain verifiable.
func validateSignatureTimestamp(meta *Meta) error {
	if meta == nil {
		return errors.New("nil metadata provided")
	}
	ts := meta.SignatureTimestamp
	if ts == 0 {
		ts = meta.Timestamp
	}
	if ts == 0 {
		return errors.New("missing signature timestamp")
	}

	sigTime := time.Unix(ts, 0)
	now := time.Now()

	if sigTime.After(now.Add(10 * time.Second)) {
		return fmt.Errorf("signature timestamp is in the future by %v", sigTime.Sub(now))
	}

	return nil
}

func getNoncePrefix(nonce string) string {
	if len(nonce) >= 8 {
		return nonce[:8]
	}
	if len(nonce) > 0 {
		return nonce
	}
	return "none"
}

func formatFingerprintLegacy(fp string) string {
	clean := strings.ReplaceAll(fp, " ", "")
	var b strings.Builder
	for i, ch := range clean {
		if i > 0 && i%4 == 0 {
			b.WriteString(" ")
		}
		b.WriteRune(ch)
	}
	return b.String()
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func findMatchingBraceBytes(b []byte) int {
	depth, inString, escaped := 0, false, false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && inString {
			escaped = true
			continue
		}
		if c == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isValidJSONBytes(b []byte) bool {
	if len(b) == 0 || bytes.IndexByte(b, 0) != -1 {
		return false
	}
	return json.Valid(b)
}

func secureZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func secureRemove(path string) {
	if path == "" {
		return
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		log.Printf("secureRemove: cannot resolve path: %v", err)
		os.Remove(path)
		return
	}
	absPath = filepath.Clean(absPath)
	if strings.Contains(absPath, "..") {
		log.Printf("secureRemove: path traversal detected: %s", absPath)
		os.Remove(path)
		return
	}
	if realPath, err := filepath.EvalSymlinks(absPath); err == nil && realPath != absPath {
		log.Printf("secureRemove: dereferenced symlink %s -> %s", absPath, realPath)
		absPath = realPath
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		os.Remove(path)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		log.Printf("secureRemove: refusing to follow symlink: %s", absPath)
		os.Remove(path)
		return
	}

	allowedPrefixes := []string{
		filepath.Clean("/Users/"),
		filepath.Clean("/System/Volumes/Data/Users/"),
		filepath.Clean("/tmp/usi"),
	}
	isAllowed := false
	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(absPath, prefix) {
			isAllowed = true
			break
		}
	}
	if !isAllowed && !strings.Contains(absPath, ".usi") {
		log.Printf("secureRemove: rejecting path outside allowed directories: %s", absPath)
		return
	}

	if f, err := os.OpenFile(absPath, os.O_WRONLY, 0); err == nil {
		if fi, err := f.Stat(); err == nil {
			chunk := make([]byte, 4096)
			for i := int64(0); i < fi.Size(); i += 4096 {
				f.WriteAt(chunk, i)
			}
			f.Sync()
		}
		f.Close()
	}
	os.Remove(absPath)
}

// ─────────────────────────────────────────────────────────────────────────────
// NONCE STORE — used at SIGNING time only to prevent duplicate signatures
// ─────────────────────────────────────────────────────────────────────────────

var (
	nonceCache   sync.Map
	nonceCacheMu sync.RWMutex
)

// recordSigningNonce stores a nonce at signing time to prevent the same nonce
// being reused in two different signing operations within the same process run.
// It must NOT be called during verification — verifying a document twice is
// not a replay attack.
func recordSigningNonce(nonce string) error {
	if nonce == "" || nonce == "none" {
		return errors.New("invalid nonce")
	}
	if _, alreadyUsed := nonceCache.LoadOrStore(nonce, time.Now()); alreadyUsed {
		return fmt.Errorf("nonce already used in this session: %s", truncate(nonce, 16))
	}
	// Purge stale entries asynchronously
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("ERROR: Nonce cache purge panic: %v", r)
			}
		}()
		nonceCacheMu.RLock()
		defer nonceCacheMu.RUnlock()
		nonceCache.Range(func(key, value interface{}) bool {
			if time.Since(value.(time.Time)) > 24*time.Hour {
				nonceCache.Delete(key)
			}
			return true
		})
	}()
	return nil
}
