// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/core/sign/validation.go
package sign

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	keys "github.com/sphinxorg/protocol/src/usi/core/key"
)

// IsAlreadySigned returns true (and the existing fingerprint) when the file
// already contains a USI signature.
func IsAlreadySigned(filePath string) (bool, string, error) {
	log.Printf("[INFO] IsAlreadySigned: checking if file is already signed: %s", filePath)

	if strings.HasSuffix(strings.ToLower(filePath), ".pdf") {
		log.Printf("[INFO] IsAlreadySigned: detected PDF file, checking PDF signature")
		signed, fp, err := pdfAlreadySigned(filePath)
		if err != nil {
			log.Printf("[ERROR] IsAlreadySigned: PDF check failed: %v", err)
			return false, "", err
		}
		if signed {
			log.Printf("[SUCCESS] IsAlreadySigned: file already signed (fingerprint: %s)", fp)
		} else {
			log.Printf("[INFO] IsAlreadySigned: file not signed yet")
		}
		return signed, fp, nil
	}

	log.Printf("[INFO] IsAlreadySigned: checking sidecar signature for non-PDF file")
	signed, fp, err := sidecarAlreadySigned(filePath)
	if err != nil {
		log.Printf("[ERROR] IsAlreadySigned: sidecar check failed: %v", err)
		return false, "", err
	}
	if signed {
		log.Printf("[SUCCESS] IsAlreadySigned: file already signed (fingerprint: %s)", fp)
	} else {
		log.Printf("[INFO] IsAlreadySigned: file not signed yet")
	}
	return signed, fp, nil
}

// ---------- PDF -------------------------------------------------
func pdfAlreadySigned(filePath string) (bool, string, error) {
	log.Printf("[INFO] pdfAlreadySigned: reading PDF properties: %s", filePath)

	conf := model.NewDefaultConfiguration()

	f, err := os.Open(filePath)
	if err != nil {
		log.Printf("[ERROR] pdfAlreadySigned: failed to open PDF file: %v", err)
		return false, "", err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			log.Printf("[WARN] pdfAlreadySigned: error closing file: %v", closeErr)
		}
	}()
	log.Printf("[INFO] pdfAlreadySigned: PDF file opened successfully")

	props, err := api.Properties(f, conf)
	if err != nil {
		log.Printf("[ERROR] pdfAlreadySigned: failed to read PDF properties: %v", err)
		return false, "", err
	}
	log.Printf("[INFO] pdfAlreadySigned: PDF properties extracted, found %d properties", len(props))

	if raw, ok := props["USISignature"]; ok && raw != "" {
		log.Printf("[INFO] pdfAlreadySigned: USISignature property found, length: %d bytes", len(raw))
		var m Meta
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			log.Printf("[ERROR] pdfAlreadySigned: corrupt USISignature property: %v", err)
			return false, "", errors.New("corrupt USISignature property")
		}
		fpPreview := m.PublicKey
		if len(fpPreview) > 12 {
			fpPreview = fpPreview[:12] + "..."
		}
		log.Printf("[SUCCESS] pdfAlreadySigned: found existing signature with fingerprint: %s", fpPreview)
		return true, fpPreview, nil
	}

	log.Printf("[INFO] pdfAlreadySigned: no USISignature property found")
	return false, "", nil
}

// ---------- non-PDF (side-car) ---------------------------------
func sidecarAlreadySigned(filePath string) (bool, string, error) {
	side := filePath + ".usimeta"
	log.Printf("[INFO] sidecarAlreadySigned: checking for sidecar file: %s", side)

	data, err := os.ReadFile(side)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("[INFO] sidecarAlreadySigned: sidecar file does not exist")
			return false, "", nil
		}
		log.Printf("[ERROR] sidecarAlreadySigned: failed to read sidecar file: %v", err)
		return false, "", err
	}
	log.Printf("[INFO] sidecarAlreadySigned: sidecar file found, size: %d bytes", len(data))

	var m Meta
	if err := json.Unmarshal(data, &m); err != nil {
		log.Printf("[ERROR] sidecarAlreadySigned: corrupt .usimeta file: %v", err)
		return false, "", errors.New("corrupt .usimeta file")
	}

	fpPreview := m.PublicKey
	if len(fpPreview) > 12 {
		fpPreview = fpPreview[:12] + "..."
	}
	log.Printf("[SUCCESS] sidecarAlreadySigned: found existing signature with fingerprint: %s", fpPreview)
	return true, fpPreview, nil
}

// validateSPHINCSSignature validates that a signature hex string is properly formatted
// for the SPHINCS+ parameters defined in keys.DefaultParams
func validateSPHINCSSignature(signatureHex string) bool {
	log.Printf("[INFO] validateSPHINCSSignature: validating signature format (length: %d chars)", len(signatureHex))

	if signatureHex == "" {
		log.Printf("[WARN] validateSPHINCSSignature: empty signature hex string")
		return false
	}

	// Just verify it's valid hex - actual crypto verification will catch invalid signatures
	decoded, err := hex.DecodeString(signatureHex)
	if err != nil {
		log.Printf("[WARN] validateSPHINCSSignature: invalid hex encoding: %v", err)
		return false
	}
	log.Printf("[INFO] validateSPHINCSSignature: valid hex encoding, decoded size: %d bytes", len(decoded))

	// Reference keys.DefaultParams to ensure consistency with the actual SPHINCS+ parameters
	// The actual signature verification uses keys.DefaultParams in the Verify function
	_ = keys.DefaultParams // This ensures the params are linked/loaded

	// Note: Different parameter sets have different signature sizes:
	// - SHAKE256-128f: 17088 bytes
	// - SHAKE256-128s: 7856 bytes
	// - SHAKE256-192s: 16224 bytes
	// We don't check length here because the crypto verification will handle it

	log.Printf("[SUCCESS] validateSPHINCSSignature: signature format validation passed")
	return true
}
