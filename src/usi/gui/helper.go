// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/helper.go
package gui

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	keys "github.com/sphinxorg/protocol/src/usi/core/key"
	"github.com/sphinxorg/protocol/src/usi/core/sign"
	pubkeydir "github.com/sphinxorg/protocol/src/usi/server/server"
)

var (
	sessionPassphrase     string
	sessionFingerprint    string
	sessionRawFingerprint string // Add this - raw fingerprint for crypto
	activityList          []string
	activityListLock      sync.Mutex
	sessionOrgCode        string // Add this - org code for display and lookup (always "SPIF")
)

var (
	keyStore     pubkeydir.Store
	keyStoreOnce sync.Once
	serverURL    = "http://localhost:8080"
)

func addActivity(activity string) {
	log.Printf("[INFO] addActivity: recording activity: %s", activity[:min(100, len(activity))])

	activityListLock.Lock()
	defer activityListLock.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	activityEntry := fmt.Sprintf("%s | %s", timestamp, activity)
	activityList = append([]string{activityEntry}, activityList...)
	if len(activityList) > 20 {
		activityList = activityList[:20]
		log.Printf("[DEBUG] addActivity: trimmed activity list to 20 entries")
	}
	log.Printf("[SUCCESS] addActivity: activity recorded: %s", activityEntry[:min(80, len(activityEntry))])
}

// loadOrgCodeFromBundle looks up the org code for the given raw public key
// from the local LevelDB directory. Always returns "SPIF" or empty on error.
func loadOrgCodeFromBundle(pubKey []byte) string {
	log.Printf("[INFO] loadOrgCodeFromBundle: looking up org code for public key")
	log.Printf("[DEBUG] loadOrgCodeFromBundle: public key size: %d bytes", len(pubKey))
	log.Printf("[DEBUG] loadOrgCodeFromBundle: public key (first 8 bytes): %x", pubKey[:min(8, len(pubKey))])

	store := getKeyStore()
	if store == nil {
		log.Printf("[WARN] loadOrgCodeFromBundle: could not connect to pubkey directory for org lookup")
		return ""
	}

	pubKeyHex := hex.EncodeToString(pubKey)
	log.Printf("[DEBUG] loadOrgCodeFromBundle: public key hex (first 16 chars): %.16s...", pubKeyHex)

	bundle, err := store.LookupByPublicKey(pubKeyHex)
	if err != nil {
		log.Printf("[WARN] loadOrgCodeFromBundle: org lookup failed: %v", err)
		return "SPIF" // Default to SPIF
	}

	// Always return SPIF regardless of what's in the bundle
	log.Printf("[SUCCESS] loadOrgCodeFromBundle: returning SPIF (bundle had: %q)", bundle.Organization)
	return "SPIF"
}

// In publishRegistrarPublicBundle — store under BOTH keys
func publishRegistrarPublicBundle(passphrase, label, org string) error {
	log.Printf("[INFO] publishRegistrarPublicBundle: publishing registrar bundle")
	log.Printf("[DEBUG] publishRegistrarPublicBundle: label=%s, org=%s, passphrase length=%d", label, org, len(passphrase))

	kp, _, err := keys.LoadKeyFromDisk(passphrase)
	if err != nil {
		log.Printf("[ERROR] publishRegistrarPublicBundle: load keypair: %v", err)
		return fmt.Errorf("publishRegistrarPublicBundle: load keypair: %w", err)
	}
	log.Printf("[DEBUG] publishRegistrarPublicBundle: keypair loaded")
	log.Printf("[DEBUG] publishRegistrarPublicBundle: public key size: %d bytes", len(kp.PublicKey))

	kemPub, err := keys.LoadKEMPublicKey()
	if err != nil {
		log.Printf("[ERROR] publishRegistrarPublicBundle: load KEM key: %v", err)
		return fmt.Errorf("publishRegistrarPublicBundle: load KEM key: %w", err)
	}
	log.Printf("[DEBUG] publishRegistrarPublicBundle: KEM public key size: %d bytes", len(kemPub))

	// Use the canonical fingerprint (SHA3-256 of public key)
	canonicalFP := pubkeydir.Fingerprint(kp.PublicKey)
	normalizedFP, err := pubkeydir.NormalizeFingerprint(canonicalFP)
	if err != nil {
		log.Printf("[ERROR] publishRegistrarPublicBundle: normalize fingerprint: %v", err)
		return fmt.Errorf("publishRegistrarPublicBundle: normalize fingerprint: %w", err)
	}
	log.Printf("[DEBUG] publishRegistrarPublicBundle: canonical fingerprint: %.16s...", canonicalFP)
	log.Printf("[DEBUG] publishRegistrarPublicBundle: normalized fingerprint: %.16s...", normalizedFP)

	msg := pubkeydir.BindingMessage(normalizedFP, kemPub)
	log.Printf("[DEBUG] publishRegistrarPublicBundle: binding message size: %d bytes", len(msg))

	sig, err := sign.Sign(msg, passphrase)
	if err != nil {
		log.Printf("[ERROR] publishRegistrarPublicBundle: sign binding: %v", err)
		return fmt.Errorf("publishRegistrarPublicBundle: sign binding: %w", err)
	}
	log.Printf("[DEBUG] publishRegistrarPublicBundle: signature size: %d bytes", len(sig.Signature))

	bundle := pubkeydir.NewBundle(label, org, kp.PublicKey, kemPub, sig.Signature)
	log.Printf("[DEBUG] publishRegistrarPublicBundle: bundle created")

	store := getKeyStore()
	if store == nil {
		log.Printf("[ERROR] publishRegistrarPublicBundle: failed to connect to key directory")
		return fmt.Errorf("failed to connect to key directory")
	}

	if err := store.Put(bundle); err != nil {
		log.Printf("[ERROR] publishRegistrarPublicBundle: store.Put: %v", err)
		return fmt.Errorf("publishRegistrarPublicBundle: store.Put: %w", err)
	}

	log.Printf("[SUCCESS] publishRegistrarPublicBundle: bundle published successfully for org %q", org)
	return nil
}

func getKeyStore() pubkeydir.Store {
	log.Printf("[INFO] getKeyStore: initializing key store connection")

	keyStoreOnce.Do(func() {
		// Always use remote server - no local fallback
		log.Printf("[INFO] getKeyStore: connecting to key server at %s", serverURL)
		client := pubkeydir.NewClient(serverURL, nil)
		keyStore = client
		log.Printf("[SUCCESS] getKeyStore: connected to remote key server at %s", serverURL)

		// Test connection
		log.Printf("[DEBUG] getKeyStore: testing server connection...")
		_, err := client.List()
		if err != nil {
			log.Printf("[WARN] getKeyStore: server connection test failed: %v", err)
			log.Printf("[INFO] getKeyStore: make sure the server is running: go run ./server/main.go")
		} else {
			log.Printf("[SUCCESS] getKeyStore: server connection verified")
		}
	})

	log.Printf("[INFO] getKeyStore: returning key store (type: %T)", keyStore)
	return keyStore
}

// getVaultSenderInfo extracts sender information from a vault file without decrypting it
func getVaultSenderInfo(vaultPath string) (senderFP string, senderOrg string, err error) {
	log.Printf("[INFO] getVaultSenderInfo: reading sender info from vault: %s", vaultPath)

	f, err := os.Open(vaultPath)
	if err != nil {
		log.Printf("[ERROR] getVaultSenderInfo: failed to open vault: %v", err)
		return "", "", err
	}
	defer f.Close()

	// Skip magic number if present
	magicBuf := make([]byte, 10)
	if _, readErr := f.Read(magicBuf); readErr == nil {
		if string(magicBuf) != "USI_VAULT\x00" {
			f.Seek(0, io.SeekStart)
		}
	} else {
		f.Seek(0, io.SeekStart)
	}

	// Read manifest until null delimiter
	var manifestBuffer bytes.Buffer
	chunk := make([]byte, 4096)
	foundDelim := false
	for !foundDelim {
		n, readErr := f.Read(chunk)
		if n > 0 {
			if idx := bytes.Index(chunk[:n], []byte{0}); idx != -1 {
				manifestBuffer.Write(chunk[:idx])
				foundDelim = true
				break
			}
			manifestBuffer.Write(chunk[:n])
		}
		if readErr != nil {
			break
		}
	}
	if !foundDelim {
		log.Printf("[ERROR] getVaultSenderInfo: manifest delimiter not found")
		return "", "", errors.New("manifest delimiter not found")
	}

	manifestBytes := manifestBuffer.Bytes()
	log.Printf("[DEBUG] getVaultSenderInfo: manifest bytes length: %d", len(manifestBytes))

	// The manifest includes the HMAC as the last 32 bytes
	if len(manifestBytes) < 32 {
		log.Printf("[ERROR] getVaultSenderInfo: manifest too short")
		return "", "", errors.New("manifest too short")
	}

	// Separate JSON from HMAC
	jsonBytes := manifestBytes[:len(manifestBytes)-32]
	log.Printf("[DEBUG] getVaultSenderInfo: JSON length: %d", len(jsonBytes))

	var manifestData map[string]interface{}
	if jsonErr := json.Unmarshal(jsonBytes, &manifestData); jsonErr != nil {
		log.Printf("[ERROR] getVaultSenderInfo: JSON parse failed: %v", jsonErr)
		return "", "", jsonErr
	}

	// Extract PublicKey bytes - try both field names
	var pubKeyBytes []byte

	// Try "public_key" first (from the logs, this is what's actually in the manifest)
	if pubKeyField, ok := manifestData["public_key"]; ok {
		log.Printf("[DEBUG] getVaultSenderInfo: found 'public_key' field")
		switch v := pubKeyField.(type) {
		case string:
			pubKeyBytes, err = base64.StdEncoding.DecodeString(v)
			if err != nil {
				log.Printf("[ERROR] getVaultSenderInfo: failed to decode public_key string: %v", err)
				return "", "", fmt.Errorf("failed to decode public_key: %w", err)
			}
		case []interface{}:
			pubKeyBytes = make([]byte, len(v))
			for i, val := range v {
				if fval, ok := val.(float64); ok {
					pubKeyBytes[i] = byte(fval)
				} else {
					return "", "", errors.New("invalid public_key format")
				}
			}
		default:
			log.Printf("[ERROR] getVaultSenderInfo: unexpected public_key type: %T", v)
		}
	} else if pubKeyField, ok := manifestData["PublicKey"]; ok {
		// Fallback to "PublicKey" (capital P, capital K)
		log.Printf("[DEBUG] getVaultSenderInfo: found 'PublicKey' field")
		switch v := pubKeyField.(type) {
		case string:
			pubKeyBytes, err = base64.StdEncoding.DecodeString(v)
			if err != nil {
				log.Printf("[ERROR] getVaultSenderInfo: failed to decode PublicKey string: %v", err)
				return "", "", fmt.Errorf("failed to decode PublicKey: %w", err)
			}
		case []interface{}:
			pubKeyBytes = make([]byte, len(v))
			for i, val := range v {
				if fval, ok := val.(float64); ok {
					pubKeyBytes[i] = byte(fval)
				} else {
					return "", "", errors.New("invalid PublicKey format")
				}
			}
		default:
			log.Printf("[ERROR] getVaultSenderInfo: unexpected PublicKey type: %T", v)
		}
	} else {
		log.Printf("[ERROR] getVaultSenderInfo: no public_key or PublicKey field in manifest")
		log.Printf("[DEBUG] getVaultSenderInfo: available keys: %v", getMapKeys(manifestData))
		return "", "", errors.New("no public key in manifest")
	}

	if len(pubKeyBytes) == 0 {
		log.Printf("[ERROR] getVaultSenderInfo: public key is empty")
		return "", "", errors.New("public key is empty")
	}

	log.Printf("[DEBUG] getVaultSenderInfo: vault PublicKey size: %d bytes, hex: %.16s...", len(pubKeyBytes), hex.EncodeToString(pubKeyBytes)[:16])

	// Try server lookup first (most reliable)
	log.Printf("[INFO] getVaultSenderInfo: attempting server lookup...")
	store := getKeyStore()
	if store != nil {
		pubKeyHex := hex.EncodeToString(pubKeyBytes)
		log.Printf("[DEBUG] getVaultSenderInfo: looking up public key: %.16s...", pubKeyHex)
		bundle, lookupErr := store.LookupByPublicKey(pubKeyHex)
		if lookupErr == nil && bundle.Organization != "" {
			// Always use SPIF
			orgCode := keys.OrgCode("SPIF")
			senderFP = keys.GetPublicKeyFingerprintFromBytes(pubKeyBytes, orgCode)
			senderOrg = "SPIF - Sphinx Fingerprint"
			log.Printf("[SUCCESS] getVaultSenderInfo: found via server lookup, using SPIF, fp: %.16s...", senderFP)
			return senderFP, senderOrg, nil
		}
		log.Printf("[DEBUG] getVaultSenderInfo: server lookup failed: %v", lookupErr)
	} else {
		log.Printf("[WARN] getVaultSenderInfo: key store is nil")
	}

	// Use session org code if available (always SPIF)
	if sessionOrgCode != "" {
		senderFP = keys.GetPublicKeyFingerprintFromBytes(pubKeyBytes, keys.OrgCode("SPIF"))
		senderOrg = "SPIF - Sphinx Fingerprint"
		log.Printf("[INFO] getVaultSenderInfo: using session org code: SPIF")
		return senderFP, senderOrg, nil
	}

	// Fallback - use SPIF
	senderFP = keys.GetPublicKeyFingerprintFromBytes(pubKeyBytes, keys.OrgCode("SPIF"))
	senderOrg = "SPIF - Sphinx Fingerprint"
	log.Printf("[WARN] getVaultSenderInfo: using SPIF as fallback, fp: %.16s...", senderFP)
	return senderFP, senderOrg, nil
}

// Helper function to get map keys as a slice
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// validatePassphraseDialog shows a dialog to validate passphrase using keys.LoadKeyFromDisk
func validatePassphraseDialog(window fyne.Window, title, message string, onSuccess func(passphrase string)) {
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("Enter your registered passphrase")

	// Create the content
	content := container.NewVBox(
		widget.NewLabel(message),
		spacer(8),
		passEntry,
	)

	// Create the custom confirm dialog
	dialog := dialog.NewCustomConfirm(title, "Confirm", "Cancel", content, func(ok bool) {
		if !ok {
			return
		}
		if passEntry.Text == "" {
			dialog.ShowError(errors.New("passphrase cannot be empty"), window)
			return
		}

		// Use existing keys.LoadKeyFromDisk to validate
		kp, _, err := keys.LoadKeyFromDisk(passEntry.Text)
		if err != nil {
			dialog.ShowError(errors.New("incorrect passphrase — please try again"), window)
			return
		}

		// Update session variables
		sessionPassphrase = passEntry.Text
		sessionFingerprint = keys.GetPublicKeyFingerprint(kp)

		onSuccess(passEntry.Text)
	}, window)

	// Set the same size as the unlock vault popup
	dialog.Resize(fyne.NewSize(420, 220))
	dialog.Show()
}

// OrgSelector handles organization selection for key generation
type OrgSelector struct {
	Widget    *fyne.Container
	selectBox *widget.Select
}

// BuildOrgSelector creates a new organization selector widget for the registration screen
// Since we only use SPIF now, this returns a fixed widget
func BuildOrgSelector(window fyne.Window) *OrgSelector {
	// Fixed label showing SPIF
	fixedLabel := widget.NewLabelWithStyle("Organization: SPIF", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	fixedLabel.Importance = widget.HighImportance

	infoLabel := widget.NewLabel("SPIF - Sphinx Fingerprint")
	infoLabel.TextStyle = fyne.TextStyle{Italic: true}
	infoLabel.Alignment = fyne.TextAlignCenter

	descriptionLabel := widget.NewLabel("Identity Defense System")
	descriptionLabel.TextStyle = fyne.TextStyle{Italic: true}
	descriptionLabel.Alignment = fyne.TextAlignCenter

	widgetContainer := container.NewVBox(
		fixedLabel,
		container.NewCenter(infoLabel),
		container.NewCenter(descriptionLabel),
	)

	// Create a dummy select box that's hidden (for compatibility)
	selectBox := widget.NewSelect([]string{"SPIF"}, func(selected string) {})
	selectBox.SetSelected("SPIF")
	selectBox.Hide()

	selector := &OrgSelector{
		Widget:    widgetContainer,
		selectBox: selectBox,
	}

	return selector
}

// SelectedOrg returns SPIF always
func (os *OrgSelector) SelectedOrg() keys.OrgCode {
	return keys.OrgCode("SPIF")
}

// SetSelectedOrg does nothing (only SPIF is available)
func (os *OrgSelector) SetSelectedOrg(orgCode keys.OrgCode) {
	// Only SPIF is available, ignore any other value
	log.Printf("[DEBUG] SetSelectedOrg called with %q, ignoring (only SPIF supported)", orgCode)
}
