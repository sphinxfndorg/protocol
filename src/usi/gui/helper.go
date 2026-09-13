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
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/sphinxfndorg/protocol/src/common"
	"github.com/sphinxfndorg/protocol/src/core"
	types "github.com/sphinxfndorg/protocol/src/core/transaction"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/rpc"
	"github.com/sphinxfndorg/protocol/src/storage"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
	"github.com/sphinxfndorg/protocol/src/usi/core/mint"
	"github.com/sphinxfndorg/protocol/src/usi/core/sign"
	pubkeydir "github.com/sphinxfndorg/protocol/src/usi/server/server"
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
		return string(keys.OrgSPIF) // Default to SPIF
	}

	// Always return SPIF regardless of what's in the bundle
	log.Printf("[SUCCESS] loadOrgCodeFromBundle: returning %s (bundle had: %q)", keys.OrgSPIF, bundle.Organization)
	return string(keys.OrgSPIF)
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
			orgCode := keys.OrgSPIF
			senderFP = keys.GetPublicKeyFingerprintFromBytes(pubKeyBytes, orgCode)
			senderOrg = string(keys.OrgSPIF) + " - Sphinx Fingerprint"
			log.Printf("[SUCCESS] getVaultSenderInfo: found via server lookup, using %s, fp: %.16s...", common.SPIFPrefix, senderFP)
			return senderFP, senderOrg, nil
		}
		log.Printf("[DEBUG] getVaultSenderInfo: server lookup failed: %v", lookupErr)
	} else {
		log.Printf("[WARN] getVaultSenderInfo: key store is nil")
	}

	// Use session org code if available (always SPIF)
	if sessionOrgCode != "" {
		senderFP = keys.GetPublicKeyFingerprintFromBytes(pubKeyBytes, keys.OrgSPIF)
		senderOrg = string(keys.OrgSPIF) + " - Sphinx Fingerprint"
		log.Printf("[INFO] getVaultSenderInfo: using session org code: %s", common.SPIFPrefix)
		return senderFP, senderOrg, nil
	}

	// Fallback - use SPIF
	senderFP = keys.GetPublicKeyFingerprintFromBytes(pubKeyBytes, keys.OrgSPIF)
	senderOrg = string(keys.OrgSPIF) + " - Sphinx Fingerprint"
	log.Printf("[WARN] getVaultSenderInfo: using %s as fallback, fp: %.16s...", common.SPIFPrefix, senderFP)
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

// showTransferStatusDialog displays a modal popup that tracks a SPX transfer
// through broadcast → pending → confirmed, mirroring the mint data block
// confirmation UI style. It shows transfer status, block height, block
// confirmation hash, and related transaction info. The dialog updates live
// from a background polling goroutine via fyne.Do.
func showTransferStatusDialog(window fyne.Window, client *WalletClient, chainHeader *core.SphinxChainHeader, amountStr, recipient, memo string, passphrase string, amountNSPX *big.Int) {
	statusIcon := canvas.NewText("⏳", colWarn)
	statusIcon.TextSize = 36
	statusTextStyle := fyne.TextStyle{Bold: true}
	statusIcon.TextStyle = statusTextStyle

	statusTitle := canvas.NewText("Broadcasting Transaction…", colWarn)
	statusTitle.TextSize = 16
	statusTitle.TextStyle = fyne.TextStyle{Bold: true}

	statusSub := canvas.NewText("Submitting to the network…", colMuted)
	statusSub.TextSize = 12

	progress := widget.NewProgressBar()
	progress.Min = 0
	progress.Max = 1
	progress.SetValue(0.1)

	txidVal := canvas.NewText("—", colFaint)
	txidVal.TextSize = 11
	txidVal.TextStyle = fyne.TextStyle{Monospace: true}

	_ = passphrase // used for signing inside SendTransaction via session

	amountVal := canvas.NewText(amountStr+" "+chainHeader.Symbol, colAccent)
	amountVal.TextSize = 12
	amountVal.TextStyle = fyne.TextStyle{Bold: true}

	recipientVal := canvas.NewText(recipient, colMuted)
	recipientVal.TextSize = 11
	recipientVal.TextStyle = fyne.TextStyle{Monospace: true}
	if len(recipient) > 40 {
		recipientVal.Text = recipient[:20] + "…" + recipient[len(recipient)-18:]
	}

	memoVal := canvas.NewText("(none)", colFaint)
	memoVal.TextSize = 11
	memoVal.TextStyle = fyne.TextStyle{Italic: true}
	if strings.TrimSpace(memo) != "" {
		memoVal.Text = memo
		memoVal.Color = colMuted
	}

	blockHeightVal := canvas.NewText("—", colFaint)
	blockHeightVal.TextSize = 11
	blockHeightVal.TextStyle = fyne.TextStyle{Monospace: true}

	blockHashVal := canvas.NewText("—", colFaint)
	blockHashVal.TextSize = 11
	blockHashVal.TextStyle = fyne.TextStyle{Monospace: true}

	confirmTimeVal := canvas.NewText("—", colFaint)
	confirmTimeVal.TextSize = 11
	confirmTimeVal.TextStyle = fyne.TextStyle{Monospace: true}

	networkConfVal := canvas.NewText("—", colFaint)
	networkConfVal.TextSize = 11
	networkConfVal.TextStyle = fyne.TextStyle{Monospace: true}

	liveStatus := canvas.NewText("Connecting to node…", colFaint)
	liveStatus.TextSize = 11
	liveStatus.TextStyle = fyne.TextStyle{Italic: true}

	inner := container.NewVBox(
		spacer(6),
		container.NewCenter(statusIcon),
		spacer(6),
		container.NewCenter(statusTitle),
		container.NewCenter(statusSub),
		spacer(16),
		progress,
		spacer(14),
		infoRowDynamic("Transaction ID", txidVal),
		spacer(4),
		infoRowDynamic("Amount", amountVal),
		spacer(4),
		infoRowDynamic("Recipient", recipientVal),
		spacer(4),
		infoRowDynamic("Memo", memoVal),
		spacer(10),
		hRule(),
		spacer(10),
		sectionLabel("Block Confirmation"),
		spacer(6),
		infoRowDynamic("Block Height", blockHeightVal),
		spacer(4),
		infoRowDynamic("Block Hash", blockHashVal),
		spacer(4),
		infoRowDynamic("Confirmed At", confirmTimeVal),
		spacer(4),
		infoRowDynamic("Confirmations", networkConfVal),
		spacer(10),
		container.NewCenter(liveStatus),
		spacer(4),
	)

	bg := canvas.NewRectangle(colSurface)
	bg.CornerRadius = 14
	bg.StrokeColor = colAccent
	bg.StrokeWidth = 1

	content := container.NewMax(bg, container.NewPadded(inner))

	dlg := dialog.NewCustomWithoutButtons("Transfer Status", content, window)
	dlg.Resize(fyne.NewSize(480, 540))
	dlg.Show()

	go transferStatusDialogWorker(dlg, inner, client, chainHeader, statusIcon, statusTitle, statusSub, progress, txidVal, liveStatus, blockHeightVal, blockHashVal, confirmTimeVal, networkConfVal, amountStr, recipient, memo, amountNSPX)
}

// transferStatusDialogWorker runs in a goroutine to broadcast the transaction
// and poll for confirmation, updating the dialog widgets via fyne.Do.
func transferStatusDialogWorker(dlg *dialog.CustomDialog, inner *fyne.Container, client *WalletClient, chainHeader *core.SphinxChainHeader, statusIcon, statusTitle, statusSub *canvas.Text, progress *widget.ProgressBar, txidVal, liveStatus, blockHeightVal, blockHashVal, confirmTimeVal, networkConfVal *canvas.Text, amountStr, recipient, memo string, amountNSPX *big.Int) {
	fyne.Do(func() {
		liveStatus.Text = "Broadcasting signed transaction to node…"
		liveStatus.Color = colInfo
		liveStatus.Refresh()
		progress.SetValue(0.25)
	})

	txID, err := client.SendTransaction(recipient, amountNSPX, memo)

	if err != nil {
		fyne.Do(func() {
			statusIcon.Text = "✗"
			statusIcon.Color = colDanger
			statusTitle.Text = "Transaction Failed"
			statusTitle.Color = colDanger
			statusSub.Text = err.Error()
			statusSub.Color = colDanger
			statusSub.TextSize = 10
			txidVal.Text = "—"
			liveStatus.Text = "Transaction rejected by node"
			liveStatus.Color = colDanger
			progress.SetValue(0)
			inner.Refresh()
		})
		addActivity(fmt.Sprintf("Send %s to %s FAILED: %v", amountStr, recipient[:min(16, len(recipient))], err))
		return
	}

	fyne.Do(func() {
		statusIcon.Text = "⏳"
		statusIcon.Color = colInfo
		statusTitle.Text = "Transaction Pending"
		statusTitle.Color = colInfo
		statusSub.Text = "Broadcast to network — awaiting block inclusion…"
		statusSub.Color = colMuted
		txidVal.Text = txID
		txidVal.Color = colText
		progress.SetValue(0.5)
		liveStatus.Text = fmt.Sprintf("Polling for confirmation (txid: %s…)", txID[:min(12, len(txID))])
		liveStatus.Color = colFaint
		inner.Refresh()
	})

	addActivity(fmt.Sprintf("Sent %s %s to %s (tx: %s)", amountStr, chainHeader.Symbol, recipient[:min(16, len(recipient))]+"…", txID[:8]+"…"))

	conf, _ := client.WaitForTxConfirmation(txID, 300*time.Second)

	fyne.Do(func() {
		if conf != nil {
			statusIcon.Text = "✓"
			statusIcon.Color = colAccent
			statusTitle.Text = "Transaction Confirmed"
			statusTitle.Color = colAccent
			statusSub.Text = "Successfully committed to the blockchain"
			statusSub.Color = colAccent

			blockHeightVal.Text = fmt.Sprintf("%d", conf.Height)
			blockHeightVal.Color = colAccent

			blockHashVal.Text = conf.Hash
			if len(conf.Hash) > 32 {
				blockHashVal.Text = conf.Hash[:16] + "…" + conf.Hash[len(conf.Hash)-14:]
			}
			blockHashVal.Color = colText

			confirmTimeVal.Text = time.Now().Format("2006-01-02 15:04:05")
			confirmTimeVal.Color = colText

			networkConfVal.Text = "1+"
			networkConfVal.Color = colAccent

			liveStatus.Text = fmt.Sprintf("Confirmed in block %d", conf.Height)
			liveStatus.Color = colAccent

			progress.SetValue(1)

			addActivity(fmt.Sprintf("Send %s to %s confirmed in block %d", amountStr, recipient[:min(16, len(recipient))]+"…", conf.Height))
		} else {
			statusIcon.Text = "⚠"
			statusIcon.Color = colWarn
			statusTitle.Text = "Transaction Still Pending"
			statusTitle.Color = colWarn
			statusSub.Text = "Not confirmed after 5 minutes — may confirm later or be dropped"
			statusSub.Color = colWarn
			liveStatus.Text = "Pending — check wallet screen for updates"
			liveStatus.Color = colWarn

			addActivity(fmt.Sprintf("Send %s to %s still pending after 5 min", amountStr, recipient[:min(16, len(recipient))]+"…"))
		}
		inner.Refresh()
	})

	fyne.Do(func() {
		closeBtn := widget.NewButtonWithIcon("Close", theme.ConfirmIcon(), func() {
			dlg.Hide()
		})
		closeBtn.Importance = widget.HighImportance
		inner.Add(spacer(12))
		inner.Add(container.NewCenter(closeBtn))
		inner.Refresh()
	})
}

// MintJob carries everything the mint status dialog and its worker need to
// run the sign → IPFS pin → on-chain anchor pipeline, independent of the
// Sign screen's own local widget state. The screen builds one of these and
// hands it to showMintStatusDialog instead of driving a bare progress
// dialog + a separate blocking ShowInformation modal itself.
type MintJob struct {
	Window             fyne.Window
	Client             *WalletClient
	ChainHeader        *core.SphinxChainHeader
	SelectedFile       string
	Passphrase         string
	SessionPassphrase  string
	SessionFingerprint string
	PublicFingerprint  string
	NFTName            string
	NFTDescription     string
	MintFeeSPX         func() float64

	// StatusText is the small inline status line already on the Sign
	// screen itself (kept in sync so it still reflects the final result
	// after the dialog is closed, same as before the refactor).
	StatusText *canvas.Text

	// ResetDropZone clears the Sign screen's drop-zone widgets once the
	// job finishes (success or the non-fatal "mint skipped" path).
	ResetDropZone func()

	// ClearSelectedFile clears the screen's selectedFile variable so a
	// finished job can't be re-submitted by mistake.
	ClearSelectedFile func()
}

// mintStatusFields groups the live-updating widgets inside the Mint Data
// status dialog so the worker goroutine can mutate them via fyne.Do —
// mirroring the Transfer Status dialog's statusIcon/statusTitle/liveStatus
// pattern instead of Mint Data's old hide-progress-then-pop-a-modal flow.
type mintStatusFields struct {
	dlg   *dialog.CustomDialog
	inner *fyne.Container

	statusIcon  *canvas.Text
	statusTitle *canvas.Text
	statusSub   *canvas.Text
	progress    *widget.ProgressBar
	stepVal     *canvas.Text

	fileVal        *canvas.Text
	cidVal         *canvas.Text
	tokenURIVal    *canvas.Text
	txidVal        *canvas.Text
	blockHeightVal *canvas.Text
	anchorVal      *canvas.Text
	feeVal         *canvas.Text

	liveStatus *canvas.Text
}

// showMintStatusDialog opens a single persistent "Mint Status" popup — the
// same NewCustomWithoutButtons + live canvas.Text/ProgressBar pattern as
// showTransferStatusDialog — and hands off to mintStatusDialogWorker to run
// the sign/upload/anchor pipeline in the background, morphing this one
// dialog from "in progress" to "success/failure" in place.
func showMintStatusDialog(job MintJob) {
	f := mintStatusFields{}

	f.statusIcon = canvas.NewText("⏳", colWarn)
	f.statusIcon.TextSize = 36
	f.statusIcon.TextStyle = fyne.TextStyle{Bold: true}

	f.statusTitle = canvas.NewText("Preparing Signature…", colWarn)
	f.statusTitle.TextSize = 16
	f.statusTitle.TextStyle = fyne.TextStyle{Bold: true}

	f.statusSub = canvas.NewText("Reading document…", colMuted)
	f.statusSub.TextSize = 12

	f.progress = widget.NewProgressBar()
	f.progress.Min = 0
	f.progress.Max = 1
	f.progress.SetValue(0.05)

	f.stepVal = canvas.NewText("Reading file…", colFaint)
	f.stepVal.TextSize = 11
	f.stepVal.TextStyle = fyne.TextStyle{Italic: true}

	f.fileVal = canvas.NewText(filepath.Base(job.SelectedFile), colMuted)
	f.fileVal.TextSize = 11
	f.fileVal.TextStyle = fyne.TextStyle{Monospace: true}

	f.cidVal = canvas.NewText("—", colFaint)
	f.cidVal.TextSize = 11
	f.cidVal.TextStyle = fyne.TextStyle{Monospace: true}

	f.tokenURIVal = canvas.NewText("—", colFaint)
	f.tokenURIVal.TextSize = 11
	f.tokenURIVal.TextStyle = fyne.TextStyle{Monospace: true}

	f.txidVal = canvas.NewText("—", colFaint)
	f.txidVal.TextSize = 11
	f.txidVal.TextStyle = fyne.TextStyle{Monospace: true}

	f.blockHeightVal = canvas.NewText("—", colFaint)
	f.blockHeightVal.TextSize = 11
	f.blockHeightVal.TextStyle = fyne.TextStyle{Monospace: true}

	f.anchorVal = canvas.NewText("—", colFaint)
	f.anchorVal.TextSize = 11
	f.anchorVal.TextStyle = fyne.TextStyle{Monospace: true}

	f.feeVal = canvas.NewText("—", colFaint)
	f.feeVal.TextSize = 11
	f.feeVal.TextStyle = fyne.TextStyle{Monospace: true}

	f.liveStatus = canvas.NewText("Starting…", colFaint)
	f.liveStatus.TextSize = 11
	f.liveStatus.TextStyle = fyne.TextStyle{Italic: true}

	f.inner = container.NewVBox(
		spacer(6),
		container.NewCenter(f.statusIcon),
		spacer(6),
		container.NewCenter(f.statusTitle),
		container.NewCenter(f.statusSub),
		spacer(16),
		f.progress,
		container.NewCenter(f.stepVal),
		spacer(14),
		infoRowDynamic("File", f.fileVal),
		spacer(4),
		infoRowDynamic("IPFS CID", f.cidVal),
		spacer(4),
		infoRowDynamic("Token URI", f.tokenURIVal),
		spacer(10),
		hRule(),
		spacer(10),
		sectionLabel("On-Chain Anchor"),
		spacer(6),
		infoRowDynamic("Transaction ID", f.txidVal),
		spacer(4),
		infoRowDynamic("Block Height", f.blockHeightVal),
		spacer(4),
		infoRowDynamic("Anchor File", f.anchorVal),
		spacer(4),
		infoRowDynamic("Mint Fee", f.feeVal),
		spacer(10),
		container.NewCenter(f.liveStatus),
		spacer(4),
	)

	bg := canvas.NewRectangle(colSurface)
	bg.CornerRadius = 14
	bg.StrokeColor = colAccent
	bg.StrokeWidth = 1

	content := container.NewMax(bg, container.NewPadded(f.inner))

	f.dlg = dialog.NewCustomWithoutButtons("Mint Status", content, job.Window)
	f.dlg.Resize(fyne.NewSize(520, 620))
	f.dlg.Show()

	go mintStatusDialogWorker(job, f)
}

// mintStatusDialogWorker runs the sign → IPFS pin → NFT metadata upload →
// on-chain anchor → confirmation-wait pipeline in the background, updating
// the dialog's live widgets via fyne.Do at each step instead of driving a
// separate progress dialog and then popping a final blocking modal.
func mintStatusDialogWorker(job MintJob, f mintStatusFields) {
	fileBase := filepath.Base(job.SelectedFile)

	step := func(pct float64, label string) {
		fyne.Do(func() {
			f.progress.SetValue(pct)
			f.stepVal.Text = label
			f.stepVal.Refresh()
		})
	}

	fail := func(title string, err error) {
		fyne.Do(func() {
			f.statusIcon.Text = "✗"
			f.statusIcon.Color = colDanger
			f.statusTitle.Text = title
			f.statusTitle.Color = colDanger
			f.statusSub.Text = err.Error()
			f.statusSub.Color = colDanger
			f.statusSub.TextSize = 10
			f.liveStatus.Text = "Mint aborted"
			f.liveStatus.Color = colDanger
			f.progress.SetValue(0)
			f.inner.Add(spacer(12))
			closeBtn := widget.NewButtonWithIcon("Close", theme.ConfirmIcon(), func() { f.dlg.Hide() })
			closeBtn.Importance = widget.HighImportance
			f.inner.Add(container.NewCenter(closeBtn))
			f.inner.Refresh()
		})
	}

	step(0.1, "Reading file…")
	data, err := os.ReadFile(job.SelectedFile)
	if err != nil {
		fail("Read Failed", err)
		return
	}

	step(0.25, "Hashing document…")
	hash := keys.SHAKE256Hash(data)

	step(0.4, "Generating signature…")
	sig, err := sign.Sign(hash, job.Passphrase)
	if err != nil {
		fail("Signing Failed", err)
		return
	}

	step(0.5, "Embedding signature…")
	meta, err := sign.NewMeta(sig, hash)
	if err != nil {
		fail("Signing Failed", err)
		return
	}

	meta.OrgCode = "SPIF"
	meta.Signer = job.SessionFingerprint
	meta.DocumentTitle = fileBase

	// Upload signed payload bytes to IPFS BEFORE the sidecar is written (so
	// the on-chain mint can bind to a real CID and the .usimeta sidecar can
	// record it). A missing/unreachable IPFS daemon must NOT block the
	// mint: AddBytesToIPFSWithFallback returns a deterministic local CID,
	// and we surface the warning while continuing with the signature,
	// receipt, and on-chain anchor.
	step(0.58, "Uploading to IPFS…")
	ipfsClient := storage.NewClient(storage.DefaultConfig())
	cid, ipfsWarn := ipfsClient.AddBytesToIPFSWithFallback(data, fileBase)
	ipfsNote := ""
	if ipfsWarn != nil {
		ipfsNote = " (IPFS unreachable — anchored with a local fallback CID)"
		log.Printf("[WARN] Mint Data: continuing without real IPFS upload: %v", ipfsWarn)
	}
	gatewayBase := storage.DefaultConfig().GatewayBaseURL
	metadataURI := gatewayBase + "/ipfs/" + cid

	fyne.Do(func() {
		f.cidVal.Text = cid
		f.cidVal.Color = colText
		if ipfsWarn != nil {
			f.cidVal.Color = colWarn
		}
		f.cidVal.Refresh()
	})

	// Build and upload ERC-721 metadata JSON to IPFS — creates the
	// tokenURI that points at the metadata JSON, just like Ethereum
	// ERC-721 NFTs (name, description, image ipfs://<mediaCID>, attrs).
	var tokenURI string
	var metadataCID string
	if cid != "" && job.NFTName != "" {
		step(0.63, "Uploading metadata JSON…")
		nftMeta := mint.BuildNFTMetadata(
			job.NFTName,
			job.NFTDescription,
			cid,
			nil, // attributes (future enhancement)
			job.PublicFingerprint,
			"SPIF",
			fileBase,
			"", // mintID not known yet
			0,  // blockHeight not known yet
		)
		metadataCID, tokenURI, err = mint.UploadNFTMetadata(nftMeta, ipfsClient)
		if err != nil {
			log.Printf("[WARN] Mint Data: metadata JSON upload failed: %v", err)
			tokenURI = ""
			metadataCID = ""
		} else {
			log.Printf("[INFO] Mint Data: metadata JSON uploaded, tokenURI=%s", tokenURI)
			fyne.Do(func() {
				f.tokenURIVal.Text = tokenURI
				f.tokenURIVal.Color = colText
				f.tokenURIVal.Refresh()
			})
		}
	}

	// Fetch the chain-tip block header (lightweight, header-only path —
	// see GetChainTipHeader) so the sidecar can record the block height
	// the document was minted at. Best-effort: an offline node must not
	// block signing, so on failure we log a warning and leave
	// BlockHeight unset.
	var blockHeight uint64
	if tipHdr, tipErr := job.Client.GetChainTipHeader(); tipErr != nil || tipHdr == nil {
		log.Printf("[WARN] Mint Data: could not fetch chain tip header for sidecar: %v", tipErr)
	} else {
		blockHeight = tipHdr.Height
	}

	meta.IPFSCID = cid
	meta.BlockHeight = blockHeight
	meta.TokenURI = tokenURI
	meta.MetadataCID = metadataCID

	step(0.7, "Embedding signature…")
	if err := sign.EmbedSignature(job.SelectedFile, meta, job.PublicFingerprint, job.Passphrase); err != nil {
		fail("Embed Failed", err)
		return
	}

	// After signing, auto-mint NFT on-chain.
	step(0.78, "Anchoring NFT on-chain…")
	fyne.Do(func() {
		f.statusTitle.Text = "Anchoring On-Chain…"
		f.statusSub.Text = "Broadcasting mint receipt to the network…"
		f.liveStatus.Text = "Broadcasting anchor transaction…"
		f.liveStatus.Color = colInfo
		f.statusTitle.Refresh()
		f.statusSub.Refresh()
		f.liveStatus.Refresh()
	})

	mintRes, mintErr := mint.Mint(data, fileBase, job.SessionPassphrase, "SPIF", cid, metadataURI)
	if mintErr == nil && tokenURI != "" {
		mintRes.Receipt.TokenURI = tokenURI
		mintRes.Receipt.MetadataCID = metadataCID
	}

	if mintErr != nil {
		fyne.Do(func() {
			f.statusIcon.Text = "✓"
			f.statusIcon.Color = colAccent
			f.statusTitle.Text = "Signed — NFT Mint Skipped"
			f.statusTitle.Color = colAccent
			f.statusSub.Text = mintErr.Error()
			f.statusSub.Color = colWarn
			f.liveStatus.Text = "Signature embedded, no on-chain anchor was created"
			f.liveStatus.Color = colWarn
			f.progress.SetValue(1)

			addActivity(fmt.Sprintf("Signed document (NFT mint skipped): %s", fileBase))
			job.StatusText.Text = "✓  Document signed — signature embedded (NFT mint skipped)"
			job.StatusText.Color = colAccent
			job.StatusText.Refresh()

			f.inner.Add(spacer(12))
			closeBtn := widget.NewButtonWithIcon("Close", theme.ConfirmIcon(), func() {
				f.dlg.Hide()
				job.ClearSelectedFile()
				job.ResetDropZone()
			})
			closeBtn.Importance = widget.HighImportance
			f.inner.Add(container.NewCenter(closeBtn))
			f.inner.Refresh()
		})
		return
	}

	txID, anchorPath, mintFeeNSPX, anchorNonce, anchorErr := job.Client.AnchorMintReceipt(mintRes.Receipt)
	if anchorErr == nil {
		if mintFeeNSPX != nil {
			meta.MintFeeNSPX = mintFeeNSPX.String()
		}
		meta.AnchorNonce = fmt.Sprintf("%d", anchorNonce)
	}

	fyne.Do(func() {
		f.txidVal.Text = txID
		f.txidVal.Color = colText
		f.anchorVal.Text = anchorPath
		f.anchorVal.Color = colText
		if mintFeeNSPX != nil {
			f.feeVal.Text = sign.FormatMintFeeNSPX(meta.MintFeeNSPX)
			f.feeVal.Color = colAccent
		}
		f.txidVal.Refresh()
		f.anchorVal.Refresh()
		f.feeVal.Refresh()
	})

	if anchorErr != nil {
		fyne.Do(func() {
			f.statusIcon.Text = "⚠"
			f.statusIcon.Color = colWarn
			f.statusTitle.Text = "Signed — NFT Anchor Failed"
			f.statusTitle.Color = colWarn
			f.statusSub.Text = anchorErr.Error()
			f.statusSub.Color = colWarn
			f.liveStatus.Text = "Document signed, but the anchor transaction failed"
			f.liveStatus.Color = colWarn
			f.progress.SetValue(1)

			log.Printf("[ERROR] Mint Data: NFT anchor failed for %s: %v", fileBase, anchorErr)
			addActivity(fmt.Sprintf("Signed document: %s (NFT anchor failed: %v)", fileBase, anchorErr))
			job.StatusText.Text = "✓  Document signed, but NFT anchor failed: " + anchorErr.Error()
			job.StatusText.Color = colWarn
			job.StatusText.Refresh()

			f.inner.Add(spacer(12))
			closeBtn := widget.NewButtonWithIcon("Close", theme.ConfirmIcon(), func() {
				f.dlg.Hide()
				job.ClearSelectedFile()
				job.ResetDropZone()
			})
			closeBtn.Importance = widget.HighImportance
			f.inner.Add(container.NewCenter(closeBtn))
			f.inner.Refresh()
		})
		return
	}

	// Wait (bounded) for the anchor tx to be committed so the provenance
	// stamped below records the REAL confirming block instead of the
	// "pending" sentinel. A timeout is NOT fatal: the anchor stays
	// on-chain and provenance falls back to pending while a background
	// poller keeps trying, so the sidecar eventually shows the real block
	// hash/height once the node validates and confirms the tx.
	step(0.9, "Waiting for block confirmation…")
	fyne.Do(func() {
		f.liveStatus.Text = fmt.Sprintf("Polling for confirmation (txid: %s…)", txID[:min(12, len(txID))])
		f.liveStatus.Color = colFaint
		f.liveStatus.Refresh()
	})
	confirmed, _ := job.Client.WaitForTxConfirmation(txID, 300*time.Second)

	var confirmedBlock interface {
		GetHeight() uint64
		GetHash() string
	}
	if confirmed != nil {
		confirmedBlock = &confirmedBlockInfo{height: confirmed.Height, hash: confirmed.Hash}
	}

	provErr := sign.RefreshOnChainProvenance(job.SelectedFile, meta, job.PublicFingerprint, txID, anchorPath, mintRes.Receipt.MintID, 0, "", confirmedBlock)
	if provErr != nil {
		log.Printf("[WARN] Mint Data: provenance refresh incomplete: %v", provErr)
	}

	// Background poller: if the initial 300s wait timed out, keep polling
	// for up to 600s more and rewrite the REAL block hash/height into the
	// provenance the moment the node confirms the anchor tx.
	if confirmed == nil {
		bgFile := job.SelectedFile
		bgTxID := txID
		bgAnchorPath := anchorPath
		log.Printf("[Mint Data] txid=%s not yet confirmed after 300s — background poller continuing (600s)", bgTxID)
		go func() {
			bgConfirmed, _ := job.Client.WaitForTxConfirmation(bgTxID, 600*time.Second)
			if bgConfirmed != nil {
				bgBlock := &confirmedBlockInfo{height: bgConfirmed.Height, hash: bgConfirmed.Hash}
				bgErr := sign.RefreshOnChainProvenance(bgFile, meta, job.PublicFingerprint, bgTxID, bgAnchorPath, mintRes.Receipt.MintID, 0, "", bgBlock)
				if bgErr != nil {
					log.Printf("[WARN] Mint Data: background provenance refresh failed: %v", bgErr)
				} else {
					log.Printf("[Mint Data] Background poller: txid=%s confirmed at height=%d hash=%s — provenance updated to REAL block", bgTxID, bgConfirmed.Height, bgConfirmed.Hash)
				}
			} else {
				log.Printf("[WARN] Mint Data: txid=%s still unconfirmed after 900s total — provenance remains pending", bgTxID)
			}
		}()
	}

	fyne.Do(func() {
		anchorSuffix := ipfsNote
		if confirmed != nil {
			f.statusIcon.Text = "✓"
			f.statusIcon.Color = colAccent
			f.statusTitle.Text = "Minted ✓"
			f.statusTitle.Color = colAccent
			f.statusSub.Text = "Signed & minted — confirmed on-chain"
			f.statusSub.Color = colAccent

			f.blockHeightVal.Text = fmt.Sprintf("%d", confirmed.Height)
			f.blockHeightVal.Color = colAccent

			f.liveStatus.Text = fmt.Sprintf("Confirmed in block %d", confirmed.Height)
			f.liveStatus.Color = colAccent
		} else {
			f.statusIcon.Text = "✓"
			f.statusIcon.Color = colAccent
			f.statusTitle.Text = "Minted — Confirmation Pending"
			f.statusTitle.Color = colWarn
			f.statusSub.Text = "Anchored on-chain; still waiting on block confirmation"
			f.statusSub.Color = colWarn

			f.liveStatus.Text = "Anchor pending — background poller will update the sidecar once confirmed"
			f.liveStatus.Color = colWarn
		}
		f.progress.SetValue(1)

		addActivity(fmt.Sprintf("Signed & minted NFT: %s (tx=%s, cid=%s, height=%d, anchor=%s%s)", fileBase, txID, cid, blockHeight, anchorPath, anchorSuffix))
		job.StatusText.Text = fmt.Sprintf("✓  Signed & minted NFT%s. txid=%s\ncid=%s\nheight=%d\nAnchor: %s", anchorSuffix, txID, cid, blockHeight, anchorPath)
		job.StatusText.Color = colAccent
		job.StatusText.Refresh()

		f.inner.Add(spacer(12))
		closeBtn := widget.NewButtonWithIcon("Close", theme.ConfirmIcon(), func() {
			f.dlg.Hide()
			job.ClearSelectedFile()
			job.ResetDropZone()
		})
		closeBtn.Importance = widget.HighImportance
		f.inner.Add(container.NewCenter(closeBtn))
		f.inner.Refresh()
	})
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
	fixedLabel := widget.NewLabelWithStyle("Organization: "+string(keys.OrgSPIF), fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	fixedLabel.Importance = widget.HighImportance

	infoLabel := widget.NewLabel(string(keys.OrgSPIF) + " - Sphinx Fingerprint")
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
	selectBox := widget.NewSelect([]string{string(keys.OrgSPIF)}, func(selected string) {})
	selectBox.SetSelected(string(keys.OrgSPIF))
	selectBox.Hide()

	selector := &OrgSelector{
		Widget:    widgetContainer,
		selectBox: selectBox,
	}

	return selector
}

// SelectedOrg returns SPIF always
func (os *OrgSelector) SelectedOrg() keys.OrgCode {
	return keys.OrgSPIF
}

// SetSelectedOrg does nothing (only SPIF is available)
func (os *OrgSelector) SetSelectedOrg(orgCode keys.OrgCode) {
	// Only SPIF is available, ignore any other value
	log.Printf("[DEBUG] SetSelectedOrg called with %q, ignoring (only SPIF supported)", orgCode)
}

// requireMintBalance asserts the logged-in wallet holds at least the policy
// minimum balance required to mint data through USI (default 100 SPX), and
// returns the live balance on success. Minting is a paid, gated operation:
// anyone below the floor is not allowed to anchor new data, and the balance is
// read from the full node's JSON-RPC (getbalance), so an offline node rejects
// the mint rather than silently bypassing the requirement.
func requireMintBalance(client *WalletClient) (*BalanceResponse, error) {
	if client == nil {
		return nil, errors.New("wallet client not initialised")
	}
	resp, err := client.GetBalance("")
	if err != nil {
		return nil, fmt.Errorf("could not verify SPX balance (is the full node online?): %w", err)
	}
	if resp == nil || resp.Balance.Int == nil {
		return nil, errors.New("could not verify SPX balance")
	}

	mintPolicy := policy.GetDefaultPolicyParams()
	minBalance := mintPolicy.GetMinMintBalance()
	if resp.Balance.Int.Cmp(minBalance) < 0 {
		held := formatSPXAmount(new(big.Float).Quo(new(big.Float).SetInt(resp.Balance.Int), big.NewFloat(1e18)))
		required := formatSPXAmount(new(big.Float).SetFloat64(mintPolicy.GetMinMintBalanceSPX()))
		return nil, fmt.Errorf("minting data requires holding at least %s SPX — your current balance is %s SPX",
			required, held)
	}
	return resp, nil
}

// AnchorMintReceipt commits a signed MintReceipt to the chain.
//
// VERIFICATION CONTRACT: the anchor tag in the transaction's ReturnData is
// now verified by EVERY node — src/core.ValidateTransactionPolicy runs
// core.ValidateAnchorData both at admission (sendrawtransaction →
// AddTransaction) and at consensus (CommitBlock re-checks every transaction
// of every proposed and synced block). An anchor whose CID commitment,
// receipt hash, or minter key does not verify is rejected before entering
// the mempool and can never be committed. This transaction therefore uses a
// self-send whose ReturnData carries the verifiable mint_anchor commitment
// (same memo pattern as SendTransaction); if Sphinx later adds a
// first-class MINT/DATA tx type, only the tag construction here changes.
// AnchorMintReceipt commits a signed MintReceipt to the chain and saves the anchor tag.
func (c *WalletClient) AnchorMintReceipt(receipt *mint.MintReceipt) (txID string, anchorPath string, mintFeeNSPX *big.Int, anchorNonce uint64, err error) {
	if sessionPassphrase == "" {
		return "", "", nil, 0, errors.New("not logged in")
	}
	if receipt == nil {
		return "", "", nil, 0, errors.New("nil receipt")
	}

	// Minting data is a paid operation gated on holding the policy minimum
	// balance. Enforce it here — in addition to the GUI screens — so every
	// wallet path that anchors a receipt obeys the holding requirement.
	if _, err := requireMintBalance(c); err != nil {
		return "", "", nil, 0, fmt.Errorf("mint rejected: %w", err)
	}

	// Build NFT off-chain storage + on-chain anchor payload (Ethereum-style: anchor CID hash).
	// 1) Upload mint receipt JSON bytes to IPFS and get CID.
	// 2) Build deterministic CIDHash and create a storage artifact payload.
	// 3) Anchor only the CIDHash/contract payload on-chain (replace receipt-anchor-only).
	//
	// NOTE: This uses storage module with safe fallbacks when IPFS is disabled.
	payloadJSON, err := json.Marshal(receipt)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("marshal mint receipt: %w", err)
	}

	ipfsClient := storage.NewClient(storage.DefaultConfig())
	cid, cidErr := ipfsClient.AddBytesToIPFSWithFallback(payloadJSON, fmt.Sprintf("mint_%s.json", receipt.MintID))
	if cidErr != nil {
		// Not fatal: the on-chain anchor only needs the CID hash commitment.
		// A missing IPFS daemon must not block anchoring the receipt.
		log.Printf("[WARN] AnchorMintReceipt: receipt not uploaded to IPFS, continuing with fallback CID: %v", cidErr)
	}
	cidHashHex := storage.CIDHash(cid)

	artifact := &storage.StorageArtifact{
		MintID:     receipt.MintID,
		Subject:    receipt.Subject,
		CID:        cid,
		CIDHashHex: cidHashHex,
		// best-effort fields
		PayloadHash:   receipt.PayloadHash,
		ReceiptHash:   "",
		AnchorTagType: "nft_anchor",
	}

	// Store artifact association on node (best-effort, bounded).
	// This is a second full RPC round-trip (handshake + storeartifact); when
	// the node is slow or unreachable it must not stall the anchor behind
	// it — a timeout here only skips an off-chain cache, never the on-chain
	// commitment. Skip it entirely when IPFS is disabled: without a real
	// pinned CID there is nothing worth caching node-side.
	if !storage.DefaultConfig().DisableIPFS {
		storeDone := make(chan struct{})
		go func() {
			defer close(storeDone)
			if _, storeErr := storage.DefaultStorageClient(c.nodeAddr).StoreMintArtifact(artifact); storeErr != nil {
				log.Printf("[WARN] AnchorMintReceipt: artifact cache skipped: %v", storeErr)
			}
		}()
		select {
		case <-storeDone:
		case <-time.After(15 * time.Second):
			log.Printf("[WARN] AnchorMintReceipt: artifact cache timed out after 15s, continuing with anchor")
		}
	}

	anchorData, err := mint.BuildAnchorData(receipt)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("build receipt anchor payload (ethereum-style): %w", err)
	}

	rawSender, err := normaliseAddress(sessionFingerprint)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("invalid sender address: %w", err)
	}

	log.Printf("[WalletRPC] AnchorMintReceipt: anchoring mint_id=%s subject=%s",
		receipt.MintID, receipt.Subject)

	kp, skBytes, err := keys.LoadKeyFromDisk(sessionPassphrase)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("failed to load key: %w", err)
	}

	defer func() {
		for i := range skBytes {
			skBytes[i] = 0
		}
	}()

	// Mint anchors are a paid operation under the shared policy schedule: the
	// ordinary gas quote only covers the data footprint, so QuoteMintDataGas
	// raises the gas price until the gas fee reaches the policy mint fee
	// (default 1 SPX). Core re-derives and enforces the minimum independently
	// when the transaction arrives; an offered gas price above the floor is
	// always accepted, and the executor deducts the full gas fee from the
	// sender and distributes it per the fee schedule.
	//
	// QuoteMintDataGas sizes the price from four dimensions:
	//   payloadBytes  — the bytes pinned to IPFS (the marshaled receipt uploaded
	//                   above is what this wallet actually pins; its CID is what
	//                   gets committed on-chain),
	//   anchorBytes   — the on-chain anchor payload (ReturnData) footprint,
	//   numHashes     — committed hashes / Merkle leaves (governance default),
	//   pinningMonths — IPFS retention (governance default).
	mintPolicy := policy.GetDefaultPolicyParams()
	gasQuote := mintPolicy.QuoteMintDataGas(uint64(len(payloadJSON)), uint64(len(anchorData)), mintPolicy.MintBaseHashes, mintPolicy.MintPinningMonths)

	// ChainID for EIP-155 replay protection — must match the node's network.
	// Fall back to the Sphinx mainnet chain ID (7331) when the header is
	// unavailable.
	chainID := uint64(7331)
	if chainHdr := core.GetSphinxChainHeader(); chainHdr != nil && chainHdr.ChainID != 0 {
		chainID = chainHdr.ChainID
	}

	// Use the node's exact current nonce (mempool enforces an EXACT match —
	// "invalid nonce: %d must equal %d"). A timestamp fallback can never pass
	// that check, so fail loudly instead of broadcasting a guaranteed-reject.
	var nonce uint64
	if cachedNonce, err := c.getCurrentNonce(sessionFingerprint); err == nil {
		nonce = cachedNonce
	} else {
		return "", "", nil, 0, fmt.Errorf("failed to get account nonce from node: %w", err)
	}

	// Calculate the mint fee from policy to represent the value of the signed
	// data on-chain. Even though this is a self-send (the anchor tx exists only
	// to carry data), the Amount field records the deterministic, policy-priced
	// worth of the minted data in nSPX — never a hardcoded constant.
	mintFeeQuote := mintPolicy.CalculateMintDataFee(uint64(len(payloadJSON)), uint64(len(anchorData)), mintPolicy.MintBaseHashes, mintPolicy.MintPinningMonths)
	mintFeeNSPX = big.NewInt(1)
	if mintFeeQuote != nil && mintFeeQuote.TotalFee != nil && mintFeeQuote.TotalFee.Sign() > 0 {
		mintFeeNSPX = mintFeeQuote.TotalFee
	}

	tx := &types.Transaction{
		ID:         "",
		ChainID:    chainID,
		Sender:     rawSender,
		Receiver:   rawSender, // self-send: this tx exists only to carry data
		Amount:     mintFeeNSPX,
		GasLimit:   gasQuote.GasLimit,
		GasPrice:   gasQuote.GasPrice,
		Nonce:      nonce,
		Timestamp:  time.Now().Unix(),
		Signature:  []byte{},
		ReturnData: anchorData,
	}
	tx.ID = tx.Hash()

	if err := signTransactionLocally(tx, skBytes, kp.PublicKey); err != nil {
		return "", "", nil, 0, fmt.Errorf("failed to sign anchor transaction: %w", err)
	}

	txData, err := json.Marshal(tx)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("failed to marshal transaction: %w", err)
	}

	rawTx := hex.EncodeToString(txData)

	resultData, err := rpc.CallRPC(c.nodeAddr, "sendrawtransaction", []interface{}{rawTx}, 120)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("RPC error: %w", err)
	}
	if len(resultData) == 0 || string(resultData) == "null" {
		return "", "", nil, 0, errors.New("empty response")
	}

	var result struct {
		TxID   string `json:"txid"`
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(resultData, &result); err != nil {
		return "", "", nil, 0, fmt.Errorf("parse response: %w", err)
	}
	if result.Error != "" {
		return "", "", nil, 0, fmt.Errorf("anchor tx rejected: %s", result.Error)
	}

	// After successful RPC call:
	// Save off-chain anchor metadata sidecar (receipt-bound on disk).
	anchorTag, err := mint.BuildAnchorTag(receipt)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("build receipt anchor tag for sidecar: %w", err)
	}

	anchorPath, err = mint.SaveAnchorTag(anchorTag, "")

	if err != nil {
		log.Printf("[WARN] AnchorMintReceipt: failed to save anchor tag: %v", err)
		// do not fail the operation, just warn
		anchorPath = ""
	}
	log.Printf("[WalletRPC] AnchorMintReceipt: anchored as txid=%s, anchor saved to %s", result.TxID, anchorPath)
	return result.TxID, anchorPath, mintFeeNSPX, nonce, nil
}

// MintNFTInCollection executes the Ethereum-close SIP-721 collection mint for
// a receipt whose TokenURI is already set via a real IPFS upload (a collection
// mint aborts without a real tokenURI). The returned tokenId is the
// per-collection counter value committed by the block — contract storage
// tokenURI[tokenId] — read back with retries until the block lands. On success
// the receipt's token binding is recorded so the subsequent receipt anchor
// carries the same token_id/token_uri/contract triple (nodes enforce that the
// three travel together). Requires the logged-in key to be the collection
// owner — the node enforces ownerOf at consensus.
func (c *WalletClient) MintNFTInCollection(receipt *mint.MintReceipt, collection, toAddress string) (tokenID uint64, txID string, err error) {
	if sessionPassphrase == "" {
		return 0, "", errors.New("not logged in")
	}
	if receipt == nil {
		return 0, "", errors.New("nil receipt")
	}
	collection = strings.TrimSpace(collection)
	if collection == "" {
		return 0, "", errors.New("collection contract address required")
	}
	if strings.TrimSpace(receipt.TokenURI) == "" {
		return 0, "", errors.New("tokenURI required: a collection mint aborts without a real IPFS tokenURI")
	}

	rawFrom, err := normaliseAddress(sessionFingerprint)
	if err != nil {
		return 0, "", fmt.Errorf("invalid sender address: %w", err)
	}
	rawTo := rawFrom
	if strings.TrimSpace(toAddress) != "" {
		rawTo, err = normaliseAddress(toAddress)
		if err != nil {
			return 0, "", fmt.Errorf("invalid recipient address: %w", err)
		}
	}

	// mint.BroadcastSIP721CollectionMint builds/signs the collection.mint
	// contract call and waits (bounded) for the tokenId to be committed. Its
	// "keyFile" parameter is the local key passphrase here.
	tokenID, txID, err = mint.BroadcastSIP721CollectionMint(c.nodeAddr, collection, rawFrom, sessionPassphrase, rawTo, receipt.TokenURI, receipt.MintID)
	if err != nil {
		return 0, "", err
	}

	receipt.TokenID = tokenID
	receipt.ContractAddress = collection
	return tokenID, txID, nil
}

// BuildMintScreen returns the "Mint & Verify" tab content.
func BuildMintScreen(window fyne.Window, client *WalletClient) fyne.CanvasObject {
	var selectedPath string
	var lastReceipt *mint.MintResult
	var lastTxID string
	_ = lastTxID

	fileLabel := widget.NewLabel("No file selected")
	fileLabel.Wrapping = fyne.TextWrapWord

	subjectEntry := widget.NewEntry()
	subjectEntry.SetPlaceHolder("Subject / token identifier")

	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord

	anchorBtn := widget.NewButton("Anchor On-Chain", nil)
	anchorBtn.Disable()

	verifyOnChainBtn := widget.NewButton("Verify On-Chain", nil)
	verifyOnChainBtn.Disable()

	verifyOnChainBtn.OnTapped = func() {
		if lastTxID == "" {
			dialog.ShowError(fmt.Errorf("no anchored txid available"), window)
			return
		}
		resultData, err := rpc.CallRPC(client.nodeAddr, "gettransaction", []interface{}{lastTxID}, 60)
		if err != nil {
			dialog.ShowError(fmt.Errorf("gettransaction rpc: %w", err), window)
			return
		}
		if len(resultData) == 0 || string(resultData) == "null" {
			dialog.ShowError(fmt.Errorf("empty gettransaction response"), window)
			return
		}
		var tx types.Transaction
		if err := json.Unmarshal(resultData, &tx); err != nil {
			dialog.ShowError(fmt.Errorf("parse gettransaction: %w", err), window)
			return
		}

		if len(tx.ReturnData) == 0 {
			dialog.ShowError(fmt.Errorf("transaction has empty return_data"), window)
			return
		}

		anchorTag, err := mint.DeserializeAnchorTag(tx.ReturnData)
		_ = anchorTag
		if err != nil {
			dialog.ShowError(fmt.Errorf("deserialize anchor tag: %w", err), window)
			return
		}

		// We only need to ensure the tx.ReturnData is decodable as an AnchorTag.
		// Full commitment verification requires the original MintReceipt; GUI does not
		// currently load the anchored receipt from chain.
		statusLabel.SetText("On-chain verification: anchor decoded OK")
		addActivity(fmt.Sprintf("On-chain verified tx %s (mint anchor)", lastTxID))
	}

	pickBtn := widget.NewButton("Choose File", func() {
		fd := dialog.NewFileOpen(func(uc fyne.URIReadCloser, err error) {
			if err != nil || uc == nil {
				return
			}
			defer uc.Close()
			selectedPath = uc.URI().Path()
			fileLabel.SetText(selectedPath)
			if subjectEntry.Text == "" {
				subjectEntry.SetText(uc.URI().Name())
			}
		}, window)
		fd.Show()
	})

	signBtn := widget.NewButton("Sign", func() {
		if selectedPath == "" {
			dialog.ShowError(fmt.Errorf("choose a file first"), window)
			return
		}
		if sessionPassphrase == "" {
			dialog.ShowError(fmt.Errorf("not logged in"), window)
			return
		}
		payload, err := os.ReadFile(selectedPath)
		if err != nil {
			dialog.ShowError(fmt.Errorf("read file: %w", err), window)
			return
		}
		subject := subjectEntry.Text
		if subject == "" {
			dialog.ShowError(fmt.Errorf("subject required"), window)
			return
		}
		res, err := mint.Mint(payload, subject, sessionPassphrase, string(keys.OrgSPIF), "", "")
		if err != nil {
			dialog.ShowError(fmt.Errorf("mint: %w", err), window)
			return
		}
		lastReceipt = res
		if _, err := mint.SaveReceipt(res.Receipt, ""); err != nil {
			statusLabel.SetText(fmt.Sprintf(
				"Signed (mint_id=%s) — WARNING: receipt not saved to disk: %v",
				res.Receipt.MintID, err))
		} else {
			statusLabel.SetText(fmt.Sprintf("Signed. mint_id=%s\npayload_hash=%s",
				res.Receipt.MintID, res.Receipt.PayloadHash))
		}
		anchorBtn.Enable()
		addActivity(fmt.Sprintf("Signed mint receipt %s for subject %q", res.Receipt.MintID, subject))
	})

	anchorBtn.OnTapped = func() {
		if lastReceipt == nil {
			dialog.ShowError(fmt.Errorf("sign a receipt first"), window)
			return
		}
		txID, anchorPath, _, _, err := client.AnchorMintReceipt(lastReceipt.Receipt)
		if err != nil {
			dialog.ShowError(fmt.Errorf("anchor: %w", err), window)
			return
		}
		statusLabel.SetText(fmt.Sprintf("Anchored on-chain. txid=%s\nAnchor saved to: %s", txID, anchorPath))
		addActivity(fmt.Sprintf("Anchored mint %s in tx %s, anchor %s", lastReceipt.Receipt.MintID, txID, anchorPath))
		lastTxID = txID
		verifyOnChainBtn.Enable()

		// Track block inclusion so the status shows the REAL confirming block
		// instead of leaving the anchor in limbo. Non-blocking: runs in background.
		go func() {
			conf, _ := client.WaitForTxConfirmation(txID, 120*time.Second)
			fyne.Do(func() {
				if conf != nil {
					statusLabel.SetText(fmt.Sprintf("Anchored & confirmed. txid=%s\nConfirmed in block %d (%s)\nAnchor saved to: %s", txID, conf.Height, conf.Hash, anchorPath))
					addActivity(fmt.Sprintf("Anchor tx %s confirmed in block %d", txID, conf.Height))
				}
			})
		}()
	}

	signForm := container.NewVBox(
		screenTitle("Mint"),
		screenSubtitle("Sign any file with your SPHINCS+ key, then anchor a commitment on-chain."),
		spacer(12),
		pickBtn, fileLabel,
		spacer(8),
		subjectEntry,
		spacer(12),
		container.NewHBox(signBtn, anchorBtn),
		spacer(12),
		statusLabel,
	)

	// ---- Verify pane ----
	var verifyReceiptPath, verifyPayloadPath string

	vReceiptLabel := widget.NewLabel("No receipt selected")
	vPayloadLabel := widget.NewLabel("No payload selected (optional)")

	vResult := widget.NewLabel("")
	vResult.Wrapping = fyne.TextWrapWord

	pickReceiptBtn := widget.NewButton("Choose Receipt (.json)", func() {
		fd := dialog.NewFileOpen(func(uc fyne.URIReadCloser, err error) {
			if err != nil || uc == nil {
				return
			}
			defer uc.Close()
			verifyReceiptPath = uc.URI().Path()
			vReceiptLabel.SetText(verifyReceiptPath)
		}, window)
		fd.Show()
	})

	pickPayloadBtn := widget.NewButton("Choose Payload (optional)", func() {
		fd := dialog.NewFileOpen(func(uc fyne.URIReadCloser, err error) {
			if err != nil || uc == nil {
				return
			}
			defer uc.Close()
			verifyPayloadPath = uc.URI().Path()
			vPayloadLabel.SetText(verifyPayloadPath)
		}, window)
		fd.Show()
	})

	verifyBtn := widget.NewButton("Verify", func() {
		if verifyReceiptPath == "" {
			dialog.ShowError(fmt.Errorf("choose a receipt file"), window)
			return
		}
		receipt, err := mint.LoadReceipt(verifyReceiptPath)
		if err != nil {
			dialog.ShowError(fmt.Errorf("load receipt: %w", err), window)
			return
		}
		var payload []byte
		if verifyPayloadPath != "" {
			payload, err = os.ReadFile(verifyPayloadPath)
			if err != nil {
				dialog.ShowError(fmt.Errorf("read payload: %w", err), window)
				return
			}
		}
		ok, err := mint.Verify(receipt, payload)
		if !ok {
			vResult.SetText(fmt.Sprintf("INVALID: %v", err))
			return
		}
		vResult.SetText(fmt.Sprintf(
			"VALID\nsubject=%s\nminter_pubkey=%.16s...\nsigned at=%s",
			receipt.Subject, receipt.MinterPublicKey,
			time.Unix(receipt.Timestamp, 0).Format(time.RFC3339)))
	})

	verifyForm := container.NewVBox(
		screenTitle("Verify"),
		screenSubtitle("Check a receipt's signature, and optionally that it matches a payload file."),
		spacer(12),
		pickReceiptBtn, vReceiptLabel,
		spacer(8),
		pickPayloadBtn, vPayloadLabel,
		spacer(12),
		verifyBtn,
		spacer(12),
		vResult,
	)

	return container.NewAppTabs(
		container.NewTabItem("Mint", container.NewPadded(signForm)),
		container.NewTabItem("Verify", container.NewPadded(verifyForm)),
	)
}
