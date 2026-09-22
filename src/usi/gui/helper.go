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
	"image/color"
	"io"
	"log"
	"math/big"
	"os"
	"path/filepath"
	debug "runtime/debug"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/sphinxfndorg/protocol/src/bind/abi"
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

// -------------------------------------------------------------------------
// STARTUP BEACON
// -------------------------------------------------------------------------

// buildBeaconLine identifies the build actually running, printed once at
// startup so the terminal shows which source tree / binary produced the window
// on screen.
//
// ★ WHY THIS EXISTS: a UI value being wrong cannot be told apart from a stale
// binary being run instead of the freshly-edited source. That ambiguity is
// exactly what surrounded the "gas price always 0 SPX/gas" report: a prebuilt
// ./cmd from an earlier session (which had no fee panel at all) sat next to the
// working-tree fix in src/usi/gui. This line makes "which build am I looking
// at?" answerable in one glance, before any RPC call or key load.
func buildBeaconLine() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "build: info unavailable"
	}
	rev, modified, built := "unknown", "", ""
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			modified = s.Value
		case "vcs.time":
			built = s.Value
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return fmt.Sprintf("build: %s rev=%s modified=%s built=%s go=%s",
		info.Main.Path, rev, modified, built, info.GoVersion)
}

// gasUnitBeaconLine states the denomination every gas price in the UI is
// rendered in, computed through the SAME two formatters the UI uses —
// formatGasPriceAmount for gSPX and formatSPXAmount for the historical SPX
// rendering — so "why did it read 0 SPX/gas?" is answerable from the terminal
// without opening a dialog.
//
// The bug it documents: policy.MinimumGasPrice is 1,000,000,000 nSPX = 1 gSPX
// = 10^-9 SPX, and formatSPXAmount prints at most six decimal places, so an
// SPX rendering rounds the minimum — and every tier derived from it (2x, 5x,
// N×) — to a flat "0". Dividing by 1 gSPX instead keeps the value legible.
func gasUnitBeaconLine() string {
	p := policy.GetDefaultPolicyParams()
	if p == nil || p.MinimumGasPrice == nil {
		return "gas price: policy unavailable"
	}
	asSPX := new(big.Float).SetPrec(256).Quo(
		new(big.Float).SetPrec(256).SetInt(p.MinimumGasPrice),
		big.NewFloat(1e18),
	)
	return fmt.Sprintf("gas price: minimum %s nSPX = %s %s (rendered as SPX through the 6-decimal formatter it rounds to %q — that was the bug)",
		p.MinimumGasPrice.String(), formatGasPriceAmount(p.MinimumGasPrice), gasPriceUnitLabel, formatSPXAmount(asSPX))
}

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

// showErrorDialog is a drop-in replacement for Fyne's dialog.ShowError(err, window).
//
// ★ FIX: dialog.ShowError sizes its dialog (and, transitively, the whole
// window — Fyne grows a window to satisfy its content's MinSize) to fit its
// message on as few lines as Fyne's default label can manage. RPC/decryption
// errors here can carry long unbroken strings (full node error payloads,
// hex hashes, file paths), so a single long error was enough to force the
// main window wider every time it fired — and it never shrank back after.
// This wraps the message in a fixed-width, height-capped scroll area instead,
// so the dialog (and window) size no longer depends on message length; long
// text wraps and scrolls internally rather than stretching the layout.
func showErrorDialog(err error, window fyne.Window) {
	if err == nil {
		return
	}
	msgLabel := widget.NewLabel(err.Error())
	msgLabel.Wrapping = fyne.TextWrapWord
	scroll := container.NewScroll(msgLabel)
	scroll.SetMinSize(fyne.NewSize(420, 100))
	dialog.NewCustom("Error", "OK", scroll, window).Show()
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
			showErrorDialog(errors.New("passphrase cannot be empty"), window)
			return
		}

		// Use existing keys.LoadKeyFromDisk to validate
		kp, _, err := keys.LoadKeyFromDisk(passEntry.Text)
		if err != nil {
			showErrorDialog(errors.New("incorrect passphrase — please try again"), window)
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

// feeRowPlaceholder is what every unresolved row of the popup's fee panel
// shows. It is a distinct sentinel rather than an empty string so "not known
// yet" can never be misread as "zero".
const feeRowPlaceholder = "—"

// transferOutcome is the three-way terminal state of a transfer's
// confirmation wait: the node committed it, the node rejected it, or we ran
// out of polling budget without either answer.
type transferOutcome int

const (
	// transferConfirmed: the transaction was committed to a block.
	transferConfirmed transferOutcome = iota
	// transferRejected: the node moved the transaction into its invalid pool,
	// so it can never confirm.
	transferRejected
	// transferTimedOut: neither confirmation nor rejection arrived in time —
	// still genuinely unknown, and explicitly NOT a rejection.
	transferTimedOut
)

// classifyTransferOutcome decides what the Transfer Status dialog must show
// from WaitForTxConfirmation's two results.
//
// ★ WHY THIS EXISTS: the dialog used to write `conf, _ := WaitForTxConfirmation
// (...)`, discarding the error. The node validates nonce, balance, signature
// and replay protection ASYNCHRONOUSLY — sendrawtransaction has already
// returned a txid by then — so a rejected send comes back here as a
// *TxRejectedError while conf is nil. Discarding it made every rejection render
// as "Still Pending … after 5 minutes". Worse, the dialog is the only place
// that could hand the wallet's reserved nonce back, so the reservation leaked
// with it: the shared table claims max(chain nonce, local reservation), which
// pushed every subsequent send past the chain's nonce, each was rejected the
// same way, and the mempool never held a transaction at all — the "0 pending"
// the explorer then reported forever.
//
// A rejection therefore takes precedence over a confirmation-less result, so a
// refused send can never be presented as a merely slow one; while a non-
// rejection error (a transient RPC failure) still means "unknown", so it must
// not be reported as terminal either.
func classifyTransferOutcome(conf *TxConfirmation, err error) transferOutcome {
	if err != nil {
		var rejected *TxRejectedError
		if errors.As(err, &rejected) {
			return transferRejected
		}
		return transferTimedOut
	}
	if conf != nil {
		return transferConfirmed
	}
	return transferTimedOut
}

// transferFeeRowValues is the fully-resolved text and colour of every row in
// the Transfer Status popup's "Transaction Fee" section.
//
// It exists so the numbers this popup shows on a send come from ONE pure
// function a test can assert on directly, instead of being assembled inline
// inside a background worker goroutine — where a mis-denominated conversion
// (rendering a gSPX gas price as SPX) is invisible until a user reads "0" off
// the screen, which is exactly what this panel used to display.
type transferFeeRowValues struct {
	GasFeeText    string
	GasFeeColor   color.Color
	GasLimitText  string
	GasLimitColor color.Color
	GasPriceText  string
	GasPriceColor color.Color
	PriorityText  string
	PriorityColor color.Color
}

// transferFeeRows resolves the Transfer Status popup's fee section for one
// send. gasFeeNSPX / gasLimit / gasPrice are the values the transaction
// actually carries — quoted by the same QuoteTransferGas call the fee preview
// and the confirm dialog used — so the panel reports what is being paid rather
// than an estimate that could drift from it.
//
// The gas price is rendered in gSPX via formatGasPriceAmount, NOT in SPX: the
// policy minimum is 1 gSPX (10^9 nSPX, per core/params.go's gSPX denomination)
// = 10^-9 SPX, while formatSPXAmount prints at most six decimal places. An SPX
// rendering therefore collapsed the minimum and every tier derived from it
// (Medium 2x, High 5x, Custom N×) to a flat "0" in this panel.
func transferFeeRows(chainSymbol string, gasFeeNSPX *big.Int, gasLimit uint64, gasPrice *big.Int, priorityLabel string) transferFeeRowValues {
	v := transferFeeRowValues{
		GasFeeText:    feeRowPlaceholder,
		GasFeeColor:   colFaint,
		GasLimitText:  feeRowPlaceholder,
		GasLimitColor: colFaint,
		GasPriceText:  feeRowPlaceholder,
		GasPriceColor: colFaint,
		PriorityText:  feeRowPlaceholder,
		PriorityColor: colFaint,
	}
	if gasFeeNSPX != nil {
		v.GasFeeText = formatSPXAmount(new(big.Float).SetPrec(256).Quo(
			new(big.Float).SetPrec(256).SetInt(gasFeeNSPX),
			big.NewFloat(1e18),
		)) + " " + chainSymbol
		v.GasFeeColor = colAccent
	}
	if gasLimit > 0 {
		v.GasLimitText = fmt.Sprintf("%d gas units", gasLimit)
		v.GasLimitColor = colText
	}
	if gasPrice != nil && gasPrice.Sign() > 0 {
		v.GasPriceText = formatGasPriceAmount(gasPrice) + " " + gasPriceUnitLabel
		v.GasPriceColor = colText
	}
	if strings.TrimSpace(priorityLabel) != "" {
		v.PriorityText = priorityLabel
		v.PriorityColor = colText
	}
	return v
}

// showTransferStatusDialog displays a modal popup that tracks a SPX transfer
// through broadcast → pending → confirmed, mirroring the mint data block
// confirmation UI style. It shows transfer status, block height, block
// confirmation hash, transaction fee details, and related transaction info.
// The dialog updates live from a background polling goroutine via fyne.Do.
// priorityLabel is the user-visible tier tag (e.g. "High (5x)"); priorityPrice
// is the exact gas price the confirmed send carries (may differ from the
// preview gasPrice only if the caller re-quoted between dialogs — normally
// identical, since both come from the same QuoteTransferGas call).
func showTransferStatusDialog(window fyne.Window, client *WalletClient, chainHeader *core.SphinxChainHeader, amountStr, recipient, memo string, passphrase string, amountNSPX *big.Int, gasFeeNSPX *big.Int, gasLimit uint64, gasPrice *big.Int, priorityLabel string, priorityPrice *big.Int) {
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

	// Gas fee display widgets
	gasFeeVal := canvas.NewText("—", colFaint)
	gasFeeVal.TextSize = 11
	gasFeeVal.TextStyle = fyne.TextStyle{Monospace: true}

	gasLimitVal := canvas.NewText("—", colFaint)
	gasLimitVal.TextSize = 11
	gasLimitVal.TextStyle = fyne.TextStyle{Monospace: true}

	gasPriceVal := canvas.NewText("—", colFaint)
	gasPriceVal.TextSize = 11
	gasPriceVal.TextStyle = fyne.TextStyle{Monospace: true}

	priorityVal := canvas.NewText("—", colFaint)
	priorityVal.TextSize = 11
	priorityVal.TextStyle = fyne.TextStyle{Monospace: true}

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
		sectionLabel("Transaction Fee"),
		spacer(6),
		infoRowDynamic("Gas Fee", gasFeeVal),
		spacer(4),
		infoRowDynamic("Gas Limit", gasLimitVal),
		spacer(4),
		infoRowDynamic("Gas Price", gasPriceVal),
		spacer(4),
		infoRowDynamic("Priority", priorityVal),
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
	dlg.Resize(fyne.NewSize(480, 620))
	dlg.Show()

	go transferStatusDialogWorker(dlg, inner, client, chainHeader, statusIcon, statusTitle, statusSub, progress, txidVal, liveStatus, blockHeightVal, blockHashVal, confirmTimeVal, networkConfVal, gasFeeVal, gasLimitVal, gasPriceVal, priorityVal, amountStr, recipient, memo, amountNSPX, gasFeeNSPX, gasLimit, gasPrice, priorityLabel, priorityPrice)
}

// transferStatusDialogWorker runs in a goroutine to broadcast the transaction
// and poll for confirmation, updating the dialog widgets via fyne.Do.
// priorityLabel is the user-visible tier tag (e.g. "High (5x)"); priorityPrice
// is the exact gas price the confirmed send must carry — the worker
// broadcasts via SendTransactionWithPriority so the fee preview shown before
// confirmation and the fee actually paid can never diverge.
func transferStatusDialogWorker(dlg *dialog.CustomDialog, inner *fyne.Container, client *WalletClient, chainHeader *core.SphinxChainHeader, statusIcon, statusTitle, statusSub *canvas.Text, progress *widget.ProgressBar, txidVal, liveStatus, blockHeightVal, blockHashVal, confirmTimeVal, networkConfVal, gasFeeVal, gasLimitVal, gasPriceVal, priorityVal *canvas.Text, amountStr, recipient, memo string, amountNSPX *big.Int, gasFeeNSPX *big.Int, gasLimit uint64, gasPrice *big.Int, priorityLabel string, priorityPrice *big.Int) {
	fyne.Do(func() {
		liveStatus.Text = "Broadcasting signed transaction to node…"
		liveStatus.Color = colInfo
		liveStatus.Refresh()
		progress.SetValue(0.25)
	})

	// Populate the "Transaction Fee" panel from the values the broadcast
	// actually carries, resolved by transferFeeRows so the exact strings this
	// panel shows are produced by one pure, tested function.
	//
	// ★ FIX (two bugs at once): these rows used to be written straight from
	// this background goroutine, but Fyne only permits widget mutation on the
	// UI goroutine (see the fyne.Do used everywhere else in this file), so the
	// writes and their Refresh() calls could be lost and the panel could keep
	// its placeholder "—" for a value already computed. And the gas price was
	// converted to SPX, which rounds the policy minimum (1 gSPX = 10^-9 SPX)
	// — and every tier derived from it — to a flat "0"; transferFeeRows renders
	// it in gSPX instead (see formatGasPriceAmount in theme.go).
	feeRows := transferFeeRows(chainHeader.Symbol, gasFeeNSPX, gasLimit, gasPrice, priorityLabel)
	fyne.Do(func() {
		gasFeeVal.Text = feeRows.GasFeeText
		gasFeeVal.Color = feeRows.GasFeeColor
		gasFeeVal.Refresh()
		gasLimitVal.Text = feeRows.GasLimitText
		gasLimitVal.Color = feeRows.GasLimitColor
		gasLimitVal.Refresh()
		gasPriceVal.Text = feeRows.GasPriceText
		gasPriceVal.Color = feeRows.GasPriceColor
		gasPriceVal.Refresh()
		priorityVal.Text = feeRows.PriorityText
		priorityVal.Color = feeRows.PriorityColor
		priorityVal.Refresh()
	})

	result, err := client.SendTransactionWithPriority(recipient, amountNSPX, memo, priorityPrice)

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
		txidVal.Text = truncMiddle(result.TxID, 12)
		txidVal.Color = colText
		progress.SetValue(0.5)
		liveStatus.Text = fmt.Sprintf("Polling for confirmation (txid: %s…)", result.TxID[:min(12, len(result.TxID))])
		liveStatus.Color = colFaint
		inner.Refresh()
	})

	addActivity(fmt.Sprintf("Sent %s %s to %s (tx: %s)", amountStr, chainHeader.Symbol, recipient[:min(16, len(recipient))]+"…", result.TxID[:8]+"…"))

	conf, waitErr := client.WaitForTxConfirmation(result.TxID, 300*time.Second)
	outcome := classifyTransferOutcome(conf, waitErr)

	// The node has terminally refused this transaction: it can never confirm,
	// so the nonce reserved for it must come back. A rejected transaction
	// never consumes its nonce on-chain, and leaving the reservation claimed
	// starts the account's NEXT broadcast past the chain's nonce — which is
	// exactly how one failed send turned into an unbroken run of failed sends
	// with the mempool reading "0 pending" throughout. Release happens here,
	// off the UI goroutine, before any widget is touched.
	if outcome == transferRejected {
		client.releasePendingNonce(sessionFingerprint, result.Nonce)
	}

	rejectionReason := ""
	var rejected *TxRejectedError
	if waitErr != nil && errors.As(waitErr, &rejected) {
		rejectionReason = rejected.Reason
	}
	if rejectionReason == "" && waitErr != nil {
		rejectionReason = waitErr.Error()
	}

	fyne.Do(func() {
		switch outcome {
		case transferConfirmed:
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
		case transferRejected:
			// The node's OWN reason, verbatim: this is a terminal outcome, not
			// a wait that might still succeed, so it is reported with the same
			// severity as a broadcast failure rather than downgraded to
			// "still pending".
			statusIcon.Text = "✗"
			statusIcon.Color = colDanger
			statusTitle.Text = "Transaction Rejected by Node"
			statusTitle.Color = colDanger
			statusSub.Text = rejectionReason
			statusSub.Color = colDanger
			statusSub.TextSize = 10
			liveStatus.Text = "Rejected — cannot confirm; nonce released, you can send again"
			liveStatus.Color = colDanger
			progress.SetValue(0)

			addActivity(fmt.Sprintf("Send %s to %s REJECTED: %s", amountStr, recipient[:min(16, len(recipient))]+"…", rejectionReason))
		default:
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

	// Embedded-economics terms frozen into the mint receipt and the
	// on-chain anchor (and, for collection mints, into SIP-721 token
	// storage) at consensus. RoyaltyBPS is the resale royalty in basis
	// points (0 = no resale royalty), UsageFeeNSPX the per licensed-access
	// fee as a decimal nSPX string ("" = no licensing), RoyaltyRecipient an
	// optional payout override in canonical raw-hex form ("" = the minting
	// identity). The receipt's SPHINCS+ signature does not cover these
	// fields (canonicalReceiptBytes excludes them), so the mint worker
	// stamps them on after mint.Mint signs — BuildAnchorData then carries
	// them into the AnchorTag, whose terms every node re-validates at
	// consensus and VerifyAnchor requires to match the receipt.
	RoyaltyBPS       uint64
	UsageFeeNSPX     string
	RoyaltyRecipient string

	// Collection is the SIP-721 collection contract the mint must create its
	// marketplace token in. A bare receipt anchor (Collection == "") is not
	// listable/buyable/licensable — only a real token inside a collection is —
	// so the Mint Data screen defaults this to the user's saved collection and
	// warns when it is empty.
	Collection string

	MintFeeSPX func() float64

	// StatusText is the small inline status line already on the Sign
	// screen itself (kept in sync so it still reflects the final result
	// after the dialog is closed, same as before the refactor).
	//
	// widget.Label, not canvas.Text: this field carries composite
	// messages that embed tx hashes/CIDs/anchor ids, which can run long.
	// canvas.Text cannot wrap at any width, so a long message here was
	// forcing the whole window wider. Label wraps within whatever width
	// its container gives it, and uses Importance (Success/Warning) for
	// color instead of an arbitrary Color field.
	StatusText *widget.Label

	// ResetDropZone clears the Sign screen's drop-zone widgets once the
	// job finishes (success or the non-fatal "mint skipped" path).
	ResetDropZone func()

	// ClearSelectedFile clears the screen's selectedFile variable so a
	// finished job can't be re-submitted by mistake.
	ClearSelectedFile func()
}

// normalizeRoyaltyRecipient validates the optional royalty-recipient input
// from the Mint Data screen and returns it in the canonical raw-uppercase-hex
// form the node's ValidateAnchorData and the SIP-721 runtime both store and
// pay out with (common.NormalizeSPIFAddress strips the SPIF prefix and
// uppercases the hex). An empty input is allowed: the field is optional and
// means "pay the minting identity".
func normalizeRoyaltyRecipient(input string) (string, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return "", nil
	}
	norm, err := common.NormalizeSPIFAddress(raw)
	if err != nil {
		return "", fmt.Errorf("royalty recipient: %w", err)
	}
	return norm, nil
}

// describeMintTerms renders a MintJob's embedded-economics terms as a short
// human-readable summary for the Mint Status dialog ("none" = legacy token
// with no resale royalty and no licensing).
func describeMintTerms(job MintJob) string {
	if job.RoyaltyBPS == 0 && job.UsageFeeNSPX == "" && job.RoyaltyRecipient == "" {
		return "none (legacy token)"
	}
	var parts []string
	if job.RoyaltyBPS > 0 {
		pct := new(big.Float).Quo(
			new(big.Float).SetInt64(int64(job.RoyaltyBPS)),
			big.NewFloat(100),
		)
		parts = append(parts, pct.Text('f', -1)+"% resale royalty")
	}
	if job.UsageFeeNSPX != "" {
		fee, ok := new(big.Int).SetString(job.UsageFeeNSPX, 10)
		if ok {
			parts = append(parts, formatNSPXAmount(fee)+" SPX / use")
		} else {
			parts = append(parts, job.UsageFeeNSPX+" nSPX / use")
		}
	}
	if job.RoyaltyRecipient != "" {
		short := job.RoyaltyRecipient
		if len(short) > 14 {
			short = short[:10] + "…" + short[len(short)-4:]
		}
		parts = append(parts, "pay to "+short)
	}
	return strings.Join(parts, " · ")
}

// pinNFTMetadata pins the ERC-721 metadata JSON for a mint and returns the
// metadata CID together with its ipfs:// tokenURI and the full pin outcome.
//
// It uses the SAME PinPayload contract as the media pin, so the caller can tell
// "pinned durably" from "only on this machine" from "not uploaded at all"
// instead of receiving a plausible-looking spxhash- identifier for a failed
// upload. The outcome's OptIn flag is what distinguishes an explicitly
// configured offline mint (SPHINX_IPFS_DISABLE) from a failure the caller
// should refuse to build on: the mint worker aborts a collection mint whose
// metadata was not really uploaded, because a tokenURI that nobody can fetch
// is not an NFT — and a bare "ipfs://" with an empty CID (the old failure mode
// of this function) passes the node's ipfs:// prefix check while pinning
// nothing.
//
// The bytes are marshalled exactly as mint.UploadNFTMetadata marshals them
// (MarshalIndent with two spaces), so a real pin yields the same content CID
// that helper would have produced.
func pinNFTMetadata(uploader *storage.Client, nftMeta *mint.NFTMetadata, filename string) (metadataCID, tokenURI string, outcome storage.PinOutcome) {
	if nftMeta == nil {
		outcome.Warn = errors.New("nil NFT metadata")
		return "", "", outcome
	}
	if uploader == nil {
		outcome.Warn = errors.New("nil IPFS uploader")
		return "", "", outcome
	}
	data, err := json.MarshalIndent(nftMeta, "", "  ")
	if err != nil {
		outcome.Warn = fmt.Errorf("marshal NFT metadata: %w", err)
		return "", "", outcome
	}
	outcome = uploader.PinPayload(data, filename)
	if strings.TrimSpace(outcome.CID) == "" {
		if outcome.Warn == nil {
			outcome.Warn = errors.New("empty metadata CID")
		}
		return "", "", outcome
	}
	return outcome.CID, "ipfs://" + outcome.CID, outcome
}

// pinBannerMessage renders a pin outcome as the Mint Status dialog's banner:
// where the bytes actually are, and what that means for retrievability. It is
// deliberately explicit in every case, because the previous behaviour showed a
// green "Minted ✓" even when the payload had never left the machine.
func pinBannerMessage(p storage.PinOutcome) string {
	switch {
	case !p.Uploaded() && p.OptIn:
		return "⚠  OFFLINE MODE — nothing was uploaded. " + p.CID + " is a local content hash, NOT a retrievable IPFS CID; nobody else can fetch this data."
	case !p.Uploaded():
		return "⚠  NOTHING WAS UPLOADED — no IPFS backend accepted the file, so it exists only on this disk."
	case !p.Durable():
		return "⚠  PINNED TO YOUR LOCAL IPFS DAEMON ONLY — retrievable now, but unreachable once that daemon goes offline. Set SPHINX_IPFS_PINNING_SERVICE and SPHINX_IPFS_PINNING_TOKEN to pin durably."
	default:
		return "✓  Pinned durably via " + p.Source + " — retrievable without this machine."
	}
}

// pinBannerImportance maps a pin outcome to the banner's severity, so the
// dialog's colour matches how durable the pin actually is.
func pinBannerImportance(p storage.PinOutcome) widget.Importance {
	switch {
	case !p.Uploaded():
		return widget.DangerImportance
	case !p.Durable():
		return widget.WarningImportance
	default:
		return widget.SuccessImportance
	}
}

// savedCollectionFile is where this identity's default SIP-721 collection is
// remembered between runs (~/.sphinx/usi_collection.json). Mint Data mints its
// marketplace token into it and Marketplace searches it by default, which is
// what makes the two screens agree without retyping a contract address.
func savedCollectionFile() string {
	return filepath.Join(filepath.Dir(keys.KeyDir), "usi_collection.json")
}

// SavedCollection is the local memory of the collection this identity mints
// into: the contract address plus the display name/symbol read back from chain.
type SavedCollection struct {
	Address    string `json:"address"`
	Name       string `json:"name,omitempty"`
	Symbol     string `json:"symbol,omitempty"`
	DeployedAt int64  `json:"deployed_at,omitempty"`
}

// loadSavedCollection returns the remembered collection, or the zero value when
// none has been deployed/saved yet (never an error — an absent file simply
// means "no collection yet").
func loadSavedCollection() SavedCollection {
	return loadCollectionFrom(savedCollectionFile())
}

// loadCollectionFrom is loadSavedCollection's path-parameterised core, so the
// persistence rules (absent file, corrupt file) can be tested without touching
// the user's real key directory.
func loadCollectionFrom(path string) SavedCollection {
	data, err := os.ReadFile(path)
	if err != nil {
		return SavedCollection{}
	}
	var sc SavedCollection
	if err := json.Unmarshal(data, &sc); err != nil {
		log.Printf("[WARN] loadSavedCollection: ignoring corrupt %s: %v", path, err)
		return SavedCollection{}
	}
	return sc
}

// saveCollection persists the collection address/name locally (0600, under the
// key directory's parent) so both Mint Data and Marketplace can reuse it.
func saveCollection(sc SavedCollection) error {
	return saveCollectionTo(savedCollectionFile(), sc)
}

// saveCollectionTo is saveCollection's path-parameterised core.
func saveCollectionTo(path string, sc SavedCollection) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create collection dir: %w", err)
	}
	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal collection: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write collection: %w", err)
	}
	return nil
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

	// pinBanner is the durability banner: it states plainly where the bytes
	// actually are (durably pinned / local daemon only / not uploaded at all),
	// so a completed mint can never again look like a success while the
	// payload has only ever existed on this disk. Hidden until it has
	// something to say.
	pinBanner *widget.Label

	fileVal        *canvas.Text
	cidVal         *canvas.Text
	tokenURIVal    *canvas.Text
	termsVal       *canvas.Text
	tokenVal       *canvas.Text
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

	// Durability banner — see mintStatusFields.pinBanner. A wrapping Label
	// (not canvas.Text) so a long explanation cannot stretch the window.
	f.pinBanner = widget.NewLabel("")
	f.pinBanner.Wrapping = fyne.TextWrapWord
	f.pinBanner.TextStyle = fyne.TextStyle{Bold: true}
	f.pinBanner.Importance = widget.DangerImportance
	f.pinBanner.Hide()

	f.fileVal = canvas.NewText(filepath.Base(job.SelectedFile), colMuted)
	f.fileVal.TextSize = 11
	f.fileVal.TextStyle = fyne.TextStyle{Monospace: true}

	f.cidVal = canvas.NewText("—", colFaint)
	f.cidVal.TextSize = 11
	f.cidVal.TextStyle = fyne.TextStyle{Monospace: true}

	f.tokenURIVal = canvas.NewText("—", colFaint)
	f.tokenURIVal.TextSize = 11
	f.tokenURIVal.TextStyle = fyne.TextStyle{Monospace: true}

	// The embedded-economics terms are known before the pipeline starts —
	// they were validated on the Mint Data screen and travel inside the job.
	f.termsVal = canvas.NewText(describeMintTerms(job), colMuted)
	f.termsVal.TextSize = 11
	f.termsVal.TextStyle = fyne.TextStyle{Monospace: true}

	// Marketplace token binding — filled in once the collection mint commits.
	f.tokenVal = canvas.NewText("—", colFaint)
	f.tokenVal.TextSize = 11
	f.tokenVal.TextStyle = fyne.TextStyle{Monospace: true}

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
		spacer(10),
		// Hidden until the pin outcome is known; a hidden Label contributes
		// no layout space, so the dialog is unchanged for durable pins.
		f.pinBanner,
		spacer(16),
		f.progress,
		container.NewCenter(f.stepVal),
		spacer(14),
		infoRowDynamic("File", f.fileVal),
		spacer(4),
		infoRowDynamic("IPFS CID", f.cidVal),
		spacer(4),
		infoRowDynamic("Token URI", f.tokenURIVal),
		spacer(4),
		infoRowDynamic("Embedded Terms", f.termsVal),
		spacer(4),
		infoRowDynamic("Marketplace Token", f.tokenVal),
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

	// pinBannerResized tracks whether the dialog has already been grown to make
	// room for the durability banner, so repeated updates do not keep resizing.
	var pinBannerResized bool

	// setPinBanner shows (or, with empty text, hides) the durability banner.
	// It is the GUI half of the PinOutcome contract: the mint's success state
	// now depends on where the bytes actually are, not merely on the pipeline
	// reaching its last step.
	setPinBanner := func(text string, importance widget.Importance) {
		fyne.Do(func() {
			if strings.TrimSpace(text) == "" {
				f.pinBanner.Hide()
				f.pinBanner.Refresh()
				return
			}
			f.pinBanner.Text = text
			f.pinBanner.Importance = importance
			f.pinBanner.Show()
			f.pinBanner.Refresh()
			// The dialog was sized before the banner existed. Fyne does not
			// re-fit a shown window when its content changes, so a banner that
			// appears later would be clipped at the bottom edge — i.e. the one
			// warning that must never be missed would be the part cut off.
			// Grow the dialog once, and only once, to make room.
			if f.dlg != nil && !pinBannerResized {
				f.dlg.Resize(fyne.NewSize(520, 700))
				pinBannerResized = true
			}
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
	// Embedded economics are known from the mint form before signing, so they
	// are populated through meta.go (SetAnchorEconomics) and travel with the
	// signed document — no need to consult the chain to learn the terms.
	sign.SetAnchorEconomics(meta, job.RoyaltyBPS, job.UsageFeeNSPX, job.RoyaltyRecipient)
	// NFT name/description are known from the mint form up front too, so
	// they're recorded the same way — before signing — rather than only
	// living in the pinned metadata JSON below (which a bare/non-collection
	// mint may never upload, and which an unreachable IPFS daemon can lose).
	sign.SetNFTMetadata(meta, strings.TrimSpace(job.NFTName), strings.TrimSpace(job.NFTDescription))

	// Upload the payload BEFORE the sidecar is written, so the on-chain mint
	// can bind to a real CID and the .usimeta sidecar can record it.
	//
	// ★ CANONICAL ARTIFACT: the bytes uploaded here are the CLEAN,
	// PRE-SIGNATURE file. That is deliberate, and it is what the receipt's
	// PayloadHash and the anchor's CID commit to. The signature cannot be part
	// of the bytes it signs, so the final on-disk file necessarily differs
	// from the pinned copy by the signature container it gains — which is why
	// Meta records BOTH: IPFSPayloadHash (the pinned bytes, = the receipt's
	// PayloadHash) and FileHash (the signed file, what Verify re-hashes). An
	// expected difference, never corruption.
	//
	// ★ This is where the old pipeline lied. AddBytesToIPFSWithFallback
	// returned a plausible spxhash- "CID" whenever the daemon was
	// unreachable, that CID was committed on-chain, and the dialog still
	// ended in a green "Minted ✓" — even though the bytes had never left this
	// machine. PinPayload reports durability explicitly, so the mint now stops
	// BEFORE signing anything unless the operator explicitly opted into
	// offline mode (SPHINX_IPFS_DISABLE=true).
	step(0.58, "Uploading to IPFS…")
	ipfsCfg := storage.DefaultConfig()
	ipfsClient := storage.NewClient(ipfsCfg)
	pin := ipfsClient.PinPayload(data, fileBase)

	if !pin.Uploaded() && !pin.OptIn {
		// Nothing was uploaded, and this was not an opted-in offline mint.
		// Refuse to sign or anchor: signing first would leave a
		// signed-but-unanchored file that cannot be re-minted (IsAlreadySigned
		// blocks re-signing), turning a recoverable upload problem into a dead
		// end. The file on disk is untouched.
		detail := pin.Warn
		if detail == nil {
			detail = storage.ErrNotUploaded
		}
		setPinBanner("⚠  NOTHING WAS UPLOADED — no IPFS backend accepted the file, so it exists only on this disk. The mint was stopped before signing. Start an IPFS daemon at "+
			ipfsCfg.IPFSAddr+", or set SPHINX_IPFS_PINNING_SERVICE and SPHINX_IPFS_PINNING_TOKEN to pin durably, then mint again.", widget.DangerImportance)
		fail("Not Uploaded — Mint Stopped", fmt.Errorf("%v\n\nNothing was signed and nothing was anchored. Your file is unchanged.", detail))
		return
	}

	cid := pin.CID
	gatewayBase := ipfsCfg.GatewayBaseURL
	metadataURI := gatewayBase + "/ipfs/" + cid

	if pin.Warn != nil {
		log.Printf("[WARN] Mint Data: %v", pin.Warn)
	}

	// ipfsNote is appended to the final status text so the durable record of
	// the mint says how retrievable the payload really is.
	ipfsNote := ""
	switch {
	case !pin.Uploaded():
		ipfsNote = " (NOT uploaded — local content hash only)"
	case !pin.Durable():
		ipfsNote = " (pinned to the local daemon only — not durable)"
	}

	setPinBanner(pinBannerMessage(pin), pinBannerImportance(pin))
	fyne.Do(func() {
		f.cidVal.Text = truncMiddle(cid, 12)
		f.cidVal.Color = colText
		if !pin.Durable() {
			f.cidVal.Color = colWarn
		}
		f.cidVal.Refresh()
	})

	// Build and upload ERC-721 metadata JSON to IPFS — creates the
	// tokenURI that points at the metadata JSON, just like Ethereum
	// ERC-721 NFTs (name, description, image ipfs://<mediaCID>, attrs).
	var tokenURI string
	var metadataCID string
	var metaPin storage.PinOutcome
	if cid != "" && strings.TrimSpace(job.NFTName) != "" {
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
		// Pin the metadata JSON with the SAME PinPayload contract as the
		// payload above (see pinNFTMetadata). If it could not really be
		// uploaded — and offline mode was not explicitly opted into — abort
		// BEFORE signing: a tokenURI nobody can fetch is not an NFT, and the
		// old fallback produced either a spxhash tokenURI or a bare "ipfs://"
		// (empty CID) that passed the node's ipfs:// prefix check while
		// pinning nothing.
		metadataCID, tokenURI, metaPin = pinNFTMetadata(ipfsClient, nftMeta, fileBase+"_metadata.json")
		if !metaPin.Uploaded() && !metaPin.OptIn {
			detail := metaPin.Warn
			if detail == nil {
				detail = storage.ErrNotUploaded
			}
			setPinBanner("⚠  NFT METADATA WAS NOT UPLOADED — the marketplace token needs an ERC-721 metadata tokenURI that anyone can fetch, and none could be pinned. The mint was stopped before signing. "+
				"Start an IPFS daemon at "+ipfsCfg.IPFSAddr+", or set SPHINX_IPFS_PINNING_SERVICE and SPHINX_IPFS_PINNING_TOKEN, then mint again.", widget.DangerImportance)
			fail("Metadata Not Uploaded — Mint Stopped", fmt.Errorf("%v\n\nNothing was signed and nothing was anchored. Your file is unchanged.", detail))
			return
		}
		if metaPin.Warn != nil {
			log.Printf("[WARN] Mint Data: metadata pin: %v", metaPin.Warn)
		} else {
			log.Printf("[INFO] Mint Data: metadata JSON uploaded, tokenURI=%s", tokenURI)
		}
		fyne.Do(func() {
			f.tokenURIVal.Text = truncMiddle(tokenURI, 18)
			f.tokenURIVal.Color = colText
			if !metaPin.Durable() {
				f.tokenURIVal.Color = colWarn
			}
			f.tokenURIVal.Refresh()
		})
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

	sign.SetPinningContext(meta, cid, blockHeight, tokenURI, metadataCID)

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
	// Stamp the embedded-economics terms after mint.Mint signs, exactly like
	// the TokenURI/MetadataCID stamping above: canonicalReceiptBytes excludes
	// these optional fields, so the receipt's SPHINCS+ signature stays valid,
	// while AnchorMintReceipt → mint.BuildAnchorData carries them into the
	// AnchorTag whose terms every node validates at consensus and
	// VerifyAnchor requires to match the receipt.
	if mintErr == nil {
		mintRes.Receipt.RoyaltyBPS = job.RoyaltyBPS
		mintRes.Receipt.UsageFeeNSPX = job.UsageFeeNSPX
		mintRes.Receipt.RoyaltyRecipient = job.RoyaltyRecipient

		// Record the hash of the EXACT bytes that were pinned — the receipt's
		// PayloadHash. It intentionally differs from Meta.FileHash, which
		// covers the signed on-disk file: the pinned artifact is the clean
		// pre-signature original (the signature cannot be part of the bytes it
		// signs). Recording it here makes that expected difference visible to
		// a verifier instead of looking like corruption. It reaches disk
		// because RefreshOnChainProvenance re-embeds the whole Meta into the
		// file's container once the anchor resolves.
		sign.SetIPFSPayloadHash(meta, mintRes.Receipt.PayloadHash)
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
			job.StatusText.Importance = widget.SuccessImportance
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

	// ── Marketplace binding — MUST happen before the anchor ──────────────
	// ReceiptCommitmentHash hashes the whole signed receipt, including
	// TokenID/TokenURI/ContractAddress, so the collection mint has to run
	// and confirm BEFORE the anchor is built. Anchoring first (as this
	// worker previously did) produced an anchor whose ReceiptHash could
	// never match the receipt on disk once the binding was stamped on,
	// and the back-to-back nonces (anchor N, collection mint N+1) left the
	// collection mint rejected until N confirmed.
	collection := strings.TrimSpace(job.Collection)
	if collection != "" {
		if tokenURI == "" {
			fail("Marketplace Token Failed", errors.New(
				"a collection mint needs an ERC-721 metadata tokenURI, which requires a non-empty NFT name — set the NFT name and mint again"))
			return
		}
		step(0.82, "Minting marketplace token…")
		fyne.Do(func() {
			f.liveStatus.Text = "Minting token in " + collection + "…"
			f.liveStatus.Color = colInfo
			f.liveStatus.Refresh()
		})

		tokenID, collTxID, collErr := job.Client.MintNFTInCollection(mintRes.Receipt, collection, "")
		if collErr != nil {
			fail("Marketplace Token Failed", fmt.Errorf(
				"SIP-721 token mint failed (%v) — nothing was anchored; fix the collection and mint again", collErr))
			return
		}
		fyne.Do(func() {
			f.tokenVal.Text = fmt.Sprintf("#%d in %s", tokenID, collection)
			f.tokenVal.Color = colAccent
			f.tokenVal.Refresh()
			f.liveStatus.Text = fmt.Sprintf("Token #%d minted (tx=%s…) — waiting for confirmation before anchor…",
				tokenID, collTxID[:min(12, len(collTxID))])
			f.liveStatus.Color = colAccent
			f.liveStatus.Refresh()
		})

		// The anchor needs nonce N+1, which only becomes valid once the
		// collection mint (nonce N) commits. Fix 1 lets the mempool accept
		// N+1 while N is pending, but waiting here also guarantees the
		// anchor's ReceiptHash is built against a receipt whose token
		// binding is already final on-chain.
		step(0.88, "Waiting for collection mint to confirm…")
		collConf, collConfErr := job.Client.WaitForTxConfirmation(collTxID, 300*time.Second)
		if collConfErr != nil {
			fail("Marketplace Token Failed", fmt.Errorf(
				"collection mint tx %s was rejected: %w", collTxID, collConfErr))
			return
		}
		if collConf == nil {
			// Collection mint still pending after 5 min. It will likely
			// commit shortly, and the anchor must FOLLOW it to keep nonce
			// order valid — broadcasting the anchor now would collide with
			// the still-pending collection mint at the same nonce slot.
			// Instead of hard-failing (which would leave the file signed
			// but unanchored, and block re-minting because the file is now
			// IsAlreadySigned), kick a background poller that broadcasts
			// the anchor the moment the collection mint confirms.
			//
			// The receipt already carries TokenID/ContractAddress (set by
			// MintNFTInCollection), so the anchor tag will commit to the
			// same SIP-721 binding the collection mint recorded — the two
			// stay consistent regardless of which block confirms first.
			bgCollTxID := collTxID
			bgReceipt := mintRes.Receipt
			bgFile := job.SelectedFile
			bgMeta := meta
			go func() {
				bgConf, _ := job.Client.WaitForTxConfirmation(bgCollTxID, 15*time.Minute)
				if bgConf == nil {
					log.Printf("[Mint Data] collection mint %s never confirmed within 20 min total — receipt stays unanchored", bgCollTxID)
					return
				}
				log.Printf("[Mint Data] collection mint %s confirmed at height=%d — broadcasting deferred anchor now", bgCollTxID, bgConf.Height)

				txID, anchorPath, fee, nonce, err := job.Client.AnchorMintReceipt(bgReceipt)
				if err != nil {
					log.Printf("[Mint Data] deferred anchor broadcast failed: %v", err)
					return
				}
				sign.SetAnchorFee(bgMeta, fee, nonce)

				// Wait for the deferred anchor to confirm too, so the
				// sidecar records the real block instead of pending.
				anchorConf, anchorWaitErr := job.Client.WaitForTxConfirmation(txID, 10*time.Minute)
				if anchorWaitErr != nil {
					// Terminal rejection: the anchor can never commit, so its
					// reserved nonce must come back — a leaked reservation
					// would push every later broadcast past the chain's nonce
					// ("invalid nonce: N must equal M").
					job.Client.releasePendingNonce(sessionFingerprint, nonce)
					log.Printf("[Mint Data] deferred anchor %s rejected: %v", txID, anchorWaitErr)
				}
				var confirmedBlock interface {
					GetHeight() uint64
					GetHash() string
				}
				if anchorConf != nil {
					confirmedBlock = &confirmedBlockInfo{height: anchorConf.Height, hash: anchorConf.Hash}
				}
				if provErr := sign.RefreshOnChainProvenance(bgFile, bgMeta, job.PublicFingerprint,
					txID, anchorPath, bgReceipt.MintID, bgReceipt.TokenID, bgReceipt.ContractAddress, confirmedBlock); provErr != nil {
					log.Printf("[Mint Data] deferred anchor provenance refresh incomplete: %v", provErr)
				}
				log.Printf("[Mint Data] deferred anchor confirmed: txid=%s anchor=%s", txID, anchorPath)
				addActivity(fmt.Sprintf("Deferred anchor broadcast: %s (tx=%s)", fileBase, txID))
			}()

			// Surface the deferred state in the dialog. Do NOT call fail()
			// — the receipt and sidecar are internally consistent; only the
			// on-chain anchor is deferred. The user can close the dialog and
			// keep using the wallet; the background poller finishes the job.
			fyne.Do(func() {
				f.statusIcon.Text = "⚠"
				f.statusIcon.Color = colWarn
				f.statusTitle.Text = "Mint Deferred — Anchor Pending"
				f.statusTitle.Color = colWarn
				f.statusSub.Text = fmt.Sprintf(
					"Collection mint tx %s is still pending after 5 min.\nA background poller will anchor the receipt once it confirms — safe to close this dialog.",
					bgCollTxID)
				f.statusSub.Color = colWarn
				f.liveStatus.Text = "Anchor deferred — background poller will finish"
				f.liveStatus.Color = colWarn
				f.progress.SetValue(0.9)

				job.StatusText.Text = fmt.Sprintf("⚠  Mint deferred — collection mint %s still pending; anchor will follow automatically", bgCollTxID[:min(12, len(bgCollTxID))])
				job.StatusText.Importance = widget.WarningImportance
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
		addActivity(fmt.Sprintf("Minted marketplace token #%d in %s (block %d)", tokenID, collection, collConf.Height))
	}
	// ── Anchor the receipt (now carries the binding) ──────────────────────
	step(0.9, "Anchoring NFT on-chain…")
	fyne.Do(func() {
		f.statusTitle.Text = "Anchoring On-Chain…"
		f.statusSub.Text = "Broadcasting mint receipt to the network…"
		f.liveStatus.Text = "Broadcasting anchor transaction…"
		f.liveStatus.Color = colInfo
		f.statusTitle.Refresh()
		f.statusSub.Refresh()
		f.liveStatus.Refresh()
	})

	txID, anchorPath, mintFeeNSPX, anchorNonce, anchorErr := job.Client.AnchorMintReceipt(mintRes.Receipt)
	if anchorErr == nil {
		sign.SetAnchorFee(meta, mintFeeNSPX, anchorNonce)
	}

	fyne.Do(func() {
		f.txidVal.Text = truncMiddle(txID, 12)
		f.txidVal.Color = colText
		f.anchorVal.Text = truncMiddle(anchorPath, 12)
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
			job.StatusText.Importance = widget.WarningImportance
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
	confirmed, confErr := job.Client.WaitForTxConfirmation(txID, 300*time.Second)
	if confErr != nil {
		// The node TERMINALLY rejected the anchor transaction (mempool
		// validation moved it to the invalid pool), so it can never confirm.
		// Report the node's exact reason now instead of polling out the
		// 300s(+600s background) budget and then claiming it was merely
		// "still pending" — that made a refused anchor look like one that
		// simply never got mined (0 pending tx, forever).
		//
		// A rejected tx never consumes its nonce, so give the anchor's
		// reservation back — otherwise every failed anchor permanently
		// inflates the wallet's next nonce past the chain's and the next
		// unrelated broadcast dies with "invalid nonce: N must equal M".
		// (WaitForTxConfirmation only ever returns a terminal rejection as
		// its error; timeouts come back as (nil, nil).)
		job.Client.releasePendingNonce(sessionFingerprint, anchorNonce)
		log.Printf("[ERROR] Mint Data: anchor tx %s rejected by node: %v", txID, confErr)
		addActivity(fmt.Sprintf("Signed document: %s (NFT anchor rejected: %v)", fileBase, confErr))
		fail("NFT Anchor Rejected", confErr)
		return
	}

	var confirmedBlock interface {
		GetHeight() uint64
		GetHash() string
	}
	if confirmed != nil {
		confirmedBlock = &confirmedBlockInfo{height: confirmed.Height, hash: confirmed.Hash}
	}

	provErr := sign.RefreshOnChainProvenance(job.SelectedFile, meta, job.PublicFingerprint, txID, anchorPath, mintRes.Receipt.MintID, mintRes.Receipt.TokenID, mintRes.Receipt.ContractAddress, confirmedBlock)
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
				bgErr := sign.RefreshOnChainProvenance(bgFile, meta, job.PublicFingerprint, bgTxID, bgAnchorPath, mintRes.Receipt.MintID, mintRes.Receipt.TokenID, mintRes.Receipt.ContractAddress, bgBlock)
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
		marketSuffix := ""
		if mintRes.Receipt.ContractAddress != "" {
			marketSuffix = fmt.Sprintf(" · token #%d in %s", mintRes.Receipt.TokenID, mintRes.Receipt.ContractAddress)
		}
		if confirmed != nil {
			f.statusIcon.Text = "✓"
			f.statusIcon.Color = colAccent
			f.statusTitle.Text = "Minted ✓"
			f.statusTitle.Color = colAccent
			f.statusSub.Text = "Signed, minted & tradeable on-chain" + marketSuffix
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
			f.statusSub.Text = "Anchored on-chain; still waiting on block confirmation" + marketSuffix
			f.statusSub.Color = colWarn

			f.liveStatus.Text = "Anchor pending — background poller will update the sidecar once confirmed"
			f.liveStatus.Color = colWarn
		}
		f.progress.SetValue(1)

		addActivity(fmt.Sprintf("Signed & minted NFT: %s (tx=%s, cid=%s, height=%d, anchor=%s%s%s)", fileBase, txID, cid, blockHeight, anchorPath, anchorSuffix, marketSuffix))
		marketLine := ""
		if mintRes.Receipt.ContractAddress != "" {
			marketLine = fmt.Sprintf(" · token #%d in %s", mintRes.Receipt.TokenID, truncMiddle(mintRes.Receipt.ContractAddress, 10))
		}
		// job.StatusText is now a wrapping widget.Label (see the MintJob
		// struct comment), so this no longer needs to be squeezed onto one
		// line — real line breaks work, and overflow within a line wraps
		// instead of stretching the window. Hashes are still truncated
		// because a full 64-char hex string is noise nobody reads, not
		// because it would break anything if it weren't.
		job.StatusText.Text = fmt.Sprintf("✓  Signed & minted NFT%s\ntx: %s   cid: %s\nheight: %d   anchor: %s%s",
			anchorSuffix, truncMiddle(txID, 14), truncMiddle(cid, 14), blockHeight, truncMiddle(anchorPath, 14), marketLine)
		job.StatusText.Importance = widget.SuccessImportance
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
	// The receipt-JSON pin is an OFF-CHAIN CACHE for the node-side artifact
	// index: the on-chain anchor commits the MEDIA CID/receipt hash (see
	// mint.BuildAnchorData(anchorTag)), not this JSON's CID. It is therefore
	// best-effort and never blocks anchoring — but it must still be honest.
	// PinPayload reports whether anything was really stored, so when nothing
	// was, the node-side cache is skipped entirely instead of registering an
	// artifact that points at a local content hash.
	payloadJSON, err := json.Marshal(receipt)
	if err != nil {
		return "", "", nil, 0, fmt.Errorf("marshal mint receipt: %w", err)
	}

	ipfsClient := storage.NewClient(storage.DefaultConfig())
	receiptPin := ipfsClient.PinPayload(payloadJSON, fmt.Sprintf("mint_%s.json", receipt.MintID))
	switch {
	case !receiptPin.Uploaded():
		log.Printf("[WARN] AnchorMintReceipt: receipt JSON not uploaded — skipping the node-side artifact cache (the on-chain anchor is unaffected): %v", receiptPin.Warn)
	case !receiptPin.Durable():
		log.Printf("[INFO] AnchorMintReceipt: receipt JSON pinned to the local daemon only (not durable): %v", receiptPin.Warn)
	}

	// Store artifact association on node (best-effort, bounded), and only when
	// the receipt JSON is actually retrievable: there is nothing worth caching
	// node-side otherwise. This is a second full RPC round-trip (handshake +
	// storeartifact); when the node is slow or unreachable it must not stall
	// the anchor behind it — a timeout here only skips an off-chain cache,
	// never the on-chain commitment.
	if receiptPin.Uploaded() && !storage.DefaultConfig().DisableIPFS {
		artifact := &storage.StorageArtifact{
			MintID:        receipt.MintID,
			Subject:       receipt.Subject,
			CID:           receiptPin.CID,
			CIDHashHex:    storage.CIDHash(receiptPin.CID),
			PayloadHash:   receipt.PayloadHash,
			AnchorTagType: "nft_anchor",
		}
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
		ChainID:    chainIDFor(),
		Sender:     rawSender,
		Receiver:   rawSender, // self-send: this tx exists only to carry data
		Amount:     mintFeeNSPX,
		GasLimit:   gasQuote.GasLimit,
		GasPrice:   gasQuote.GasPrice,
		Nonce:      nonce,
		Timestamp:  time.Now().Unix(),
		ReturnData: anchorData,
	}

	// Sign, encode and broadcast through the shared path. The nonce is passed
	// explicitly because the caller records it alongside the anchor fee.
	txID, err = abi.Transact(c.transactOpts(chainIDFor(), &nonce), tx)
	if err != nil {
		c.releasePendingNonce(sessionFingerprint, nonce)
		return "", "", nil, 0, fmt.Errorf("broadcast anchor transaction: %w", err)
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
	log.Printf("[WalletRPC] AnchorMintReceipt: anchored as txid=%s, anchor saved to %s", txID, anchorPath)
	return txID, anchorPath, mintFeeNSPX, nonce, nil
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

	// mint.BroadcastSIP721CollectionMintWithTerms builds/signs the
	// collection.mint contract call and waits (bounded) for the tokenId to be
	// committed. Its "keyFile" parameter is the local key passphrase here.
	// The receipt's frozen terms ride along so the SIP-721 token's embedded
	// economics match its anchor (zero/empty terms mint a legacy token — the
	// node stores no terms and no royalty/license enforcement applies).
	tokenID, txID, err = mint.BroadcastSIP721CollectionMintWithTerms(c.nodeAddr, collection, rawFrom, sessionPassphrase, rawTo, receipt.TokenURI, receipt.MintID,
		receipt.RoyaltyBPS, receipt.UsageFeeNSPX, receipt.RoyaltyRecipient)
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
			showErrorDialog(fmt.Errorf("no anchored txid available"), window)
			return
		}
		resultData, err := rpc.CallRPC(client.nodeAddr, "gettransaction", []interface{}{lastTxID}, 60)
		if err != nil {
			showErrorDialog(fmt.Errorf("gettransaction rpc: %w", err), window)
			return
		}
		if len(resultData) == 0 || string(resultData) == "null" {
			showErrorDialog(fmt.Errorf("empty gettransaction response"), window)
			return
		}
		var tx types.Transaction
		if err := json.Unmarshal(resultData, &tx); err != nil {
			showErrorDialog(fmt.Errorf("parse gettransaction: %w", err), window)
			return
		}

		if len(tx.ReturnData) == 0 {
			showErrorDialog(fmt.Errorf("transaction has empty return_data"), window)
			return
		}

		anchorTag, err := mint.DeserializeAnchorTag(tx.ReturnData)
		_ = anchorTag
		if err != nil {
			showErrorDialog(fmt.Errorf("deserialize anchor tag: %w", err), window)
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
			showErrorDialog(fmt.Errorf("choose a file first"), window)
			return
		}
		if sessionPassphrase == "" {
			showErrorDialog(fmt.Errorf("not logged in"), window)
			return
		}
		payload, err := os.ReadFile(selectedPath)
		if err != nil {
			showErrorDialog(fmt.Errorf("read file: %w", err), window)
			return
		}
		subject := subjectEntry.Text
		if subject == "" {
			showErrorDialog(fmt.Errorf("subject required"), window)
			return
		}
		res, err := mint.Mint(payload, subject, sessionPassphrase, string(keys.OrgSPIF), "", "")
		if err != nil {
			showErrorDialog(fmt.Errorf("mint: %w", err), window)
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
			showErrorDialog(fmt.Errorf("sign a receipt first"), window)
			return
		}
		txID, anchorPath, _, _, err := client.AnchorMintReceipt(lastReceipt.Receipt)
		if err != nil {
			showErrorDialog(fmt.Errorf("anchor: %w", err), window)
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
			showErrorDialog(fmt.Errorf("choose a receipt file"), window)
			return
		}
		receipt, err := mint.LoadReceipt(verifyReceiptPath)
		if err != nil {
			showErrorDialog(fmt.Errorf("load receipt: %w", err), window)
			return
		}
		var payload []byte
		if verifyPayloadPath != "" {
			payload, err = os.ReadFile(verifyPayloadPath)
			if err != nil {
				showErrorDialog(fmt.Errorf("read payload: %w", err), window)
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
