// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/gui.go
package gui

import (
	"errors"
	"fmt"
	"image/color"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	seed "github.com/sphinxfndorg/protocol/src/accounts/phrase"
	"github.com/sphinxfndorg/protocol/src/core"
	vault "github.com/sphinxfndorg/protocol/src/core/wallet/vault"
	"github.com/sphinxfndorg/protocol/src/storage"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
	"github.com/sphinxfndorg/protocol/src/usi/core/mint"
	"github.com/sphinxfndorg/protocol/src/usi/core/sign"
	pubkeydir "github.com/sphinxfndorg/protocol/src/usi/server/server"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// =========================================================================
// USI-MAIN FUNCTION
// =========================================================================
func Run() {
	log.Println("Starting USI GUI application")

	myApp := app.NewWithID("com.usi.UniversalSovereignIdentity")
	window := myApp.NewWindow("Universal Sovereign Identity")
	window.Resize(fyne.NewSize(1100, 680))
	window.CenterOnScreen()

	// Get chain header for display
	chainHeader := core.GetSphinxChainHeader()
	if chainHeader == nil {
		chainHeader = core.GetMainnetChainHeader()
	}

	// Add this line:
	// Use the HTTP JSON-RPC port of the node (default 8545)
	walletClient := NewWalletClient("") // will read from env or default

	themeToggle := widget.NewCheck("Dark Theme", func(on bool) {
		if on {
			myApp.Settings().SetTheme(theme.DarkTheme())
		} else {
			myApp.Settings().SetTheme(theme.LightTheme())
		}
	})
	themeToggle.SetChecked(true)

	// NEW — asks the actual storage layer whether any key has been stored
	isRegistered := func() bool {
		ids, err := keys.ListKeys()
		return err == nil && len(ids) > 0
	}

	var publicFingerprint string

	// Legacy helpers kept for Register screen compatibility
	smallSpacer := func(h float32) fyne.CanvasObject {
		return spacer(h)
	}

	bashBox := func(text, copyText string) fyne.CanvasObject {
		lbl := widget.NewLabel(text)
		lbl.TextStyle = fyne.TextStyle{Monospace: true}
		lbl.Wrapping = fyne.TextWrapBreak

		bg := canvas.NewRectangle(colSurface2)
		bg.CornerRadius = 8
		bg.StrokeColor = colAccent
		bg.StrokeWidth = 1
		bg.SetMinSize(fyne.NewSize(420, 60))

		copyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
			myApp.Clipboard().SetContent(copyText)
			dialog.ShowInformation("Copied", "Copied to clipboard", window)
		})
		copyBtn.Importance = widget.LowImportance

		content := container.NewBorder(nil, nil, nil, copyBtn, container.NewPadded(lbl))
		return container.NewMax(bg, content)
	}

	var (
		showDashboardScreen func()
		showEncryptScreen   func()
		showDecryptScreen   func()
		showSignScreen      func()
		showVerifyScreen    func()
		showKeysScreen      func()
		showWalletScreen    func()
		showRegisterScreen  func()
		showWelcomeScreen   func()
		showSendScreen      func()
		showReceiveScreen   func()
	)

	var mainContentContainer *fyne.Container
	var sidebar fyne.CanvasObject

	updateLayout := func(showSidebar bool) {
		if showSidebar {
			split := container.NewHSplit(sidebar, mainContentContainer)
			split.Offset = 0.18
			window.SetContent(split)
		} else {
			window.SetContent(mainContentContainer)
		}
	}

	setScreen := func(content fyne.CanvasObject) {
		mainContentContainer.Objects = []fyne.CanvasObject{container.NewPadded(container.NewScroll(content))}
		mainContentContainer.Refresh()
	}

	// =========================================================================
	// DASHBOARD SCREEN
	// =========================================================================
	showDashboardScreen = func() {
		log.Println("Displaying dashboard screen")
		updateLayout(true)

		title := screenTitle("Dashboard")
		subtitle := screenSubtitle(fmt.Sprintf("%s · %s Identity System", chainHeader.ChainName, chainHeader.Symbol))

		vaultCount := "0"
		if files, err := os.ReadDir("."); err == nil {
			count := 0
			for _, f := range files {
				if strings.HasSuffix(f.Name(), ".vault") {
					count++
				}
			}
			vaultCount = fmt.Sprintf("%d", count)
		}

		signedCount := "0"
		if files, err := os.ReadDir("."); err == nil {
			count := 0
			for _, f := range files {
				if strings.HasSuffix(f.Name(), ".usimeta") {
					count++
				}
			}
			signedCount = fmt.Sprintf("%d", count)
		}

		lastActivity := "Never"
		activityListLock.Lock()
		if len(activityList) > 0 {
			parts := strings.SplitN(activityList[0], " | ", 2)
			if len(parts) == 2 {
				lastActivity = parts[0]
			}
		}
		activityListLock.Unlock()

		makeStatCard := func(icon, labelText, valueText string, valueCol color.Color, subText string) fyne.CanvasObject {
			iconT := canvas.NewText(icon, colAccent)
			iconT.TextSize = 22
			labelT := canvas.NewText(strings.ToUpper(labelText), colFaint)
			labelT.TextSize = 10
			labelT.TextStyle = fyne.TextStyle{Monospace: true}
			valueT := canvas.NewText(valueText, valueCol)
			valueT.TextSize = 30
			valueT.TextStyle = fyne.TextStyle{Bold: true}
			subT := canvas.NewText(subText, colMuted)
			subT.TextSize = 11

			inner := container.NewVBox(
				container.NewCenter(iconT),
				spacer(4),
				container.NewCenter(labelT),
				container.NewCenter(valueT),
				container.NewCenter(subT),
			)
			return styledCard(inner, 0, 110)
		}

		statsRow := container.NewGridWithColumns(3,
			makeStatCard("", "Total Vaults", vaultCount, colText, "encrypted folders"),
			makeStatCard("✍", "Signed Docs", signedCount, colText, "with valid signatures"),
			makeStatCard("🕐", "Last Activity", lastActivity, colWarn, "most recent operation"),
		)

		fpShort := publicFingerprint
		if len(fpShort) > 40 {
			fpShort = fpShort[:20] + "…" + fpShort[len(fpShort)-20:]
		}

		keyStatus := "Active"
		keyStatusCol := colAccent
		if sessionPassphrase == "" {
			keyStatus = "Not logged in"
			keyStatusCol = colDanger
		}

		fpLabel := widget.NewLabel(fpShort)
		fpLabel.TextStyle = fyne.TextStyle{Monospace: true}
		fpLabel.Wrapping = fyne.TextWrapBreak
		fpBg := canvas.NewRectangle(colSurface2)
		fpBg.CornerRadius = 8
		fpBg.StrokeColor = colAccent
		fpBg.StrokeWidth = 1
		fpContainer := container.NewMax(fpBg, container.NewPadded(fpLabel))

		keyInfoRows := []fyne.CanvasObject{
			infoRow("Network", chainHeader.ChainName, colAccent),
			infoRow("Symbol", chainHeader.Symbol, colAccent),
			infoRow("Chain ID", fmt.Sprintf("%d", chainHeader.ChainID), colText),
			infoRow("Status", keyStatus, keyStatusCol),
			infoRow("Signature", "SPHINCS+", colText),
			infoRow("Hash", "SHAKE-256", colText),
			infoRow("Encryption", "AES-256-GCM", colText),
			infoRow("KDF", "Argon2id", colText),
			infoRow("Organization", "SPIF - Sphinx Fingerprint", colAccent),
		}
		keyInfoPanel := infoPanel("Network & Key Information", keyInfoRows)

		keySection := container.NewVBox(
			sectionLabel("Cryptographic Identity"),
			spacer(8),
			fpContainer,
			spacer(10),
			keyInfoPanel,
		)

		activityBox := container.NewVBox()
		activityListLock.Lock()
		if len(activityList) == 0 {
			noAct := canvas.NewText("No activities recorded yet.", colMuted)
			noAct.TextSize = 12
			activityBox.Add(container.NewCenter(noAct))
		} else {
			for i, activity := range activityList {
				if i >= 10 {
					break
				}
				icon := "·"
				iconCol := colMuted
				switch {
				case strings.Contains(activity, "Encrypt"):
					icon = ""
					iconCol = colAccent
				case strings.Contains(activity, "Decrypt"):
					icon = ""
					iconCol = colInfo
				case strings.Contains(activity, "Sign"):
					icon = "✍"
					iconCol = colWarn
				case strings.Contains(activity, "Verify"):
					icon = "✓"
					iconCol = colAccent
				case strings.Contains(activity, "Login"), strings.Contains(activity, "logged in"):
					icon = "🔑"
					iconCol = colInfo
				case strings.Contains(activity, "Register"):
					icon = ""
					iconCol = colWarn
				case strings.Contains(activity, "Logout"), strings.Contains(activity, "logged out"):
					icon = "🚪"
					iconCol = colDanger
				case strings.Contains(activity, "Sent"), strings.Contains(activity, "Received"):
					icon = "💸"
					iconCol = colAccent
				}

				iconT := canvas.NewText(icon, iconCol)
				iconT.TextSize = 11
				actT := canvas.NewText(activity, colText)
				actT.TextSize = 11
				actT.TextStyle = fyne.TextStyle{Monospace: true}

				rowBg := canvas.NewRectangle(colSurface)
				rowBg.CornerRadius = 6
				rowBg.StrokeColor = colBorder
				rowBg.StrokeWidth = 1
				row := container.NewMax(rowBg, container.NewPadded(
					container.NewHBox(iconT, spacer(6), actT),
				))
				activityBox.Add(row)
				activityBox.Add(spacer(4))
			}
		}
		activityListLock.Unlock()

		actScroll := container.NewScroll(activityBox)
		actScroll.SetMinSize(fyne.NewSize(0, 180))
		actCard := styledCard(actScroll, 0, 180)

		content := container.NewVBox(
			title,
			spacer(4),
			subtitle,
			spacer(20),
			statsRow,
			spacer(20),
			hRule(),
			spacer(16),
			keySection,
			spacer(20),
			hRule(),
			spacer(16),
			sectionLabel("Recent Activity"),
			spacer(8),
			actCard,
			spacer(24),
		)
		setScreen(content)
	}

	// =========================================================================
	// SEND SCREEN
	// =========================================================================
	showSendScreen = func() {
		log.Println("Displaying send screen")
		updateLayout(true)

		if sessionPassphrase == "" {
			dialog.ShowError(errors.New("please login first"), window)
			return
		}

		recipientEntry := widget.NewEntry()
		recipientEntry.SetPlaceHolder("Recipient SPIF address")

		amountEntry := widget.NewEntry()
		amountEntry.SetPlaceHolder(fmt.Sprintf("Amount in %s", chainHeader.Symbol))

		memoEntry := widget.NewMultiLineEntry()
		memoEntry.SetPlaceHolder("Optional memo (OP_RETURN data)")
		memoEntry.Wrapping = fyne.TextWrapWord
		memoEntry.SetMinRowsVisible(3)

		statusText := canvas.NewText("", colMuted)
		statusText.TextSize = 13
		statusText.TextStyle = fyne.TextStyle{Bold: true}

		sendBtn := widget.NewButtonWithIcon(fmt.Sprintf("Send %s", chainHeader.Symbol), theme.MailSendIcon(), func() {
			if recipientEntry.Text == "" {
				dialog.ShowError(errors.New("please enter a recipient address"), window)
				return
			}
			if amountEntry.Text == "" {
				dialog.ShowError(errors.New("please enter an amount"), window)
				return
			}

			amount := new(big.Float)
			_, ok := amount.SetString(amountEntry.Text)
			if !ok || amount.Cmp(big.NewFloat(0)) <= 0 {
				dialog.ShowError(errors.New("invalid amount"), window)
				return
			}

			// Convert to nSPX (1 SPX = 10^18 nSPX)
			amountNSPX := new(big.Int)
			amountFloat, _ := amount.Float64()
			amountNSPX.SetInt64(int64(amountFloat * 1e18))

			validatePassphraseDialog(window, "Confirm Transaction", fmt.Sprintf("Send %.6f %s to:\n%s\n\nMemo: %s",
				amount, chainHeader.Symbol, recipientEntry.Text, memoEntry.Text),
				func(passphrase string) {
					statusText.Text = "Processing transaction..."
					statusText.Color = colMuted
					statusText.Refresh()

					go func() {
						// Use real RPC transaction
						txID, err := walletClient.SendTransaction(recipientEntry.Text, amountNSPX, memoEntry.Text)

						fyne.Do(func() {
							if err != nil {
								statusText.Text = "ERROR Transaction failed: " + err.Error()
								statusText.Color = colDanger
								statusText.Refresh()
								dialog.ShowError(fmt.Errorf("transaction failed: %w", err), window)
								return
							}

							addActivity(fmt.Sprintf("Sent %.6f %s to %s (tx: %s)",
								amount, chainHeader.Symbol, recipientEntry.Text[:16], txID[:8]+"..."))
							statusText.Text = "SUCCESS Transaction sent! TxID: " + txID[:16] + "..."
							statusText.Color = colAccent
							statusText.Refresh()

							dialog.ShowInformation("Transaction Sent",
								fmt.Sprintf("Successfully sent %.6f %s to %s\n\nTxID: %s",
									amount, chainHeader.Symbol, recipientEntry.Text, txID), window)

							recipientEntry.SetText("")
							amountEntry.SetText("")
							memoEntry.SetText("")
						})
					}()
				})
		})
		sendBtn.Importance = widget.HighImportance

		clearBtn := widget.NewButtonWithIcon("Clear", theme.CancelIcon(), func() {
			recipientEntry.SetText("")
			amountEntry.SetText("")
			memoEntry.SetText("")
			statusText.Text = ""
			statusText.Refresh()
		})

		panel := container.NewVBox(
			infoPanel("Transaction Details", []fyne.CanvasObject{
				infoRow("Network", chainHeader.ChainName, colAccent),
				infoRow("Symbol", chainHeader.Symbol, colAccent),
				infoRow("Chain ID", fmt.Sprintf("%d", chainHeader.ChainID), colText),
				infoRow("Identity", publicFingerprint[:16]+"...", colText),
				infoRow("Gas", "SPHINCS+ SPX", colText),
				infoRow("KEM", "Kyber768+X25519", colText),
			}),
			spacer(12),
			alertBox(fmt.Sprintf("Sending %s on %s network. Transaction will be signed with your SPHINCS+ key.",
				chainHeader.Symbol, chainHeader.ChainName), color.RGBA{74, 222, 158, 15}, colAccent),
		)

		form := container.NewVBox(
			screenTitle(fmt.Sprintf("Send %s", chainHeader.Symbol)),
			spacer(4),
			screenSubtitle(fmt.Sprintf("Send %s on %s", chainHeader.Symbol, chainHeader.ChainName)),
			spacer(20),
			sectionLabel("Recipient"),
			spacer(6),
			recipientEntry,
			spacer(16),
			sectionLabel("Amount"),
			spacer(6),
			amountEntry,
			spacer(16),
			sectionLabel("Memo (Optional)"),
			spacer(6),
			memoEntry,
			spacer(20),
			container.NewCenter(statusText),
			spacer(10),
			container.NewHBox(sendBtn, spacer(8), clearBtn),
		)

		setScreen(opLayout(form, panel))
	}

	// =========================================================================
	// RECEIVE SCREEN
	// =========================================================================
	showReceiveScreen = func() {
		log.Println("Displaying receive screen")
		updateLayout(true)

		if sessionPassphrase == "" {
			dialog.ShowError(errors.New("please login first"), window)
			return
		}

		addrLbl := widget.NewLabel(publicFingerprint)
		addrLbl.TextStyle = fyne.TextStyle{Monospace: true}
		addrLbl.Wrapping = fyne.TextWrapBreak

		addrBg := canvas.NewRectangle(colSurface2)
		addrBg.CornerRadius = 12
		addrBg.StrokeColor = colAccent
		addrBg.StrokeWidth = 2
		addrBox := container.NewMax(addrBg, container.NewPadded(addrLbl))

		copyAddrBtn := widget.NewButtonWithIcon("Copy Address", theme.ContentCopyIcon(), func() {
			myApp.Clipboard().SetContent(publicFingerprint)
			dialog.ShowInformation("Copied", "Address copied to clipboard", window)
		})
		copyAddrBtn.Importance = widget.HighImportance

		panel := container.NewVBox(
			infoPanel("Receive Details", []fyne.CanvasObject{
				infoRow("Network", chainHeader.ChainName, colAccent),
				infoRow("Symbol", chainHeader.Symbol, colAccent),
				infoRow("Chain ID", fmt.Sprintf("%d", chainHeader.ChainID), colText),
				infoRow("Organization", "SPIF", colAccent),
				infoRow("Address Format", "SPIF (SHAKE-256)", colText),
				infoRow("KEM", "Kyber768+X25519", colText),
			}),
			spacer(12),
			alertBox(fmt.Sprintf("Share this address to receive %s on %s network.",
				chainHeader.Symbol, chainHeader.ChainName), color.RGBA{74, 222, 158, 15}, colAccent),
		)

		form := container.NewVBox(
			screenTitle(fmt.Sprintf("Receive %s", chainHeader.Symbol)),
			spacer(4),
			screenSubtitle(fmt.Sprintf("Your %s address on %s", chainHeader.Symbol, chainHeader.ChainName)),
			spacer(20),
			sectionLabel("Your Address"),
			spacer(8),
			addrBox,
			spacer(8),
			container.NewCenter(copyAddrBtn),
			spacer(20),
			hRule(),
			spacer(16),
			sectionLabel("Quick Actions"),
			spacer(8),
			widget.NewButtonWithIcon("Copy to Clipboard", theme.ContentCopyIcon(), func() {
				myApp.Clipboard().SetContent(publicFingerprint)
				dialog.ShowInformation("Copied", "Address copied to clipboard", window)
			}),
		)

		setScreen(opLayout(form, panel))
	}

	// =========================================================================
	// ENCRYPT SCREEN
	// =========================================================================
	showEncryptScreen = func() {
		log.Println("Displaying message screen")
		updateLayout(true)

		var selectedFolder string

		dropBg := canvas.NewRectangle(colSurface)
		dropBg.CornerRadius = 12
		dropBg.StrokeColor = colBorder2
		dropBg.StrokeWidth = 1
		dropBg.SetMinSize(fyne.NewSize(0, 120))

		dropIcon := canvas.NewText("", colMuted)
		dropIcon.TextSize = 28
		dropMain := canvas.NewText("Select folder to message", colText)
		dropMain.TextSize = 14
		dropMain.TextStyle = fyne.TextStyle{Bold: true}
		dropSub := canvas.NewText("Click 'Browse' to choose a folder", colMuted)
		dropSub.TextSize = 12

		dropContent := container.NewCenter(container.NewVBox(
			container.NewCenter(dropIcon),
			spacer(8),
			container.NewCenter(dropMain),
			container.NewCenter(dropSub),
		))
		dropZone := container.NewMax(dropBg, dropContent)

		updateDropZone := func(path string) {
			dropBg.FillColor = colAccentDim
			dropBg.StrokeColor = colAccent
			dropIcon.Text = ""
			dropIcon.Color = colAccent
			dropMain.Text = filepath.Base(path)
			dropMain.Color = colAccent
			dropSub.Text = path
			dropSub.Color = colMuted
			dropBg.Refresh()
			dropIcon.Refresh()
			dropMain.Refresh()
			dropSub.Refresh()
		}

		resetDropZone := func() {
			dropBg.FillColor = colSurface
			dropBg.StrokeColor = colBorder2
			dropIcon.Text = ""
			dropIcon.Color = colMuted
			dropMain.Text = "Select folder to message"
			dropMain.Color = colText
			dropSub.Text = "Click 'Browse' to choose a folder"
			dropSub.Color = colMuted
			dropBg.Refresh()
			dropIcon.Refresh()
			dropMain.Refresh()
			dropSub.Refresh()
		}

		browseBtn := widget.NewButtonWithIcon("Browse Folder", theme.FolderOpenIcon(), func() {
			dlg := dialog.NewFolderOpen(func(uri fyne.ListableURI, err error) {
				if err == nil && uri != nil {
					p := uri.Path()
					if strings.HasSuffix(p, ".vault") {
						dialog.ShowError(errors.New("select a regular folder, not a .vault file"), window)
						return
					}
					selectedFolder = p
					updateDropZone(p)
				}
			}, window)
			dlg.Resize(fyne.NewSize(800, 600))
			dlg.Show()
		})
		browseBtn.Importance = widget.HighImportance

		recipientEntry := widget.NewEntry()
		recipientEntry.SetPlaceHolder("Fingerprints, comma-separated (leave blank for self)")

		messageEntry := widget.NewMultiLineEntry()
		messageEntry.SetPlaceHolder("Optional secure message embedded inside the .vault file…\n\nExample: 'Q4 financial reports. Finance team only.'")
		messageEntry.Wrapping = fyne.TextWrapWord
		messageEntry.SetMinRowsVisible(5)

		charCount := canvas.NewText("0 characters", colFaint)
		charCount.TextSize = 11
		messageEntry.OnChanged = func(text string) {
			charCount.Text = fmt.Sprintf("%d characters", len(text))
			charCount.Refresh()
		}

		progressBar := widget.NewProgressBar()
		progressBar.Hide()
		progressLbl := canvas.NewText("", colMuted)
		progressLbl.TextSize = 12

		encryptBtn := widget.NewButtonWithIcon("Lock Folder", theme.ConfirmIcon(), func() {
			if selectedFolder == "" {
				dialog.ShowError(errors.New("please select a folder first"), window)
				return
			}
			if sessionPassphrase == "" {
				dialog.ShowError(errors.New("not logged in — please log in again"), window)
				return
			}

			validatePassphraseDialog(window, "Confirm Passphrase", "Enter your passphrase to encrypt this folder:", func(passphrase string) {
				var recipients []string
				var recipientPubs []*vault.HybridPublicKey

				if recipientEntry.Text != "" {
					recipients = keys.ParseFingerprints(recipientEntry.Text)
					normalizedRecipients, err := vault.ValidateAndNormalizeRecipients(recipients)
					if err != nil {
						dialog.ShowError(fmt.Errorf("invalid recipient fingerprints: %w", err), window)
						return
					}
					recipients = normalizedRecipients

					store := getKeyStore()
					if store == nil {
						dialog.ShowError(fmt.Errorf("failed to connect to key directory"), window)
						return
					}

					recipientPubs, err = vault.ResolveMultipleRecipients(store, recipients)
					if err != nil {
						dialog.ShowError(fmt.Errorf("failed to resolve recipients: %w\n\nMake sure they have registered", err), window)
						return
					}
					defer store.Close()
				}

				embeddedMessage := messageEntry.Text
				var messageFilePath string
				if embeddedMessage != "" {
					messageFilePath = filepath.Join(selectedFolder, ".encrypted_message.txt")
					if err := os.WriteFile(messageFilePath, []byte(embeddedMessage), 0600); err != nil {
						dialog.ShowError(fmt.Errorf("failed to create message file: %w", err), window)
						return
					}
				}

				prog := widget.NewProgressBar()
				progLbl := widget.NewLabel("Encrypting folder…")
				progDlg := dialog.NewCustom("Encrypting", "Cancel", container.NewVBox(progLbl, prog), window)
				progDlg.Show()

				go func() {
					var err error
					if len(recipientPubs) > 0 {
						err = vault.EncryptFolderWithResolvedKeys(selectedFolder, passphrase, recipients, recipientPubs)
					} else {
						err = vault.EncryptFolder(selectedFolder, passphrase)
					}

					if messageFilePath != "" {
						os.Remove(messageFilePath)
					}

					fyne.Do(func() {
						progDlg.Hide()
						if err != nil {
							dialog.ShowError(err, window)
							return
						}
						if embeddedMessage != "" {
							addActivity(fmt.Sprintf("Encrypted: %s (message: %d chars, recipients: %d)",
								filepath.Base(selectedFolder), len(embeddedMessage), len(recipients)))
							dialog.ShowInformation("Locked",
								fmt.Sprintf("Folder encrypted.\nMessage embedded inside .vault (%d chars).\nShared with %d recipient(s).",
									len(embeddedMessage), len(recipients)), window)
						} else {
							addActivity(fmt.Sprintf("Encrypted: %s (recipients: %d)", filepath.Base(selectedFolder), len(recipients)))
							dialog.ShowInformation("Locked", fmt.Sprintf("Folder encrypted successfully.\nShared with %d recipient(s).", len(recipients)), window)
						}
						selectedFolder = ""
						resetDropZone()
						recipientEntry.SetText("")
						messageEntry.SetText("")
					})
				}()
			})
		})
		encryptBtn.Importance = widget.HighImportance

		clearBtn := widget.NewButtonWithIcon("Clear", theme.CancelIcon(), func() {
			selectedFolder = ""
			resetDropZone()
			recipientEntry.SetText("")
			messageEntry.SetText("")
		})

		panel := container.NewVBox(
			infoPanel("Encryption Details", []fyne.CanvasObject{
				infoRow("Algorithm", "AES-256-GCM", colText),
				infoRow("KDF", "Argon2id", colText),
				infoRow("KEM", "Kyber768+X25519", colText),
				infoRow("Output", ".vault", colAccent),
				infoRow("Organization", "SPIF", colAccent),
				infoRow("Network", chainHeader.ChainName, colAccent),
			}),
			spacer(12),
			alertBox("The original folder remains intact until encryption completes.", color.RGBA{96, 165, 250, 20}, colInfo),
			spacer(12),
			alertBox("Add recipient fingerprints to share vault access with others.", color.RGBA{74, 222, 158, 15}, colAccent),
		)

		form := container.NewVBox(
			screenTitle("Message"),
			spacer(4),
			screenSubtitle("Lock a folder into an encrypted .vault file"),
			spacer(20),
			dropZone,
			spacer(8),
			browseBtn,
			spacer(20),
			hRule(),
			spacer(12),
			sectionLabel("Recipients (optional)"),
			spacer(6),
			recipientEntry,
			spacer(16),
			hRule(),
			spacer(12),
			sectionLabel("Embedded Message (optional)"),
			spacer(6),
			messageEntry,
			container.NewHBox(layout.NewSpacer(), charCount),
			spacer(20),
			container.NewHBox(encryptBtn, spacer(8), clearBtn),
		)

		setScreen(opLayout(form, panel))
	}

	// =========================================================================
	// DECRYPT SCREEN
	// =========================================================================
	showDecryptScreen = func() {
		log.Println("Displaying inbox screen")
		updateLayout(true)

		var selectedVault string
		var cachedSenderFP string

		dropBg := canvas.NewRectangle(colSurface)
		dropBg.CornerRadius = 12
		dropBg.StrokeColor = colBorder2
		dropBg.StrokeWidth = 1
		dropBg.SetMinSize(fyne.NewSize(0, 120))

		dropIcon := canvas.NewText("", colMuted)
		dropIcon.TextSize = 28
		dropMain := canvas.NewText("Select .vault file for inbox", colText)
		dropMain.TextSize = 14
		dropMain.TextStyle = fyne.TextStyle{Bold: true}
		dropSub := canvas.NewText("Click 'Browse' to choose a .vault file", colMuted)
		dropSub.TextSize = 12
		dropZone := container.NewMax(dropBg, container.NewCenter(container.NewVBox(
			container.NewCenter(dropIcon),
			spacer(8),
			container.NewCenter(dropMain),
			container.NewCenter(dropSub),
		)))

		fileNameVal := canvas.NewText("—", colMuted)
		fileNameVal.TextSize = 11
		fileNameVal.TextStyle = fyne.TextStyle{Monospace: true}
		recipientsVal := canvas.NewText("—", colMuted)
		recipientsVal.TextSize = 11
		accessVal := canvas.NewText("Select a file first", colMuted)
		accessVal.TextSize = 11

		senderVal := canvas.NewText("—", colMuted)
		senderVal.TextSize = 11
		senderVal.TextStyle = fyne.TextStyle{Monospace: true}
		senderOrgVal := canvas.NewText("—", colMuted)
		senderOrgVal.TextSize = 11
		senderOrgVal.TextStyle = fyne.TextStyle{Bold: true}

		updatePanelWithSenderInfo := func(senderFP, senderOrg string) {
			if senderFP != "" {
				formattedFP := keys.FormatOrgAddressForDisplay(senderFP)
				if len(formattedFP) > 50 {
					formattedFP = formattedFP[:47] + "..."
				}
				senderVal.Text = formattedFP
				senderVal.Color = colInfo

				if senderOrg != "" && senderOrg != "Unknown Organization" {
					senderOrgVal.Text = senderOrg
					senderOrgVal.Color = colAccent
				} else {
					senderOrgVal.Text = "SPIF - Sphinx Fingerprint"
					senderOrgVal.Color = colAccent
				}
			} else {
				senderVal.Text = "Unknown sender"
				senderVal.Color = colMuted
				senderOrgVal.Text = "SPIF"
				senderOrgVal.Color = colAccent
			}
			senderVal.Refresh()
			senderOrgVal.Refresh()
		}

		panelBg := canvas.NewRectangle(colSurface)
		panelBg.CornerRadius = 12
		panelBg.StrokeColor = colBorder
		panelBg.StrokeWidth = 1

		makeInfoLine := func(label string, val *canvas.Text) fyne.CanvasObject {
			lbl := canvas.NewText(label, colMuted)
			lbl.TextSize = 11
			return container.NewHBox(lbl, layout.NewSpacer(), val)
		}

		panelInner := container.NewVBox(
			sectionLabel("Vault Info"),
			spacer(10),
			makeInfoLine("File", fileNameVal),
			spacer(6),
			makeInfoLine("Organization", senderOrgVal),
			spacer(6),
			makeInfoLine("Sender", senderVal),
			spacer(6),
			makeInfoLine("Recipients", recipientsVal),
			spacer(6),
			makeInfoLine("Access", accessVal),
			spacer(6),
			infoRow("Output", "Same directory", colText),
			infoRow("Network", chainHeader.ChainName, colAccent),
		)

		panel := container.NewVBox(
			container.NewMax(panelBg, container.NewPadded(panelInner)),
			spacer(12),
			alertBox("You must be an authorized recipient. Unauthorized decryption attempts are rejected.", color.RGBA{255, 179, 71, 20}, colWarn),
		)

		updateDropZone := func(path string) {
			dropBg.FillColor = color.RGBA{96, 165, 250, 20}
			dropBg.StrokeColor = colInfo
			dropIcon.Text = ""
			dropIcon.Color = colInfo
			dropMain.Text = filepath.Base(path)
			dropMain.Color = colInfo
			dropSub.Text = path
			dropSub.Color = colMuted
			dropBg.Refresh()
			dropIcon.Refresh()
			dropMain.Refresh()
			dropSub.Refresh()

			fileNameVal.Text = filepath.Base(path)
			fileNameVal.Color = colText
			fileNameVal.Refresh()

			accessVal.Text = "Checking..."
			accessVal.Color = colMuted
			accessVal.Refresh()

			senderVal.Text = "Loading..."
			senderVal.Color = colMuted
			senderVal.Refresh()
			senderOrgVal.Text = "Loading..."
			senderOrgVal.Color = colMuted
			senderOrgVal.Refresh()

			go func() {
				r, err := vault.GetVaultRecipients(path)
				isAuth := vault.IsUserAuthorizedForVaultPublic(path, sessionPassphrase)
				senderFP, senderOrg, senderErr := getVaultSenderInfo(path)
				cachedSenderFP = senderFP
				fyne.Do(func() {
					if err != nil || len(r) == 0 {
						recipientsVal.Text = "Personal vault"
					} else {
						recipientsVal.Text = fmt.Sprintf("%d recipient(s)", len(r))
					}
					recipientsVal.Refresh()

					if isAuth {
						accessVal.Text = "✓ Authorized"
						accessVal.Color = colAccent
					} else {
						if len(r) == 0 {
							accessVal.Text = "✓ No restrictions"
							accessVal.Color = colAccent
						} else {
							accessVal.Text = "✗ Not Authorized"
							accessVal.Color = colDanger
						}
					}
					accessVal.Refresh()

					if senderErr == nil && senderOrg != "" {
						updatePanelWithSenderInfo(senderFP, senderOrg)
					} else {
						updatePanelWithSenderInfo("", "SPIF")
					}
					panel.Refresh()
				})
			}()
		}

		resetDropZone := func(preserveSenderInfo bool) {
			dropBg.FillColor = colSurface
			dropBg.StrokeColor = colBorder2
			dropIcon.Text = ""
			dropIcon.Color = colMuted
			dropMain.Text = "Select .vault file for inbox"
			dropMain.Color = colText
			dropSub.Text = "Click 'Browse' to choose a .vault file"
			dropSub.Color = colMuted
			dropBg.Refresh()
			dropIcon.Refresh()
			dropMain.Refresh()
			dropSub.Refresh()
			fileNameVal.Text = "—"
			fileNameVal.Color = colMuted
			recipientsVal.Text = "—"
			accessVal.Text = "Select a file first"
			accessVal.Color = colMuted
			fileNameVal.Refresh()
			recipientsVal.Refresh()
			accessVal.Refresh()

			if !preserveSenderInfo {
				senderVal.Text = "—"
				senderVal.Color = colMuted
				senderOrgVal.Text = "—"
				senderOrgVal.Color = colMuted
				senderVal.Refresh()
				senderOrgVal.Refresh()
			}
		}

		browseBtn := widget.NewButtonWithIcon("Browse Vault", theme.FileIcon(), func() {
			dlg := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
				if err == nil && reader != nil {
					p := reader.URI().Path()
					reader.Close()
					if !strings.HasSuffix(p, ".vault") {
						dialog.ShowError(errors.New("please select a .vault file"), window)
						return
					}
					selectedVault = p
					updateDropZone(p)
				}
			}, window)
			// NOTE: leaving default file filter (failing build in this branch)

			dlg.Resize(fyne.NewSize(800, 600))
			dlg.Show()
		})
		browseBtn.Importance = widget.HighImportance

		messageDisplay := widget.NewLabel("(No message yet — decrypt a vault to reveal.)")
		messageDisplay.Wrapping = fyne.TextWrapWord
		messageDisplay.TextStyle = fyne.TextStyle{Italic: true}
		msgBg := canvas.NewRectangle(colSurface2)
		msgBg.CornerRadius = 8
		msgBg.StrokeColor = colBorder2
		msgBg.StrokeWidth = 1
		msgScroll := container.NewScroll(messageDisplay)
		msgScroll.SetMinSize(fyne.NewSize(0, 90))
		msgContainer := container.NewMax(msgBg, container.NewPadded(msgScroll))

		statusText := canvas.NewText("", colMuted)
		statusText.TextSize = 13
		statusText.TextStyle = fyne.TextStyle{Bold: true}

		decryptBtn := widget.NewButtonWithIcon("Unlock Vault", theme.ConfirmIcon(), func() {
			if selectedVault == "" {
				dialog.ShowError(errors.New("please select a .vault file"), window)
				return
			}
			if sessionPassphrase == "" {
				dialog.ShowError(errors.New("not logged in — please log in again"), window)
				return
			}

			validatePassphraseDialog(window, "Confirm Passphrase", "Enter your passphrase to unlock this vault:", func(passphrase string) {
				prog := widget.NewProgressBar()
				progLbl := widget.NewLabel("Decrypting vault…")
				progDlg := dialog.NewCustom("Decrypting", "Cancel", container.NewVBox(progLbl, prog), window)
				progDlg.Show()

				go func() {
					var senderFP string
					if cachedSenderFP != "" {
						senderFP = cachedSenderFP
					} else {
						senderFP, _, _ = getVaultSenderInfo(selectedVault)
					}

					err := vault.DecryptVault(selectedVault, passphrase)

					fyne.Do(func() {
						progDlg.Hide()
						if err != nil {
							statusText.Text = "✗  Decryption failed"
							statusText.Color = colDanger
							statusText.Refresh()
							dialog.ShowError(err, window)
							return
						}

						senderDisplay := ""
						if senderFP != "" {
							formattedFP := keys.FormatOrgAddressForDisplay(senderFP)
							if len(formattedFP) > 50 {
								senderDisplay = formattedFP[:47] + "..."
							} else {
								senderDisplay = formattedFP
							}
						}

						updatePanelWithSenderInfo(senderFP, "SPIF")

						decryptedFolder := strings.TrimSuffix(selectedVault, ".vault")
						msgPath := filepath.Join(decryptedFolder, ".encrypted_message.txt")

						if msgData, err2 := os.ReadFile(msgPath); err2 == nil {
							messageDisplay.SetText(string(msgData))
							messageDisplay.TextStyle = fyne.TextStyle{Bold: true}
							_ = os.Remove(msgPath)

							addActivity(fmt.Sprintf("Decrypted vault with embedded message from SPIF: %s", filepath.Base(selectedVault)))
							statusText.Text = "✓  Vault unlocked — embedded message found"
							statusText.Color = colAccent

							dialog.ShowInformation("Unlocked",
								fmt.Sprintf("Vault decrypted successfully.\n\n📤 Organization: SPIF\n🔑 Sender: %s\n\n Embedded message recovered.",
									senderDisplay), window)
						} else {
							messageDisplay.SetText("(No embedded message in this vault)")
							messageDisplay.TextStyle = fyne.TextStyle{Italic: true}
							addActivity(fmt.Sprintf("Decrypted vault from SPIF (no message): %s", filepath.Base(selectedVault)))
							statusText.Text = "✓  Vault unlocked"
							statusText.Color = colAccent

							dialog.ShowInformation("Unlocked",
								fmt.Sprintf("Vault decrypted successfully.\n\n📤 Organization: SPIF\n🔑 Sender: %s",
									senderDisplay), window)
						}
						statusText.Refresh()
						selectedVault = ""
						resetDropZone(true)
					})
				}()
			})
		})
		decryptBtn.Importance = widget.HighImportance

		clearBtn := widget.NewButtonWithIcon("Clear", theme.CancelIcon(), func() {
			selectedVault = ""
			resetDropZone(false)
			messageDisplay.SetText("(No message yet — decrypt a vault to reveal.)")
			messageDisplay.TextStyle = fyne.TextStyle{Italic: true}
			statusText.Text = ""
			statusText.Refresh()
			cachedSenderFP = ""
		})

		form := container.NewVBox(
			screenTitle("Inbox"),
			spacer(4),
			screenSubtitle("Unlock a .vault file and restore the original folder"),
			spacer(20),
			dropZone,
			spacer(8),
			browseBtn,
			spacer(20),
			hRule(),
			spacer(12),
			sectionLabel("Embedded Message"),
			spacer(6),
			msgContainer,
			spacer(10),
			container.NewCenter(statusText),
			spacer(20),
			container.NewHBox(decryptBtn, spacer(8), clearBtn),
		)

		setScreen(opLayout(form, panel))
	}

	// =========================================================================
	// SIGN SCREEN
	// =========================================================================
	showSignScreen = func() {

		log.Println("Displaying mint data screen")
		updateLayout(true)

		var selectedFile string

		dropBg := canvas.NewRectangle(colSurface)
		dropBg.CornerRadius = 12
		dropBg.StrokeColor = colBorder2
		dropBg.StrokeWidth = 1
		dropBg.SetMinSize(fyne.NewSize(0, 120))

		dropIcon := canvas.NewText("", colMuted)
		dropIcon.TextSize = 28
		dropMain := canvas.NewText("Select document to mint", colText)
		dropMain.TextSize = 14
		dropMain.TextStyle = fyne.TextStyle{Bold: true}
		dropSub := canvas.NewText("PDF, TXT, MD, JSON, XML — any file", colMuted)
		dropSub.TextSize = 12
		dropZone := container.NewMax(dropBg, container.NewCenter(container.NewVBox(
			container.NewCenter(dropIcon),
			spacer(8),
			container.NewCenter(dropMain),
			container.NewCenter(dropSub),
		)))

		fileNameVal := canvas.NewText("—", colMuted)
		fileNameVal.TextSize = 11
		fileNameVal.TextStyle = fyne.TextStyle{Monospace: true}
		fileSizeVal := canvas.NewText("—", colMuted)
		fileSizeVal.TextSize = 11
		fileModVal := canvas.NewText("—", colMuted)
		fileModVal.TextSize = 11
		signerVal := canvas.NewText("—", colMuted)
		signerVal.TextSize = 11
		signerVal.TextStyle = fyne.TextStyle{Monospace: true}

		updateDropZone := func(path string) {
			dropBg.FillColor = color.RGBA{255, 179, 71, 15}
			dropBg.StrokeColor = colWarn
			dropIcon.Text = ""
			dropIcon.Color = colWarn
			dropMain.Text = filepath.Base(path)
			dropMain.Color = colWarn
			dropSub.Text = path
			dropSub.Color = colMuted
			dropBg.Refresh()
			dropIcon.Refresh()
			dropMain.Refresh()
			dropSub.Refresh()

			fileNameVal.Text = filepath.Base(path)
			fileNameVal.Color = colText
			fileNameVal.Refresh()

			if info, err := os.Stat(path); err == nil {
				fileSizeVal.Text = fmt.Sprintf("%.2f MB", float64(info.Size())/(1024*1024))
				fileSizeVal.Color = colText
				fileSizeVal.Refresh()
				fileModVal.Text = info.ModTime().Format("2006-01-02 15:04")
				fileModVal.Color = colText
				fileModVal.Refresh()
			}

			fp := publicFingerprint
			if len(fp) > 20 {
				fp = fp[:16] + "…"
			}
			signerVal.Text = fp
			signerVal.Color = colAccent
			signerVal.Refresh()
		}

		resetDropZone := func() {
			dropBg.FillColor = colSurface
			dropBg.StrokeColor = colBorder2
			dropIcon.Text = ""
			dropIcon.Color = colMuted
			dropMain.Text = "Select document to mint"
			dropMain.Color = colText
			dropSub.Text = "PDF, TXT, MD, JSON, XML — any file"
			dropSub.Color = colMuted
			dropBg.Refresh()
			dropIcon.Refresh()
			dropMain.Refresh()
			dropSub.Refresh()
			fileNameVal.Text = "—"
			fileNameVal.Color = colMuted
			fileSizeVal.Text = "—"
			fileSizeVal.Color = colMuted
			fileModVal.Text = "—"
			fileModVal.Color = colMuted
			signerVal.Text = "—"
			signerVal.Color = colMuted
			fileNameVal.Refresh()
			fileSizeVal.Refresh()
			fileModVal.Refresh()
			signerVal.Refresh()
		}

		browseBtn := widget.NewButtonWithIcon("Browse File", theme.DocumentCreateIcon(), func() {
			dlg := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
				if err == nil && reader != nil {
					p := reader.URI().Path()
					reader.Close()
					if strings.HasSuffix(p, ".vault") {
						dialog.ShowError(errors.New("cannot sign a .vault file"), window)
						return
					}
					selectedFile = p
					updateDropZone(p)
				}
			}, window)
			dlg.Resize(fyne.NewSize(800, 600))
			dlg.Show()
		})
		browseBtn.Importance = widget.HighImportance

		statusText := canvas.NewText("", colMuted)
		statusText.TextSize = 13
		statusText.TextStyle = fyne.TextStyle{Bold: true}

		signBtn := widget.NewButtonWithIcon("Mint Data", theme.ConfirmIcon(), func() {
			if selectedFile == "" {
				dialog.ShowError(errors.New("please select a file"), window)
				return
			}
			if sessionPassphrase == "" {
				dialog.ShowError(errors.New("not logged in — please log in again"), window)
				return
			}

			signed, prevFP, err := sign.IsAlreadySigned(selectedFile)
			if err != nil {
				dialog.ShowError(fmt.Errorf("metadata error: %w", err), window)
				return
			}
			if signed {
				dialog.ShowInformation("Already Signed",
					fmt.Sprintf("This document is already signed.\n\nSigned by: %s\n\nRe-signing is not permitted.", prevFP), window)
				return
			}

			validatePassphraseDialog(window, "Confirm Passphrase", "Enter your passphrase to sign this document:", func(passphrase string) {
				prog := widget.NewProgressBar()
				progLbl := widget.NewLabel("Preparing signature…")
				progDlg := dialog.NewCustom("Signing", "Cancel", container.NewVBox(progLbl, prog), window)
				progDlg.Show()

				go func() {
					data, err := os.ReadFile(selectedFile)
					if err != nil {
						fyne.Do(func() { progDlg.Hide(); dialog.ShowError(err, window) })
						return
					}

					fyne.Do(func() { prog.SetValue(0.3); progLbl.SetText("Hashing document…") })
					hash := keys.SHAKE256Hash(data)

					fyne.Do(func() { prog.SetValue(0.5); progLbl.SetText("Generating signature…") })
					sig, err := sign.Sign(hash, passphrase)
					if err != nil {
						fyne.Do(func() { progDlg.Hide(); dialog.ShowError(err, window) })
						return
					}

					fyne.Do(func() { prog.SetValue(0.75); progLbl.SetText("Embedding signature…") })
					meta, err := sign.NewMeta(sig, hash)
					if err != nil {
						fyne.Do(func() { progDlg.Hide(); dialog.ShowError(err, window) })
						return
					}

					meta.OrgCode = "SPIF"
					meta.Signer = sessionFingerprint
					meta.DocumentTitle = filepath.Base(selectedFile)

					if err := sign.EmbedSignature(selectedFile, meta, publicFingerprint, passphrase); err != nil {
						fyne.Do(func() { progDlg.Hide(); dialog.ShowError(err, window) })
						return
					}

					// After signing, auto-mint NFT on-chain
					fyne.Do(func() { prog.SetValue(0.9); progLbl.SetText("Anchoring NFT on-chain…") })

					// Upload signed payload bytes to IPFS (so the on-chain mint can bind to a real CID)

					ipfsClient := storage.NewClient(storage.DefaultConfig())
					cid, ipfsErr := ipfsClient.AddBytesToIPFS(data, filepath.Base(selectedFile))
					if ipfsErr != nil {
						fyne.Do(func() {
							progDlg.Hide()
							dialog.ShowError(fmt.Errorf("ipfs upload failed: %w", ipfsErr), window)
						})
						return
					}
					gatewayBase := storage.DefaultConfig().GatewayBaseURL
					metadataURI := gatewayBase + "/ipfs/" + cid

					mintRes, mintErr := mint.Mint(data, filepath.Base(selectedFile), sessionPassphrase, "SPIF", cid, metadataURI)

					if mintErr == nil {
						txID, anchorPath, anchorErr := walletClient.AnchorMintReceipt(mintRes.Receipt)
						fyne.Do(func() {
							progDlg.Hide()
							if anchorErr != nil {
								addActivity(fmt.Sprintf("Signed document: %s (NFT anchor failed: %v)", filepath.Base(selectedFile), anchorErr))
								statusText.Text = "✓  Document signed, but NFT anchor failed: " + anchorErr.Error()
								statusText.Color = colWarn
								statusText.Refresh()
								dialog.ShowInformation("Signed",
									fmt.Sprintf("Document signed successfully.\nSignature: %s.usimeta\n\nNFT anchor failed: %v",
										filepath.Base(selectedFile), anchorErr), window)
							} else {
								addActivity(fmt.Sprintf("Signed & minted NFT: %s (tx=%s, anchor=%s)", filepath.Base(selectedFile), txID, anchorPath))
								statusText.Text = fmt.Sprintf("✓  Signed & minted NFT. txid=%s\nAnchor: %s", txID, anchorPath)
								statusText.Color = colAccent
								statusText.Refresh()
								dialog.ShowInformation("Minted ✓",
									fmt.Sprintf("Document signed and NFT minted on-chain!\n\nSignature: %s.usimeta\nTXID: %s\nAnchor: %s",
										filepath.Base(selectedFile), txID, anchorPath), window)
							}
							selectedFile = ""
							resetDropZone()
						})
					} else {
						fyne.Do(func() {
							progDlg.Hide()
							addActivity(fmt.Sprintf("Signed document (NFT mint skipped): %s", filepath.Base(selectedFile)))
							statusText.Text = "✓  Document signed — signature embedded (NFT mint skipped)"
							statusText.Color = colAccent
							statusText.Refresh()
							dialog.ShowInformation("Signed",
								fmt.Sprintf("Document signed successfully.\nSignature saved as: %s.usimeta\n\nNFT mint skipped: %v",
									filepath.Base(selectedFile), mintErr), window)
							selectedFile = ""
							resetDropZone()
						})
					}
				}()
			})
		})
		signBtn.Importance = widget.HighImportance

		clearBtn := widget.NewButtonWithIcon("Clear", theme.CancelIcon(), func() {
			selectedFile = ""
			resetDropZone()
			statusText.Text = ""
			statusText.Refresh()
		})

		panelBg := canvas.NewRectangle(colSurface)
		panelBg.CornerRadius = 12
		panelBg.StrokeColor = colBorder
		panelBg.StrokeWidth = 1

		makeInfoLine := func(label string, val *canvas.Text) fyne.CanvasObject {
			lbl := canvas.NewText(label, colMuted)
			lbl.TextSize = 11
			return container.NewHBox(lbl, layout.NewSpacer(), val)
		}

		panelInner := container.NewVBox(
			sectionLabel("Document Details"),
			spacer(10),
			makeInfoLine("File", fileNameVal),
			spacer(6),
			makeInfoLine("Size", fileSizeVal),
			spacer(6),
			makeInfoLine("Modified", fileModVal),
			spacer(6),
			makeInfoLine("Signer", signerVal),
			spacer(6),
			infoRow("Organization", "SPIF", colAccent),
			infoRow("Network", chainHeader.ChainName, colAccent),
		)
		panel := container.NewVBox(
			container.NewMax(panelBg, container.NewPadded(panelInner)),
			spacer(12),
			infoPanel("Signature Algorithm", []fyne.CanvasObject{
				infoRow("Scheme", "SPHINCS+", colText),
				infoRow("Hash", "SHAKE-256", colText),
				infoRow("Sidecar", ".usimeta", colAccent),
				infoRow("Network", chainHeader.ChainName, colAccent),
			}),
			spacer(12),
			alertBox("A document can only be signed once. Re-signing is blocked to preserve integrity.", color.RGBA{255, 179, 71, 20}, colWarn),
		)

		form := container.NewVBox(
			screenTitle("Mint Data"),
			spacer(4),
			screenSubtitle("Attach your cryptographic identity to a file — automatically mints an NFT on-chain"),
			spacer(20),
			dropZone,
			spacer(8),
			browseBtn,
			spacer(20),
			container.NewCenter(statusText),
			spacer(20),
			container.NewHBox(signBtn, spacer(8), clearBtn),
		)

		setScreen(opLayout(form, panel))
	}

	// =========================================================================
	// VERIFY SCREEN
	// =========================================================================
	showVerifyScreen = func() {
		log.Println("Displaying verify data screen")
		updateLayout(true)

		var selectedFile string

		dropBg := canvas.NewRectangle(colSurface)
		dropBg.CornerRadius = 12
		dropBg.StrokeColor = colBorder2
		dropBg.StrokeWidth = 1
		dropBg.SetMinSize(fyne.NewSize(0, 120))

		dropIcon := canvas.NewText("INFO", colMuted)
		dropIcon.TextSize = 28
		dropMain := canvas.NewText("Select file to verify", colText)
		dropMain.TextSize = 14
		dropMain.TextStyle = fyne.TextStyle{Bold: true}
		dropSub := canvas.NewText("The .usimeta sidecar must be in the same folder", colMuted)
		dropSub.TextSize = 12
		dropZone := container.NewMax(dropBg, container.NewCenter(container.NewVBox(
			container.NewCenter(dropIcon),
			spacer(8),
			container.NewCenter(dropMain),
			container.NewCenter(dropSub),
		)))

		resultFileLbl := canvas.NewText("—", colMuted)
		resultFileLbl.TextSize = 11
		resultFileLbl.TextStyle = fyne.TextStyle{Monospace: true}
		resultSignerLbl := canvas.NewText("—", colMuted)
		resultSignerLbl.TextSize = 11
		resultSignerLbl.TextStyle = fyne.TextStyle{Monospace: true}
		resultOrgLbl := canvas.NewText("—", colMuted)
		resultOrgLbl.TextSize = 11
		resultTimeLbl := canvas.NewText("—", colMuted)
		resultTimeLbl.TextSize = 11
		resultStatusLbl := canvas.NewText("Pending", colFaint)
		resultStatusLbl.TextSize = 11
		resultStatusLbl.TextStyle = fyne.TextStyle{Bold: true}

		updateDropZone := func(path string) {
			dropBg.FillColor = color.RGBA{96, 165, 250, 15}
			dropBg.StrokeColor = colInfo
			dropIcon.Text = ""
			dropIcon.Color = colInfo
			dropMain.Text = filepath.Base(path)
			dropMain.Color = colInfo
			dropSub.Text = path
			dropSub.Color = colMuted
			dropBg.Refresh()
			dropIcon.Refresh()
			dropMain.Refresh()
			dropSub.Refresh()
			resultFileLbl.Text = filepath.Base(path)
			resultFileLbl.Color = colText
			resultFileLbl.Refresh()
			resultStatusLbl.Text = "Pending"
			resultStatusLbl.Color = colFaint
			resultStatusLbl.Refresh()
		}

		resetDropZone := func() {
			dropBg.FillColor = colSurface
			dropBg.StrokeColor = colBorder2
			dropIcon.Text = "INFO"
			dropIcon.Color = colMuted
			dropMain.Text = "Select file to verify"
			dropMain.Color = colText
			dropSub.Text = "The .usimeta sidecar must be in the same folder"
			dropSub.Color = colMuted
			dropBg.Refresh()
			dropIcon.Refresh()
			dropMain.Refresh()
			dropSub.Refresh()
			resultFileLbl.Text = "—"
			resultFileLbl.Color = colMuted
			resultSignerLbl.Text = "—"
			resultSignerLbl.Color = colMuted
			resultOrgLbl.Text = "—"
			resultOrgLbl.Color = colMuted
			resultTimeLbl.Text = "—"
			resultTimeLbl.Color = colMuted
			resultStatusLbl.Text = "Pending"
			resultStatusLbl.Color = colFaint
			resultFileLbl.Refresh()
			resultSignerLbl.Refresh()
			resultOrgLbl.Refresh()
			resultTimeLbl.Refresh()
			resultStatusLbl.Refresh()
		}

		browseBtn := widget.NewButtonWithIcon("Browse File", theme.ViewRefreshIcon(), func() {
			dlg := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
				if err == nil && reader != nil {
					p := reader.URI().Path()
					reader.Close()
					if strings.HasSuffix(p, ".vault") {
						dialog.ShowError(errors.New("cannot verify .vault files — verify the source files instead"), window)
						return
					}
					selectedFile = p
					updateDropZone(p)
				}
			}, window)
			dlg.Resize(fyne.NewSize(800, 600))
			dlg.Show()
		})
		browseBtn.Importance = widget.HighImportance

		statusBig := canvas.NewText("", colMuted)
		statusBig.TextSize = 16
		statusBig.TextStyle = fyne.TextStyle{Bold: true}
		statusBig.Alignment = fyne.TextAlignCenter

		verifyBtn := widget.NewButtonWithIcon("Verify Data", theme.ConfirmIcon(), func() {
			if selectedFile == "" {
				dialog.ShowError(errors.New("please select a file"), window)
				return
			}

			statusBig.Text = "Verifying…"
			statusBig.Color = colMuted
			statusBig.Refresh()

			go func() {
				ok, meta, _ := sign.VerifyUniversal(selectedFile, sessionPassphrase)
				fyne.Do(func() {
					if ok && meta != nil {
						addActivity(fmt.Sprintf("Verified: %s — VALID", filepath.Base(selectedFile)))
						statusBig.Text = "✓  SIGNATURE VALID"
						statusBig.Color = colAccent
						if meta != nil && meta.Signer != "" {
							resultSignerLbl.Text = meta.Signer
						} else {
							resultSignerLbl.Text = "Unknown signer"
						}
						resultSignerLbl.Color = colAccent
						if meta != nil && meta.OrgCode != "" {
							resultOrgLbl.Text = meta.OrgCode
						} else {
							resultOrgLbl.Text = "SPIF"
						}
						resultOrgLbl.Color = colAccent
						resultTimeLbl.Text = time.Unix(meta.Timestamp, 0).Format("2006-01-02 15:04")
						resultTimeLbl.Color = colText
						resultStatusLbl.Text = "VERIFIED"
						resultStatusLbl.Color = colAccent
						dialog.ShowInformation("Verified ✓", "Signature is valid. File is authentic and untampered.", window)
					} else {
						addActivity(fmt.Sprintf("Verified: %s — INVALID", filepath.Base(selectedFile)))
						statusBig.Text = "✗  SIGNATURE INVALID"
						statusBig.Color = colDanger
						resultStatusLbl.Text = "FAILED"
						resultStatusLbl.Color = colDanger
						dialog.ShowError(errors.New("signature invalid — file may have been tampered with"), window)
					}
					statusBig.Refresh()
					resultSignerLbl.Refresh()
					resultOrgLbl.Refresh()
					resultTimeLbl.Refresh()
					resultStatusLbl.Refresh()
				})
			}()
		})
		verifyBtn.Importance = widget.HighImportance

		clearBtn := widget.NewButtonWithIcon("Clear", theme.CancelIcon(), func() {
			selectedFile = ""
			resetDropZone()
			statusBig.Text = ""
			statusBig.Refresh()
		})

		panelBg := canvas.NewRectangle(colSurface)
		panelBg.CornerRadius = 12
		panelBg.StrokeColor = colBorder
		panelBg.StrokeWidth = 1

		makeInfoLine := func(label string, val *canvas.Text) fyne.CanvasObject {
			lbl := canvas.NewText(label, colMuted)
			lbl.TextSize = 11
			return container.NewHBox(lbl, layout.NewSpacer(), val)
		}

		panelInner := container.NewVBox(
			sectionLabel("Verification Result"),
			spacer(10),
			makeInfoLine("File", resultFileLbl),
			spacer(6),
			makeInfoLine("Organization", resultOrgLbl),
			spacer(6),
			makeInfoLine("Signer", resultSignerLbl),
			spacer(6),
			makeInfoLine("Signed at", resultTimeLbl),
			spacer(6),
			makeInfoLine("Status", resultStatusLbl),
			infoRow("Network", chainHeader.ChainName, colAccent),
		)
		panel := container.NewVBox(
			container.NewMax(panelBg, container.NewPadded(panelInner)),
			spacer(12),
			alertBox("Make sure the .usimeta sidecar file is in the same folder as the file being verified.", color.RGBA{96, 165, 250, 20}, colInfo),
		)

		form := container.NewVBox(
			screenTitle("Verify Data"),
			spacer(4),
			screenSubtitle("Confirm a file is authentic and has not been tampered with"),
			spacer(20),
			dropZone,
			spacer(8),
			browseBtn,
			spacer(20),
			container.NewCenter(statusBig),
			spacer(20),
			container.NewHBox(verifyBtn, spacer(8), clearBtn),
		)

		setScreen(opLayout(form, panel))
	}

	// =========================================================================
	// KEYS SCREEN
	// =========================================================================
	showKeysScreen = func() {
		log.Println("Displaying keys screen")
		updateLayout(true)

		fp := publicFingerprint
		fpFormatted := fp
		if len(fp) >= 48 {
			parts := []string{fp[0:12], fp[12:24], fp[24:36], fp[36:48]}
			fpFormatted = strings.Join(parts, "  ·  ")
		}

		fpLbl := widget.NewLabel(fpFormatted)
		fpLbl.TextStyle = fyne.TextStyle{Monospace: true}
		fpLbl.Wrapping = fyne.TextWrapBreak
		fpBg := canvas.NewRectangle(colSurface2)
		fpBg.CornerRadius = 10
		fpBg.StrokeColor = colAccent
		fpBg.StrokeWidth = 1
		fpContainer := container.NewMax(fpBg, container.NewPadded(fpLbl))

		copyFPBtn := widget.NewButtonWithIcon("Copy Fingerprint", theme.ContentCopyIcon(), func() {
			myApp.Clipboard().SetContent(publicFingerprint)
			dialog.ShowInformation("Copied", "Fingerprint copied to clipboard", window)
		})

		makeMetaCard := func(labelText, valueText string, col color.Color) fyne.CanvasObject {
			lbl := canvas.NewText(strings.ToUpper(labelText), colFaint)
			lbl.TextSize = 10
			lbl.TextStyle = fyne.TextStyle{Monospace: true}
			val := canvas.NewText(valueText, col)
			val.TextSize = 13
			val.TextStyle = fyne.TextStyle{Bold: true}
			inner := container.NewVBox(lbl, spacer(4), val)
			return styledCard(inner, 0, 60)
		}

		keyStatus := "Active"
		keyStatusCol := colAccent
		if sessionPassphrase == "" {
			keyStatus = "Not logged in"
			keyStatusCol = colDanger
		}

		metaGrid := container.NewGridWithColumns(2,
			makeMetaCard("Network", chainHeader.ChainName, colAccent),
			makeMetaCard("Symbol", chainHeader.Symbol, colAccent),
			makeMetaCard("Chain ID", fmt.Sprintf("%d", chainHeader.ChainID), colText),
			makeMetaCard("Organization", "SPIF", colAccent),
			makeMetaCard("Signature Scheme", "SPHINCS+", colText),
			makeMetaCard("Hash Function", "SHAKE-256", colText),
			makeMetaCard("Encryption", "AES-256-GCM", colText),
			makeMetaCard("KDF", "Argon2id", colText),
			makeMetaCard("KEM", "Kyber768+X25519", colText),
			makeMetaCard("Status", keyStatus, keyStatusCol),
		)

		storagePanel := infoPanel("Key Storage", []fyne.CanvasObject{
			infoRow("Private key", "~/.sphinx/disk-keystore/keys/", colText),
			infoRow("Public key", "~/.sphinx/disk-keystore/keys/", colText),
			infoRow("Key dir", keys.KeyDir, colText),
			infoRow("Protection", "Passphrase (Argon2id)", colText),
		})

		warnBox := alertBox(
			"Your passphrase is the only way to unlock your private key. "+
				"If lost, all encrypted data becomes permanently inaccessible.",
			color.RGBA{255, 179, 71, 20}, colWarn,
		)

		content := container.NewVBox(
			screenTitle("My Keys"),
			spacer(4),
			screenSubtitle(fmt.Sprintf("Your cryptographic identity on %s", chainHeader.ChainName)),
			spacer(20),
			sectionLabel("Public Fingerprint"),
			spacer(8),
			fpContainer,
			spacer(8),
			copyFPBtn,
			spacer(20),
			hRule(),
			spacer(16),
			sectionLabel("Key Parameters"),
			spacer(10),
			metaGrid,
			spacer(20),
			hRule(),
			spacer(16),
			storagePanel,
			spacer(16),
			warnBox,
			spacer(24),
		)

		setScreen(content)
	}

	// =========================================================================
	// WALLET SCREEN
	// =========================================================================
	showWalletScreen = func() {
		log.Println("Displaying wallet screen")
		updateLayout(true)

		activeOrgCode := sessionOrgCode
		if activeOrgCode == "" {
			activeOrgCode = "SPIF"
		}
		orgDisplayName, err := keys.OrgDisplayName(activeOrgCode)
		if err != nil {
			orgDisplayName = activeOrgCode
		}
		orgDescription, err := keys.OrgDescription(activeOrgCode)
		if err != nil {
			orgDescription = ""
		}

		walletAddress := publicFingerprint
		addrShort := walletAddress
		if len(addrShort) > 48 {
			addrShort = addrShort[:24] + "…" + addrShort[len(addrShort)-24:]
		}

		// ── Hero balance card ─────────────────────────────────────
		balBg := canvas.NewRectangle(colSurface2)
		balBg.CornerRadius = 14
		balBg.StrokeColor = colAccent
		balBg.StrokeWidth = 1
		balBg.SetMinSize(fyne.NewSize(0, 120))

		balLabel := canvas.NewText(fmt.Sprintf("%s BALANCE", strings.ToUpper(chainHeader.Symbol)), colFaint)
		balLabel.TextSize = 10
		balLabel.TextStyle = fyne.TextStyle{Monospace: true}

		balValue := canvas.NewText("Loading...", colAccent)
		balValue.TextSize = 36
		balValue.TextStyle = fyne.TextStyle{Bold: true}

		balSubtext := fmt.Sprintf("%s identity · %s mainnet", orgDisplayName, chainHeader.ChainName)
		balUnit := canvas.NewText(balSubtext, colMuted)
		balUnit.TextSize = 12

		balInner := container.NewVBox(
			container.NewCenter(balLabel),
			spacer(6),
			container.NewCenter(balValue),
			container.NewCenter(balUnit),
		)
		balCard := container.NewMax(balBg, container.NewPadded(balInner))

		// ── Fetch balance asynchronously ──────────────────────────
		fetchBalance := func() {
			resp, err := walletClient.GetBalance("")
			fyne.Do(func() {
				if err != nil {
					balValue.Text = "Error"
					balValue.Color = colDanger
					balValue.Refresh()
					log.Printf("[Wallet] Failed to fetch balance: %v", err)
					return
				}
				if resp != nil && resp.Balance != nil {
					balanceSPX := new(big.Float).Quo(
						new(big.Float).SetInt(resp.Balance),
						big.NewFloat(1e18),
					)
					balValue.Text = balanceSPX.Text('f', 6)
					balValue.Color = colAccent
					balValue.Refresh()
					log.Printf("[Wallet] Balance updated: %s SPX", balValue.Text)
				}
			})
		}

		// Initial balance fetch
		go fetchBalance()

		// ── Transaction history container ─────────────────────────
		txBox := container.NewVBox()
		txScroll := container.NewScroll(txBox)
		txScroll.SetMinSize(fyne.NewSize(0, 220))
		txCard := styledCard(txScroll, 0, 220)

		// ── Fetch transaction history ─────────────────────────────
		fetchTransactionHistory := func() {
			if sessionFingerprint == "" {
				return
			}

			txs, err := walletClient.GetTransactionHistory(sessionFingerprint, 20)
			fyne.Do(func() {
				txBox.Objects = nil

				if err != nil {
					log.Printf("[Wallet] Failed to fetch transaction history: %v", err)
					errLbl := canvas.NewText("Failed to load transaction history", colDanger)
					errLbl.TextSize = 12
					txBox.Add(container.NewCenter(errLbl))
					txBox.Refresh()
					return
				}

				if len(txs) == 0 {
					noTx := canvas.NewText("No transactions yet.", colMuted)
					noTx.TextSize = 12
					txBox.Add(container.NewCenter(noTx))
				} else {
					for _, tx := range txs {
						tx := tx
						ts := ""
						if !tx.Timestamp.IsZero() {
							ts = tx.Timestamp.Format("2006-01-02 15:04")
						}

						// Determine direction and icon
						var icon string
						var iconCol color.Color
						if tx.Sender == sessionFingerprint {
							icon = "↑"
							iconCol = colDanger
						} else if tx.Receiver == sessionFingerprint {
							icon = "↓"
							iconCol = colAccent
						} else {
							icon = "•"
							iconCol = colMuted
						}

						dirT := canvas.NewText(icon, iconCol)
						dirT.TextSize = 14
						dirT.TextStyle = fyne.TextStyle{Bold: true}
						dirBadgeBg := canvas.NewRectangle(colSurface2)
						dirBadgeBg.CornerRadius = 20
						dirBadgeBg.SetMinSize(fyne.NewSize(30, 30))
						dirBadge := container.NewMax(dirBadgeBg, container.NewCenter(dirT))

						// Format amount
						amountSPX := "0.000000"
						if tx.Amount != nil {
							amountFloat := new(big.Float).Quo(
								new(big.Float).SetInt(tx.Amount),
								big.NewFloat(1e18),
							)
							amountSPX = amountFloat.Text('f', 6)
						}

						// Build message
						msg := fmt.Sprintf("%s %s", amountSPX, chainHeader.Symbol)
						if tx.Sender == sessionFingerprint {
							msg += fmt.Sprintf(" → %s…", tx.Receiver[:16])
						} else {
							msg += fmt.Sprintf(" ← %s…", tx.Sender[:16])
						}

						msgT := canvas.NewText(msg, colText)
						msgT.TextSize = 11

						tsT := canvas.NewText(ts, colFaint)
						tsT.TextSize = 10
						tsT.Alignment = fyne.TextAlignTrailing

						rowBg := canvas.NewRectangle(colSurface)
						rowBg.CornerRadius = 8
						rowBg.StrokeColor = colBorder
						rowBg.StrokeWidth = 1

						inner := container.NewBorder(nil, nil,
							container.NewHBox(dirBadge, spacer(10)),
							nil,
							container.NewBorder(nil, nil, msgT, tsT),
						)
						row := container.NewMax(rowBg, container.NewPadded(inner))
						txBox.Add(row)
						txBox.Add(spacer(4))
					}
				}
				txBox.Refresh()
			})
		}

		// Fetch transaction history
		go fetchTransactionHistory()

		// ── Send button ────────────────────────────────────────────
		sendBtn := widget.NewButtonWithIcon(fmt.Sprintf("Send %s", chainHeader.Symbol), theme.MailSendIcon(), func() {
			if sessionPassphrase == "" {
				dialog.ShowError(errors.New("please login first"), window)
				return
			}
			showSendScreen()
		})
		sendBtn.Importance = widget.HighImportance

		// ── Receive button ────────────────────────────────────────────
		receiveBtn := widget.NewButtonWithIcon(fmt.Sprintf("Receive %s", chainHeader.Symbol), theme.DownloadIcon(), func() {
			if sessionPassphrase == "" {
				dialog.ShowError(errors.New("please login first"), window)
				return
			}
			showReceiveScreen()
		})
		receiveBtn.Importance = widget.HighImportance

		// ── Refresh button ────────────────────────────────────────
		refreshBtn := widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), func() {
			go fetchBalance()
			go fetchTransactionHistory()
		})
		refreshBtn.Importance = widget.LowImportance

		actionRow := container.NewHBox(sendBtn, spacer(8), receiveBtn, layout.NewSpacer(), refreshBtn)

		// ── Address display bar ───────────────────────────────────
		addrDisplay := widget.NewLabel(addrShort)
		addrDisplay.TextStyle = fyne.TextStyle{Monospace: true}
		addrDisplay.Wrapping = fyne.TextWrapBreak
		addrDispBg := canvas.NewRectangle(colSurface2)
		addrDispBg.CornerRadius = 8
		addrDispBg.StrokeColor = colBorder
		addrDispBg.StrokeWidth = 1
		addrContainer := container.NewMax(addrDispBg, container.NewPadded(addrDisplay))

		copyAddrInlineBtn := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
			myApp.Clipboard().SetContent(walletAddress)
			dialog.ShowInformation("Copied", "Address copied to clipboard", window)
		})
		copyAddrInlineBtn.Importance = widget.LowImportance

		addrRow := container.NewBorder(nil, nil, nil, copyAddrInlineBtn, addrContainer)

		// ── Right info panel ──────────────────────────────────────
		makeStatMini := func(label, value string, col color.Color) fyne.CanvasObject {
			lbl := canvas.NewText(strings.ToUpper(label), colFaint)
			lbl.TextSize = 9
			lbl.TextStyle = fyne.TextStyle{Monospace: true}
			val := canvas.NewText(value, col)
			val.TextSize = 14
			val.TextStyle = fyne.TextStyle{Bold: true}
			inner := container.NewVBox(lbl, spacer(2), val)
			return styledCard(inner, 0, 52)
		}

		statsGrid := container.NewGridWithColumns(2,
			makeStatMini("Network", chainHeader.ChainName, colAccent),
			makeStatMini("Symbol", chainHeader.Symbol, colAccent),
			makeStatMini("Chain ID", fmt.Sprintf("%d", chainHeader.ChainID), colText),
			makeStatMini("Address", addrShort[:16]+"…", colAccent),
		)

		panel := container.NewVBox(
			infoPanel("Network & Identity Details", []fyne.CanvasObject{
				infoRow("Network", chainHeader.ChainName, colAccent),
				infoRow("Symbol", chainHeader.Symbol, colAccent),
				infoRow("Chain ID", fmt.Sprintf("%d", chainHeader.ChainID), colText),
				infoRow("System", orgDisplayName, colAccent),
				infoRow("Description", orgDescription, colText),
				infoRow("Identity Scheme", "USI / SPHINCS+", colText),
				infoRow("Org Code", activeOrgCode, colAccent),
			}),
			spacer(12),
			sectionLabel("Statistics"),
			spacer(8),
			statsGrid,
			spacer(12),
			alertBox(fmt.Sprintf("Send and receive %s on the %s network.",
				chainHeader.Symbol, chainHeader.ChainName),
				color.RGBA{74, 222, 158, 15}, colAccent),
			spacer(8),
			alertBox("Keep your passphrase safe — it authorises every signature and transaction.",
				color.RGBA{255, 179, 71, 20}, colWarn),
		)

		// ── Main form ─────────────────────────────────────────────
		form := container.NewVBox(
			screenTitle(fmt.Sprintf("%s Wallet", chainHeader.Symbol)),
			spacer(4),
			screenSubtitle(fmt.Sprintf("%s identity — %s network", orgDisplayName, chainHeader.ChainName)),
			spacer(20),
			balCard,
			spacer(16),
			hRule(),
			spacer(12),
			sectionLabel("Address"),
			spacer(6),
			addrRow,
			spacer(16),
			hRule(),
			spacer(12),
			actionRow,
			spacer(20),
			hRule(),
			spacer(12),
			sectionLabel("Transaction History"),
			spacer(8),
			txCard,
			spacer(24),
		)

		setScreen(opLayout(form, panel))
	}

	// =========================================================================
	// REGISTER SCREEN (no sidebar)
	// =========================================================================
	showRegisterScreen = func() {
		log.Println("Displaying register screen")
		updateLayout(false)

		header := canvas.NewText("Create Your Secure Account", theme.PrimaryColor())
		header.TextSize = 26
		header.TextStyle = fyne.TextStyle{Bold: true}
		header.Alignment = fyne.TextAlignCenter

		instruction := widget.NewLabel(fmt.Sprintf("Create your master keys for %s on %s.", chainHeader.Symbol, chainHeader.ChainName))
		instruction.Alignment = fyne.TextAlignCenter

		orgDisplay := widget.NewLabelWithStyle("Organization: SPIF", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
		orgDesc := widget.NewLabelWithStyle("Sphinx Fingerprint - Identity Defense System", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})

		orgContainer := container.NewVBox(
			orgDisplay,
			orgDesc,
		)

		progLabel := widget.NewLabel("")
		progLabel.Alignment = fyne.TextAlignCenter
		progBar := widget.NewProgressBar()
		progBar.Hide()
		progLabel.Hide()

		var generateBtn *widget.Button

		generateBtn = widget.NewButtonWithIcon("Setup Master Key", theme.ViewRefreshIcon(), func() {
			log.Println("Starting key generation process")

			generateBtn.Disable()
			generateBtn.SetText("Generating Keys…")

			progLabel.SetText("Generating secure key pair…")
			progLabel.Show()
			progBar.Show()
			progBar.SetValue(0.2)

			chosenOrg := keys.OrgCode("SPIF")

			go func() {
				passphrase, _, _, _, _, _, err := seed.GenerateKeys()
				if err != nil {
					fyne.Do(func() {
						dialog.ShowError(fmt.Errorf("failed to generate passphrase: %w", err), window)
						progBar.Hide()
						progLabel.Hide()
						generateBtn.Enable()
						generateBtn.SetText("Setup Master Key")
					})
					return
				}

				if len(passphrase) < 8 {
					fyne.Do(func() {
						dialog.ShowError(fmt.Errorf("generated passphrase is too short (%d chars), need at least 8", len(passphrase)), window)
						progBar.Hide()
						progLabel.Hide()
						generateBtn.Enable()
						generateBtn.SetText("Setup Master Key")
					})
					return
				}

				fyne.Do(func() { progBar.SetValue(0.6) })

				kp, err := keys.GenerateKeyPairWithOrg(passphrase, chosenOrg)
				if err != nil {
					fyne.Do(func() {
						dialog.ShowError(err, window)
						progBar.Hide()
						progLabel.Hide()
						generateBtn.Enable()
						generateBtn.SetText("Setup Master Key")
					})
					return
				}

				// publishRegistrarPublicBundle requires the key server.
				// If it is offline (e.g. localhost:8080 not running) we log
				// warning and continue — the local key pair was already written
				// to disk successfully. The bundle can be re-published later.
				publishErr := publishRegistrarPublicBundle(passphrase, "Registrar", string(chosenOrg))
				if publishErr != nil {
					log.Printf("[WARN] Register: key server unavailable, continuing offline: %v", publishErr)
				}

				fyne.Do(func() {
					progBar.SetValue(1.0)
					progLabel.SetText("Key pair generated!")

					publicFingerprint = keys.GetPublicKeyFingerprint(kp)
					rawFingerprint := pubkeydir.Fingerprint(kp.PublicKey)

					sessionRawFingerprint = rawFingerprint
					sessionPassphrase = passphrase
					sessionFingerprint = publicFingerprint
					sessionOrgCode = string(chosenOrg)

					addActivity(fmt.Sprintf("New user registered — keys created for %s on %s", chainHeader.Symbol, chainHeader.ChainName))

					passBox := bashBox(passphrase, passphrase)
					fingerBox := bashBox(publicFingerprint, publicFingerprint)

					warnIcon := canvas.NewImageFromResource(theme.WarningIcon())
					warnIcon.FillMode = canvas.ImageFillContain
					warnIcon.SetMinSize(fyne.NewSize(24, 24))

					warnText := canvas.NewText(
						"IMPORTANT: If you forget this passphrase, your keys are permanently lost.",
						colDanger,
					)
					warnText.TextStyle = fyne.TextStyle{Bold: true}
					warnText.Alignment = fyne.TextAlignLeading
					warnText.TextSize = 13

					warningRow := container.NewHBox(layout.NewSpacer(), warnIcon, smallSpacer(4), container.NewMax(warnText), layout.NewSpacer())

					resultBox := container.NewVBox(
						widget.NewLabelWithStyle("Passphrase:", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
						smallSpacer(4),
						warningRow,
						smallSpacer(4),
						passBox,
						smallSpacer(12),
						widget.NewLabelWithStyle("Fingerprint:", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
						smallSpacer(4),
						fingerBox,
						smallSpacer(12),
						widget.NewLabelWithStyle(fmt.Sprintf("Network: %s", chainHeader.ChainName), fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
						widget.NewLabelWithStyle(fmt.Sprintf("Token: %s", chainHeader.Symbol), fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
						widget.NewLabelWithStyle("Organization: SPIF", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
					)

					// If the key server was offline, append a soft notice inside
					// the success dialog — registration still succeeded locally.
					dlgHeight := float32(580)
					if publishErr != nil {
						offlineNote := widget.NewLabel(
							"WARNING  Key server offline — bundle not published. Start the server and re-login to sync.",
						)
						offlineNote.Wrapping = fyne.TextWrapWord
						offlineNote.TextStyle = fyne.TextStyle{Italic: true}
						resultBox.Add(smallSpacer(8))
						resultBox.Add(container.NewPadded(offlineNote))
						dlgHeight = 640
					}

					customDlg := dialog.NewCustomWithoutButtons("Registration Complete", resultBox, window)
					customDlg.Resize(fyne.NewSize(560, dlgHeight))

					doneBtn := widget.NewButtonWithIcon("Continue to USI Vault", theme.LoginIcon(), func() {
						customDlg.Hide()
						showDashboardScreen()
					})
					doneBtn.Importance = widget.HighImportance
					resultBox.Add(container.NewCenter(doneBtn))
					customDlg.Show()

					time.AfterFunc(1*time.Second, func() {
						fyne.Do(func() { progBar.Hide(); progLabel.Hide() })
					})
				})
			}()
		})
		generateBtn.Importance = widget.HighImportance

		backBtn := widget.NewButtonWithIcon("Back", theme.NavigateBackIcon(), showWelcomeScreen)

		buttonWidth := float32(300)
		buttonHeight := float32(40)

		content := container.NewVBox(
			header,
			smallSpacer(12),
			instruction,
			smallSpacer(12),
			orgContainer,
			smallSpacer(12),
			container.NewHBox(layout.NewSpacer(), container.NewGridWrap(fyne.NewSize(buttonWidth, buttonHeight), generateBtn), layout.NewSpacer()),
			smallSpacer(8),
			container.NewHBox(layout.NewSpacer(), container.NewGridWrap(fyne.NewSize(buttonWidth, buttonHeight), backBtn), layout.NewSpacer()),
			smallSpacer(20),
			container.NewCenter(themeToggle),
		)

		mainContentContainer.Objects = []fyne.CanvasObject{container.NewCenter(content)}
		mainContentContainer.Refresh()
	}

	// =========================================================================
	// WELCOME SCREEN
	// =========================================================================
	showWelcomeScreen = func() {
		log.Println("Displaying welcome screen")
		updateLayout(false)

		title := canvas.NewText(fmt.Sprintf("%s Software", chainHeader.Symbol), theme.PrimaryColor())
		title.TextSize = 32
		title.TextStyle = fyne.TextStyle{Bold: true}
		title.Alignment = fyne.TextAlignCenter

		subtitle := widget.NewLabel(fmt.Sprintf("Universal Sovereign Identity - %s Identity System", chainHeader.ChainName))
		subtitle.Alignment = fyne.TextAlignCenter
		subtitle.Wrapping = fyne.TextWrapWord

		registerBtn := widget.NewButtonWithIcon("Register", theme.LoginIcon(), showRegisterScreen)
		registerBtn.Importance = widget.HighImportance

		loginBtn := widget.NewButtonWithIcon("Login using Passphrase", theme.AccountIcon(), func() {
			if isRegistered() {
				passEntry := widget.NewPasswordEntry()
				passEntry.SetPlaceHolder("Enter your passphrase")
				passEntry.Validator = func(s string) error {
					if len(s) < 8 {
						return errors.New("minimum 8 characters")
					}
					return nil
				}

				d := dialog.NewForm("Load Fingerprint", "Continue", "Cancel",
					[]*widget.FormItem{{Text: "Your Passphrase", Widget: passEntry}},
					func(ok bool) {
						if !ok {
							publicFingerprint = ""
							showWelcomeScreen()
							return
						}
						if err := passEntry.Validate(); err != nil {
							dialog.ShowError(err, window)
							return
						}
						kp, _, err := keys.LoadKeyFromDisk(passEntry.Text)
						if err != nil {
							errorMsg := "Failed to load key pair: " + err.Error()
							if strings.Contains(err.Error(), "decryption") || strings.Contains(err.Error(), "passphrase") {
								errorMsg = "Wrong passphrase. Please try again."
							}
							dialog.ShowError(errors.New(errorMsg), window)
							publicFingerprint = ""
							sessionRawFingerprint = ""
							showWelcomeScreen()
							return
						}
						publicFingerprint = keys.GetPublicKeyFingerprint(kp)
						sessionRawFingerprint = pubkeydir.Fingerprint(kp.PublicKey)
						sessionPassphrase = passEntry.Text
						sessionFingerprint = publicFingerprint
						sessionOrgCode = loadOrgCodeFromBundle(kp.PublicKey)
						if sessionOrgCode == "" {
							sessionOrgCode = "SPIF"
						}
						addActivity(fmt.Sprintf("User logged in — Fingerprint: %s…", publicFingerprint[:16]))
						showDashboardScreen()
					}, window)
				d.Resize(fyne.NewSize(420, 220))
				d.Show()
			} else {
				dialog.ShowInformation("Not Registered", "No key pair found. Please register first.", window)
			}
		})
		loginBtn.Importance = widget.MediumImportance

		buttonWidth := float32(300)
		buttonHeight := float32(40)

		content := container.NewVBox(
			title,
			smallSpacer(12),
			subtitle,
			smallSpacer(12),
			container.NewHBox(layout.NewSpacer(), container.NewGridWrap(fyne.NewSize(buttonWidth, buttonHeight), registerBtn), layout.NewSpacer()),
			smallSpacer(8),
			container.NewHBox(layout.NewSpacer(), container.NewGridWrap(fyne.NewSize(buttonWidth, buttonHeight), loginBtn), layout.NewSpacer()),
			smallSpacer(20),
			container.NewCenter(themeToggle),
		)

		mainContentContainer.Objects = []fyne.CanvasObject{container.NewCenter(content)}
		mainContentContainer.Refresh()
	}

	// =========================================================================
	// SIDEBAR
	// =========================================================================
	createSidebar := func() fyne.CanvasObject {
		sidebarBg := canvas.NewRectangle(colSurface)

		appName := canvas.NewText(fmt.Sprintf("%s", chainHeader.Symbol), colAccent)
		appName.TextSize = 18
		appName.TextStyle = fyne.TextStyle{Bold: true}
		appVersion := canvas.NewText(fmt.Sprintf("v2.0 · %s · %s", chainHeader.ChainName, chainHeader.Symbol), colFaint)
		appVersion.TextSize = 10
		appVersion.TextStyle = fyne.TextStyle{Monospace: true}

		headerBlock := container.NewVBox(
			container.NewCenter(appName),
			container.NewCenter(appVersion),
		)
		headerBg := canvas.NewRectangle(colSurface2)
		headerBg.CornerRadius = 10
		headerBg.StrokeColor = colBorder
		headerBg.StrokeWidth = 1
		styledHeader := container.NewMax(headerBg, container.NewPadded(headerBlock))

		navSection := func(text string) fyne.CanvasObject {
			t := canvas.NewText(strings.ToUpper(text), colFaint)
			t.TextSize = 9
			t.TextStyle = fyne.TextStyle{Monospace: true}
			return container.NewPadded(t)
		}

		navBtn := func(label string, icon fyne.Resource, fn func()) *widget.Button {
			b := widget.NewButtonWithIcon(label, icon, fn)
			b.Importance = widget.MediumImportance
			b.Alignment = widget.ButtonAlignLeading
			return b
		}

		dashBtn := navBtn("Dashboard", theme.HomeIcon(), showDashboardScreen)
		encBtn := navBtn("Message", theme.UploadIcon(), showEncryptScreen)
		decBtn := navBtn("Inbox", theme.DownloadIcon(), showDecryptScreen)
		signBtn := navBtn("Mint Data", theme.DocumentCreateIcon(), showSignScreen)
		verBtn := navBtn("Verify Data", theme.ConfirmIcon(), showVerifyScreen)
		walletBtn := navBtn(fmt.Sprintf("%s Wallet", chainHeader.Symbol), theme.StorageIcon(), showWalletScreen)
		keysBtn := navBtn("My Keys", theme.InfoIcon(), showKeysScreen)

		logoutBtn := widget.NewButtonWithIcon("Sign Out", theme.LogoutIcon(), func() {
			dialog.ShowConfirm("Sign out", "End your session? Your keys remain on disk.", func(ok bool) {
				if ok {
					addActivity("User signed out")
					publicFingerprint = ""
					sessionRawFingerprint = ""
					sessionPassphrase = ""
					sessionFingerprint = ""
					sessionOrgCode = ""
					showWelcomeScreen()
				}
			}, window)
		})
		logoutBtn.Importance = widget.DangerImportance
		logoutBtn.Alignment = widget.ButtonAlignLeading

		fpShort := "—"
		if len(publicFingerprint) > 16 {
			fpShort = publicFingerprint[:8] + "…" + publicFingerprint[len(publicFingerprint)-8:]
		}
		fpPillText := canvas.NewText(fpShort, colAccent)
		fpPillText.TextSize = 10
		fpPillText.TextStyle = fyne.TextStyle{Monospace: true}

		dotColor := colAccent
		if sessionPassphrase == "" {
			dotColor = colDanger
		}
		statusDot := canvas.NewRectangle(dotColor)
		statusDot.CornerRadius = 4
		statusDot.SetMinSize(fyne.NewSize(7, 7))

		fpPillBg := canvas.NewRectangle(colSurface2)
		fpPillBg.CornerRadius = 8
		fpPillBg.StrokeColor = colBorder
		fpPillBg.StrokeWidth = 1
		fpPill := container.NewMax(fpPillBg, container.NewPadded(
			container.NewHBox(statusDot, spacer(4), fpPillText),
		))

		menu := container.NewVBox(
			container.NewPadded(styledHeader),
			spacer(8),
			navSection("Workspace"),
			dashBtn,
			spacer(4),
			navSection("Operations"),
			encBtn,
			decBtn,
			signBtn,
			verBtn,
			spacer(4),
			navSection("Finance"),
			walletBtn,
			spacer(4),
			navSection("Identity"),
			keysBtn,
			layout.NewSpacer(),
			widget.NewSeparator(),
			spacer(4),
			container.NewPadded(fpPill),
			spacer(4),
			logoutBtn,
			spacer(4),
		)

		return container.NewMax(sidebarBg, menu)
	}

	// =========================================================================
	// BOOTSTRAP
	// =========================================================================
	sidebar = createSidebar()
	mainContentContainer = container.NewMax()

	if isRegistered() {
		log.Println("[INFO] Bootstrap: key found in storage, prompting for passphrase")
		passEntry := widget.NewPasswordEntry()
		passEntry.SetPlaceHolder("Enter your passphrase")
		passEntry.Validator = func(s string) error {
			if len(s) < 8 {
				return errors.New("minimum 8 characters")
			}
			return nil
		}

		d := dialog.NewForm("Load Fingerprint", "Continue", "Cancel",
			[]*widget.FormItem{{Text: "Your Passphrase", Widget: passEntry}},
			func(ok bool) {
				if !ok {
					publicFingerprint = ""
					showWelcomeScreen()
					return
				}
				if err := passEntry.Validate(); err != nil {
					dialog.ShowError(err, window)
					return
				}
				kp, _, err := keys.LoadKeyFromDisk(passEntry.Text)
				if err != nil {
					errorMsg := "Failed to load key pair: " + err.Error()
					if strings.Contains(err.Error(), "decryption") || strings.Contains(err.Error(), "passphrase") {
						errorMsg = "Wrong passphrase. Please try again."
					}
					dialog.ShowError(errors.New(errorMsg), window)
					publicFingerprint = ""
					sessionRawFingerprint = ""
					showWelcomeScreen()
					return
				}
				publicFingerprint = keys.GetPublicKeyFingerprint(kp)
				sessionRawFingerprint = pubkeydir.Fingerprint(kp.PublicKey)
				sessionPassphrase = passEntry.Text
				sessionFingerprint = publicFingerprint
				sessionOrgCode = loadOrgCodeFromBundle(kp.PublicKey)
				if sessionOrgCode == "" {
					sessionOrgCode = "SPIF"
				}
				addActivity(fmt.Sprintf("User logged in — Fingerprint: %s…", publicFingerprint[:16]))
				showDashboardScreen()
			}, window)
		d.Resize(fyne.NewSize(420, 220))
		d.Show()
	} else {
		log.Println("[INFO] Bootstrap: no key found, showing welcome screen")
		publicFingerprint = ""
		showWelcomeScreen()
	}

	window.ShowAndRun()
}
