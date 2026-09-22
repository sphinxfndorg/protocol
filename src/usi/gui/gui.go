// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/usi/gui/gui.go
package gui

import (
	"context"
	"errors"
	"fmt"
	"image/color"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	seed "github.com/sphinxfndorg/protocol/src/accounts/phrase"
	"github.com/sphinxfndorg/protocol/src/core"
	vault "github.com/sphinxfndorg/protocol/src/core/wallet/vault"
	"github.com/sphinxfndorg/protocol/src/policy"
	"github.com/sphinxfndorg/protocol/src/storage"
	keys "github.com/sphinxfndorg/protocol/src/usi/core/key"
	"github.com/sphinxfndorg/protocol/src/usi/core/sign"
	usimail "github.com/sphinxfndorg/protocol/src/usi/mail"
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

	// Startup beacon: one line identifying the build, one line stating the gas
	// denomination the fee panel renders. Both are printed BEFORE any key load
	// or RPC call, so "the GUI shows 0 SPX/gas" can be diagnosed from the
	// terminal alone (stale binary vs. wrong unit).
	log.Printf("[USI-GUI] %s", buildBeaconLine())
	log.Printf("[USI-GUI] %s", gasUnitBeaconLine())

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
		showDashboardScreen   func()
		showEncryptScreen     func()
		showDecryptScreen     func()
		showSignScreen        func()
		showVerifyScreen      func()
		showKeysScreen        func()
		showWalletScreen      func()
		showRegisterScreen    func()
		showWelcomeScreen     func()
		showSendScreen        func()
		showReceiveScreen     func()
		showMarketplaceScreen func()
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

		// makeStatCardDynamic is the same visual as makeStatCard but also
		// hands back the value *canvas.Text so callers can update it in
		// place once an async fetch (e.g. wallet balance) resolves,
		// without rebuilding the whole stats row.
		makeStatCardDynamic := func(icon, labelText, valueText string, valueCol color.Color, subText string) (fyne.CanvasObject, *canvas.Text) {
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
			return styledCard(inner, 0, 110), valueT
		}

		balanceCard, balanceValueText := makeStatCardDynamic("◆", fmt.Sprintf("%s Balance", chainHeader.Symbol), "···", colAccent, "wallet balance")

		statsRow := container.NewGridWithColumns(4,
			balanceCard,
			makeStatCard("", "Total Vaults", vaultCount, colText, "encrypted folders"),
			makeStatCard("✍", "Signed Docs", signedCount, colText, "with valid signatures"),
			makeStatCard("🕐", "Last Activity", lastActivity, colWarn, "most recent operation"),
		)

		// Fetch balance asynchronously so the dashboard renders immediately
		// and the card fills in once the node responds — same pattern the
		// Wallet screen already uses for its hero balance card.
		go func() {
			resp, err := walletClient.GetBalance("")
			fyne.Do(func() {
				if err != nil || resp == nil || resp.Balance.Int == nil {
					balanceValueText.Text = "—"
					balanceValueText.Color = colMuted
					balanceValueText.Refresh()
					return
				}
				balanceSPX := new(big.Float).Quo(
					new(big.Float).SetInt(resp.Balance.Int),
					big.NewFloat(1e18),
				)
				balanceValueText.Text = formatSPXAmount(balanceSPX)
				balanceValueText.Color = colAccent
				balanceValueText.Refresh()
			})
		}()

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

		// Copy button for the fingerprint — the dashboard is the first place
		// a user sees their identity, but until now only the Receive screen
		// let them copy it. Same icon/action as copyAddrBtn on Receive.
		fpCopyBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
			myApp.Clipboard().SetContent(publicFingerprint)
			dialog.ShowInformation("Copied", "Fingerprint copied to clipboard", window)
		})
		fpCopyBtn.Importance = widget.LowImportance
		fpContainer := container.NewMax(fpBg, container.NewBorder(nil, nil, nil, fpCopyBtn, container.NewPadded(fpLabel)))

		// Live network-sync value — mirrors the "CHAIN TIP · HEADER SYNC"
		// readout already used on the Wallet screen, so the dashboard shows
		// at a glance whether this lightweight client is actually talking
		// to a node, not just displaying the static chain descriptor.
		syncValue := canvas.NewText("Checking…", colMuted)
		syncValue.TextSize = 11
		syncValue.TextStyle = fyne.TextStyle{Monospace: true}
		go func() {
			hdr, err := walletClient.GetChainTipHeader()
			fyne.Do(func() {
				if err != nil || hdr == nil {
					syncValue.Text = "Offline"
					syncValue.Color = colDanger
					syncValue.Refresh()
					return
				}
				syncValue.Text = fmt.Sprintf("Synced · height %d", hdr.Height)
				syncValue.Color = colAccent
				syncValue.Refresh()
			})
		}()

		keyInfoRows := []fyne.CanvasObject{
			infoRow("Network", chainHeader.ChainName, colAccent),
			infoRow("Symbol", chainHeader.Symbol, colAccent),
			infoRow("Chain ID", fmt.Sprintf("%d", chainHeader.ChainID), colText),
			infoRow("Status", keyStatus, keyStatusCol),
			infoRowDynamic("Sync", syncValue),
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
			activityBox.Add(spacer(8))
			// Give first-time users a next step instead of a dead end —
			// jumps straight to Mint Data (Sign), the most common first
			// action, using the same nav target the sidebar's "Mint Data"
			// button already points to.
			firstActionBtn := widget.NewButtonWithIcon("Sign your first document", theme.DocumentCreateIcon(), func() {
				showSignScreen()
			})
			firstActionBtn.Importance = widget.LowImportance
			activityBox.Add(container.NewCenter(firstActionBtn))
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
				// ★ FIX: activity strings routinely embed full tx hashes,
				// CIDs, or anchor ids (e.g. "Signed & minted NFT: file.pdf
				// (tx=<64 chars>, cid=<64 chars>, ...)"). canvas.Text never
				// wraps, so one long entry here was enough to force the
				// whole dashboard — and window — wider. This only clips the
				// on-screen row; the full string stays in activityList
				// untouched (used elsewhere, e.g. the "Last Activity" stat
				// card's timestamp parsing above).
				activityDisplay := activity
				const maxActivityChars = 90
				if len(activityDisplay) > maxActivityChars {
					activityDisplay = activityDisplay[:maxActivityChars] + "…"
				}
				actT := canvas.NewText(activityDisplay, colText)
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
			showErrorDialog(errors.New("please login first"), window)
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

		// ── Transfer priority ─────────────────────────────────────
		// Tiers are gas-price multipliers on the policy minimum (see
		// TransferPriority in rpc.go): Standard 1x (cheapest), Medium 2x
		// (balanced), High 5x (faster under congestion — deliberately not
		// "fastest", a static multiplier cannot outbid a mempool it never
		// observes), Custom (user multiplier, validated >= 1x).
		prioritySelected := PriorityStandard.Label()
		customMult := uint64(1)
		feePreview := canvas.NewText("", colFaint)
		feePreview.TextSize = 11
		feePreview.TextStyle = fyne.TextStyle{Monospace: true}

		customEntry := widget.NewEntry()
		customEntry.SetPlaceHolder("Multiplier, e.g. 3 = 3x (min 1x)")
		customEntry.Hide()

		// quoteForPreview is the single fee-math path for the preview line,
		// the confirm dialog, and the broadcast — all three read the same
		// selector state, so preview and paid fee can never diverge.
		quoteForPreview := func() (*policy.GasQuote, TransferPriority, uint64, string) {
			priority := priorityFromLabel(prioritySelected)
			mult := customMult
			if priority == PriorityCustom {
				if parsed, perr := strconv.ParseUint(strings.TrimSpace(customEntry.Text), 10, 64); perr == nil && parsed >= 1 {
					mult = parsed
				} else {
					mult = customMult
				}
			}
			return QuoteTransferGas(len(memoEntry.Text), priority, mult), priority, mult, priorityTierLabel(priority, mult)
		}

		updateFeePreview := func() {
			quote, priority, mult, tierLabel := quoteForPreview()
			feeSPX := new(big.Float).Quo(new(big.Float).SetInt(quote.GasFee), big.NewFloat(1e18))
			// Gas price is quoted in gSPX, NOT SPX (the policy minimum is
			// 1 gSPX = 10^-9 SPX). Rendering it as SPX rounded every tier to
			// a flat "0" — see formatGasPriceAmount in theme.go.
			feePreview.Text = fmt.Sprintf("Fee: %s %s · %s · %d gas @ %s %s",
				formatSPXAmount(feeSPX), chainHeader.Symbol, tierLabel, quote.GasLimit.Uint64(), formatGasPriceAmount(quote.GasPrice), gasPriceUnitLabel)
			feePreview.Color = colMuted
			if priority == PriorityCustom {
				if warn, werr := ValidateCustomMultiplier(mult); werr != nil {
					feePreview.Text = "Custom multiplier must be at least 1x"
					feePreview.Color = colDanger
				} else if warn {
					feePreview.Text += "  ⚠ unusually high (>100x) — double-check before sending"
					feePreview.Color = colWarn
				}
			}
			feePreview.Refresh()
		}

		prioritySelect := widget.NewSelect(transferPriorityOptions, func(sel string) {
			prioritySelected = sel
			if priorityFromLabel(sel) == PriorityCustom {
				customEntry.Show()
			} else {
				customEntry.Hide()
			}
			updateFeePreview()
		})
		prioritySelect.SetSelected(prioritySelected)
		memoEntry.OnChanged = func(string) { updateFeePreview() }
		customEntry.OnChanged = func(string) { updateFeePreview() }
		updateFeePreview()

		sendBtn := widget.NewButtonWithIcon(fmt.Sprintf("Send %s", chainHeader.Symbol), theme.MailSendIcon(), func() {
			if recipientEntry.Text == "" {
				showErrorDialog(errors.New("please enter a recipient address"), window)
				return
			}
			if amountEntry.Text == "" {
				showErrorDialog(errors.New("please enter an amount"), window)
				return
			}

			// SetPrec(256) before SetString: the default big.Float precision
			// (0, which SetString bumps to just 64 bits) is only good for
			// integers up to ~1.8e19 with no fractional part. SPX amounts
			// can be both large (millions of SPX) and carry up to 18
			// decimal places at once, so we ask for headroom explicitly
			// rather than silently losing low-order digits.
			amount := new(big.Float).SetPrec(256)
			_, ok := amount.SetString(amountEntry.Text)
			if !ok || amount.Cmp(big.NewFloat(0)) <= 0 {
				showErrorDialog(errors.New("invalid amount"), window)
				return
			}

			// Convert to nSPX (1 SPX = 10^18 nSPX) using big.Float/big.Int
			// arithmetic throughout.
			//
			// ★ FIX: the previous conversion routed through float64 and
			// int64(...) — `amountNSPX.SetInt64(int64(amountFloat * 1e18))`
			// — which silently overflows for any amount whose nSPX
			// equivalent exceeds int64's ~9.223e18 ceiling, i.e. any send
			// above ~9.22 SPX. Converting an out-of-range float to int64 in
			// Go is implementation-defined (in practice it wraps/clamps to
			// garbage), so a wallet with a typical multi-million-SPX
			// balance could never send correctly: the signed transaction
			// would carry a wildly wrong amount while the confirmation
			// dialog above it (which formats `amount`, a big.Float,
			// directly) kept showing the correct one — the two silently
			// diverged only past the overflow threshold.
			multiplier := new(big.Float).SetPrec(256).SetInt(big.NewInt(1e18))
			scaledNSPX := new(big.Float).SetPrec(256).Mul(amount, multiplier)
			amountNSPX, _ := scaledNSPX.Int(nil)
			if amountNSPX == nil || amountNSPX.Sign() <= 0 {
				showErrorDialog(errors.New("invalid amount"), window)
				return
			}

			// proceedWithSend runs everything after the >100x gate: fee
			// resolution, confirm message, passphrase dialog, status dialog.
			// It is a plain closure invoked either directly (normal path) or
			// from inside the ShowConfirm callback (warn path) — never across
			// a channel, so the UI goroutine is never blocked waiting for a
			// callback that itself needs the UI goroutine to fire.
			proceedWithSend := func(quote *policy.GasQuote, tierLabel string) {
				gasFeeNSPX := quote.GasFee
				gasLimit := quote.GasLimit.Uint64()
				gasPrice := quote.GasPrice
				feeSPX := new(big.Float).Quo(new(big.Float).SetInt(gasFeeNSPX), big.NewFloat(1e18))
				priorityPrice := new(big.Int).Set(gasPrice)
				confirmMsg := fmt.Sprintf("Send %s %s to:\n%s\n\nMemo: %s\n\nPriority: %s\nTransaction Fee: %s %s (gas limit: %d, gas price: %s %s)",
					formatSPXAmount(amount), chainHeader.Symbol, recipientEntry.Text, memoEntry.Text, tierLabel,
					formatSPXAmount(feeSPX), chainHeader.Symbol, gasLimit, formatGasPriceAmount(gasPrice), gasPriceUnitLabel)

				validatePassphraseDialog(window, "Confirm Transaction", confirmMsg,
					func(passphrase string) {
						// Show transfer status popup with live block confirmation tracking
						showTransferStatusDialog(window, walletClient, chainHeader, formatSPXAmount(amount), recipientEntry.Text, memoEntry.Text, passphrase, amountNSPX, gasFeeNSPX, gasLimit, gasPrice, tierLabel, priorityPrice)

						recipientEntry.SetText("")
						amountEntry.SetText("")
						memoEntry.SetText("")
					})
			}

			// Resolve the tier at send time from the live selector state (same
			// path as the preview), then clamp: <1x is rejected, >100x warns
			// but proceeds.
			quote, priority, mult, tierLabel := quoteForPreview()
			if priority == PriorityCustom {
				if warn, werr := ValidateCustomMultiplier(mult); werr != nil {
					showErrorDialog(werr, window)
					return
				} else if warn {
					// Async gate — no channel, no wait. Fyne invokes this
					// callback on the UI goroutine, so blocking the tapped
					// handler here until the user answers would deadlock:
					// the goroutine that must fire the callback is the same
					// one parked on the receive. Instead the handler returns
					// immediately after posting the dialog, and the "send
					// anyway" path continues inside the callback. Cancel is
					// a no-op.
					dialog.ShowConfirm("Unusually high fee",
						fmt.Sprintf("Custom multiplier %dx is unusually high (>100x). The fee will be %s %s. Send anyway?",
							mult, formatSPXAmount(new(big.Float).Quo(new(big.Float).SetInt(quote.GasFee), big.NewFloat(1e18))), chainHeader.Symbol),
						func(ok bool) {
							if !ok {
								return
							}
							proceedWithSend(quote, tierLabel)
						}, window)
					return
				}
			}
			proceedWithSend(quote, tierLabel)
		})
		sendBtn.Importance = widget.HighImportance

		clearBtn := widget.NewButtonWithIcon("Clear", theme.CancelIcon(), func() {
			recipientEntry.SetText("")
			amountEntry.SetText("")
			memoEntry.SetText("")
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
			spacer(16),
			sectionLabel("Transfer Speed"),
			spacer(6),
			prioritySelect,
			spacer(6),
			customEntry,
			spacer(4),
			feePreview,
			spacer(16),
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
			showErrorDialog(errors.New("please login first"), window)
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
						showErrorDialog(errors.New("select a regular folder, not a .vault file"), window)
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

		peerEntry := widget.NewEntry()
		peerEntry.SetPlaceHolder("Optional recipient peer, e.g. 192.0.2.10:2525")

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
				showErrorDialog(errors.New("please select a folder first"), window)
				return
			}
			if sessionPassphrase == "" {
				showErrorDialog(errors.New("not logged in — please log in again"), window)
				return
			}

			validatePassphraseDialog(window, "Confirm Passphrase", "Enter your passphrase to encrypt this folder:", func(passphrase string) {
				var recipients []string
				var recipientPubs []*vault.HybridPublicKey

				if recipientEntry.Text != "" {
					recipients = keys.ParseFingerprints(recipientEntry.Text)
					normalizedRecipients, err := vault.ValidateAndNormalizeRecipients(recipients)
					if err != nil {
						showErrorDialog(fmt.Errorf("invalid recipient fingerprints: %w", err), window)
						return
					}
					recipients = normalizedRecipients

					store := getKeyStore()
					if store == nil {
						showErrorDialog(fmt.Errorf("failed to connect to key directory"), window)
						return
					}

					recipientPubs, err = vault.ResolveMultipleRecipients(store, recipients)
					if err != nil {
						showErrorDialog(fmt.Errorf("failed to resolve recipients: %w\n\nMake sure they have registered", err), window)
						return
					}
					defer store.Close()
				}

				embeddedMessage := messageEntry.Text
				peerAddress := strings.TrimSpace(peerEntry.Text)
				var messageFilePath string
				if embeddedMessage != "" {
					messageFilePath = filepath.Join(selectedFolder, ".encrypted_message.txt")
					if err := os.WriteFile(messageFilePath, []byte(embeddedMessage), 0600); err != nil {
						showErrorDialog(fmt.Errorf("failed to create message file: %w", err), window)
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
					var deliveryErr error
					if err == nil && peerAddress != "" {
						if len(recipients) != 1 {
							deliveryErr = errors.New("peer delivery requires exactly one recipient fingerprint")
						} else {
							_, deliveryErr = usimail.SendVault(context.Background(), peerAddress, sessionRawFingerprint, recipients[0], selectedFolder+".vault")
						}
					}

					fyne.Do(func() {
						progDlg.Hide()
						if err != nil {
							showErrorDialog(err, window)
							return
						}
						if deliveryErr != nil {
							addActivity(fmt.Sprintf("Encrypted but not delivered: %s", filepath.Base(selectedFolder)))
							showErrorDialog(fmt.Errorf("vault was encrypted, but peer delivery failed: %w", deliveryErr), window)
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
						if peerAddress != "" {
							addActivity(fmt.Sprintf("Delivered encrypted vault to %s", peerAddress))
						}
						selectedFolder = ""
						resetDropZone()
						recipientEntry.SetText("")
						peerEntry.SetText("")
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
			peerEntry.SetText("")
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
			spacer(12),
			alertBox("Peer delivery sends the encrypted .vault unchanged. Run a USI mail peer on the recipient first.", color.RGBA{96, 165, 250, 20}, colInfo),
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
			sectionLabel("Recipient Peer (optional)"),
			spacer(6),
			peerEntry,
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
						showErrorDialog(errors.New("please select a .vault file"), window)
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
				showErrorDialog(errors.New("please select a .vault file"), window)
				return
			}
			if sessionPassphrase == "" {
				showErrorDialog(errors.New("not logged in — please log in again"), window)
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
							showErrorDialog(err, window)
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

		// Mint Data is a paid, gated operation: the wallet must hold the
		// policy minimum balance (100 SPX) and each mint charges the policy
		// mint fee on-chain. Pull the values once from the governance policy so
		// the UI always reflects what the node will enforce.
		mintPolicy := policy.GetDefaultPolicyParams()

		var selectedFile string
		var selectedFileSize uint64
		// NFT metadata fields (ERC-721 compatible) - declared early because the
		// IPFS metadata upload below (before the sign action) reads their text.
		nftNameEntry := widget.NewEntry()
		nftNameEntry.SetPlaceHolder("NFT name (e.g. My Digital Artwork)")

		nftDescriptionEntry := widget.NewMultiLineEntry()
		nftDescriptionEntry.SetPlaceHolder("NFT description")
		nftDescriptionEntry.Wrapping = fyne.TextWrapWord
		nftDescriptionEntry.SetMinRowsVisible(2)

		// ── Marketplace collection (SIP-721) ────────────────────────────────
		// A bare receipt anchor is not listable/buyable/rentable on the
		// Marketplace screen — only a token minted inside a SIP-721 collection
		// is. This lets Mint Data create or reuse that collection so the data
		// it mints is immediately searchable/buyable/rentable there.
		savedColl := loadSavedCollection()
		activeCollection := savedColl

		collectionAddrVal := canvas.NewText("—", colMuted)
		collectionAddrVal.TextSize = 11
		collectionAddrVal.TextStyle = fyne.TextStyle{Monospace: true}

		collectionStatus := canvas.NewText("", colFaint)
		collectionStatus.TextSize = 11
		setCollectionStatus := func(text string, col color.Color) {
			collectionStatus.Text = text
			collectionStatus.Color = col
			collectionStatus.Refresh()
		}

		// refreshCollectionDisplay is the single place the visible collection
		// state is derived, so the shown address, the value the mint uses, and
		// the saved record can never disagree.
		refreshCollectionDisplay := func() {
			if activeCollection.Address == "" {
				collectionAddrVal.Text = "— none yet —"
				collectionAddrVal.Color = colMuted
				setCollectionStatus("No collection yet — deploy one so your mint can be listed/bought/rented.", colWarn)
			} else {
				collectionAddrVal.Text = truncMiddle(activeCollection.Address, 14)
				collectionAddrVal.Color = colAccent
				setCollectionStatus(fmt.Sprintf("Generated for you: %s (%s) — mints go into this collection.",
					activeCollection.Name, activeCollection.Symbol), colAccent)
			}
			collectionAddrVal.Refresh()
		}

		// adoptCollection makes a collection active in memory + on disk and
		// repaints the display. It is the ONLY way the active collection
		// changes: the address is either GENERATED by a deploy (the node
		// derives it deterministically from sender+nonce+code) or validated
		// against the chain — never typed and trusted blindly.
		adoptCollection := func(sc SavedCollection) error {
			activeCollection = sc
			saveErr := saveCollection(sc)
			refreshCollectionDisplay()
			return saveErr
		}
		refreshCollectionDisplay()

		// copyCollectionBtn copies the CURRENTLY active collection's contract
		// address to the clipboard — read at click time, not captured at
		// construction, so it always copies whatever deploy/adopt selected
		// most recently. This is the address pasted into the Marketplace
		// screen's collection field (or shared so someone else can adopt the
		// same collection via "Use Existing Address…").
		copyCollectionBtn := widget.NewButtonWithIcon("", theme.ContentCopyIcon(), func() {
			addr := activeCollection.Address
			if strings.TrimSpace(addr) == "" {
				showErrorDialog(errors.New("no collection yet — deploy one first, then copy its address here"), window)
				return
			}
			myApp.Clipboard().SetContent(addr)
			dialog.ShowInformation("Copied", "Collection contract address copied to clipboard", window)
		})
		copyCollectionBtn.Importance = widget.LowImportance

		// Adopting an ALREADY-DEPLOYED collection is an explicit, secondary
		// action (e.g. the same identity deployed it from another machine):
		// the address is validated against the chain before it can go live.
		useExistingCollectionBtn := widget.NewButtonWithIcon("Use Existing Address…", theme.FolderOpenIcon(), func() {
			addrEntry := widget.NewEntry()
			addrEntry.SetPlaceHolder("Existing SIP-721 collection address")
			formDlg := dialog.NewForm("Use Existing Collection", "Use", "Cancel",
				[]*widget.FormItem{widget.NewFormItem("Collection address", addrEntry)},
				func(ok bool) {
					if !ok {
						return
					}
					addr := strings.TrimSpace(addrEntry.Text)
					if addr == "" {
						showErrorDialog(errors.New("enter the collection contract address"), window)
						return
					}
					setCollectionStatus("Checking collection…", colInfo)
					go func() {
						info, err := walletClient.GetSIP721CollectionInfo(addr)
						if err != nil {
							fyne.Do(func() { setCollectionStatus("Not a SIP-721 collection: "+err.Error(), colDanger) })
							return
						}
						fyne.Do(func() {
							saveErr := adoptCollection(SavedCollection{Address: addr, Name: info.Name, Symbol: info.Symbol, DeployedAt: time.Now().Unix()})
							if saveErr != nil {
								setCollectionStatus("Verified but failed to save locally: "+saveErr.Error(), colWarn)
							}
						})
					}()
				}, window)
			formDlg.Resize(fyne.NewSize(520, 200))
			formDlg.Show()
		})

		deployCollectionBtn := widget.NewButtonWithIcon("Deploy New Collection", theme.ContentAddIcon(), func() {
			nameEntry := widget.NewEntry()
			nameEntry.SetPlaceHolder("Collection name (e.g. My Dataset Collection)")
			symbolEntry := widget.NewEntry()
			symbolEntry.SetPlaceHolder("Collection symbol (e.g. MDC)")
			deployDlg := dialog.NewForm("Deploy SIP-721 Collection", "Deploy", "Cancel",
				[]*widget.FormItem{
					widget.NewFormItem("Name", nameEntry),
					widget.NewFormItem("Symbol", symbolEntry),
				}, func(ok bool) {
					if !ok {
						return
					}
					name := strings.TrimSpace(nameEntry.Text)
					symbol := strings.TrimSpace(symbolEntry.Text)
					if name == "" || symbol == "" {
						showErrorDialog(errors.New("name and symbol are both required"), window)
						return
					}
					setCollectionStatus("Deploying collection… the contract address is generated on-chain.", colInfo)
					go func() {
						addr, txID, err := walletClient.DeploySIP721Collection(name, symbol)
						if err != nil {
							fyne.Do(func() { setCollectionStatus("Deploy failed: "+err.Error(), colDanger) })
							return
						}
						sc := SavedCollection{Address: addr, Name: name, Symbol: strings.ToUpper(symbol), DeployedAt: time.Now().Unix()}
						fyne.Do(func() {
							if saveErr := adoptCollection(sc); saveErr != nil {
								setCollectionStatus(fmt.Sprintf("Deployed %s (tx %s…) but failed to save locally: %v", addr, txID[:min(12, len(txID))], saveErr), colWarn)
							}
						})
					}()
				}, window)
			deployDlg.Resize(fyne.NewSize(480, 220))
			deployDlg.Show()
		})

		// Embedded-economics terms (optional). These are frozen into the
		// mint receipt and the SIP-721 token at mint and enforced by the
		// native contract runtime at consensus — no post-mint rewrite is
		// possible, so the values entered here are final. Empty fields mint
		// a legacy no-terms token (no resale royalty, no licensing).
		nftRoyaltyEntry := widget.NewEntry()
		nftRoyaltyEntry.SetPlaceHolder("Resale royalty % (optional, 0–100, e.g. 5 = 5% of every resale)")

		nftUsageFeeEntry := widget.NewEntry()
		nftUsageFeeEntry.SetPlaceHolder("License fee per use in SPX (optional, e.g. 0.05)")

		nftRecipientEntry := widget.NewEntry()
		nftRecipientEntry.SetPlaceHolder("Royalty recipient SPIF address (optional, default = you)")

		// mintFeeSPX projects the policy mint fee (in SPX) for the currently
		// selected file. Mint data is priced deterministically from four
		// dimensions — payload bytes (what gets pinned to IPFS), on-chain
		// anchor bytes, committed hashes, and IPFS retention — and the node
		// enforces the same dimensions through the anchor transaction's gas
		// quote (see AnchorMintReceipt). The anchor/hash/pinning dimensions
		// use the governance defaults; the payload dimension tracks the actual
		// size of the file being minted (0 before any file is picked).
		mintFeeSPX := func() float64 {
			return mintPolicy.CalculateMintDataFeeInSPX(selectedFileSize, mintPolicy.MintAnchorBytes, mintPolicy.MintBaseHashes, mintPolicy.MintPinningMonths)
		}

		// Resale floor (policy MinTokenSaleValue): royalties are priced on
		// max(sale price, floor) so settling a sale at a dust price still
		// pays the creator a real royalty.
		resaleFloorText := "—"
		if mintPolicy.MinTokenSaleValue != nil {
			resaleFloorText = formatNSPXAmount(mintPolicy.MinTokenSaleValue) + " " + chainHeader.Symbol
		}

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
				selectedFileSize = uint64(info.Size())
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
			selectedFileSize = 0
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
						showErrorDialog(errors.New("cannot sign a .vault file"), window)
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

		// ★ FIX: this was a canvas.Text — which cannot wrap, at any width,
		// ever. Truncating individual hashes wasn't enough on its own: the
		// assembled success message (icon + description + tx + cid +
		// height + anchor + token) is still a long sentence, and one long
		// unbroken line is exactly what was forcing the window wider on
		// every completed mint (see the two prior screenshots). A
		// wrapping widget.Label reflows within whatever width the layout
		// actually gives it instead of demanding one line's worth of
		// pixels no matter how long the text is.
		statusText := widget.NewLabel("")
		statusText.Wrapping = fyne.TextWrapWord
		statusText.Alignment = fyne.TextAlignCenter
		statusText.TextStyle = fyne.TextStyle{Bold: true}
		statusText.Importance = widget.LowImportance

		signBtn := widget.NewButtonWithIcon("Mint Data", theme.ConfirmIcon(), func() {
			if selectedFile == "" {
				showErrorDialog(errors.New("please select a file"), window)
				return
			}
			if sessionPassphrase == "" {
				showErrorDialog(errors.New("not logged in — please log in again"), window)
				return
			}

			signed, prevFP, err := sign.IsAlreadySigned(selectedFile)
			if err != nil {
				showErrorDialog(fmt.Errorf("metadata error: %w", err), window)
				return
			}
			if signed {
				dialog.ShowInformation("Already Signed",
					fmt.Sprintf("This document is already signed.\n\nSigned by: %s\n\nRe-signing is not permitted.", prevFP), window)
				return
			}

			// Mint data is gated on holding the policy minimum balance (default
			// 100 SPX in this wallet). Verify through the node before spending
			// anything on the anchor transaction.
			if _, balErr := requireMintBalance(walletClient); balErr != nil {
				showErrorDialog(balErr, window)
				return
			}

			// Parse the optional embedded-economics terms before anything is
			// signed or broadcast — fail fast with a dialog rather than
			// producing an anchor the node's ValidateAnchorData would reject.
			// The royalty is entered as a percentage (0–100) and stored as
			// basis points; the license fee is entered in SPX and stored as a
			// decimal nSPX string; the recipient (optional) is normalized to
			// the raw uppercase-hex form the contract runtime pays out to.
			royaltyBPS := uint64(0)
			if txt := strings.TrimSpace(nftRoyaltyEntry.Text); txt != "" {
				pct, ok := new(big.Float).SetPrec(256).SetString(txt)
				if !ok || pct.Sign() < 0 || pct.Cmp(big.NewFloat(100)) > 0 {
					showErrorDialog(errors.New("resale royalty must be a percentage between 0 and 100"), window)
					return
				}
				bpsInt, _ := new(big.Float).Mul(pct, big.NewFloat(100)).Int(nil)
				if bpsInt == nil || bpsInt.IsUint64() == false || bpsInt.Uint64() > 10000 {
					showErrorDialog(errors.New("resale royalty out of range (max 100%)"), window)
					return
				}
				royaltyBPS = bpsInt.Uint64()
			}
			usageFeeNSPX := ""
			if txt := strings.TrimSpace(nftUsageFeeEntry.Text); txt != "" {
				feeSPX, ok := new(big.Float).SetPrec(256).SetString(txt)
				if !ok || feeSPX.Sign() <= 0 {
					showErrorDialog(errors.New("license fee must be a positive SPX amount"), window)
					return
				}
				feeNSPX, _ := new(big.Float).Mul(feeSPX, big.NewFloat(1e18)).Int(nil)
				if feeNSPX == nil || feeNSPX.Sign() <= 0 {
					showErrorDialog(errors.New("license fee is too small to represent in nSPX"), window)
					return
				}
				usageFeeNSPX = feeNSPX.String()
			}
			royaltyRecipient, recipErr := normalizeRoyaltyRecipient(nftRecipientEntry.Text)
			if recipErr != nil {
				showErrorDialog(recipErr, window)
				return
			}

			// A collection mint needs an ERC-721 metadata tokenURI, which is
			// only produced when an NFT name is set — catch this here instead
			// of letting the mint worker fail after the file is already signed.
			collectionAddr := strings.TrimSpace(activeCollection.Address)
			if collectionAddr != "" && strings.TrimSpace(nftNameEntry.Text) == "" {
				showErrorDialog(errors.New(
					"a collection is set — fill in the NFT name so the marketplace metadata can be pinned to IPFS, or clear the collection field to mint a bare (non-tradeable) receipt"), window)
				return
			}

			// Embedded economics (resale royalty / licence fee) are only
			// enforceable — and the data only rentable — through a SIP-721
			// token inside a collection. A bare receipt anchor records the
			// terms but has no contract to honour them, so such a mint would
			// never turn up as discoverable/buyable/rentable on the
			// Marketplace. Confirm before spending, so minted data and the
			// Marketplace never silently disagree about tradeability.
			hasEconomics := royaltyBPS > 0 || usageFeeNSPX != "" || royaltyRecipient != ""
			finishMint := func() {
				validatePassphraseDialog(window, "Confirm Passphrase",
					fmt.Sprintf("Enter your passphrase to sign this document.\n\nMinting costs ~%s %s (policy estimate), charged on-chain. Your wallet must hold at least %.0f %s.",
						formatSPXAmount(new(big.Float).SetFloat64(mintFeeSPX())), chainHeader.Symbol, mintPolicy.GetMinMintBalanceSPX(), chainHeader.Symbol),
					func(passphrase string) {
						showMintStatusDialog(MintJob{
							Window:             window,
							Client:             walletClient,
							ChainHeader:        chainHeader,
							SelectedFile:       selectedFile,
							Passphrase:         passphrase,
							SessionPassphrase:  sessionPassphrase,
							SessionFingerprint: sessionFingerprint,
							PublicFingerprint:  publicFingerprint,
							NFTName:            nftNameEntry.Text,
							NFTDescription:     nftDescriptionEntry.Text,
							Collection:         collectionAddr,
							RoyaltyBPS:         royaltyBPS,
							UsageFeeNSPX:       usageFeeNSPX,
							RoyaltyRecipient:   royaltyRecipient,
							MintFeeSPX:         mintFeeSPX,
							StatusText:         statusText,
							ResetDropZone:      resetDropZone,
							ClearSelectedFile:  func() { selectedFile = "" },
						})
					})
			}
			if collectionAddr == "" && hasEconomics {
				dialog.ShowConfirm("Mint without a collection?",
					"Embedded economics are set, but no Marketplace collection is selected.\n\n"+
						"The resale royalty and licence fee can only be enforced — and the data only listed, bought or rented — "+
						"once the mint is a SIP-721 token inside a collection. Minting now still records the terms in the signed "+
						"document and the on-chain anchor, but the item will NOT be discoverable or tradeable on the Marketplace.\n\n"+
						"Deploy a collection above to make this data tradeable.\n\nMint anyway?",
					func(ok bool) {
						if ok {
							finishMint()
						}
					}, window)
				return
			}
			finishMint()
		})
		signBtn.Importance = widget.HighImportance

		clearBtn := widget.NewButtonWithIcon("Clear", theme.CancelIcon(), func() {
			selectedFile = ""
			resetDropZone()
			statusText.Text = ""
			statusText.Importance = widget.LowImportance
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
			infoPanel("Mint Pricing (policy)", []fyne.CanvasObject{
				infoRow("Min. balance", fmt.Sprintf("%.0f %s", mintPolicy.GetMinMintBalanceSPX(), chainHeader.Symbol), colAccent),
				infoRow("Est. cost per mint", fmt.Sprintf("%s %s", formatSPXAmount(new(big.Float).SetFloat64(mintFeeSPX())), chainHeader.Symbol), colWarn),
				infoRow("Resale floor", resaleFloorText, colText),
				infoRow("Charged via", "anchor tx gas", colText),
			}),
			spacer(12),
			alertBox(fmt.Sprintf("You must hold at least %.0f %s in your wallet to mint data. The node rejects the mint below this floor.",
				mintPolicy.GetMinMintBalanceSPX(), chainHeader.Symbol), color.RGBA{96, 165, 250, 20}, colInfo),
			spacer(12),
			alertBox(fmt.Sprintf("Each mint costs %s %s, deducted on-chain through the anchor transaction.",
				formatSPXAmount(new(big.Float).SetFloat64(mintFeeSPX())), chainHeader.Symbol), color.RGBA{74, 222, 158, 15}, colAccent),
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
			hRule(),
			spacer(12),
			sectionLabel("NFT Metadata (ERC-721)"),
			spacer(6),
			nftNameEntry,
			spacer(8),
			nftDescriptionEntry,
			spacer(16),
			hRule(),
			spacer(12),
			sectionLabel("Marketplace Collection (SIP-721)"),
			spacer(6),
			container.NewHBox(collectionAddrVal, spacer(6), copyCollectionBtn),
			spacer(8),
			container.NewHBox(deployCollectionBtn, spacer(8), useExistingCollectionBtn),
			spacer(6),
			collectionStatus,
			spacer(16),
			sectionLabel("Embedded Economics (optional — frozen at mint)"),
			spacer(6),
			nftRoyaltyEntry,
			spacer(8),
			nftUsageFeeEntry,
			spacer(8),
			nftRecipientEntry,
			spacer(20),
			// Not wrapped in container.NewCenter — Center resizes a child
			// to its own MinSize before centering, which for a wrapping
			// Label reports its natural (unwrapped) width on first layout,
			// silently reproducing the exact same width-blowout bug. Left
			// directly in this VBox, the label gets the VBox's actual
			// (bounded) width to wrap within; centered text is achieved via
			// Alignment on the label itself instead.
			statusText,
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
		// NFT display metadata, recovered from the embedded Meta JSON
		// (types.Meta.NFTName/NFTDescription) that the Mint Data flow froze
		// into the signed document. "—" until a verified file supplies them.
		resultNFTNameLbl := canvas.NewText("—", colMuted)
		resultNFTNameLbl.TextSize = 11
		resultNFTDescLbl := canvas.NewText("—", colMuted)
		resultNFTDescLbl.TextSize = 11

		// ── Backend-recorded provenance ────────────────────────────────
		// Everything below is data the backend ALREADY wrote into the file's
		// metadata at mint time (sign.Meta) and re-embeds on every provenance
		// refresh. None of it was displayed here before, so a user could not
		// see the anchor, the token binding, or the economics their own file
		// has carried all along.
		newProvText := func() *canvas.Text {
			t := canvas.NewText("—", colMuted)
			t.TextSize = 11
			t.TextStyle = fyne.TextStyle{Monospace: true}
			return t
		}
		// resultAssuranceLbl is the tri-state the backend distinguishes but
		// this screen previously collapsed into one "VALID" (see provenance.go).
		resultAssuranceLbl := canvas.NewText("—", colMuted)
		resultAssuranceLbl.TextSize = 11
		resultAssuranceLbl.TextStyle = fyne.TextStyle{Bold: true}

		pinStatusVal := canvas.NewText("—", colMuted)
		pinStatusVal.TextSize = 12
		pinStatusVal.TextStyle = fyne.TextStyle{Bold: true}
		pinStatusDetailLbl := widget.NewLabel("Run Verify to read the payload retrievability and on-chain provenance this file carries.")
		pinStatusDetailLbl.Wrapping = fyne.TextWrapWord
		pinStatusDetailLbl.TextStyle = fyne.TextStyle{Italic: true}

		provCIDVal := newProvText()
		provPinnedHashVal := newProvText()
		provSignedHashVal := newProvText()
		provMintIDVal := newProvText()
		provAnchorTxVal := newProvText()
		provConfirmedVal := newProvText()
		provBlockHashVal := newProvText()
		provNonceVal := newProvText()
		provMintPriceVal := newProvText()
		provTokenVal := newProvText()
		provTermsVal := newProvText()

		// provTexts is the single list every reset walks, so a newly added
		// field cannot be forgotten in one of the two reset paths.
		provTexts := []*canvas.Text{
			provCIDVal, provPinnedHashVal, provSignedHashVal, provMintIDVal,
			provAnchorTxVal, provConfirmedVal, provBlockHashVal, provNonceVal,
			provMintPriceVal, provTokenVal, provTermsVal,
		}

		resetProvenance := func() {
			for _, t := range provTexts {
				t.Text = "—"
				t.Color = colMuted
				t.Refresh()
			}
			resultAssuranceLbl.Text = "—"
			resultAssuranceLbl.Color = colMuted
			resultAssuranceLbl.Refresh()
			pinStatusVal.Text = "—"
			pinStatusVal.Color = colMuted
			pinStatusVal.Refresh()
			pinStatusDetailLbl.SetText("Run Verify to read the payload retrievability and on-chain provenance this file carries.")
		}

		// checkRetrievability asks the SAME storage probe the CLI's
		// "ipfs verify" uses, so both surfaces report one verdict. It runs off
		// the UI thread and never blocks the signature result from appearing.
		checkRetrievability := func(meta *sign.Meta) {
			if meta == nil || strings.TrimSpace(meta.IPFSCID) == "" {
				fyne.Do(func() {
					pinStatusVal.Text = "n/a — no IPFS CID"
					pinStatusVal.Color = colMuted
					pinStatusVal.Refresh()
					pinStatusDetailLbl.SetText("This file was signed but never minted to IPFS, so there is no pin to check.")
				})
				return
			}
			durability, err := storage.NewClient(storage.DefaultConfig()).CheckRetrievability(meta.IPFSCID)
			fyne.Do(func() {
				if err != nil {
					pinStatusVal.Text = "CHECK FAILED"
					pinStatusVal.Color = colWarn
					pinStatusVal.Refresh()
					pinStatusDetailLbl.SetText("Could not check retrievability: " + err.Error())
					return
				}
				pinStatusVal.Text = pinStatusTitle(durability)
				pinStatusVal.Color = pinStatusColor(durability)
				pinStatusVal.Refresh()
				pinStatusDetailLbl.SetText(pinStatusDetail(durability))
			})
		}

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
			resultNFTNameLbl.Text = "—"
			resultNFTNameLbl.Color = colMuted
			resultNFTDescLbl.Text = "—"
			resultNFTDescLbl.Color = colMuted
			resultFileLbl.Refresh()
			resultSignerLbl.Refresh()
			resultOrgLbl.Refresh()
			resultTimeLbl.Refresh()
			resultNFTNameLbl.Refresh()
			resultNFTDescLbl.Refresh()
			resetProvenance()
		}

		browseBtn := widget.NewButtonWithIcon("Browse File", theme.ViewRefreshIcon(), func() {
			dlg := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
				if err == nil && reader != nil {
					p := reader.URI().Path()
					reader.Close()
					if strings.HasSuffix(p, ".vault") {
						showErrorDialog(errors.New("cannot verify .vault files — verify the source files instead"), window)
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
				showErrorDialog(errors.New("please select a file"), window)
				return
			}

			statusBig.Text = "Verifying…"
			statusBig.Color = colMuted
			statusBig.Refresh()

			go func() {
				result, meta, _ := sign.VerifyUniversal(selectedFile, sessionPassphrase)
				// The backend reports a TRI-STATE, not a boolean. Collapsing
				// INTEGRITY_ONLY into a flat "VALID" would claim authenticity
				// the verification never established (see provenance.go).
				assurance := assuranceFor(result)
				fyne.Do(func() {
					// ─ Provenance recorded in the file ────────────────
					// Rendered for EVERY outcome, including an invalid one: a
					// file whose signature fails still displays the anchor and
					// terms it claims, which is what lets a user see WHAT was
					// tampered with, not merely that something was.
					if meta != nil {
						provCIDVal.Text = valueOr(meta.IPFSCID, "unpinned")
						provCIDVal.Color = colText
						provPinnedHashVal.Text = truncMiddle(valueOr(meta.IPFSPayloadHash, "n/a"), 14)
						provSignedHashVal.Text = truncMiddle(valueOr(meta.FileHash, "n/a"), 14)
						provMintIDVal.Text = truncMiddle(valueOr(meta.MintID, "unanchored"), 14)
						provAnchorTxVal.Text = truncMiddle(valueOr(meta.AnchorTxID, "unanchored"), 14)
						provConfirmedVal.Text = heightOr(meta.ConfirmedHeight, "pending")
						provBlockHashVal.Text = truncMiddle(valueOr(meta.BlockHash, "pending"), 14)
						provNonceVal.Text = valueOr(meta.AnchorNonce, "n/a")
						provMintPriceVal.Text = valueOr(sign.FormatMintFeeNSPX(meta.MintFeeNSPX), "n/a")
						provTokenVal.Text = tokenBinding(meta)
						provTermsVal.Text = describeMetaTerms(meta)
						for _, t := range provTexts {
							t.Refresh()
						}
					}

					resultAssuranceLbl.Text = assuranceTitle(assurance)
					resultAssuranceLbl.Color = assuranceColor(assurance)
					resultAssuranceLbl.Refresh()

					if assurance != assuranceInvalid && meta != nil {
						addActivity(fmt.Sprintf("Verified: %s — %s", filepath.Base(selectedFile), assuranceTitle(assurance)))
						if assurance == assuranceAuthenticated {
							statusBig.Text = "✓  SIGNATURE VALID — AUTHENTICATED"
						} else {
							statusBig.Text = "⚠  SIGNATURE VALID — INTEGRITY ONLY"
						}
						statusBig.Color = assuranceColor(assurance)

						resultSignerLbl.Text = valueOr(meta.Signer, "Unknown signer")
						resultSignerLbl.Color = colAccent
						resultOrgLbl.Text = valueOr(meta.OrgCode, "SPIF")
						resultOrgLbl.Color = colAccent
						resultTimeLbl.Text = time.Unix(meta.Timestamp, 0).Format("2006-01-02 15:04")
						resultTimeLbl.Color = colText

						// NFT name/description frozen into the signed Meta at
						// mint time (see sign.SetNFTMetadata). A plain signed
						// file has none, so fall back to an explicit sentinel
						// rather than an empty row.
						if meta.NFTName != "" {
							resultNFTNameLbl.Text = meta.NFTName
							resultNFTNameLbl.Color = colAccent
						} else {
							resultNFTNameLbl.Text = "n/a (not an NFT mint)"
							resultNFTNameLbl.Color = colMuted
						}
						if meta.NFTDescription != "" {
							resultNFTDescLbl.Text = meta.NFTDescription
							resultNFTDescLbl.Color = colText
						} else {
							resultNFTDescLbl.Text = "n/a (not an NFT mint)"
							resultNFTDescLbl.Color = colMuted
						}

						// The dialog must match the assurance level: an
						// integrity-only result must never be announced as
						// proof of who signed.
						dialog.ShowInformation("Verified — "+assuranceTitle(assurance),
							assuranceDetail(assurance), window)
					} else {
						addActivity(fmt.Sprintf("Verified: %s — INVALID", filepath.Base(selectedFile)))
						statusBig.Text = "✗  SIGNATURE INVALID"
						statusBig.Color = colDanger
						showErrorDialog(errors.New("signature invalid — file may have been tampered with"), window)
					}

					statusBig.Refresh()
					resultSignerLbl.Refresh()
					resultOrgLbl.Refresh()
					resultTimeLbl.Refresh()
					resultNFTNameLbl.Refresh()
					resultNFTDescLbl.Refresh()
				})

				// Retrievability is a separate, network-bound question. It runs
				// after the verdict is on screen and never delays it.
				if meta != nil {
					go checkRetrievability(meta)
				}
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
			// Assurance is the backend's tri-state, shown as its own row so
			// "self-consistent" is never read as "authenticated".
			makeInfoLine("Assurance", resultAssuranceLbl),
			spacer(6),
			makeInfoLine("Signed at", resultTimeLbl),
			spacer(6),
			makeInfoLine("NFT Name", resultNFTNameLbl),
			spacer(6),
			makeInfoLine("NFT Description", resultNFTDescLbl),
			infoRow("Network", chainHeader.ChainName, colAccent),
		)
		panel := container.NewVBox(
			container.NewMax(panelBg, container.NewPadded(panelInner)),
			spacer(12),
			alertBox("The result distinguishes an AUTHENTICATED signature (signer's key confirmed against the key directory) from INTEGRITY ONLY (self-consistent, but signer identity unconfirmed).", color.RGBA{96, 165, 250, 20}, colInfo),
		)

		// ── Backend-recorded provenance — full width ───────────────────
		// Mirrors the Wallet screen's txSection pattern: this is tabular
		// evidence, not a form field, and squeezing hashes into the 38% side
		// column would truncate exactly the values a user needs to check.
		provCard := styledCard(container.NewVBox(
			sectionLabel("Payload Retrievability"),
			spacer(8),
			pinStatusVal,
			spacer(4),
			pinStatusDetailLbl,
			spacer(14),
			hRule(),
			spacer(12),
			sectionLabel("On-Chain Provenance (as recorded in this file)"),
			spacer(8),
			infoRowDynamic("Mint ID", provMintIDVal),
			spacer(4),
			infoRowDynamic("Anchor Tx", provAnchorTxVal),
			spacer(4),
			infoRowDynamic("Confirmed Block", provConfirmedVal),
			spacer(4),
			infoRowDynamic("Block Hash", provBlockHashVal),
			spacer(4),
			infoRowDynamic("Tx Nonce", provNonceVal),
			spacer(4),
			infoRowDynamic("Mint Price", provMintPriceVal),
			spacer(4),
			infoRowDynamic("Marketplace Token", provTokenVal),
			spacer(4),
			infoRowDynamic("Embedded Terms", provTermsVal),
			spacer(14),
			hRule(),
			spacer(12),
			sectionLabel("Storage"),
			spacer(8),
			infoRowDynamic("IPFS CID", provCIDVal),
			spacer(4),
			infoRowDynamic("Pinned Payload Hash", provPinnedHashVal),
			spacer(4),
			infoRowDynamic("Signed File Hash", provSignedHashVal),
		), 0, 0)

		provSection := container.NewVBox(
			hRule(),
			spacer(12),
			sectionLabel("Backend-Recorded Provenance"),
			spacer(8),
			provCard,
			spacer(12),
			alertBox("These values are read from the document's own metadata — the same on-chain block the signer embedded into every container (PDF/XMP/Office/footer) at mint time. They are displayed exactly as recorded; re-checking them against the chain is what 'sphinx ipfs verify' does. Pinned Payload Hash covers the clean bytes uploaded to IPFS, Signed File Hash covers this signed file — they differ by design.", color.RGBA{96, 165, 250, 20}, colInfo),
			spacer(24),
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

		setScreen(container.NewVBox(opLayout(form, panel), provSection))
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

		balInner := container.NewVBox(
			container.NewCenter(balLabel),
			spacer(6),
			container.NewCenter(balValue),
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
				if resp != nil && resp.Balance.Int != nil {
					balanceSPX := new(big.Float).Quo(
						new(big.Float).SetInt(resp.Balance.Int),
						big.NewFloat(1e18),
					)
					balValue.Text = formatSPXAmount(balanceSPX)
					balValue.Color = colAccent
					balValue.Refresh()
					log.Printf("[Wallet] Balance updated: %s SPX", balValue.Text)
				}
			})
		}

		// Initial balance fetch
		go fetchBalance()

		// ── Chain tip header (LIGHTWEIGHT HEADER-ONLY SYNC) ──────────
		// USI is a lightweight wallet, not a vault full node: it never
		// downloads full block bodies (that is src/core/sync.go's job on
		// full nodes). The only chain data this wallet pulls from the node
		// is the block header, via the getblockheader RPC.
		tipLabel := canvas.NewText("CHAIN TIP · HEADER SYNC", colFaint)
		tipLabel.TextSize = 9
		tipLabel.TextStyle = fyne.TextStyle{Monospace: true}

		tipValue := widget.NewLabel("Header sync: —")
		tipValue.TextStyle = fyne.TextStyle{Monospace: true}
		tipValue.Wrapping = fyne.TextWrapBreak

		fetchChainTip := func() {
			hdr, err := walletClient.GetChainTipHeader()
			fyne.Do(func() {
				if err != nil {
					tipValue.Text = fmt.Sprintf("Header sync offline (%v)", err)
					tipValue.Refresh()
					return
				}
				if hdr == nil {
					tipValue.Text = "Header sync offline (no tip)"
					tipValue.Refresh()
					return
				}
				hash := ""
				if len(hdr.Hash) > 0 {
					hash = fmt.Sprintf("%x", hdr.Hash)
					if len(hash) > 22 {
						hash = hash[:10] + "…" + hash[len(hash)-10:]
					}
				}
				proposer := hdr.ProposerID
				if proposer == "" {
					proposer = "—"
				}
				tipValue.Text = fmt.Sprintf("Height %d · hash 0x%s · proposer %s", hdr.Height, hash, proposer)
				tipValue.Refresh()
			})
		}
		go fetchChainTip()

		tipBg := canvas.NewRectangle(colSurface2)
		tipBg.CornerRadius = 8
		tipBg.StrokeColor = colBorder
		tipBg.StrokeWidth = 1
		tipInner := container.NewVBox(tipLabel, spacer(4), tipValue)
		tipCard := container.NewMax(tipBg, container.NewPadded(tipInner))

		// ── Transaction history container ─────────────────────────
		txBox := container.NewVBox()
		// Width left at 0 so the card fills whatever space it's given —
		// now the full screen width (see txSection below) instead of the
		// old 62%-wide form column. Height nudged up slightly since a
		// wider box can comfortably show a bit more without scrolling.
		txScroll := container.NewScroll(txBox)
		txScroll.SetMinSize(fyne.NewSize(0, 260))
		txCard := styledCard(txScroll, 0, 260)

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
						if sameIdentity(tx.Sender, sessionFingerprint) {
							icon = "↑"
							iconCol = colDanger
						} else if sameIdentity(tx.Receiver, sessionFingerprint) {
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
						amountSPX := "0"
						if tx.Amount.Int != nil {
							amountFloat := new(big.Float).Quo(
								new(big.Float).SetInt(tx.Amount.Int),
								big.NewFloat(1e18),
							)
							amountSPX = formatSPXAmount(amountFloat)
						}

						// Build message
						msg := fmt.Sprintf("%s %s", amountSPX, chainHeader.Symbol)
						if sameIdentity(tx.Sender, sessionFingerprint) {
							msg += fmt.Sprintf(" → %s…", tx.Receiver[:min(16, len(tx.Receiver))])
						} else {
							msg += fmt.Sprintf(" ← %s…", tx.Sender[:min(16, len(tx.Sender))])
						}

						msgT := canvas.NewText(msg, colText)
						msgT.TextSize = 11

						// Display memo/OP_RETURN data if present
						var memoT *canvas.Text
						if len(tx.ReturnData) > 0 {
							memoText := string(tx.ReturnData)
							if len(memoText) > 50 {
								memoText = memoText[:47] + "..."
							}
							memoT = canvas.NewText("📝 "+memoText, colMuted)
							memoT.TextSize = 9
							memoT.TextStyle = fyne.TextStyle{Italic: true}
						}

						tsT := canvas.NewText(ts, colFaint)
						tsT.TextSize = 10
						tsT.Alignment = fyne.TextAlignTrailing

						rowBg := canvas.NewRectangle(colSurface)
						rowBg.CornerRadius = 8
						rowBg.StrokeColor = colBorder
						rowBg.StrokeWidth = 1

						// Build row content with optional memo
						rowContent := container.NewVBox(msgT)
						if memoT != nil {
							rowContent.Add(container.NewPadded(memoT))
						}

						inner := container.NewBorder(nil, nil,
							container.NewHBox(dirBadge, spacer(10)),
							nil,
							container.NewBorder(nil, nil, rowContent, tsT),
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
				showErrorDialog(errors.New("please login first"), window)
				return
			}
			showSendScreen()
		})
		sendBtn.Importance = widget.HighImportance

		// ── Receive button ────────────────────────────────────────────
		receiveBtn := widget.NewButtonWithIcon(fmt.Sprintf("Receive %s", chainHeader.Symbol), theme.DownloadIcon(), func() {
			if sessionPassphrase == "" {
				showErrorDialog(errors.New("please login first"), window)
				return
			}
			showReceiveScreen()
		})
		receiveBtn.Importance = widget.HighImportance

		// ── Refresh button ────────────────────────────────────────
		refreshBtn := widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), func() {
			go fetchBalance()
			go fetchTransactionHistory()
			go fetchChainTip()
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
			spacer(12),
			tipCard,
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
		)

		// ── Transaction history — full width ───────────────────────
		// Previously this sat inside the 62%-wide left column of the
		// balance/address split, which cramped every row (date, txid,
		// amount, status) into a narrow strip. It reads as a table, not a
		// form field, so it gets its own full-width section below the
		// split instead of competing for space with the stats panel.
		txSection := container.NewVBox(
			hRule(),
			spacer(12),
			sectionLabel("Transaction History"),
			spacer(8),
			txCard,
			spacer(24),
		)

		setScreen(container.NewVBox(opLayout(form, panel), txSection))
	}
	// =========================================================================
	// MARKETPLACE SCREEN
	// =========================================================================
	showMarketplaceScreen = func() {
		log.Println("Displaying marketplace screen")
		updateLayout(true)

		if sessionPassphrase == "" {
			showErrorDialog(errors.New("please login first"), window)
			return
		}

		collectionEntry := widget.NewEntry()
		collectionEntry.SetPlaceHolder("SIP-721 collection contract address")
		if savedColl := loadSavedCollection(); savedColl.Address != "" {
			collectionEntry.SetText(savedColl.Address)
		}

		tokenIDEntry := widget.NewEntry()
		tokenIDEntry.SetPlaceHolder("Token ID (decimal integer)")

		priceEntry := widget.NewEntry()
		priceEntry.SetPlaceHolder("List price in SPX (positive decimal, e.g. 0.5)")

		// Live conversion preview under the price field — SPX/nSPX mix-ups
		// are a real-money mistake, so show both units as the user types
		// rather than only at confirmation time.
		pricePreview := canvas.NewText("", colFaint)
		pricePreview.TextSize = 11

		// unitSelectSelected mirrors unitSelect.Selected so updatePricePreview
		// (defined before unitSelect exists) can read the current unit — Go
		// closures can't forward-reference a not-yet-declared local, so this
		// must be declared ahead of the closure that captures it.
		var unitSelectSelected string

		// Unit selector for the list price. SPX accepts a decimal like
		// "0.5" (converted to nSPX via rpc.go's parseSPXToNSPX); nSPX
		// accepts the exact raw integer the contract stores
		// (parsePositiveDecimalNSPX) — the same canonical form
		// listing_of reports, so an integrator can paste it verbatim.
		updatePricePreview := func() {
			raw := strings.TrimSpace(priceEntry.Text)
			if raw == "" {
				pricePreview.Text = ""
				pricePreview.Refresh()
				return
			}
			var nspx *big.Int
			var err error
			if unitSelectSelected == "nSPX" {
				nspx, err = parsePositiveDecimalNSPX(raw)
			} else {
				nspx, err = parseSPXToNSPX(raw)
			}
			if err != nil || nspx == nil {
				pricePreview.Text = "invalid amount"
				pricePreview.Color = colDanger
				pricePreview.Refresh()
				return
			}
			if unitSelectSelected == "nSPX" {
				pricePreview.Text = "= " + formatNSPXAmount(nspx) + " " + chainHeader.Symbol
			} else {
				pricePreview.Text = "= " + nspx.String() + " nSPX"
			}
			pricePreview.Color = colMuted
			pricePreview.Refresh()
		}

		unitSelectSelected = "SPX"
		unitSelect := widget.NewSelect([]string{"SPX", "nSPX"}, nil)
		unitSelect.SetSelected("SPX")
		unitSelect.OnChanged = func(unit string) {
			unitSelectSelected = unit
			if unit == "nSPX" {
				priceEntry.SetPlaceHolder("List price in nSPX (positive decimal integer, e.g. 500000000000000000)")
			} else {
				priceEntry.SetPlaceHolder("List price in SPX (positive decimal, e.g. 0.5)")
			}
			updatePricePreview()
		}
		priceEntry.OnChanged = func(string) { updatePricePreview() }
		priceRow := container.NewBorder(nil, nil, nil, unitSelect, priceEntry)

		type liveState struct {
			exists       bool
			owner        string
			listed       bool
			seller       string
			priceNSPX    *big.Int
			hasTerms     bool
			creator      string
			royaltyBPS   uint64
			royaltyRecip string
			hasFee       bool
			feeNSPX      *big.Int
			licensee     string
		}
		state := &liveState{}

		// ── Status hero card ──────────────────────────────────────────
		// One glanceable answer to "what's the deal with this token"
		// instead of reading down a list of dashes to piece it together.
		statusDot := canvas.NewRectangle(colMuted)
		statusDot.CornerRadius = 6
		statusDot.SetMinSize(fyne.NewSize(12, 12))
		statusTitle := canvas.NewText("Enter a collection and token ID", colMuted)
		statusTitle.TextSize = 20
		statusTitle.TextStyle = fyne.TextStyle{Bold: true}
		statusSub := canvas.NewText("Press Enter or click Refresh to look it up", colFaint)
		statusSub.TextSize = 12
		statusBg := canvas.NewRectangle(colSurface2)
		statusBg.CornerRadius = 14
		statusBg.StrokeColor = colBorder
		statusBg.StrokeWidth = 1
		statusInner := container.NewVBox(
			container.NewHBox(container.NewCenter(statusDot), spacer(8), statusTitle),
			spacer(4),
			statusSub,
		)
		statusCard := container.NewMax(statusBg, container.NewPadded(statusInner))

		setStatusCard := func(dotColor color.Color, title, sub string, borderColor color.Color) {
			statusDot.FillColor = dotColor
			statusDot.Refresh()
			statusTitle.Text = title
			statusTitle.Color = dotColor
			statusTitle.Refresh()
			statusSub.Text = sub
			statusSub.Refresh()
			statusBg.StrokeColor = borderColor
			statusBg.Refresh()
		}

		existsVal := canvas.NewText("—", colMuted)
		existsVal.TextSize = 11
		existsVal.TextStyle = fyne.TextStyle{Monospace: true}
		ownerVal := canvas.NewText("—", colMuted)
		ownerVal.TextSize = 11
		ownerVal.TextStyle = fyne.TextStyle{Monospace: true}
		listedVal := canvas.NewText("—", colMuted)
		listedVal.TextSize = 11
		listedVal.TextStyle = fyne.TextStyle{Monospace: true}
		sellerVal := canvas.NewText("—", colMuted)
		sellerVal.TextSize = 11
		sellerVal.TextStyle = fyne.TextStyle{Monospace: true}
		priceVal := canvas.NewText("—", colMuted)
		priceVal.TextSize = 11
		priceVal.TextStyle = fyne.TextStyle{Monospace: true}
		creatorVal := canvas.NewText("—", colMuted)
		creatorVal.TextSize = 11
		creatorVal.TextStyle = fyne.TextStyle{Monospace: true}
		royaltyVal := canvas.NewText("—", colMuted)
		royaltyVal.TextSize = 11
		royaltyVal.TextStyle = fyne.TextStyle{Monospace: true}
		recipVal := canvas.NewText("—", colMuted)
		recipVal.TextSize = 11
		recipVal.TextStyle = fyne.TextStyle{Monospace: true}
		feeVal := canvas.NewText("—", colMuted)
		feeVal.TextSize = 11
		feeVal.TextStyle = fyne.TextStyle{Monospace: true}
		licenseeVal := canvas.NewText("—", colMuted)
		licenseeVal.TextSize = 11
		licenseeVal.TextStyle = fyne.TextStyle{Monospace: true}

		refreshResult := canvas.NewText("", colFaint)
		refreshResult.TextSize = 11

		var refreshListing func()
		// updateActionButtons is assigned once the buttons below exist; it
		// enables/disables each action based on the latest known state so
		// invalid actions (buying your own listing, cancelling someone
		// else's, listing something already listed) are simply not
		// clickable rather than clickable-then-rejected.
		var updateActionButtons func(st *liveState)

		refreshBtn := widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), func() {
			refreshListing()
		})
		refreshBtn.Importance = widget.MediumImportance

		// Pressing Enter in either field re-checks the token immediately,
		// so you don't have to remember to click Refresh after typing a
		// new token ID.
		lookupOnSubmit := func(string) { refreshListing() }
		collectionEntry.OnSubmitted = lookupOnSubmit
		tokenIDEntry.OnSubmitted = lookupOnSubmit

		// ── Discover ─────────────────────────────────────────────────────
		// Buying/renting minted data means finding it first: this scans the
		// collection above for its minted tokens (via SearchSIP721Tokens) and
		// lets the user pick one instead of already knowing a token ID.
		discoverQueryEntry := widget.NewEntry()
		discoverQueryEntry.SetPlaceHolder("Search minted data (name, description, subject, creator…) — blank browses all")

		discoverStatus := canvas.NewText("", colFaint)
		discoverStatus.TextSize = 11

		discoverResults := container.NewVBox()
		discoverScroll := container.NewVScroll(discoverResults)
		discoverScroll.SetMinSize(fyne.NewSize(0, 220))

		renderDiscoverResults := func(results []SIP721TokenSummary) {
			discoverResults.Objects = nil
			if len(results) == 0 {
				discoverResults.Add(canvas.NewText("No tokens found in this collection.", colMuted))
			}
			for _, r := range results {
				r := r
				row := widget.NewButton(r.Label(), func() {
					collectionEntry.SetText(r.Collection)
					tokenIDEntry.SetText(fmt.Sprintf("%d", r.TokenID))
					refreshListing()
				})
				row.Alignment = widget.ButtonAlignLeading
				discoverResults.Add(row)
			}
			discoverResults.Refresh()
		}

		runDiscoverSearch := func() {
			coll := strings.TrimSpace(collectionEntry.Text)
			if coll == "" {
				fyne.Do(func() {
					discoverStatus.Text = "Enter a collection address above first."
					discoverStatus.Color = colWarn
					discoverStatus.Refresh()
				})
				return
			}
			fyne.Do(func() {
				discoverStatus.Text = "Searching…"
				discoverStatus.Color = colInfo
				discoverStatus.Refresh()
				discoverResults.Objects = nil
				discoverResults.Refresh()
			})
			query := strings.TrimSpace(discoverQueryEntry.Text)
			go func() {
				results, err := walletClient.SearchSIP721Tokens(coll, query, 50)
				fyne.Do(func() {
					if err != nil {
						discoverStatus.Text = "Search failed: " + err.Error()
						discoverStatus.Color = colDanger
						discoverStatus.Refresh()
						return
					}
					discoverStatus.Text = fmt.Sprintf("%d token(s) found", len(results))
					discoverStatus.Color = colFaint
					discoverStatus.Refresh()
					renderDiscoverResults(results)
				})
			}()
		}

		discoverBtn := widget.NewButtonWithIcon("Search", theme.SearchIcon(), runDiscoverSearch)
		discoverBtn.Importance = widget.MediumImportance
		discoverQueryEntry.OnSubmitted = func(string) { runDiscoverSearch() }

		discoverCard := styledCard(container.NewVBox(
			sectionLabel("Discover Minted Data"),
			spacer(8),
			container.NewBorder(nil, nil, nil, discoverBtn, discoverQueryEntry),
			spacer(6),
			discoverStatus,
			spacer(8),
			discoverScroll,
		), 0, 0)

		// refreshListing polls the contract for the current on-chain state.
		refreshListing = func() {
			coll := strings.TrimSpace(collectionEntry.Text)
			tidStr := strings.TrimSpace(tokenIDEntry.Text)
			if coll == "" || tidStr == "" {
				fyne.Do(func() {
					refreshResult.Text = "Please enter a collection address and token ID."
					refreshResult.Refresh()
				})
				return
			}
			if _, err := formatTokenID(tidStr); err != nil {
				fyne.Do(func() {
					refreshResult.Text = fmt.Sprintf("Invalid token ID: %q", tidStr)
					refreshResult.Refresh()
				})
				return
			}

			fyne.Do(func() {
				refreshResult.Text = "Loading..."
				refreshResult.Refresh()
				setStatusCard(colMuted, "Looking up token…", "Querying "+chainHeader.ChainName, colBorder)
			})

			go func() {
				// Reads go through the typed RPC layer (getcontractstorage at
				// consensus state). Owner read error = missing token; listing
				// nil = unlisted (doc §2); terms error = legacy no-terms
				// token, surfaced distinctly from "unlisted" (doc §2/§4).
				st := &liveState{}

				owner, ownerErr := walletClient.GetSIP721Owner(coll, tidStr)
				if ownerErr == nil {
					st.exists, st.owner = true, owner
				}

				if st.exists {
					if listing, lerr := walletClient.GetSIP721Listing(coll, tidStr); lerr == nil && listing != nil {
						st.listed, st.seller, st.priceNSPX = true, listing.Seller, listing.Price
					}
					if terms, terr := walletClient.GetSIP721Terms(coll, tidStr); terr == nil && terms != nil {
						st.hasTerms = true
						st.creator = terms.Creator
						st.royaltyBPS = terms.RoyaltyBPS
						st.royaltyRecip = terms.RoyaltyRecipient
						if terms.UsageFeeNSPX != nil {
							st.hasFee, st.feeNSPX = true, terms.UsageFeeNSPX
						}
						st.licensee = terms.CurrentLicensee
					}
				}

				*state = *st

				// All widget mutation happens on the UI thread via fyne.Do.
				fyne.Do(func() {

					// Status hero card — the one-line answer.
					switch {
					case !st.exists:
						setStatusCard(colDanger, "Token does not exist", fmt.Sprintf("No token %s in this collection", tidStr), colDanger)
					case st.listed:
						priceStr := "—"
						if st.priceNSPX != nil {
							priceStr = formatNSPXAmount(st.priceNSPX) + " " + chainHeader.Symbol
						}
						setStatusCard(colAccent, "For sale — "+priceStr, "Seller: "+st.seller, colAccent)
					default:
						setStatusCard(colWarn, "Not listed", "Owned by "+st.owner, colWarn)
					}

					// Token existence + owner (owner read error = missing token).
					if st.exists {
						existsVal.Text = "✓ yes"
						existsVal.Color = colAccent
						ownerVal.Text = st.owner
						ownerVal.Color = colText
					} else {
						existsVal.Text = "✗ no"
						existsVal.Color = colDanger
						ownerVal.Text = "token does not exist"
						ownerVal.Color = colDanger
					}
					existsVal.Refresh()
					ownerVal.Refresh()

					// Sale state (doc §2: nil listing = unlisted, covering
					// never-listed, just bought, just cancelled, and cleared
					// by direct transfer — hide the buy button).
					if st.listed {
						listedVal.Text = "✓ yes"
						listedVal.Color = colAccent
						sellerVal.Text = st.seller
						sellerVal.Color = colText
						if st.priceNSPX != nil {
							priceVal.Text = formatNSPXAmount(st.priceNSPX) + " " + chainHeader.Symbol
							priceVal.Color = colText
						} else {
							priceVal.Text = "—"
							priceVal.Color = colMuted
						}
					} else {
						listedVal.Text = "✗ no"
						listedVal.Color = colMuted
						sellerVal.Text = "—"
						sellerVal.Color = colMuted
						priceVal.Text = "—"
						priceVal.Color = colMuted
					}
					listedVal.Refresh()
					sellerVal.Refresh()
					priceVal.Refresh()

					// Embedded economics (terms read error = legacy no-terms
					// token, per doc §4 — surfaced distinctly from "unlisted").
					if st.hasTerms {
						royaltyVal.Text = "✓ yes"
						royaltyVal.Color = colAccent

						creatorVal.Text = st.creator
						creatorVal.Color = colText

						if st.royaltyBPS > 0 {
							recipVal.Text = fmt.Sprintf("%d bps (%.2f%%) → %s",
								st.royaltyBPS, float64(st.royaltyBPS)/100, st.royaltyRecip)
							recipVal.Color = colText
						} else {
							recipVal.Text = "0 bps (legacy pass-through)"
							recipVal.Color = colMuted
						}

						if st.hasFee && st.feeNSPX != nil {
							feeVal.Text = formatNSPXAmount(st.feeNSPX) + " " + chainHeader.Symbol
							feeVal.Color = colText
						} else {
							feeVal.Text = "— no license fee"
							feeVal.Color = colMuted
						}

						if st.licensee != "" {
							if sameIdentity(st.licensee, sessionFingerprint) {
								licenseeVal.Text = "you"
								licenseeVal.Color = colAccent
							} else {
								licenseeVal.Text = st.licensee
								licenseeVal.Color = colText
							}
						} else {
							licenseeVal.Text = "— no active license"
							licenseeVal.Color = colMuted
						}
					} else {
						royaltyVal.Text = "✗ no (legacy token)"
						royaltyVal.Color = colMuted
						creatorVal.Text = "—"
						creatorVal.Color = colMuted
						recipVal.Text = "—"
						recipVal.Color = colMuted
						feeVal.Text = "—"
						feeVal.Color = colMuted
						licenseeVal.Text = "—"
						licenseeVal.Color = colMuted
					}
					royaltyVal.Refresh()
					creatorVal.Refresh()
					recipVal.Refresh()
					feeVal.Refresh()
					licenseeVal.Refresh()

					refreshResult.Text = fmt.Sprintf("Refreshed token %s.", tidStr)
					refreshResult.Refresh()

					if updateActionButtons != nil {
						updateActionButtons(st)
					}
				})
			}()
		}

		// callSIP721Method submits a signed SIP-721 write through the wallet
		// RPC layer. amountNSPX is the exact-value escrow the tx must carry
		// (integration doc §1): nil for list/cancel/revoke_license, the
		// exact price/fee for buy/purchase_license — the node rejects any
		// mismatch.
		callSIP721Method := func(collection, method string, args map[string]string, amountNSPX *big.Int) error {
			_, err := walletClient.CallSIP721(collection, method, args, amountNSPX)
			return err
		}

		listingBtn := widget.NewButtonWithIcon("List Item", theme.ContentAddIcon(), func() {
			if state.listed {
				showErrorDialog(errors.New("this token is already listed"), window)
				return
			}
			if state.owner == "" {
				showErrorDialog(errors.New("cannot list: token does not exist"), window)
				return
			}
			if !sameIdentity(state.owner, sessionFingerprint) {
				showErrorDialog(errors.New("only the token owner can list it"), window)
				return
			}
			rawPrice := priceEntry.Text
			if rawPrice == "" {
				showErrorDialog(errors.New("please enter a list price"), window)
				return
			}
			// The user enters the price in the selected unit; the contract
			// stores/expects an nSPX decimal string. SPX decimals convert
			// via rpc.go's parseSPXToNSPX; raw-nSPX entry validates via
			// parsePositiveDecimalNSPX (the canonical form listing_of
			// reports). Send the canonical nSPX form as price_nspx.
			var price *big.Int
			var parseErr error
			if unitSelectSelected == "nSPX" {
				price, parseErr = parsePositiveDecimalNSPX(rawPrice)
			} else {
				price, parseErr = parseSPXToNSPX(rawPrice)
			}
			if parseErr != nil || price == nil || price.Sign() <= 0 {
				showErrorDialog(fmt.Errorf("invalid list price: %w", parseErr), window)
				return
			}
			validatePassphraseDialog(window, "Confirm Listing",
				fmt.Sprintf("List token %s for %s %s?\n\nCollection: %s\nToken ID: %s",
					tokenIDEntry.Text, formatNSPXAmount(price), chainHeader.Symbol, collectionEntry.Text, tokenIDEntry.Text),
				func(passphrase string) {
					if err := callSIP721Method(collectionEntry.Text, "list",
						// "price" is the ABI-required argument name — the typed
						// SIP721Contract.List packs the same key and the node's
						// dispatcher reads it first (falling back to price_nspx).
						// Sending price_nspx alone failed EncodeCall with
						// "ABI method list requires price" before the tx could
						// ever reach the node.
						map[string]string{"token_id": tokenIDEntry.Text, "price": price.String()}, nil); err != nil {
						showErrorDialog(err, window)
						return
					}
					dialog.ShowInformation("Listed", fmt.Sprintf("Token %s is now listed for sale.", tokenIDEntry.Text), window)
					refreshListing()
				})
		})
		listingBtn.Importance = widget.HighImportance

		buyBtn := widget.NewButtonWithIcon("Buy Item", theme.ConfirmIcon(), func() {
			if !state.listed {
				showErrorDialog(errors.New("this token is not listed"), window)
				return
			}
			if sameIdentity(state.seller, sessionFingerprint) {
				showErrorDialog(errors.New("you cannot buy your own listing"), window)
				return
			}
			if state.priceNSPX == nil {
				showErrorDialog(errors.New("invalid listing price"), window)
				return
			}
			validatePassphraseDialog(window, "Confirm Purchase",
				fmt.Sprintf("Buy token %s for %s %s?\n\nSeller: %s…\n\nThe royalty (if any) will be paid to the creator automatically.",
					tokenIDEntry.Text, formatNSPXAmount(state.priceNSPX), chainHeader.Symbol, state.seller[:min(16, len(state.seller))]),
				func(passphrase string) {
					// buy is exact-value gated (doc §1): the tx must carry
					// exactly the listing price or the node reverts it.
					// Re-read once more immediately before submitting so a
					// stale cached price (doc §2) can't be sent.
					fresh, ferr := walletClient.GetSIP721Listing(collectionEntry.Text, tokenIDEntry.Text)
					if ferr != nil || fresh == nil {
						showErrorDialog(errors.New("listing changed — please refresh and try again"), window)
						refreshListing()
						return
					}
					if err := callSIP721Method(collectionEntry.Text, "buy",
						map[string]string{"token_id": tokenIDEntry.Text}, fresh.Price); err != nil {
						showErrorDialog(err, window)
						return
					}
					dialog.ShowInformation("Purchased", fmt.Sprintf("You now own token %s.", tokenIDEntry.Text), window)
					refreshListing()
				})
		})
		buyBtn.Importance = widget.HighImportance

		cancelBtn := widget.NewButtonWithIcon("Cancel Listing", theme.CancelIcon(), func() {
			if !state.listed {
				showErrorDialog(errors.New("there is no listing to cancel"), window)
				return
			}
			if !sameIdentity(state.seller, sessionFingerprint) {
				showErrorDialog(errors.New("only the listing seller can cancel"), window)
				return
			}
			validatePassphraseDialog(window, "Confirm Cancel",
				fmt.Sprintf("Cancel the listing for token %s?\n\nCollection: %s\nToken ID: %s",
					tokenIDEntry.Text, collectionEntry.Text, tokenIDEntry.Text),
				func(passphrase string) {
					if err := callSIP721Method(collectionEntry.Text, "cancel",
						map[string]string{"token_id": tokenIDEntry.Text}, nil); err != nil {
						showErrorDialog(err, window)
						return
					}
					dialog.ShowInformation("Cancelled", "Listing cancelled.", window)
					refreshListing()
				})
		})
		cancelBtn.Importance = widget.MediumImportance

		purchaseLicenseBtn := widget.NewButtonWithIcon("Purchase License", theme.DocumentIcon(), func() {
			if !state.hasTerms || !state.hasFee || state.feeNSPX == nil {
				showErrorDialog(errors.New("this token has no license fee set"), window)
				return
			}
			if sameIdentity(state.licensee, sessionFingerprint) {
				showErrorDialog(errors.New("you already hold an active license for this token"), window)
				return
			}
			validatePassphraseDialog(window, "Confirm License Purchase",
				fmt.Sprintf("Purchase a license for token %s?\n\nFee: %s %s (paid to the creator)",
					tokenIDEntry.Text, formatNSPXAmount(state.feeNSPX), chainHeader.Symbol),
				func(passphrase string) {
					// purchase_license is exact-value gated (doc §1) — re-read
					// the fee immediately before submitting, same as buy.
					fresh, ferr := walletClient.GetSIP721Terms(collectionEntry.Text, tokenIDEntry.Text)
					if ferr != nil || fresh == nil || fresh.UsageFeeNSPX == nil {
						showErrorDialog(errors.New("license terms changed — please refresh and try again"), window)
						refreshListing()
						return
					}
					if err := callSIP721Method(collectionEntry.Text, "purchase_license",
						map[string]string{"token_id": tokenIDEntry.Text}, fresh.UsageFeeNSPX); err != nil {
						showErrorDialog(err, window)
						return
					}
					dialog.ShowInformation("Licensed", fmt.Sprintf("License purchased for token %s.", tokenIDEntry.Text), window)
					refreshListing()
				})
		})
		purchaseLicenseBtn.Importance = widget.HighImportance

		revokeLicenseBtn := widget.NewButtonWithIcon("Revoke License", theme.DeleteIcon(), func() {
			if !sameIdentity(state.licensee, sessionFingerprint) {
				showErrorDialog(errors.New("you don't hold an active license to revoke"), window)
				return
			}
			validatePassphraseDialog(window, "Confirm Revoke",
				fmt.Sprintf("Revoke your license for token %s? This cannot be undone — you would need to purchase again to regain access.", tokenIDEntry.Text),
				func(passphrase string) {
					if err := callSIP721Method(collectionEntry.Text, "revoke_license",
						map[string]string{"token_id": tokenIDEntry.Text}, nil); err != nil {
						showErrorDialog(err, window)
						return
					}
					dialog.ShowInformation("Revoked", "License revoked.", window)
					refreshListing()
				})
		})
		revokeLicenseBtn.Importance = widget.MediumImportance

		// All actions start disabled — nothing is known about any token
		// until the first lookup completes.
		listingBtn.Disable()
		buyBtn.Disable()
		cancelBtn.Disable()
		purchaseLicenseBtn.Disable()
		revokeLicenseBtn.Disable()

		updateActionButtons = func(st *liveState) {
			setEnabled := func(b *widget.Button, ok bool) {
				if ok {
					b.Enable()
				} else {
					b.Disable()
				}
			}
			setEnabled(listingBtn, st.exists && !st.listed && sameIdentity(st.owner, sessionFingerprint))
			setEnabled(buyBtn, st.listed && !sameIdentity(st.seller, sessionFingerprint) && st.priceNSPX != nil)
			setEnabled(cancelBtn, st.listed && sameIdentity(st.seller, sessionFingerprint))
			setEnabled(purchaseLicenseBtn, st.hasTerms && st.hasFee && st.feeNSPX != nil && !sameIdentity(st.licensee, sessionFingerprint))
			setEnabled(revokeLicenseBtn, sameIdentity(st.licensee, sessionFingerprint))
		}

		saleActions := container.NewVBox(
			sectionLabel("Sale"),
			spacer(8),
			container.NewHBox(listingBtn, spacer(8), buyBtn, spacer(8), cancelBtn),
		)
		licenseActions := container.NewVBox(
			sectionLabel("Licensing"),
			spacer(8),
			container.NewHBox(purchaseLicenseBtn, spacer(8), revokeLicenseBtn),
		)

		// infoRowDynamic binds the live canvas.Text widgets so the panel
		// updates when refreshListing completes (infoRow would snapshot the
		// initial "—" text and never change). Split into two cards so sale
		// state and royalty/license terms don't blur into one flat list.
		listingCard := styledCard(container.NewVBox(
			sectionLabel("Listing"),
			spacer(8),
			infoRowDynamic("Exists", existsVal),
			infoRowDynamic("Owner", ownerVal),
			infoRowDynamic("Listed", listedVal),
			infoRowDynamic("Seller", sellerVal),
			infoRowDynamic("Price", priceVal),
		), 0, 0)

		royaltyCard := styledCard(container.NewVBox(
			sectionLabel("Royalty & Licensing"),
			spacer(8),
			infoRowDynamic("Has Terms", royaltyVal),
			infoRowDynamic("Creator", creatorVal),
			infoRowDynamic("Royalty", recipVal),
			infoRowDynamic("License Fee", feeVal),
			infoRowDynamic("Licensee", licenseeVal),
		), 0, 0)

		panel := container.NewVBox(
			statusCard,
			spacer(16),
			listingCard,
			spacer(12),
			royaltyCard,
			spacer(12),
			container.NewCenter(refreshResult),
			spacer(16),
			alertBox("Marketplace actions require exact-value escrow. The node enforces buy price and license fees exactly — no overpay or partial-pay paths exist.",
				color.RGBA{96, 165, 250, 20}, colInfo),
			spacer(12),
			alertBox("Listings are cleared automatically by any direct transfer. This screen re-reads the price/fee right before submitting a buy or license purchase.",
				color.RGBA{255, 179, 71, 20}, colWarn),
		)

		form := container.NewVBox(
			screenTitle("Marketplace"),
			spacer(4),
			screenSubtitle(fmt.Sprintf("Buy, sell, and license SIP-721 tokens on %s", chainHeader.ChainName)),
			spacer(20),
			sectionLabel("Collection & Token"),
			spacer(6),
			collectionEntry,
			spacer(12),
			tokenIDEntry,
			spacer(16),
			discoverCard,
			spacer(16),
			sectionLabel("List Price"),
			spacer(6),
			priceRow,
			container.NewPadded(pricePreview),
			spacer(16),
			refreshBtn,
			spacer(20),
			hRule(),
			spacer(16),
			saleActions,
			spacer(16),
			licenseActions,
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
						showErrorDialog(fmt.Errorf("failed to generate passphrase: %w", err), window)
						progBar.Hide()
						progLabel.Hide()
						generateBtn.Enable()
						generateBtn.SetText("Setup Master Key")
					})
					return
				}

				if len(passphrase) < 8 {
					fyne.Do(func() {
						showErrorDialog(fmt.Errorf("generated passphrase is too short (%d chars), need at least 8", len(passphrase)), window)
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
						showErrorDialog(err, window)
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
							showErrorDialog(err, window)
							return
						}
						kp, _, err := keys.LoadKeyFromDisk(passEntry.Text)
						if err != nil {
							errorMsg := "Failed to load key pair: " + err.Error()
							if strings.Contains(err.Error(), "decryption") || strings.Contains(err.Error(), "passphrase") {
								errorMsg = "Wrong passphrase. Please try again."
							}
							showErrorDialog(errors.New(errorMsg), window)
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
		marketBtn := navBtn("Marketplace", theme.ListIcon(), showMarketplaceScreen)

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
			marketBtn,
			spacer(4),
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
					showErrorDialog(err, window)
					return
				}
				kp, _, err := keys.LoadKeyFromDisk(passEntry.Text)
				if err != nil {
					errorMsg := "Failed to load key pair: " + err.Error()
					if strings.Contains(err.Error(), "decryption") || strings.Contains(err.Error(), "passphrase") {
						errorMsg = "Wrong passphrase. Please try again."
					}
					showErrorDialog(errors.New(errorMsg), window)
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
