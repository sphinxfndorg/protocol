package gui

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	console "github.com/sphinxfndorg/protocol/src/console"
	"github.com/sphinxfndorg/protocol/src/rpc"
)

type syncResponse struct {
	Syncing  bool     `json:"syncing"`
	Current  uint64   `json:"current_height"`
	Target   uint64   `json:"highest_known_peer_height"`
	Peers    int      `json:"peer_count"`
	Progress *float64 `json:"progress_percent"`
	State    string   `json:"state"`
	Age      int64    `json:"observed_age_ms"`
}

func fetchSync(addr string) (syncResponse, error) {
	b, err := rpc.CallRPC(addr, "getsyncstatus", nil, 10)
	if err != nil {
		return syncResponse{}, err
	}
	var out syncResponse
	err = json.Unmarshal(b, &out)
	return out, err
}
func synced(s syncResponse) bool { return sendGate(s.Syncing, s.Peers, s.Age) }

func Run() {
	console.DisableSignalHandler()
	a := app.NewWithID("org.sphinx.wallet")
	w := a.NewWindow("SPX Wallet")
	w.Resize(fyne.NewSize(1050, 700))
	cfg := DefaultNodeConfig()
	node := &EmbeddedNode{}
	if err := node.Start(cfg); err != nil {
		dialog.ShowError(err, w)
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go func() { <-ctx.Done(); _ = node.Stop(20 * time.Second); a.Quit() }()
	stop := func() { _ = node.Stop(20 * time.Second) }
	w.SetCloseIntercept(func() { stop(); a.Quit() })
	a.Lifecycle().SetOnStopped(stop)

	status := widget.NewLabel("Starting node…")
	progress := widget.NewProgressBar()
	heights := widget.NewLabel("Current: —  Target: —  Peers: 0")
	logView := widget.NewMultiLineEntry()
	logView.Wrapping = fyne.TextWrapWord
	logView.Disable()
	networkLabel := widget.NewLabel("Network: checking…")
	recipient := widget.NewEntry()
	recipient.SetPlaceHolder("SPIF recipient")
	amount := widget.NewEntry()
	amount.SetPlaceHolder("Amount in SPX")
	pass := widget.NewPasswordEntry()
	pass.SetPlaceHolder("Wallet passphrase")
	address := widget.NewLabel("No wallet unlocked")
	balance := widget.NewLabel("Balance: —")
	history := widget.NewMultiLineEntry()
	history.Disable()
	var wallet *Wallet
	var latest syncResponse
	sendButton := widget.NewButton("Send", func() {
		if !synced(latest) {
			dialog.ShowInformation("Not synced", "Sending is disabled until the node is synced with at least one fresh peer.", w)
			return
		}
		if wallet == nil {
			dialog.ShowInformation("Unlock wallet", "Unlock or create a wallet first.", w)
			return
		}
		go func() {
			id, err := sendSPX(wallet, node.RPCAddr(), recipient.Text, amount.Text)
			fyne.Do(func() {
				if err != nil {
					dialog.ShowError(err, w)
				} else {
					dialog.ShowInformation("Transaction sent", id, w)
				}
			})
		}()
	})
	refreshWallet := func() {
		if wallet == nil {
			return
		}
		go func() {
			wallet.Attach(node.RPCAddr())
			b, err := wallet.Client.GetBalance(wallet.Address)
			h, herr := wallet.Client.GetTransactionHistory(wallet.Address, 25)
			fyne.Do(func() {
				if err == nil && b != nil && b.Balance.Int != nil {
					balance.SetText("Balance: " + formatSPX(b.Balance.Int))
				}
				if herr == nil {
					var lines []string
					for _, tx := range h {
						lines = append(lines, fmt.Sprintf("%s  %s  %s", tx.Status, tx.TxID, formatSPX(tx.Amount.Int)))
					}
					history.SetText(strings.Join(lines, "\n"))
				}
			})
		}()
	}
	unlock := widget.NewButton("Unlock", func() {
		go func() {
			x, err := UnlockWallet(pass.Text)
			fyne.Do(func() {
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				wallet = x
				address.SetText(x.Address)
				refreshWallet()
			})
		}()
	})
	create := widget.NewButton("Create", func() {
		go func() {
			x, err := CreateWallet(pass.Text)
			fyne.Do(func() {
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				wallet = x
				address.SetText(x.Address)
				refreshWallet()
			})
		}()
	})

	syncScreen := container.NewBorder(container.NewVBox(status, progress, heights, networkLabel), nil, nil, nil, logView)
	walletScreen := container.NewBorder(container.NewVBox(address, balance, container.NewHBox(pass, unlock, create)), container.NewVBox(recipient, amount, sendButton), nil, nil, history)
	content := container.NewMax(walletScreen)
	show := func(obj fyne.CanvasObject) { content.Objects = []fyne.CanvasObject{obj}; content.Refresh() }
	walletTab := widget.NewButtonWithIcon("Wallet", theme.AccountIcon(), func() { show(walletScreen) })
	nodeTab := widget.NewButtonWithIcon("Sync / Node", theme.ComputerIcon(), func() { show(syncScreen) })
	side := container.NewVBox(widget.NewLabel("SPX Wallet"), walletTab, nodeTab, widget.NewButton("Settings", func() { dialog.ShowInformation("Settings", "Data directory: "+cfg.DataDir, w) }))
	w.SetContent(container.NewHSplit(side, content))
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for range t.C {
			s, err := fetchSync(node.RPCAddr())
			logs := node.Logs()
			fyne.Do(func() {
				if err != nil {
					status.SetText("Status unavailable")
					progress.SetValue(0)
					return
				}
				latest = s
				if synced(s) {
					status.SetText("Synced")
					progress.SetValue(1)
				} else if s.Peers == 0 {
					status.SetText("No peers")
					progress.SetValue(0)
				} else {
					status.SetText("Syncing")
					if s.Progress != nil {
						progress.SetValue(*s.Progress / 100)
					}
				}
				heights.SetText(fmt.Sprintf("Current: %d  Target: %d  Peers: %d", s.Current, s.Target, s.Peers))
				logView.SetText(logs)
				if info, e := rpc.CallRPC(node.RPCAddr(), "getnetworkinfo", nil, 10); e == nil {
					networkLabel.SetText("Network: " + string(info))
				}
				sendButton.Enable()
				if !synced(s) {
					sendButton.Disable()
				}
			})
		}
	}()
	a.Run()
}

func formatSPX(i interface{ String() string }) string {
	if i == nil {
		return "0 SPX"
	}
	v, _, err := new(big.Float).Parse(i.String(), 10)
	if err != nil {
		return i.String() + " nSPX"
	}
	return new(big.Float).Quo(v, big.NewFloat(1e18)).Text('f', 6) + " SPX"
}
