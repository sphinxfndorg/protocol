// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/console/console.go
package logger

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// TerminalLogger provides a high-level interface for terminal-aware logging
// with integrated live progress display for blockchain node operations.
type TerminalLogger struct {
	renderer *Renderer
	log      *Logger
	progress *BlockchainProgress
}

// NewTerminalLogger creates a terminal-aware logger with live progress support.
// It automatically detects TTY capabilities and sets up proper signal handlers.
func NewTerminalLogger(out io.Writer) *TerminalLogger {
	r := NewRenderer(out)
	log := NewLogger(r)
	log.SetLevel(INFO)

	return &TerminalLogger{
		renderer: r,
		log:      log,
		progress: NewBlockchainProgress(r, log),
	}
}

// Renderer returns the underlying renderer for advanced usage.
func (tl *TerminalLogger) Renderer() *Renderer {
	return tl.renderer
}

// Logger returns the underlying logger for direct log calls.
func (tl *TerminalLogger) Logger() *Logger {
	return tl.log
}

// Progress returns the blockchain progress dashboard.
func (tl *TerminalLogger) Progress() *BlockchainProgress {
	return tl.progress
}

// Log methods delegate to the underlying logger with all standard levels.
func (tl *TerminalLogger) Trace(format string, args ...interface{}) {
	tl.log.Trace(format, args...)
}

func (tl *TerminalLogger) Debug(format string, args ...interface{}) {
	tl.log.Debug(format, args...)
}

func (tl *TerminalLogger) Info(format string, args ...interface{}) {
	tl.log.Info(format, args...)
}

func (tl *TerminalLogger) Success(format string, args ...interface{}) {
	tl.log.Success(format, args...)
}

func (tl *TerminalLogger) Warn(format string, args ...interface{}) {
	tl.log.Warn(format, args...)
}

func (tl *TerminalLogger) Error(format string, args ...interface{}) {
	tl.log.Error(format, args...)
}

func (tl *TerminalLogger) Fatal(format string, args ...interface{}) {
	tl.log.Fatal(format, args...)
}

// Stop cleanly shuts down the terminal logger, restoring cursor and clearing live regions.
func (tl *TerminalLogger) Stop() {
	if tl.progress != nil {
		tl.progress.Stop()
	}
	tl.renderer.Shutdown()
}

// Recover restores terminal state on panic and rethrows.
func (tl *TerminalLogger) Recover() {
	if r := recover(); r != nil {
		tl.Stop()
		panic(r)
	}
}

// With creates a derived terminal logger with an additional field.
func (tl *TerminalLogger) With(key string, value interface{}) *TerminalLogger {
	return &TerminalLogger{
		renderer: tl.renderer,
		log:      tl.log.With(key, value),
		progress: tl.progress,
	}
}

// IsTTY reports whether output is an interactive terminal.
func (tl *TerminalLogger) IsTTY() bool {
	return tl.renderer.IsTTY()
}

// TerminalAware sets up a terminal logger with signal handlers for graceful shutdown.
// It returns a TerminalLogger and a cancel function that triggers clean shutdown.
func TerminalAware(out io.Writer) (*TerminalLogger, func()) {
	tl := NewTerminalLogger(out)

	cancel := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		tl.Stop()
		close(cancel)
	}()

	return tl, func() {
		signal.Stop(sigCh)
		tl.Stop()
	}
}

// DefaultTerminalLogger creates a terminal logger using stdout with signal handlers.
// This is the default entry point for CLI applications.
func DefaultTerminalLogger() *TerminalLogger {
	tl, _ := TerminalAware(os.Stdout)
	return tl
}

// BlockchainProgress wires together a MultiProgress, a StatusLine and a
// Logger into a dashboard covering the full lifecycle of a blockchain
// node: startup, genesis, peers, header/block sync, verification,
// consensus, block production, mempool and network health.
//
// Only genuinely long-running or measurable operations animate (spinners
// or progress bars). One-off events (chain divergence, a completed block)
// and continuously-changing stats (mempool size, validator counts) are
// either logged once as a permanent line or reflected in the always-on
// status line -- never both, and never animated needlessly.
type BlockchainProgress struct {
	r      *Renderer
	log    *Logger
	multi  *MultiProgress
	status *StatusLine

	mu          sync.Mutex
	localHeight uint64
	networkTip  uint64
	rate        float64 // blocks/sec, from whichever sync phase is active
	peers       int
	consensus   string // consensus status string
	network     string // network status string (ONLINE/DEGRADED)
	startedAt   time.Time
}

// NewBlockchainProgress builds a dashboard on top of r and log. Passing an
// explicit Logger (rather than constructing one internally) lets callers
// share one Logger, with consistent level filtering, across the whole
// node.
func NewBlockchainProgress(r *Renderer, log *Logger) *BlockchainProgress {
	bp := &BlockchainProgress{
		r:         r,
		log:       log,
		multi:     NewMultiProgress(r),
		status:    NewStatusLine(),
		startedAt: time.Now(),
		network:   fmt.Sprintf("%sONLINE%s", FGGreen, ResetColor),
		consensus: "INITIALIZING",
	}
	bp.status.SetTitle("SPHINX Node")
	r.Attach(bp.status)
	// Every node gets a "Block synchronization" bar from the moment its
	// dashboard exists, regardless of whether it ever falls behind a peer.
	// Previously this bar was only created on-demand inside runBlockSyncLoop
	// (StartBlockSync, helpers.go) when a node discovered it was behind —
	// so the bootstrap node (which never has anything to download from a
	// peer) and any node that happened to already be caught up the first
	// time it checked never showed the line at all, purely as an accident
	// of startup timing. Creating it here, and never completing/removing it
	// (see UpdateBlockSync and the removed CompleteBlockSync call sites in
	// helpers.go), makes it a permanent, continuously-updated part of the
	// dashboard on every node, exactly like Height/Sync/Rate.
	bp.StartBlockSync(0)
	bp.refreshStatus()
	return bp
}

// Renderer returns the underlying renderer for UI operations.
func (bp *BlockchainProgress) Renderer() *Renderer {
	return bp.r
}

// ============================================================================
// Node startup / genesis
// ============================================================================

// StartNodeStartup begins the node initialization spinner.
func (bp *BlockchainProgress) StartNodeStartup() {
	bp.multi.AddSpinner("node-startup", "Initializing node")
}

// CompleteNodeStartup marks startup complete.
func (bp *BlockchainProgress) CompleteNodeStartup() {
	if sp, ok := bp.multi.Spinner("node-startup"); ok {
		sp.Stop(SpinnerSuccess, "Node initialized")
	}
}

// FailNodeStartup marks startup as failed.
func (bp *BlockchainProgress) FailNodeStartup(err error) {
	if sp, ok := bp.multi.Spinner("node-startup"); ok {
		sp.Stop(SpinnerError, fmt.Sprintf("Node startup failed: %v", err))
	}
}

// StartGenesisInit begins genesis block initialization/verification.
func (bp *BlockchainProgress) StartGenesisInit() {
	bp.multi.AddSpinner("genesis-init", "Genesis initialization")
}

// CompleteGenesisInit marks genesis verified, with its hash truncated for
// display.
func (bp *BlockchainProgress) CompleteGenesisInit(genesisHash string) {
	h := genesisHash
	if len(h) > 16 {
		h = h[:16]
	}
	if sp, ok := bp.multi.Spinner("genesis-init"); ok {
		sp.Stop(SpinnerSuccess, fmt.Sprintf("Genesis verified (%s)", h))
	}
}

// FailGenesisInit marks genesis initialization as failed.
func (bp *BlockchainProgress) FailGenesisInit(err error) {
	if sp, ok := bp.multi.Spinner("genesis-init"); ok {
		sp.Stop(SpinnerError, fmt.Sprintf("Genesis failed: %v", err))
	}
}

// ============================================================================
// Peer discovery, connection and reconnection
// ============================================================================

// StartPeerDiscovery begins the peer discovery spinner.
func (bp *BlockchainProgress) StartPeerDiscovery() {
	bp.multi.AddSpinner("peer-discovery", "Discovering peers")
}

// UpdatePeerDiscovery reports discovery progress without ending it.
func (bp *BlockchainProgress) UpdatePeerDiscovery(found, connected int) {
	if sp, ok := bp.multi.Spinner("peer-discovery"); ok {
		sp.UpdateMessage(fmt.Sprintf("Discovering peers: %d found (%d connected)", found, connected))
	}
	bp.setPeers(connected)
}

// CompletePeerDiscovery marks discovery complete with a final peer count.
func (bp *BlockchainProgress) CompletePeerDiscovery(peerCount int) {
	if sp, ok := bp.multi.Spinner("peer-discovery"); ok {
		sp.Stop(SpinnerSuccess, fmt.Sprintf("Discovered %d peers", peerCount))
	}
	bp.setPeers(peerCount)
}

// PeerConnected logs a new peer connection. Bursts of connect/disconnect
// churn (e.g. during a network blip) are rate-limited to one line per
// second so a flapping peer can't flood the terminal.
func (bp *BlockchainProgress) PeerConnected(peerID string) {
	bp.log.Limited("peer-churn", time.Second).Info("Peer connected: %s", peerID)
	bp.adjustPeers(1)
}

// PeerDisconnected logs a peer disconnection, same rate limiting as
// PeerConnected.
func (bp *BlockchainProgress) PeerDisconnected(peerID string) {
	bp.log.Limited("peer-churn", time.Second).Warn("Peer disconnected: %s", peerID)
	bp.adjustPeers(-1)
}

// StartPeerReconnect begins a reconnection spinner for a specific peer.
func (bp *BlockchainProgress) StartPeerReconnect(peerID string) {
	bp.multi.AddSpinner("reconnect-"+peerID, fmt.Sprintf("Reconnecting to %s", peerID))
}

// CompletePeerReconnect marks a reconnection attempt as successful.
func (bp *BlockchainProgress) CompletePeerReconnect(peerID string) {
	if sp, ok := bp.multi.Spinner("reconnect-" + peerID); ok {
		sp.Stop(SpinnerSuccess, fmt.Sprintf("Reconnected to %s", peerID))
	}
	bp.adjustPeers(1)
}

// FailPeerReconnect marks a reconnection attempt as failed.
func (bp *BlockchainProgress) FailPeerReconnect(peerID string, err error) {
	if sp, ok := bp.multi.Spinner("reconnect-" + peerID); ok {
		sp.Stop(SpinnerError, fmt.Sprintf("Failed to reconnect to %s: %v", peerID, err))
	}
}

func (bp *BlockchainProgress) setPeers(n int) {
	bp.mu.Lock()
	bp.peers = n
	bp.mu.Unlock()
	bp.refreshStatus()
}

func (bp *BlockchainProgress) adjustPeers(delta int) {
	bp.mu.Lock()
	bp.peers += delta
	if bp.peers < 0 {
		bp.peers = 0
	}
	bp.mu.Unlock()
	bp.refreshStatus()
}

// ============================================================================
// Header / block synchronization and verification
// ============================================================================

// StartHeaderSync begins a determinate header-sync progress bar.
func (bp *BlockchainProgress) StartHeaderSync(totalHeaders int64) {
	bp.multi.AddProgressBar("header-sync", "Header synchronization", totalHeaders, "hdr")
}

// UpdateHeaderSync reports header sync progress and updates the
// height-vs-tip status fields.
func (bp *BlockchainProgress) UpdateHeaderSync(current, total int64) {
	if pb, ok := bp.multi.Bar("header-sync"); ok {
		pb.Set(current)
	}
	bp.setHeight(uint64(current), uint64(total), 0)
}

// CompleteHeaderSync marks header sync complete.
func (bp *BlockchainProgress) CompleteHeaderSync() {
	if pb, ok := bp.multi.Bar("header-sync"); ok {
		pb.Complete()
	}
}

// StartBlockSync begins a determinate block-sync progress bar.
func (bp *BlockchainProgress) StartBlockSync(totalBlocks int64) {
	bp.multi.AddProgressBar("block-sync", "Block synchronization", totalBlocks, "blk")
}

// UpdateBlockSync reports block sync progress, download rate, and updates
// the height-vs-tip / rate / ETA status fields.
func (bp *BlockchainProgress) UpdateBlockSync(current, total int64) {
	if pb, ok := bp.multi.Bar("block-sync"); ok {
		pb.SetTotal(total)
		pb.Set(current)
		_, _, _, rate, _ := pb.Stats()
		bp.setHeight(uint64(current), uint64(total), rate)
		return
	}
	bp.setHeight(uint64(current), uint64(total), 0)
}

// CompleteBlockSync marks block sync complete.
func (bp *BlockchainProgress) CompleteBlockSync() {
	if pb, ok := bp.multi.Bar("block-sync"); ok {
		pb.Complete()
	}
}

// HasProgressBar checks if a progress bar with the given ID exists.
func (bp *BlockchainProgress) HasProgressBar(id string) bool {
	_, ok := bp.multi.Bar(id)
	return ok
}

// StartBlockVerification begins a determinate verification progress bar.
func (bp *BlockchainProgress) StartBlockVerification(totalBlocks int64) {
	bp.multi.AddProgressBar("block-verify", "Verifying blocks", totalBlocks, "blk")
}

// UpdateBlockVerification reports verification progress.
func (bp *BlockchainProgress) UpdateBlockVerification(current int64) {
	if pb, ok := bp.multi.Bar("block-verify"); ok {
		pb.Set(current)
	}
}

// CompleteBlockVerification marks verification complete.
func (bp *BlockchainProgress) CompleteBlockVerification() {
	if pb, ok := bp.multi.Bar("block-verify"); ok {
		pb.Complete()
	}
}

// FailBlockVerification marks verification as failed.
func (bp *BlockchainProgress) FailBlockVerification() {
	if pb, ok := bp.multi.Bar("block-verify"); ok {
		pb.Fail()
	}
}

// StartCatchupSync begins a determinate catch-up sync bar for a
// currently-lagging node.
func (bp *BlockchainProgress) StartCatchupSync(blocksBehind int64) {
	bp.multi.AddProgressBar("catchup-sync", "Catch-up synchronization", blocksBehind, "blk")
}

// UpdateCatchupSync reports blocks caught up so far.
func (bp *BlockchainProgress) UpdateCatchupSync(caughtUp int64) {
	if pb, ok := bp.multi.Bar("catchup-sync"); ok {
		pb.Set(caughtUp)
	}
}

// CompleteCatchupSync marks catch-up as complete.
func (bp *BlockchainProgress) CompleteCatchupSync() {
	if pb, ok := bp.multi.Bar("catchup-sync"); ok {
		pb.Complete()
	}
}

func (bp *BlockchainProgress) setHeight(local, tip uint64, rate float64) {
	bp.mu.Lock()
	bp.localHeight = local
	bp.networkTip = tip
	if rate > 0 {
		bp.rate = rate
	}
	bp.mu.Unlock()
	bp.refreshStatus()
}

// LocalHeight, NetworkTip, BlocksRemaining, SyncPercent and IsSyncing are
// read-only queries against the last reported height/tip, useful for
// callers deciding when to transition out of a SYNCING state.

func (bp *BlockchainProgress) LocalHeight() uint64 {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	return bp.localHeight
}

func (bp *BlockchainProgress) NetworkTip() uint64 {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	return bp.networkTip
}

func (bp *BlockchainProgress) BlocksRemaining() uint64 {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	if bp.networkTip > bp.localHeight {
		return bp.networkTip - bp.localHeight
	}
	return 0
}

func (bp *BlockchainProgress) SyncPercent() float64 {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	if bp.networkTip == 0 {
		return 0
	}
	return float64(bp.localHeight) / float64(bp.networkTip) * 100
}

func (bp *BlockchainProgress) IsSyncing() bool {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	return bp.localHeight < bp.networkTip
}

// ============================================================================
// Chain divergence, fork resolution
// ============================================================================

// DetectChainDivergence logs a one-off warning; divergence is a discrete
// event, not an ongoing operation, so it is never animated.
func (bp *BlockchainProgress) DetectChainDivergence(localHash, networkHash string) {
	l, n := localHash, networkHash
	if len(l) > 16 {
		l = l[:16]
	}
	if len(n) > 16 {
		n = n[:16]
	}
	bp.log.Warn("Chain divergence detected (local=%s, network=%s)", l, n)
}

// StartForkResolution begins the fork-resolution spinner.
func (bp *BlockchainProgress) StartForkResolution() {
	bp.multi.AddSpinner("fork-resolution", "Resolving fork")
}

// CompleteForkResolution marks fork resolution finished, reporting how many
// blocks were reorganized.
func (bp *BlockchainProgress) CompleteForkResolution(blocksReorged int) {
	if sp, ok := bp.multi.Spinner("fork-resolution"); ok {
		sp.Stop(SpinnerSuccess, fmt.Sprintf("Fork resolved (%d blocks reorganized)", blocksReorged))
	}
}

// FailForkResolution marks fork resolution as failed.
func (bp *BlockchainProgress) FailForkResolution(err error) {
	if sp, ok := bp.multi.Spinner("fork-resolution"); ok {
		sp.Stop(SpinnerError, fmt.Sprintf("Fork resolution failed: %v", err))
	}
}

// ============================================================================
// Consensus
// ============================================================================

// StartConsensus begins the consensus-startup spinner.
func (bp *BlockchainProgress) StartConsensus() {
	bp.multi.AddSpinner("consensus-start", "Starting consensus")
}

// CompleteConsensusStart marks consensus as active.
func (bp *BlockchainProgress) CompleteConsensusStart() {
	if sp, ok := bp.multi.Spinner("consensus-start"); ok {
		sp.Stop(SpinnerSuccess, "Consensus active")
	}
}

// UpdateConsensusRound reports round and quorum progress in the status
// line. Rounds happen frequently, so this is a status update, not a log
// line -- logging every round would flood the terminal for no benefit.
func (bp *BlockchainProgress) UpdateConsensusRound(round, totalRounds int64, quorum, totalValidators int) {
	bp.status.Set("Consensus", fmt.Sprintf("round %d/%d (quorum %d/%d)", round, totalRounds, quorum, totalValidators))
}

// CompleteConsensusRound logs the round's outcome, rate-limited so a fast
// steady-state consensus loop doesn't flood the terminal with a line per
// round.
func (bp *BlockchainProgress) CompleteConsensusRound(round int64) {
	bp.log.Limited("consensus-round", 2*time.Second).Debug("Consensus round %d committed", round)
}

// UpdateValidatorStatus reflects active/total validator counts in the
// status line.
func (bp *BlockchainProgress) UpdateValidatorStatus(active, total int) {
	bp.status.Set("Validators", fmt.Sprintf("%d/%d active", active, total))
}

// ============================================================================
// Block production
// ============================================================================

// StartBlockProduction begins the block-production spinner for the block
// currently being minted.
func (bp *BlockchainProgress) StartBlockProduction() {
	bp.multi.AddSpinner("block-production", "Producing block")
}

// UpdateBlockProductionStage relabels the in-flight block-production
// spinner with the sub-step currently running (selecting transactions,
// calculating the merkle root, calculating the state root, mining the
// nonce, ...). These sub-steps are normally sub-second, so they update the
// existing spinner's message rather than getting spinners of their own --
// consistent with the "never animated needlessly" rule above. A no-op if
// no block-production spinner is currently active.
func (bp *BlockchainProgress) UpdateBlockProductionStage(stage string) {
	if sp, ok := bp.multi.Spinner("block-production"); ok {
		sp.UpdateMessage(fmt.Sprintf("Producing block — %s", stage))
	}
}

// CompleteBlockProduction marks a block as produced.
func (bp *BlockchainProgress) CompleteBlockProduction(blockHash string, txCount int) {
	h := blockHash
	if len(h) > 16 {
		h = h[:16]
	}
	if sp, ok := bp.multi.Spinner("block-production"); ok {
		sp.Stop(SpinnerSuccess, fmt.Sprintf("Block produced %s (%d tx)", h, txCount))
	}
}

// FailBlockProduction marks block production as failed.
func (bp *BlockchainProgress) FailBlockProduction(err error) {
	if sp, ok := bp.multi.Spinner("block-production"); ok {
		sp.Stop(SpinnerError, fmt.Sprintf("Block production failed: %v", err))
	}
}

// ============================================================================
// Mempool and network health
// ============================================================================

// UpdateMempoolActivity reflects mempool size and throughput in the status
// line. This is a continuous stat, not a task, so it is never animated or
// logged on its own.
func (bp *BlockchainProgress) UpdateMempoolActivity(pending int, txPerSecond float64) {
	bp.status.Set("Mempool", fmt.Sprintf("%s pending (%.1f tx/s)", formatNumber(int64(pending)), txPerSecond))
}

// CheckNetworkHealth reflects network health in the status line and logs a
// warning line on unhealthy transitions (rate-limited so a flapping
// network doesn't flood the terminal with repeated warnings).
func (bp *BlockchainProgress) CheckNetworkHealth(healthy bool, peerCount int) {
	bp.mu.Lock()
	if healthy {
		bp.network = fmt.Sprintf("%sONLINE%s", FGGreen, ResetColor)
	} else {
		bp.network = fmt.Sprintf("%sDEGRADED%s", FGYellow, ResetColor)
	}
	bp.mu.Unlock()
	if !healthy {
		bp.log.Limited("network-health", 5*time.Second).Warn("Network unhealthy (%d peers)", peerCount)
	}
	bp.setPeers(peerCount)
}

// SetConsensusStatus updates the consensus status string displayed in the status line
func (bp *BlockchainProgress) SetConsensusStatus(status string) {
	bp.mu.Lock()
	bp.consensus = status
	bp.mu.Unlock()
	bp.refreshStatus()
}

// refreshStatus updates the status line with all current metrics
func (bp *BlockchainProgress) refreshStatus() {
	bp.mu.Lock()
	local, tip, rate, peers := bp.localHeight, bp.networkTip, bp.rate, bp.peers
	bp.mu.Unlock()

	// Clear and rebuild status line for consistent ordering. Consensus is
	// cleared and re-set last (below) so it always renders as the final
	// line of the panel -- previously it was set right after Height and
	// never cleared/re-appended, so it rendered ahead of Sync/Behind/
	// Rate/ETA instead of after them, in both solo and PBFT mode.
	bp.status.Clear("Sync")
	bp.status.Clear("Behind")
	bp.status.Clear("Rate")
	bp.status.Clear("ETA")
	bp.status.Clear("Consensus")

	// Network status with color indicator
	bp.status.Set("Network", bp.network)
	bp.status.Set("Peers", fmt.Sprintf("%d", peers))
	bp.status.Set("Height", fmt.Sprintf("%s / %s", formatNumber(int64(local)), formatNumber(int64(tip))))

	// Sync percentage bar and blocks behind
	// Always show sync bar for visual consistency, even when tip is 0
	syncPct := float64(0)
	if tip > 0 {
		syncPct = float64(local) / float64(tip) * 100
	}
	bp.status.Set("Sync", bp.formatProgressBar(syncPct))
	if tip > local && tip > 0 {
		bp.status.Set("Behind", fmt.Sprintf("%s%s blocks%s", ColorMuted, formatNumber(int64(tip-local)), ResetColor))
	}

	if rate > 0 {
		bp.status.Set("Rate", formatRate(rate, "blocks"))
		if tip > local {
			eta := time.Duration(float64(tip-local)/rate) * time.Second
			bp.status.Set("ETA", formatDuration(eta))
		}
	}

	// Consensus renders last, always, so the panel ends the same way in
	// both solo mode (a full node with no PBFT role) and PBFT mode (a
	// validator): "PAUSED — synchronizing" while anywhere in the sync
	// pipeline, "ACTIVE — validating"/"ACTIVE — full node" once caught up.
	bp.status.Set("Consensus", bp.consensus)
}

// formatProgressBar creates a visual progress bar for the given percentage
func (bp *BlockchainProgress) formatProgressBar(percent float64) string {
	width := 20
	filled := int(percent / 100.0 * float64(width))
	if filled > width {
		filled = width
	}
	if filled < 0 {
		filled = 0
	}
	bar := fmt.Sprintf("%s%s%s%s%s",
		FGBlue, strings.Repeat("█", filled), ColorMuted, strings.Repeat("░", width-filled), ResetColor)
	return fmt.Sprintf("[%s] %5.1f%%", bar, percent)
}

// Summary prints a final, permanent report of the sync session. Intended
// to be called once, at the end of a sync or on shutdown.
func (bp *BlockchainProgress) Summary() {
	bp.mu.Lock()
	elapsed := time.Since(bp.startedAt)
	local, tip, rate := bp.localHeight, bp.networkTip, bp.rate
	bp.mu.Unlock()

	bp.log.Info("=== Synchronization summary ===")
	bp.log.Info("Total time: %s", formatDuration(elapsed))
	bp.log.Info("Final height: %d / %d", local, tip)
	bp.log.Info("Average rate: %s", formatRate(rate, "blk"))
}

// Status returns the status line for direct updates.
func (bp *BlockchainProgress) Status() *StatusLine {
	return bp.status
}

// Stop force-finishes any still-active spinners/bars, so a shutdown never
// leaves an orphaned animation with nothing driving it.
func (bp *BlockchainProgress) Stop() {
	bp.multi.Stop()
}
