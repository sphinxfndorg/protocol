// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/console/live.go
package logger

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// SpinnerState is the terminal outcome (or ongoing state) of a Spinner.
type SpinnerState int

const (
	SpinnerRunning SpinnerState = iota
	SpinnerSuccess
	SpinnerWarning
	SpinnerError
	SpinnerStopped
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const (
	successSymbol = "✔"
	warningSymbol = "⚠"
	errorSymbol   = "✖"
	stoppedSymbol = "◼"
)

// Spinner is a single animated line for an operation of unknown duration
// (peer discovery, genesis verification, consensus startup, ...).
//
// A Spinner never writes to the terminal itself -- it only reports its
// current line through Lines(), which the owning Renderer calls on its own
// clock. That means Start/UpdateMessage/Stop are safe to call from any
// goroutine with no risk of racing against the redraw.
type Spinner struct {
	mu       sync.Mutex
	message  string
	state    SpinnerState
	frameIdx int
	start    time.Time
	finished bool

	// onFinish, if set, is invoked exactly once when the spinner reaches a
	// terminal state, with its final rendered line. MultiProgress uses this
	// to log completed spinners permanently and drop them from the live
	// region, so finished work stops animating and clutters nothing.
	onFinish func(finalLine string)
}

// NewSpinner creates a standalone spinner. Call Start to begin animating.
func NewSpinner(message string) *Spinner {
	return &Spinner{message: message, state: SpinnerStopped}
}

// Start begins (or restarts) the spinner in the running state.
func (s *Spinner) Start() {
	s.mu.Lock()
	s.state = SpinnerRunning
	s.start = time.Now()
	s.finished = false
	s.mu.Unlock()
}

// UpdateMessage changes the spinner's label without altering its state,
// e.g. "Discovered 3 peers (1 connected)" while discovery continues.
func (s *Spinner) UpdateMessage(msg string) {
	s.mu.Lock()
	s.message = msg
	s.mu.Unlock()
}

// Stop finalizes the spinner into a terminal state. message, if non-empty,
// replaces the current label for the final line. Stop is idempotent: only
// the first call takes effect, so it is safe to call from a defer alongside
// an explicit success/failure path.
func (s *Spinner) Stop(state SpinnerState, message string) {
	s.mu.Lock()
	if s.finished {
		s.mu.Unlock()
		return
	}
	s.finished = true
	s.state = state
	if message != "" {
		s.message = message
	}
	line := s.lineLocked(false)
	cb := s.onFinish
	s.mu.Unlock()

	if cb != nil {
		cb(line)
	}
}

func (s *Spinner) symbolAndColor(frame string) (string, string) {
	switch s.state {
	case SpinnerSuccess:
		return successSymbol, FGGreen
	case SpinnerWarning:
		return warningSymbol, FGYellow
	case SpinnerError:
		return errorSymbol, FGRed
	case SpinnerStopped:
		return stoppedSymbol, ColorMuted
	default:
		return frame, FGBlue
	}
}

// lineLocked renders the current line. If advance is true and the spinner
// is running, the animation frame is advanced first -- this is the only
// place the frame index changes, and it only happens when the shared
// render clock actually asks for a new frame.
func (s *Spinner) lineLocked(advance bool) string {
	if advance && s.state == SpinnerRunning {
		s.frameIdx = (s.frameIdx + 1) % len(spinnerFrames)
	}
	symbol, color := s.symbolAndColor(spinnerFrames[s.frameIdx])
	elapsed := time.Since(s.start)
	return fmt.Sprintf("%s%s%s %s %s(%s)%s",
		color, symbol, ResetColor, s.message, ColorMuted, formatDuration(elapsed), ResetColor)
}

// Lines implements Renderable.
func (s *Spinner) Lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return []string{s.lineLocked(true)}
}

// ProgressBar is a single-line indicator for an operation with a known
// total (header sync, block download, verification, ...): percentage,
// current/total counts, a smoothed throughput estimate, elapsed time and
// ETA. Like Spinner, it never writes to the terminal itself.
type ProgressBar struct {
	mu       sync.Mutex
	message  string
	unit     string
	current  int64
	total    int64
	width    int
	start    time.Time
	lastAt   time.Time
	lastVal  int64
	rate     float64 // exponentially smoothed items/sec
	finished bool
	failed   bool

	onFinish func(finalLine string)
}

// NewProgressBar creates a bar tracking progress toward total, labeled with
// unit (e.g. "blocks", "headers", "tx").
func NewProgressBar(message string, total int64, unit string) *ProgressBar {
	now := time.Now()
	return &ProgressBar{
		message: message,
		total:   total,
		unit:    unit,
		width:   30,
		start:   now,
		lastAt:  now,
	}
}

// SetTotal updates the total, e.g. once the real target becomes known.
func (pb *ProgressBar) SetTotal(total int64) {
	pb.mu.Lock()
	pb.total = total
	pb.mu.Unlock()
}

// Set updates current progress and refreshes the smoothed rate estimate.
// Safe to call from any goroutine, including concurrently with rendering.
func (pb *ProgressBar) Set(current int64) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if pb.finished {
		return
	}
	if pb.total > 0 && current > pb.total {
		current = pb.total
	}
	now := time.Now()
	if dt := now.Sub(pb.lastAt).Seconds(); dt > 0 {
		inst := float64(current-pb.lastVal) / dt
		if pb.rate == 0 {
			pb.rate = inst
		} else {
			// EMA smooths bursty/irregular updates into a stable rate.
			pb.rate = 0.3*inst + 0.7*pb.rate
		}
	}
	pb.lastAt = now
	pb.lastVal = current
	pb.current = current
}

// Add increments current progress by n.
func (pb *ProgressBar) Add(n int64) {
	pb.mu.Lock()
	next := pb.current + n
	pb.mu.Unlock()
	pb.Set(next)
}

// Complete finalizes the bar as fully done and successful.
func (pb *ProgressBar) Complete() { pb.finish(false) }

// Fail finalizes the bar as stopped due to failure, at whatever progress
// it last reached.
func (pb *ProgressBar) Fail() { pb.finish(true) }

func (pb *ProgressBar) finish(failed bool) {
	pb.mu.Lock()
	if pb.finished {
		pb.mu.Unlock()
		return
	}
	pb.finished = true
	pb.failed = failed
	if !failed {
		pb.current = pb.total
	}
	line := pb.lineFinal()
	cb := pb.onFinish
	pb.mu.Unlock()

	if cb != nil {
		cb(line)
	}
}

// Stats returns a snapshot: current, total, fraction complete, smoothed
// rate, and ETA (-1 if not yet estimable).
func (pb *ProgressBar) Stats() (current, total int64, percent, rate float64, eta time.Duration) {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	return pb.statsLocked()
}

func (pb *ProgressBar) statsLocked() (current, total int64, percent, rate float64, eta time.Duration) {
	current, total, rate = pb.current, pb.total, pb.rate
	if total > 0 {
		percent = float64(current) / float64(total)
	}
	if rate > 0 && current < total {
		eta = time.Duration(float64(total-current)/rate) * time.Second
	} else {
		eta = -1
	}
	return
}

func (pb *ProgressBar) barGlyph(percent float64) string {
	filled := int(float64(pb.width) * percent)
	if filled > pb.width {
		filled = pb.width
	}
	if filled < 0 {
		filled = 0
	}
	return fmt.Sprintf("%s%s%s%s%s",
		FGBlue, strings.Repeat("█", filled), ColorMuted, strings.Repeat("░", pb.width-filled), ResetColor)
}

func (pb *ProgressBar) lineFinal() string {
	current, total, percent, rate, _ := pb.statsLocked()
	icon, color := successSymbol, FGGreen
	if pb.failed {
		icon, color = errorSymbol, FGRed
	}
	elapsed := time.Since(pb.start)
	return fmt.Sprintf("%s%s%s %s %s%3.0f%%%s %s/%s %s in %s (avg %s)",
		color, icon, ResetColor, pb.message,
		FGCyan, percent*100, ResetColor,
		formatNumber(current), formatNumber(total), pb.unit,
		formatDuration(elapsed), formatRate(rate, pb.unit))
}

// Lines implements Renderable.
func (pb *ProgressBar) Lines() []string {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	current, total, percent, rate, eta := pb.statsLocked()
	etaStr := formatDuration(eta)
	line := fmt.Sprintf("%s %s %s%3.0f%%%s %s/%s %s %s%s%s eta %s",
		pb.message, pb.barGlyph(percent),
		FGCyan, percent*100, ResetColor,
		formatNumber(current), formatNumber(total), pb.unit,
		ColorMuted, formatRate(rate, pb.unit), ResetColor,
		etaStr)
	return []string{line}
}

type liveItem interface {
	Lines() []string
}

// MultiProgress renders any number of concurrently active spinners and
// progress bars as a single flicker-free block. When an item finishes
// (success, warning, error, or fail) it is logged as one permanent line
// and removed from the block immediately -- so completed work leaves a
// durable record in scrollback instead of continuing to occupy, or
// clutter, the live animated region.
//
// All methods are safe to call from multiple goroutines concurrently.
type MultiProgress struct {
	mu       sync.Mutex
	r        *Renderer
	order    []string
	items    map[string]liveItem
	attached bool
	detach   func()
}

// NewMultiProgress creates a manager attached to r. Logging of finished
// items goes through r.Log directly, which is exactly what Logger itself
// uses, so finished spinners/bars interleave correctly with structured
// logs from a Logger sharing the same Renderer.
func NewMultiProgress(r *Renderer) *MultiProgress {
	return &MultiProgress{r: r, items: make(map[string]liveItem)}
}

// AddSpinner starts a new animated spinner under id and adds it to the
// live block. If id is already active it is replaced.
func (mp *MultiProgress) AddSpinner(id, message string) *Spinner {
	sp := NewSpinner(message)
	sp.onFinish = func(line string) { mp.finish(id, line) }

	mp.mu.Lock()
	mp.registerLocked(id, sp)
	mp.mu.Unlock()

	sp.Start()
	mp.r.ForceRedraw()
	return sp
}

// AddProgressBar starts a new determinate bar under id and adds it to the
// live block. If id is already active it is replaced.
func (mp *MultiProgress) AddProgressBar(id, message string, total int64, unit string) *ProgressBar {
	pb := NewProgressBar(message, total, unit)
	pb.onFinish = func(line string) { mp.finish(id, line) }

	mp.mu.Lock()
	mp.registerLocked(id, pb)
	mp.mu.Unlock()

	mp.r.ForceRedraw()
	return pb
}

// registerLocked must be called with mp.mu held.
func (mp *MultiProgress) registerLocked(id string, item liveItem) {
	if _, exists := mp.items[id]; !exists {
		mp.order = append(mp.order, id)
	}
	mp.items[id] = item
	if !mp.attached {
		mp.detach = mp.r.Attach(mp)
		mp.attached = true
	}
}

func (mp *MultiProgress) finish(id, line string) {
	mp.mu.Lock()
	if _, ok := mp.items[id]; ok {
		delete(mp.items, id)
		for i, x := range mp.order {
			if x == id {
				mp.order = append(mp.order[:i], mp.order[i+1:]...)
				break
			}
		}
	}
	empty := len(mp.items) == 0
	var detachFn func()
	if empty && mp.attached {
		detachFn = mp.detach
		mp.attached = false
	}
	mp.mu.Unlock()

	mp.r.Log(line)
	if detachFn != nil {
		detachFn() // also forces a final redraw of whatever remains
	} else {
		mp.r.ForceRedraw()
	}
}

// Lines implements Renderable.
func (mp *MultiProgress) Lines() []string {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	var out []string
	for _, id := range mp.order {
		out = append(out, mp.items[id].Lines()...)
	}
	return out
}

// Spinner returns a still-active spinner by id.
func (mp *MultiProgress) Spinner(id string) (*Spinner, bool) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	sp, ok := mp.items[id].(*Spinner)
	return sp, ok
}

// Bar returns a still-active progress bar by id.
func (mp *MultiProgress) Bar(id string) (*ProgressBar, bool) {
	mp.mu.Lock()
	defer mp.mu.Unlock()
	pb, ok := mp.items[id].(*ProgressBar)
	return pb, ok
}

// Stop force-finishes everything still active, e.g. on shutdown or
// cancellation, so nothing is left animating with no one driving it.
func (mp *MultiProgress) Stop() {
	mp.mu.Lock()
	pending := make([]liveItem, 0, len(mp.order))
	for _, id := range mp.order {
		pending = append(pending, mp.items[id])
	}
	mp.mu.Unlock()

	for _, it := range pending {
		switch v := it.(type) {
		case *Spinner:
			v.Stop(SpinnerStopped, "")
		case *ProgressBar:
			v.Fail()
		}
	}
}
