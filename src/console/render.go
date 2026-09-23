// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/console/render.go
package logger

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Renderable is anything that can contribute lines to the live, in-place
// region at the bottom of the terminal (spinners, progress bars, status
// lines, task trees, ...). Lines is called under the Renderer's own lock;
// implementations must be fast and must never write to the terminal
// themselves -- the Renderer is the single writer.
type Renderable interface {
	Lines() []string
}

// Renderer owns every byte written to the terminal. All logging and all
// live-region redraws funnel through its single mutex, which is what makes
// it safe for many goroutines (sync workers, consensus loops, peer
// handlers, ...) to log and update progress concurrently without ever
// corrupting or interleaving output.
type Renderer struct {
	mu    sync.Mutex
	out   io.Writer
	isTTY bool
	ansi  bool

	attached  []Renderable
	liveLines int

	cursorHidden bool
	closed       bool

	ticking    bool
	tickerStop chan struct{}

	minInterval time.Duration
	lastPaint   time.Time

	plainInterval time.Duration
	lastPlain     time.Time
}

var (
	defaultRenderer *Renderer
	rendererOnce    sync.Once
)

// Process-wide host-integration switches.
//
// Both default to false, so a plain CLI process behaves exactly as it always
// has. They exist for hosts — the desktop GUI — that embed the node in a
// larger application and therefore own the terminal, the log stream and the
// shutdown path themselves.
var (
	// signalHandlerDisabled makes the SIGINT/SIGTERM handler installed by
	// Default() ignore signals. See DisableSignalHandler.
	signalHandlerDisabled atomic.Bool

	// liveRegionDisabled suppresses every live-region repaint (spinners,
	// progress bars, status lines). See DisableLiveRegion.
	liveRegionDisabled atomic.Bool
)

// DisableSignalHandler makes the already-installed SIGINT/SIGTERM handler stop
// acting: it no longer restores the terminal and, above all, no longer calls
// os.Exit(130).
//
// The handler is installed at import time by Default() (which package-level
// logging triggers), so it cannot simply "not be installed" — this switch is
// checked when a signal arrives instead. That is also why the registration is
// deliberately left in place: while any signal.Notify registration exists, the
// Go runtime suppresses the default terminate-the-process action, so
// SIGINT/SIGTERM keep being delivered to the host's own handler (bind's node
// shutdown) instead of killing the process instantly. Calling signal.Stop or
// signal.Reset here would restore that default action and break exactly that
// property.
//
// One-way and process-wide; intended to be called by the host before it starts
// a node. The CLI never calls it.
func DisableSignalHandler() { signalHandlerDisabled.Store(true) }

// signalHandlerDisabledNow reports whether the installed handler must ignore
// signals. Extracted so the ignore path is testable without os.Exit.
func signalHandlerDisabledNow() bool { return signalHandlerDisabled.Load() }

// DisableLiveRegion makes the default renderer stop painting the live region:
// Attach becomes a no-op (so nothing is ever registered and the animation
// ticker never starts) and lines already collected are dropped. Permanent log
// lines keep flowing to the renderer's writer, which is what a host that pipes
// node output into its own pane (the desktop GUI) needs.
//
// One-way and process-wide, like DisableSignalHandler. The default (false)
// leaves the CLI's terminal dashboard untouched.
func DisableLiveRegion() { liveRegionDisabled.Store(true) }

// liveRegionEnabled reports whether live-region painting is still on.
func liveRegionEnabled() bool { return !liveRegionDisabled.Load() }

// Default returns the process-wide renderer bound to os.Stdout and installs
// a SIGINT/SIGTERM handler that restores the terminal before exiting. Safe
// to call from multiple goroutines; initialization happens exactly once.
func Default() *Renderer {
	rendererOnce.Do(func() {
		defaultRenderer = NewRenderer(os.Stdout)
		defaultRenderer.InstallSignalHandler()
	})
	return defaultRenderer
}

// NewRenderer builds a renderer around an arbitrary writer. Non-*os.File
// writers (buffers, network connections, etc.) are always treated as
// non-interactive, which disables ANSI animation and falls back to plain,
// periodic text -- exactly what you want when output is piped or captured.
func NewRenderer(w io.Writer) *Renderer {
	f, _ := w.(*os.File)
	tty := f != nil && isTerminal(f)
	return &Renderer{
		out:           w,
		isTTY:         tty,
		ansi:          tty && runtime.GOOS != "windows",
		minInterval:   80 * time.Millisecond,
		plainInterval: 2 * time.Second,
	}
}

// SetWriter rebinds the renderer to a new output writer and re-detects whether
// that writer is an interactive terminal (ANSI animation on a TTY, plain
// throttled text otherwise). Anything already attached stays attached; the next
// paint goes to the new writer. This is the seam SetDefaultWriter uses so a host
// can capture node output without rebuilding the process-wide renderer.
func (r *Renderer) SetWriter(w io.Writer) {
	f, _ := w.(*os.File)
	tty := f != nil && isTerminal(f)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.out = w
	r.isTTY = tty
	r.ansi = tty && runtime.GOOS != "windows"
	// Drop the throttle timestamps so the first line/snapshot through the new
	// writer is emitted immediately instead of waiting out the previous
	// writer's window.
	r.lastPaint = time.Time{}
	r.lastPlain = time.Time{}
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	// A character device is the portable signal of an interactive terminal;
	// regular files and pipes (redirected output, `| tee`, CI logs) are not.
	return fi.Mode()&os.ModeCharDevice != 0
}

// IsTTY reports whether output is an interactive terminal.
func (r *Renderer) IsTTY() bool { return r.isTTY }

// ANSI reports whether ANSI escape sequences (and therefore animation) are
// in use. False on non-TTY output and on Windows consoles that don't
// support ANSI without extra setup.
func (r *Renderer) ANSI() bool { return r.ansi }

// Attach registers a Renderable in the live region and starts the shared
// animation clock if this is the first active Renderable. The returned
// function detaches it; call it exactly once when the Renderable's work is
// done. Detaching triggers one final redraw so the region reflects removal
// immediately instead of waiting for the next tick.
func (r *Renderer) Attach(rr Renderable) (detach func()) {
	if !liveRegionEnabled() {
		// The host owns output (see DisableLiveRegion): never register, never
		// start the animation ticker. The no-op detach keeps every caller's
		// contract intact.
		return func() {}
	}
	r.mu.Lock()
	r.attached = append(r.attached, rr)
	if r.ansi && !r.ticking {
		r.startTickingLocked()
	}
	r.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			for i, x := range r.attached {
				if x == rr {
					r.attached = append(r.attached[:i], r.attached[i+1:]...)
					break
				}
			}
			stopTick := len(r.attached) == 0 && r.ticking
			if stopTick {
				r.stopTickingLocked()
			}
			r.mu.Unlock()
			r.ForceRedraw()
		})
	}
}

// startTickingLocked must be called with r.mu held.
func (r *Renderer) startTickingLocked() {
	r.ticking = true
	stop := make(chan struct{})
	r.tickerStop = stop
	go func() {
		t := time.NewTicker(100 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				r.redraw(false)
			case <-stop:
				return
			}
		}
	}()
}

// stopTickingLocked must be called with r.mu held.
func (r *Renderer) stopTickingLocked() {
	if r.ticking {
		close(r.tickerStop)
		r.ticking = false
	}
}

// ForceRedraw immediately repaints the live region (or, on non-TTY output,
// is a no-op -- non-interactive output only ever gets explicit Log lines
// and throttled plain snapshots, never a forced repaint).
func (r *Renderer) ForceRedraw() {
	r.redraw(true)
}

func (r *Renderer) redraw(force bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if !r.ansi {
		r.maybePlainSnapshotLocked()
		return
	}
	now := time.Now()
	if !force && now.Sub(r.lastPaint) < r.minInterval {
		return
	}
	r.lastPaint = now
	r.paintLocked(r.collectLinesLocked())
}

func (r *Renderer) collectLinesLocked() []string {
	if !liveRegionEnabled() {
		// The live region was disabled — possibly after something had already
		// attached. Report an empty region so paintLocked erases whatever was
		// on screen once, maybePlainSnapshotLocked writes nothing, and Log
		// stops appending a region beneath every line.
		return nil
	}
	var out []string
	for _, a := range r.attached {
		out = append(out, a.Lines()...)
	}
	return out
}

// paintLocked repaints the live region in a single write: move to the top
// of the current region, erase everything below the cursor (so a region
// that shrank leaves no orphaned lines behind), then draw the new lines.
// Must be called with r.mu held, ansi mode only.
func (r *Renderer) paintLocked(lines []string) {
	var b strings.Builder
	if !r.cursorHidden {
		b.WriteString(CursorHide)
		r.cursorHidden = true
	}
	if r.liveLines > 0 {
		fmt.Fprintf(&b, "\r\033[%dA", r.liveLines)
	} else {
		b.WriteString("\r")
	}
	b.WriteString(eraseFromCursor)
	for _, line := range lines {
		b.WriteString(line)
		b.WriteString("\n")
	}
	r.liveLines = len(lines)
	io.WriteString(r.out, b.String())
}

func (r *Renderer) maybePlainSnapshotLocked() {
	now := time.Now()
	if now.Sub(r.lastPlain) < r.plainInterval {
		return
	}
	lines := r.collectLinesLocked()
	if len(lines) == 0 {
		return
	}
	r.lastPlain = now
	joined := stripANSI(strings.Join(lines, "  |  "))
	fmt.Fprintln(r.out, joined)
}

// Log writes a permanent, scrolled-into-history line. If a live region is
// currently shown, it is cleared, the log line is written above it, and the
// region is redrawn immediately below -- so completed events and active
// animations never collide or corrupt each other's output. On non-TTY
// output this is just a plain line, ANSI stripped.
func (r *Renderer) Log(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if !r.ansi {
		fmt.Fprintln(r.out, stripANSI(line))
		return
	}
	var b strings.Builder
	if r.liveLines > 0 {
		fmt.Fprintf(&b, "\r\033[%dA%s", r.liveLines, eraseFromCursor)
	} else {
		b.WriteString("\r")
		b.WriteString(eraseFromCursor)
	}
	b.WriteString(line)
	b.WriteString("\n")
	lines := r.collectLinesLocked()
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	r.liveLines = len(lines)
	r.lastPaint = time.Now()
	io.WriteString(r.out, b.String())
}

// Shutdown clears any live region and restores the cursor. It is
// idempotent and safe to call from a signal handler or a recover() block,
// which is exactly how it is used: to guarantee the terminal is never left
// in a broken state (hidden cursor, half-drawn progress bar) on success,
// failure, cancellation, panic, or process termination.
func (r *Renderer) Shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	if r.ticking {
		close(r.tickerStop)
		r.ticking = false
	}
	if r.ansi {
		var b strings.Builder
		if r.liveLines > 0 {
			fmt.Fprintf(&b, "\r\033[%dA%s", r.liveLines, eraseFromCursor)
			r.liveLines = 0
		}
		if r.cursorHidden {
			b.WriteString(CursorShow)
			r.cursorHidden = false
		}
		if b.Len() > 0 {
			io.WriteString(r.out, b.String())
		}
	}
}

// InstallSignalHandler restores the terminal on SIGINT/SIGTERM before the
// process exits, so an interactive user hitting Ctrl-C never gets left
// with a hidden cursor or a half-drawn progress bar.
func (r *Renderer) InstallSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-c
		if signalHandlerDisabledNow() {
			// A host owns shutdown (see DisableSignalHandler). Restoring the
			// terminal or exiting here would race the host's graceful node
			// shutdown, so the signal is consumed and ignored — the host's own
			// registration receives the same signal independently.
			return
		}
		r.Shutdown()
		fmt.Fprintf(os.Stderr, "\nreceived %s, shutting down\n", sig)
		os.Exit(130)
	}()
}

// Recover restores the terminal on a panic and then re-panics so the
// original stack trace and process exit behavior are preserved. Use it as:
//
//	defer terminal.Default().Recover()
//
// at the top of main (or any goroutine that owns terminal output) to
// guarantee a crash never leaves the cursor hidden or the screen in a
// half-rendered state.
func (r *Renderer) Recover() {
	if p := recover(); p != nil {
		r.Shutdown()
		panic(p)
	}
}

// ANSI escape codes used for in-place, flicker-free rendering.
const (
	CursorHide = "\033[?25l"
	CursorShow = "\033[?25h"

	// eraseFromCursor clears everything from the cursor to the end of the
	// screen. Combined with moving the cursor to the top of the live
	// region, this lets a shrinking region (e.g. spinners completing)
	// clean up its own leftover lines in a single write.
	eraseFromCursor = "\033[J"

	ResetColor = "\033[0m"
	Bold       = "\033[1m"
	Dim        = "\033[2m"

	FGRed    = "\033[31m"
	FGGreen  = "\033[32m"
	FGYellow = "\033[33m"
	FGBlue   = "\033[34m"
	FGCyan   = "\033[36m"
	FGWhite  = "\033[37m"
	BGRed    = "\033[41m"
)

// Color constants for log levels and UI elements.
const (
	ColorTRACE   = Dim + FGWhite
	ColorDEBUG   = FGCyan
	ColorINFO    = FGWhite
	ColorSUCCESS = FGGreen
	ColorWARN    = FGYellow
	ColorERROR   = FGRed
	ColorFATAL   = BGRed + FGWhite
	ColorMuted   = Dim + FGWhite
)

// formatDuration renders a duration as mm:ss, or hh:mm:ss once it exceeds an
// hour. Negative durations (used as a "not yet known" sentinel, e.g. ETA
// before a rate estimate exists) render as a dashed placeholder rather than
// a misleading negative time.
func formatDuration(d time.Duration) string {
	if d < 0 {
		return "--:--"
	}
	total := int(d.Seconds())
	hours := total / 3600
	minutes := (total % 3600) / 60
	secs := total % 60
	if hours > 0 {
		return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, secs)
	}
	return fmt.Sprintf("%02d:%02d", minutes, secs)
}

// formatNumber renders large counts compactly (1.2K, 3.4M, 5.6B).
func formatNumber(n int64) string {
	abs := n
	if abs < 0 {
		abs = -abs
	}
	switch {
	case abs < 1000:
		return fmt.Sprintf("%d", n)
	case abs < 1000000:
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	case abs < 1000000000:
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	default:
		return fmt.Sprintf("%.1fB", float64(n)/1000000000)
	}
}

// formatRate renders a throughput value with a fixed unit suffix.
func formatRate(perSecond float64, unit string) string {
	return fmt.Sprintf("%.1f %s/s", perSecond, unit)
}

// stripANSI removes escape sequences so non-TTY output (files, pipes, CI
// logs) stays clean plain text.
func stripANSI(s string) string {
	var out []byte
	inEscape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !inEscape && c == '\033' && i+1 < len(s) && s[i+1] == '[' {
			inEscape = true
			i++
			continue
		}
		if inEscape {
			if c >= 0x40 && c <= 0x7e {
				inEscape = false
			}
			continue
		}
		out = append(out, c)
	}
	return string(out)
}
