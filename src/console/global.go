// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/console/global.go
package logger

import (
	"io"
	"os"
	"time"
)

var defaultLogger *Logger

func init() {
	defaultLogger = NewLogger(Default())

	// Every non-terminal package (rawdb, sync, mempool, ...) logs through
	// this package-level logger. Left at NewLogger's TRACE default it would
	// print per-operation DEBUG lines — one for every LevelDB read, write
	// and delete — to stdout at full volume, each behind the renderer's
	// global lock. INFO is the same level NewTerminalLogger picks; use
	// SetLevel to lower it again when debugging.
	SetLevel(INFO)
}

// Standard package-level logging functions using the default renderer.
// These are safe to call from any goroutine without creating a Logger instance.
func Trace(format string, args ...interface{}) {
	defaultLogger.Trace(format, args...)
}

func Debug(format string, args ...interface{}) {
	defaultLogger.Debug(format, args...)
}

func Info(format string, args ...interface{}) {
	defaultLogger.Info(format, args...)
}

func Success(format string, args ...interface{}) {
	defaultLogger.Success(format, args...)
}

func Warn(format string, args ...interface{}) {
	defaultLogger.Warn(format, args...)
}

func Error(format string, args ...interface{}) {
	defaultLogger.Error(format, args...)
}

func Fatal(format string, args ...interface{}) {
	defaultLogger.Fatal(format, args...)
}

// With returns a derived logger with an additional field, using the default renderer.
func With(key string, value interface{}) *Logger {
	return defaultLogger.With(key, value)
}

// Limited returns a rate-limited logger for the given key, using the default renderer.
func Limited(key string, interval time.Duration) *LimitedLogger {
	return defaultLogger.Limited(key, interval)
}

// DefaultLogger returns the package-level default logger.
func DefaultLogger() *Logger {
	return defaultLogger
}

// SetDefaultWriter rebinds the process-wide default renderer — the one every
// package-level Info/Warn/Error call and the node dashboard write through — to
// w, re-detecting its TTY properties (see Renderer.SetWriter). Passing nil
// restores os.Stdout.
//
// This is the supported way for a host process (the desktop GUI) to capture
// node output into its own log pane: the renderer is created once at import
// time, so replacing its writer is the only seam that does not require touching
// every call site. The CLI never calls it, so its output path is unchanged.
func SetDefaultWriter(w io.Writer) {
	if w == nil {
		w = os.Stdout
	}
	defaultLogger.r.SetWriter(w)
}

// SetLevel sets the minimum level for the default logger.
func SetLevel(lv Level) {
	defaultLogger.SetLevel(lv)
}

// NewConsole creates a logger bound to Stderr with ANSI colors, or a plain
// logger if Stderr is not a TTY. Passing nil falls back to the default
// renderer attached to Stdout.
func NewConsole(w ...io.Writer) *Logger {
	var out io.Writer
	if len(w) > 0 && w[0] != nil {
		out = w[0]
	} else {
		out = os.Stderr
	}
	return NewLogger(NewRenderer(out))
}
