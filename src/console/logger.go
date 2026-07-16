// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/console/logger.go
package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is a log severity, ordered so filtering by SetLevel works with a
// simple comparison.
type Level int

const (
	TRACE Level = iota
	DEBUG
	INFO
	SUCCESS
	WARN
	ERROR
	FATAL
)

func (l Level) String() string {
	switch l {
	case TRACE:
		return "TRACE"
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case SUCCESS:
		return "SUCCESS"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "?"
	}
}

func (l Level) color() string {
	switch l {
	case TRACE:
		return ColorTRACE
	case DEBUG:
		return ColorDEBUG
	case INFO:
		return ColorINFO
	case SUCCESS:
		return ColorSUCCESS
	case WARN:
		return ColorWARN
	case ERROR:
		return ColorERROR
	case FATAL:
		return ColorFATAL
	default:
		return ""
	}
}

type field struct{ key, value string }

// limitState tracks the last time a rate-limited key was actually emitted
// and how many calls were suppressed since then.
type limitState struct {
	last       time.Time
	suppressed int
}

// Logger writes persistent, structured log lines through a Renderer. Every
// call is safe from any goroutine: the Renderer's lock serializes actual
// terminal writes, so logs from concurrent workers never interleave or
// corrupt each other, and never collide with an active live region.
type Logger struct {
	r        *Renderer
	minLevel Level
	fields   []field

	limMu    *sync.Mutex
	limiters map[string]*limitState
}

// NewLogger creates a logger writing through r. The default minimum level
// is TRACE (everything shown); call SetLevel to raise it.
func NewLogger(r *Renderer) *Logger {
	return &Logger{
		r:        r,
		minLevel: TRACE,
		limMu:    &sync.Mutex{},
		limiters: make(map[string]*limitState),
	}
}

// SetLevel sets the minimum level that will actually be emitted.
func (l *Logger) SetLevel(lv Level) { l.minLevel = lv }

// With returns a derived logger that attaches an extra structured
// key/value field to every line it logs, without mutating the parent.
// Useful for scoping a logger to a subsystem: log.With("peer", id).
func (l *Logger) With(key string, value interface{}) *Logger {
	nl := &Logger{
		r:        l.r,
		minLevel: l.minLevel,
		limMu:    l.limMu,
		limiters: l.limiters,
	}
	nl.fields = append(append([]field{}, l.fields...), field{key, fmt.Sprint(value)})
	return nl
}

func (l *Logger) format(lv Level, msg string) string {
	ts := time.Now().Format("15:04:05.000")
	var fb strings.Builder
	for _, f := range l.fields {
		fmt.Fprintf(&fb, " %s%s=%s%s", ColorMuted, f.key, ResetColor, f.value)
	}
	return fmt.Sprintf("%s%s%s %s%-7s%s %s%s",
		ColorMuted, ts, ResetColor,
		lv.color(), lv.String(), ResetColor,
		msg, fb.String())
}

func (l *Logger) emit(lv Level, msg string) {
	if lv < l.minLevel {
		return
	}
	l.r.Log(l.format(lv, msg))
}

func (l *Logger) Trace(format string, args ...interface{}) {
	l.emit(TRACE, fmt.Sprintf(format, args...))
}
func (l *Logger) Debug(format string, args ...interface{}) {
	l.emit(DEBUG, fmt.Sprintf(format, args...))
}
func (l *Logger) Info(format string, args ...interface{}) { l.emit(INFO, fmt.Sprintf(format, args...)) }
func (l *Logger) Success(format string, args ...interface{}) {
	l.emit(SUCCESS, fmt.Sprintf(format, args...))
}
func (l *Logger) Warn(format string, args ...interface{}) { l.emit(WARN, fmt.Sprintf(format, args...)) }
func (l *Logger) Error(format string, args ...interface{}) {
	l.emit(ERROR, fmt.Sprintf(format, args...))
}

// Fatal logs at FATAL level, restores the terminal (cursor, live region),
// and terminates the process. Terminal restoration happens before exit so
// a fatal error never leaves the screen in a broken state.
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.emit(FATAL, fmt.Sprintf(format, args...))
	l.r.Shutdown()
	os.Exit(1)
}

// Limited returns a helper bound to key that coalesces repeated calls
// within interval into a single line, appending a "(+N suppressed)"
// summary once the window elapses. Use it to guard hot paths -- per-peer
// chatter, retry loops, mempool churn -- that would otherwise flood the
// terminal with near-duplicate lines.
func (l *Logger) Limited(key string, interval time.Duration) *LimitedLogger {
	return &LimitedLogger{l: l, key: key, interval: interval}
}

// LimitedLogger is a rate-limited view onto a Logger for one key.
type LimitedLogger struct {
	l        *Logger
	key      string
	interval time.Duration
}

func (ll *LimitedLogger) allow() (suppressed int, ok bool) {
	ll.l.limMu.Lock()
	defer ll.l.limMu.Unlock()
	now := time.Now()
	st, exists := ll.l.limiters[ll.key]
	if !exists {
		ll.l.limiters[ll.key] = &limitState{last: now}
		return 0, true
	}
	if now.Sub(st.last) < ll.interval {
		st.suppressed++
		return 0, false
	}
	n := st.suppressed
	st.suppressed = 0
	st.last = now
	return n, true
}

func (ll *LimitedLogger) log(lv Level, format string, args ...interface{}) {
	n, ok := ll.allow()
	if !ok {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if n > 0 {
		msg = fmt.Sprintf("%s %s(+%d suppressed)%s", msg, ColorMuted, n, ResetColor)
	}
	ll.l.emit(lv, msg)
}

func (ll *LimitedLogger) Trace(format string, args ...interface{}) { ll.log(TRACE, format, args...) }
func (ll *LimitedLogger) Debug(format string, args ...interface{}) { ll.log(DEBUG, format, args...) }
func (ll *LimitedLogger) Info(format string, args ...interface{})  { ll.log(INFO, format, args...) }
func (ll *LimitedLogger) Warn(format string, args ...interface{})  { ll.log(WARN, format, args...) }
func (ll *LimitedLogger) Error(format string, args ...interface{}) { ll.log(ERROR, format, args...) }
