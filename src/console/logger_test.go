// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/console/logger_test.go
package logger

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// recordingStringer records whether fmt formatted it. A logger that checks
// the level before formatting must never call String() on an argument of a
// suppressed log line.
type recordingStringer struct {
	called *bool
}

func (r recordingStringer) String() string {
	*r.called = true
	return "formatted"
}

func newBufferLogger() (*Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return NewLogger(NewRenderer(buf)), buf
}

func TestSuppressedLevelSkipsFormatting(t *testing.T) {
	log, buf := newBufferLogger()
	log.SetLevel(INFO)

	var formatted bool
	log.Debug("value=%v", recordingStringer{&formatted})

	if formatted {
		t.Fatal("Debug formatted its arguments even though it was below the logger's level")
	}
	if buf.Len() != 0 {
		t.Fatalf("suppressed Debug wrote %q", buf.String())
	}
}

func TestEnabledLevelFormatsAndWrites(t *testing.T) {
	log, buf := newBufferLogger()
	log.SetLevel(INFO)

	var formatted bool
	log.Warn("value=%v", recordingStringer{&formatted})

	if !formatted {
		t.Fatal("Warn did not format its arguments")
	}
	if !strings.Contains(buf.String(), "value=formatted") {
		t.Fatalf("Warn wrote %q, want it to contain %q", buf.String(), "value=formatted")
	}
}

func TestErrorSuppressedBelowItsLevel(t *testing.T) {
	log, buf := newBufferLogger()
	log.SetLevel(FATAL)

	var formatted bool
	log.Error("value=%v", recordingStringer{&formatted})

	if formatted {
		t.Fatal("Error formatted its arguments even though it was below the logger's level")
	}
	if buf.Len() != 0 {
		t.Fatalf("suppressed Error wrote %q", buf.String())
	}
}

func TestLimitedLoggerSkipsFormattingWhenSuppressed(t *testing.T) {
	log, buf := newBufferLogger()
	log.SetLevel(WARN)
	lim := log.Limited("test-key", time.Minute)

	var formatted bool
	lim.Debug("value=%v", recordingStringer{&formatted})

	if formatted {
		t.Fatal("suppressed LimitedLogger.Debug formatted its arguments")
	}
	if buf.Len() != 0 {
		t.Fatalf("suppressed LimitedLogger.Debug wrote %q", buf.String())
	}
}

func TestDerivedLoggerInheritsLevel(t *testing.T) {
	log, buf := newBufferLogger()
	log.SetLevel(WARN)

	derived := log.With("peer", "abc")
	var formatted bool
	derived.Info("value=%v", recordingStringer{&formatted})

	if formatted {
		t.Fatal("derived logger formatted a suppressed Info line")
	}
	if buf.Len() != 0 {
		t.Fatalf("suppressed Info wrote %q", buf.String())
	}
}

// TestDefaultLoggerIsNotAtTrace pins the process-wide default: per-operation
// DEBUG lines (one per LevelDB read/write) must be off unless a caller
// deliberately lowers the level with SetLevel.
func TestDefaultLoggerIsNotAtTrace(t *testing.T) {
	if min := defaultLogger.minLevel; min < INFO {
		t.Fatalf("package-level logger level = %v, want at least INFO so per-operation DEBUG lines are off by default", min)
	}
}
