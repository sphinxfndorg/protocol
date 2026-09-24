// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/licenses/MIT

// go/src/dht/dht_test.go
package dht

import (
	"net"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestNewDHTUsesErrorOnlyLogger(t *testing.T) {
	core, observed := observer.New(zap.DebugLevel)
	d, err := NewDHT(Config{
		Proto:   "udp4",
		Address: net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
	}, zap.New(core))
	if err != nil {
		t.Fatalf("NewDHT returned an error: %v", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("DHT.Close returned an error: %v", err)
		}
	})

	d.log.Debug("debug message")
	d.log.Info("info message")
	d.log.Warn("warning message")
	d.log.Error("error message")

	entries := observed.All()
	if len(entries) != 1 {
		t.Fatalf("DHT logger emitted %d entries, want only the error entry: %#v", len(entries), entries)
	}
	if entries[0].Level != zap.ErrorLevel {
		t.Errorf("emitted level = %v, want %v", entries[0].Level, zap.ErrorLevel)
	}
	if entries[0].Message != "error message" {
		t.Errorf("emitted message = %q, want %q", entries[0].Message, "error message")
	}
}
