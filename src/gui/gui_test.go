package gui

import (
	"math/big"
	"testing"
)

func TestSendGate(t *testing.T) {
	if synced(syncResponse{Syncing: false, Peers: 1, Age: 100}) != true {
		t.Fatal("fresh synced status should enable sending")
	}

	if synced(syncResponse{Syncing: false, Peers: 0, Age: 100}) {
		t.Fatal("peerless status must disable sending")
	}
	if synced(syncResponse{Syncing: false, Peers: 1, Age: 60001}) {
		t.Fatal("stale status must disable sending")
	}
}

func TestAmountConversion(t *testing.T) {
	got, err := nspx("1.25")
	if err != nil {
		t.Fatal(err)
	}
	if got.Cmp(big.NewInt(1250000000000000000)) != 0 {
		t.Fatalf("amount = %s", got)
	}
}
