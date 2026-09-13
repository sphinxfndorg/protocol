// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/state_db_test.go
package core

import (
	"math/big"
	"testing"

	database "github.com/sphinxfndorg/protocol/src/core/state"
)

// newTestStateDB creates a StateDB backed by a temporary LevelDB for testing.
func newTestStateDB(t *testing.T) *StateDB {
	t.Helper()
	dir := t.TempDir()
	db, err := database.NewLevelDB(dir)
	if err != nil {
		t.Fatalf("NewLevelDB: %v", err)
	}
	return NewStateDB(db)
}

// ============================================================================
// Transfer tests
// ============================================================================

func TestTransfer_Basic(t *testing.T) {
	s := newTestStateDB(t)

	alice := "alice"
	bob := "bob"
	amount := big.NewInt(1000)

	// Fund alice
	s.SetBalance(alice, big.NewInt(5000))

	// Transfer 1000 from alice to bob
	if err := s.Transfer(alice, bob, amount); err != nil {
		t.Fatalf("Transfer: %v", err)
	}

	// Check balances
	balAlice, _ := s.GetBalance(alice)
	if balAlice.Cmp(big.NewInt(4000)) != 0 {
		t.Errorf("alice balance: want 4000, got %s", balAlice.String())
	}
	balBob, _ := s.GetBalance(bob)
	if balBob.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("bob balance: want 1000, got %s", balBob.String())
	}
}

func TestTransfer_ConservesSupply(t *testing.T) {
	s := newTestStateDB(t)

	alice := "alice"
	bob := "bob"
	charlie := "charlie"

	// Set initial balances
	s.SetBalance(alice, big.NewInt(10000))
	s.SetBalance(bob, big.NewInt(5000))
	s.SetBalance(charlie, big.NewInt(2000))

	// Calculate total before
	totalBefore, _ := s.GetBalance(alice)
	bobBefore, _ := s.GetBalance(bob)
	charlieBefore, _ := s.GetBalance(charlie)
	totalBefore.Add(totalBefore, bobBefore)
	totalBefore.Add(totalBefore, charlieBefore)

	// Perform multiple transfers
	transfers := []struct {
		from, to string
		amount   int64
	}{
		{alice, bob, 3000},
		{bob, charlie, 1500},
		{charlie, alice, 500},
		{alice, charlie, 2000},
	}

	for _, tr := range transfers {
		if err := s.Transfer(tr.from, tr.to, big.NewInt(tr.amount)); err != nil {
			t.Fatalf("Transfer(%s→%s, %d): %v", tr.from, tr.to, tr.amount, err)
		}
	}

	// Calculate total after
	totalAfter, _ := s.GetBalance(alice)
	bobAfter, _ := s.GetBalance(bob)
	charlieAfter, _ := s.GetBalance(charlie)
	totalAfter.Add(totalAfter, bobAfter)
	totalAfter.Add(totalAfter, charlieAfter)

	// Supply must be conserved
	if totalBefore.Cmp(totalAfter) != 0 {
		t.Errorf("supply not conserved: before=%s, after=%s", totalBefore.String(), totalAfter.String())
	}
}

func TestTransfer_InsufficientBalance(t *testing.T) {
	s := newTestStateDB(t)

	alice := "alice"
	bob := "bob"

	s.SetBalance(alice, big.NewInt(100))

	// Try to transfer more than balance
	err := s.Transfer(alice, bob, big.NewInt(200))
	if err == nil {
		t.Fatal("expected error for insufficient balance, got nil")
	}

	// Balances should be unchanged
	balAlice, _ := s.GetBalance(alice)
	if balAlice.Cmp(big.NewInt(100)) != 0 {
		t.Errorf("alice balance should be unchanged: want 100, got %s", balAlice.String())
	}
	balBob, _ := s.GetBalance(bob)
	if balBob.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("bob balance should be 0: got %s", balBob.String())
	}
}

func TestTransfer_EmptyAddress(t *testing.T) {
	s := newTestStateDB(t)
	s.SetBalance("alice", big.NewInt(1000))

	// Empty sender
	err := s.Transfer("", "bob", big.NewInt(100))
	if err == nil {
		t.Error("expected error for empty sender, got nil")
	}

	// Empty receiver
	err = s.Transfer("alice", "", big.NewInt(100))
	if err == nil {
		t.Error("expected error for empty receiver, got nil")
	}
}

func TestTransfer_SameSenderReceiver(t *testing.T) {
	s := newTestStateDB(t)
	s.SetBalance("alice", big.NewInt(1000))

	// Self-send is intentionally allowed: it is a mathematical no-op (debit and
	// credit cancel out) and is used by wallets to anchor data/NFT receipts
	// via ReturnData. See state_db.go Transfer for the rationale.
	if err := s.Transfer("alice", "alice", big.NewInt(100)); err != nil {
		t.Fatalf("self-send should be allowed, got error: %v", err)
	}

	// Balance must be unchanged after a self-send.
	bal, _ := s.GetBalance("alice")
	if bal.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("alice balance should be unchanged after self-send: want 1000, got %s", bal.String())
	}
}

func TestTransfer_InvalidAmount(t *testing.T) {
	s := newTestStateDB(t)
	s.SetBalance("alice", big.NewInt(1000))

	// Zero amount
	err := s.Transfer("alice", "bob", big.NewInt(0))
	if err == nil {
		t.Error("expected error for zero amount, got nil")
	}

	// Negative amount
	err = s.Transfer("alice", "bob", big.NewInt(-100))
	if err == nil {
		t.Error("expected error for negative amount, got nil")
	}

	// Nil amount
	err = s.Transfer("alice", "bob", nil)
	if err == nil {
		t.Error("expected error for nil amount, got nil")
	}
}

func TestTransfer_NewReceiver(t *testing.T) {
	s := newTestStateDB(t)
	s.SetBalance("alice", big.NewInt(1000))

	// Transfer to a new address that doesn't exist yet
	if err := s.Transfer("alice", "newbob", big.NewInt(500)); err != nil {
		t.Fatalf("Transfer to new address: %v", err)
	}

	balBob, _ := s.GetBalance("newbob")
	if balBob.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("newbob balance: want 500, got %s", balBob.String())
	}
}

func TestTransfer_ExactBalance(t *testing.T) {
	s := newTestStateDB(t)
	s.SetBalance("alice", big.NewInt(1000))

	// Transfer exactly the balance (should succeed, leaving zero)
	if err := s.Transfer("alice", "bob", big.NewInt(1000)); err != nil {
		t.Fatalf("Transfer exact balance: %v", err)
	}

	balAlice, _ := s.GetBalance("alice")
	if balAlice.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("alice balance should be 0: got %s", balAlice.String())
	}
	balBob, _ := s.GetBalance("bob")
	if balBob.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("bob balance: want 1000, got %s", balBob.String())
	}
}

func TestTransfer_FailureDoesNotCorruptState(t *testing.T) {
	s := newTestStateDB(t)
	s.SetBalance("alice", big.NewInt(1000))
	s.SetBalance("bob", big.NewInt(500))

	// First transfer succeeds
	if err := s.Transfer("alice", "bob", big.NewInt(300)); err != nil {
		t.Fatalf("first Transfer: %v", err)
	}

	// Second transfer fails (insufficient balance)
	if err := s.Transfer("alice", "bob", big.NewInt(800)); err == nil {
		t.Fatal("expected second transfer to fail")
	}

	// State should reflect only the first transfer
	balAlice, _ := s.GetBalance("alice")
	if balAlice.Cmp(big.NewInt(700)) != 0 {
		t.Errorf("alice balance: want 700, got %s", balAlice.String())
	}
	balBob, _ := s.GetBalance("bob")
	if balBob.Cmp(big.NewInt(800)) != 0 {
		t.Errorf("bob balance: want 800, got %s", balBob.String())
	}
}

func TestTransfer_ConcurrentSafety(t *testing.T) {
	// Verify that Transfer holds the mutex correctly by doing concurrent transfers.
	// The StateDB mutex should serialize access.
	s := newTestStateDB(t)
	s.SetBalance("alice", big.NewInt(100000))
	s.SetBalance("bob", big.NewInt(100000))

	// Run many small transfers concurrently
	done := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() {
			// Each goroutine does a small transfer
			_ = s.Transfer("alice", "bob", big.NewInt(1))
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Total supply should be conserved
	balAlice, _ := s.GetBalance("alice")
	balBob, _ := s.GetBalance("bob")
	total := new(big.Int).Add(balAlice, balBob)
	expected := big.NewInt(200000)
	if total.Cmp(expected) != 0 {
		t.Errorf("total supply after concurrent transfers: want %s, got %s", expected.String(), total.String())
	}
}

// TestTransfer_WithFeeDeduction simulates the executor.go pattern:
// Transfer(amount) followed by SubBalance(gasFee), where the upfront
// check ensures balance >= amount + gasFee. Verifies that SubBalance
// cannot fail after Transfer succeeds.
func TestTransfer_WithFeeDeduction(t *testing.T) {
	s := newTestStateDB(t)

	sender := "sender"
	receiver := "receiver"
	gasFee := big.NewInt(200)
	amount := big.NewInt(800)

	// Fund sender with exactly amount + gasFee
	s.SetBalance(sender, big.NewInt(1000))

	// Simulate upfront check: balance >= amount + gasFee
	bal, _ := s.GetBalance(sender)
	totalCost := new(big.Int).Add(amount, gasFee)
	if bal.Cmp(totalCost) < 0 {
		t.Fatalf("upfront check failed: bal=%s, totalCost=%s", bal.String(), totalCost.String())
	}

	// Transfer amount to receiver
	if err := s.Transfer(sender, receiver, amount); err != nil {
		t.Fatalf("Transfer: %v", err)
	}

	// Deduct gas fee — this MUST succeed because upfront check passed
	if err := s.SubBalance(sender, gasFee); err != nil {
		t.Fatalf("SubBalance(gas) failed after Transfer: %v (this should be impossible)", err)
	}

	// Verify final balances
	balSender, _ := s.GetBalance(sender)
	if balSender.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("sender balance: want 0, got %s", balSender.String())
	}
	balReceiver, _ := s.GetBalance(receiver)
	if balReceiver.Cmp(amount) != 0 {
		t.Errorf("receiver balance: want %s, got %s", amount.String(), balReceiver.String())
	}
}

// TestTransfer_FeeDeductionFailsWithoutUpfrontCheck verifies that if you
// skip the upfront check, Transfer + SubBalance can leave partial state
// (which the caller must handle by aborting the transaction).
func TestTransfer_FeeDeductionFailsWithoutUpfrontCheck(t *testing.T) {
	s := newTestStateDB(t)

	sender := "sender"
	receiver := "receiver"
	amount := big.NewInt(800)
	gasFee := big.NewInt(200)

	// Fund sender with amount + gasFee - 1 (not enough for both)
	s.SetBalance(sender, big.NewInt(999))

	// Transfer succeeds (balance >= amount: 999 >= 800)
	if err := s.Transfer(sender, receiver, amount); err != nil {
		t.Fatalf("Transfer should have succeeded: %v", err)
	}

	// SubBalance fails (balance after transfer: 999 - 800 = 199 < 200)
	err := s.SubBalance(sender, gasFee)
	if err == nil {
		t.Fatal("SubBalance should have failed (insufficient balance after transfer)")
	}

	// At this point, the pending map has the transfer applied but not the fee.
	// The caller must abort (return error) — the pending map is never committed.
	// Verify the partial state exists in pending but is NOT committed:
	balSender, _ := s.GetBalance(sender)
	// Balance reflects the transfer deduction (999 - 800 = 199) but not the fee
	if balSender.Cmp(big.NewInt(199)) != 0 {
		t.Errorf("sender balance in pending: want 199, got %s", balSender.String())
	}
	balReceiver, _ := s.GetBalance(receiver)
	if balReceiver.Cmp(amount) != 0 {
		t.Errorf("receiver balance: want %s, got %s", amount.String(), balReceiver.String())
	}
}