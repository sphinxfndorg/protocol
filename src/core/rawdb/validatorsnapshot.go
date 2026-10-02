// Copyright (c) 2024-present Sphinx Core Dev
// MIT License https://opensource.org/license/mit

// go/src/core/rawdb/validatorsnapshot.go
package rawdb

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	database "github.com/sphinxfndorg/protocol/src/core/state"
)

// WriteValidatorSnapshot persists one epoch's validator snapshot.
//
// A snapshot is written IMMEDIATELY when taken, never at shutdown and never in
// a batch that something else may abort. That is deliberate: the snapshot is
// the only authority for verifying blocks in its epoch, so a crash between two
// epoch boundaries must not leave the node unable to verify the epoch it is
// currently in. Losing a snapshot fails CLOSED (blocks are rejected) rather
// than open, but failing closed on every restart of a healthy chain is still a
// liveness bug, so it is written eagerly.
func WriteValidatorSnapshot(db *database.DB, row *ValidatorSnapshotRow) error {
	if db == nil {
		return fmt.Errorf("rawdb: nil db for validator snapshot epoch %d", rowEpoch(row))
	}
	if row == nil {
		return fmt.Errorf("rawdb: nil validator snapshot row")
	}
	// Refuse to persist a row whose declared total disagrees with its own
	// members. A snapshot whose denominator is unreachable by its own voters
	// can never satisfy quorum, and a corrupt denominator written to disk
	// would survive every restart.
	if err := row.Validate(); err != nil {
		return fmt.Errorf("rawdb: refusing to write validator snapshot: %w", err)
	}
	data, err := json.Marshal(row)
	if err != nil {
		return fmt.Errorf("rawdb: encoding validator snapshot epoch %d: %w", row.Epoch, err)
	}
	if err := db.Put(validatorSnapshotKey(row.Epoch), data); err != nil {
		return fmt.Errorf("rawdb: writing validator snapshot epoch %d: %w", row.Epoch, err)
	}
	return nil
}

// ReadValidatorSnapshot returns the snapshot row stored for `epoch`.
func ReadValidatorSnapshot(db *database.DB, epoch uint64) (*ValidatorSnapshotRow, error) {
	if db == nil {
		return nil, fmt.Errorf("rawdb: nil db for validator snapshot epoch %d", epoch)
	}
	data, err := db.GetQuiet(validatorSnapshotKey(epoch))
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil, fmt.Errorf("%w: validator snapshot for epoch %d", ErrNotFound, epoch)
		}
		return nil, fmt.Errorf("rawdb: read validator snapshot epoch %d: %w", epoch, err)
	}
	var row ValidatorSnapshotRow
	if err := json.Unmarshal(data, &row); err != nil {
		return nil, fmt.Errorf("rawdb: corrupt validator snapshot epoch %d: %w", epoch, err)
	}
	// The key carries the epoch; a row that disagrees is corruption, and
	// trusting it would verify blocks against the wrong epoch's set.
	if row.Epoch != epoch {
		return nil, fmt.Errorf("rawdb: validator snapshot keyed for epoch %d carries epoch %d", epoch, row.Epoch)
	}
	if err := row.Validate(); err != nil {
		return nil, fmt.Errorf("rawdb: inconsistent validator snapshot epoch %d: %w", epoch, err)
	}
	return &row, nil
}

// DeleteValidatorSnapshot removes the stored snapshot for `epoch`, if any.
//
// This exists for the crash-window path and for tests: the production code
// never deletes a snapshot, because losing one fails CLOSED and the startup
// rebuild is the only sanctioned way to restore one. Deleting a single epoch
// reproduces exactly that state — a chain whose tip is inside an epoch whose
// snapshot never reached disk — which is otherwise impossible to construct
// without editing raw storage by hand.
func DeleteValidatorSnapshot(db *database.DB, epoch uint64) error {
	if db == nil {
		return fmt.Errorf("rawdb: nil db for validator snapshot epoch %d", epoch)
	}
	if err := db.Delete(validatorSnapshotKey(epoch)); err != nil {
		return fmt.Errorf("rawdb: deleting validator snapshot epoch %d: %w", epoch, err)
	}
	return nil
}

// ReadAllValidatorSnapshots returns every stored snapshot, in ascending epoch
// order. This is what a node replays on startup to rebuild its in-memory
// snapshot store.
func ReadAllValidatorSnapshots(db *database.DB) ([]*ValidatorSnapshotRow, error) {
	if db == nil {
		return nil, fmt.Errorf("rawdb: nil db for validator snapshot scan")
	}
	keys, err := db.ListKeysWithPrefix(validatorSnapshotPrefix)
	if err != nil {
		return nil, fmt.Errorf("rawdb: scanning validator snapshots: %w", err)
	}
	rows := make([]*ValidatorSnapshotRow, 0, len(keys))
	for _, key := range keys {
		epoch, err := decodeHeight(key[len(validatorSnapshotPrefix):])
		if err != nil {
			return nil, fmt.Errorf("rawdb: bad validator snapshot key %q: %w", key, err)
		}
		row, err := ReadValidatorSnapshot(db, epoch)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	// Fixed-width hex keys already sort ascending, but ListKeysWithPrefix does
	// not promise an ordering guarantee across backends, so the invariant the
	// replay loop depends on is enforced here rather than assumed.
	for i := 1; i < len(rows); i++ {
		if rows[i-1].Epoch >= rows[i].Epoch {
			return nil, fmt.Errorf("rawdb: validator snapshots out of order or duplicated at epoch %d", rows[i].Epoch)
		}
	}
	return rows, nil
}

// Validate checks that the row is internally consistent: every member's stake
// parses, and TotalStake is exactly the sum of them.
func (r *ValidatorSnapshotRow) Validate() error {
	if r == nil {
		return fmt.Errorf("nil snapshot row")
	}
	total, ok := new(big.Int).SetString(r.TotalStake, 10)
	if !ok {
		return fmt.Errorf("unparseable total stake %q", r.TotalStake)
	}
	sum := big.NewInt(0)
	for id, v := range r.Validators {
		stake, ok := new(big.Int).SetString(v.Stake, 10)
		if !ok {
			return fmt.Errorf("unparseable stake %q for validator %s", v.Stake, id)
		}
		if stake.Sign() <= 0 {
			return fmt.Errorf("validator %s has non-positive stake %s in a snapshot", id, v.Stake)
		}
		sum.Add(sum, stake)
	}
	if sum.Cmp(total) != 0 {
		return fmt.Errorf("total stake %s does not equal the sum of members %s", r.TotalStake, sum.String())
	}
	return nil
}

func rowEpoch(r *ValidatorSnapshotRow) uint64 {
	if r == nil {
		return 0
	}
	return r.Epoch
}
