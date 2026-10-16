package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gofrs/flock"
)

type Store struct {
	path string
	lock *flock.Flock
}

type Journal interface {
	Load() (State, error)
	Save(State) error
}

func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lock := flock.New(path + ".lock")
	ok, err := lock.TryLock()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("state file is already in use")
	}
	return &Store{path: path, lock: lock}, nil
}

func (s *Store) Close() error { return s.lock.Unlock() }

func (s *Store) Load() (State, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return State{Desired: EmptyConfig(), Transactions: map[string]*Transaction{}}, nil
	}
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(b, &state); err != nil {
		return State{}, fmt.Errorf("decode durable state: %w", err)
	}
	if state.Transactions == nil {
		return State{}, fmt.Errorf("invalid durable state: missing transactions")
	}
	state.Desired.Normalize()
	if err := state.Desired.Validate(); err != nil {
		return State{}, fmt.Errorf("invalid durable desired state: %w", err)
	}
	for id, t := range state.Transactions {
		if t == nil || t.ID != id {
			return State{}, fmt.Errorf("invalid transaction journal entry %q", id)
		}
		t.Candidate.Normalize()
		t.Previous.Normalize()
		if err := t.Candidate.Validate(); err != nil {
			return State{}, fmt.Errorf("invalid candidate in %s: %w", id, err)
		}
		if err := t.Previous.Validate(); err != nil {
			return State{}, fmt.Errorf("invalid rollback configuration in %s: %w", id, err)
		}
		switch t.Status {
		case "applying", "rolling_back", "recovery_failed", "pending_confirmation":
			if state.Active != id || t.BaseRevision != state.Revision || !Equal(t.Previous, state.Desired) || t.Deadline.IsZero() {
				return State{}, fmt.Errorf("inconsistent active journal entry %q", id)
			}
		case "committed", "rolled_back":
		default:
			return State{}, fmt.Errorf("unknown transaction status in %q", id)
		}
	}
	return state, nil
}

func (s *Store) Save(state State) error {
	b, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".netcontrol-state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, s.path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(s.path))
}
