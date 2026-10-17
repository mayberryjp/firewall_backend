package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func commitConfig(t *testing.T, e *Engine, c Config) Transaction {
	t.Helper()
	tx := submit(t, e, e.Snapshot().Revision, c)
	result, err := e.Confirm(context.Background(), tx.ID, "reviewer")
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestRevisionMetadataAndConfigurationsSurviveRestart(t *testing.T) {
	store := testStore(t)
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.FixedZone("test", 19800))
	e.now = func() time.Time { return now }
	submittedAt := now
	tx, err := e.Submit(context.Background(), "author", Request{Config: candidate(), ConfirmSeconds: 30, Description: "  WAN migration  "})
	if err != nil {
		t.Fatal(err)
	}
	page, err := e.ListRevisions(50, nil)
	if err != nil || len(page.Revisions) != 1 || page.Revisions[0].Revision != 0 || page.Revisions[0].CommittedAt == nil {
		t.Fatalf("pending candidate leaked into history: %+v %v", page, err)
	}
	if _, err := e.GetRevision(1); !errors.Is(err, ErrRevisionNotFound) {
		t.Fatalf("unconfirmed revision exists: %v", err)
	}
	now = now.Add(2 * time.Second)
	if _, err := e.Confirm(context.Background(), tx.ID, "reviewer"); err != nil {
		t.Fatal(err)
	}
	e = testEngine(t, store, NewSimulator(candidate()))
	r, err := e.GetRevision(1)
	if err != nil {
		t.Fatal(err)
	}
	if r.SubmittedAt == nil || !r.SubmittedAt.Equal(submittedAt) || r.CommittedAt == nil || !r.CommittedAt.Equal(now) ||
		r.SubmittedAt.Location() != time.UTC || r.CommittedAt.Location() != time.UTC ||
		r.SubmittedBy != "author" || r.CommittedBy != "reviewer" || r.Description != "WAN migration" ||
		r.TransactionID != tx.ID || !r.Current || !Equal(r.Config, candidate()) {
		t.Fatalf("incorrect persisted metadata: %+v", r)
	}
	r.Config.Interfaces[0].MTU = 9000
	*r.CommittedAt = time.Time{}
	again, err := e.GetRevision(1)
	if err != nil || !Equal(again.Config, candidate()) || !again.CommittedAt.Equal(now) {
		t.Fatalf("history was mutable through response: %+v %v", again, err)
	}
	initial, err := e.GetRevision(0)
	if err != nil || !Equal(initial.Config, EmptyConfig()) || initial.Current {
		t.Fatalf("initial revision: %+v %v", initial, err)
	}
}

func TestHistoricalRestoreCreatesNewRevisionsWithoutRewritingHistory(t *testing.T) {
	e := testEngine(t, testStore(t), NewSimulator(EmptyConfig()))
	first := candidate()
	commitConfig(t, e, first)
	second := Clone(first)
	second.Interfaces[0].MTU = 1400
	commitConfig(t, e, second)
	tx, err := e.Restore(context.Background(), "restorer", 1, RestoreRequest{BaseRevision: 2, ConfirmSeconds: 30})
	if err != nil || tx.RestoredFrom == nil || *tx.RestoredFrom != 1 || tx.Description != "Restore revision 1" || !Equal(tx.Candidate, first) {
		t.Fatalf("restore candidate: %+v %v", tx, err)
	}
	if e.Snapshot().Revision != 2 {
		t.Fatal("restore advanced revision before confirmation")
	}
	if _, err := e.GetRevision(3); !errors.Is(err, ErrRevisionNotFound) {
		t.Fatal("provisional restore published to history")
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "approver"); err != nil {
		t.Fatal(err)
	}
	restored, err := e.GetRevision(3)
	if err != nil || restored.RestoredFrom == nil || *restored.RestoredFrom != 1 || restored.CommittedBy != "approver" || !Equal(restored.Config, first) {
		t.Fatalf("restored revision: %+v %v", restored, err)
	}
	unchanged, err := e.GetRevision(2)
	if err != nil || unchanged.Current || !Equal(unchanged.Config, second) {
		t.Fatalf("old revision changed: %+v %v", unchanged, err)
	}
	zero, err := e.Restore(context.Background(), "restorer", 0, RestoreRequest{BaseRevision: 3, ConfirmSeconds: 30, Description: "Reset lab"})
	if err != nil || zero.RestoredFrom == nil || *zero.RestoredFrom != 0 {
		t.Fatalf("restore initial revision: %+v %v", zero, err)
	}
	if _, err := e.Confirm(context.Background(), zero.ID, "approver"); err != nil {
		t.Fatal(err)
	}
	final, err := e.GetRevision(4)
	if err != nil || !Equal(final.Config, EmptyConfig()) || final.RestoredFrom == nil || *final.RestoredFrom != 0 {
		t.Fatalf("initial restoration: %+v %v", final, err)
	}
}

func TestRevisionPaginationExcludesAbandonedCandidates(t *testing.T) {
	e := testEngine(t, testStore(t), NewSimulator(EmptyConfig()))
	for i := 0; i < 3; i++ {
		c := candidate()
		c.Interfaces[0].MTU += i
		commitConfig(t, e, c)
	}
	abandoned := submit(t, e, 3, EmptyConfig())
	if _, err := e.Rollback(abandoned.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	page, err := e.ListRevisions(2, nil)
	if err != nil || len(page.Revisions) != 2 || page.Revisions[0].Revision != 3 || page.Revisions[1].Revision != 2 ||
		page.NextBeforeRevision == nil || *page.NextBeforeRevision != 2 {
		t.Fatalf("first page: %+v %v", page, err)
	}
	last, err := e.ListRevisions(2, page.NextBeforeRevision)
	if err != nil || len(last.Revisions) != 2 || last.Revisions[0].Revision != 1 || last.Revisions[1].Revision != 0 ||
		last.NextBeforeRevision != nil {
		t.Fatalf("second page: %+v %v", last, err)
	}
	before := uint64(0)
	empty, err := e.ListRevisions(2, &before)
	if err != nil || empty.Revisions == nil || len(empty.Revisions) != 0 {
		t.Fatalf("empty page: %+v %v", empty, err)
	}
	for _, limit := range []int{0, 101} {
		if _, err := e.ListRevisions(limit, nil); !errors.Is(err, ErrValidation) {
			t.Fatalf("invalid list limit: %v", err)
		}
	}
}

func TestRestoreReusesConflictValidationAndRecovery(t *testing.T) {
	e := testEngine(t, testStore(t), NewSimulator(EmptyConfig()))
	commitConfig(t, e, candidate())
	if _, err := e.Restore(context.Background(), "operator", 99, RestoreRequest{BaseRevision: 1, ConfirmSeconds: 30}); !errors.Is(err, ErrRevisionNotFound) {
		t.Fatalf("unknown revision: %v", err)
	}
	if _, err := e.Restore(context.Background(), "operator", 0, RestoreRequest{BaseRevision: 0, ConfirmSeconds: 30}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale restore: %v", err)
	}
	if _, err := e.Restore(context.Background(), "operator", 0, RestoreRequest{BaseRevision: 1, ConfirmSeconds: 0}); !errors.Is(err, ErrValidation) {
		t.Fatalf("invalid timeout: %v", err)
	}
	if _, err := e.Restore(context.Background(), "operator", 0, RestoreRequest{BaseRevision: 1, ConfirmSeconds: 30, Description: strings.Repeat("x", 1025)}); !errors.Is(err, ErrValidation) {
		t.Fatalf("oversize description: %v", err)
	}
	tx, err := e.Restore(context.Background(), "operator", 0, RestoreRequest{BaseRevision: 1, ConfirmSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	e.now = func() time.Time { return tx.Deadline }
	if err := e.Tick(); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().Revision != 1 || !Equal(e.Snapshot().Desired, candidate()) {
		t.Fatal("restore timeout did not preserve committed revision")
	}
	if _, err := e.GetRevision(2); !errors.Is(err, ErrRevisionNotFound) {
		t.Fatal("abandoned restore entered history")
	}
}

func TestFailedConfirmationDoesNotPublishRevisionMetadata(t *testing.T) {
	j := &failingJournal{Journal: testStore(t), failAt: 4}
	e := testEngine(t, j, NewSimulator(EmptyConfig()))
	tx := submit(t, e, 0, candidate())
	if _, err := e.Confirm(context.Background(), tx.ID, "reviewer"); err == nil {
		t.Fatal("injected persistence failure hidden")
	}
	if _, err := e.GetRevision(1); !errors.Is(err, ErrRevisionNotFound) {
		t.Fatal("failed confirmation published revision")
	}
	pending := e.Snapshot().Transactions[tx.ID]
	if pending.CommittedAt != nil || pending.CommittedBy != "" {
		t.Fatal("unpersisted commit metadata published")
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "retry-reviewer"); err != nil {
		t.Fatal(err)
	}
	r, err := e.GetRevision(1)
	if err != nil || r.CommittedBy != "retry-reviewer" {
		t.Fatalf("retry metadata: %+v %v", r, err)
	}
}

func TestLegacyRevisionDatesRemainUnknown(t *testing.T) {
	store := testStore(t)
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	commitConfig(t, e, candidate())
	data, err := json.Marshal(e.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "initialized_at")
	for _, value := range legacy["transactions"].(map[string]any) {
		txn := value.(map[string]any)
		for _, field := range []string{"submitted_at", "committed_at", "committed_by", "description", "restored_from_revision"} {
			delete(txn, field)
		}
	}
	data, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	e = testEngine(t, store, NewSimulator(candidate()))
	page, err := e.ListRevisions(50, nil)
	if err != nil || len(page.Revisions) != 2 {
		t.Fatalf("legacy history: %+v %v", page, err)
	}
	for _, r := range page.Revisions {
		if r.CommittedAt != nil || r.SubmittedAt != nil {
			t.Fatal("invented date for legacy revision")
		}
	}
	tx, err := e.Restore(context.Background(), "operator", 0, RestoreRequest{BaseRevision: 1, ConfirmSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	r, err := e.GetRevision(2)
	if err != nil || r.CommittedAt == nil || r.RestoredFrom == nil || *r.RestoredFrom != 0 {
		t.Fatalf("new revision after legacy load: %+v %v", r, err)
	}
}

func TestRestoreRecoveryPreservesHistoryAndProvenance(t *testing.T) {
	store := testStore(t)
	a := NewSimulator(EmptyConfig())
	e := testEngine(t, store, a)
	commitConfig(t, e, candidate())
	restore, err := e.Restore(context.Background(), "operator", 0, RestoreRequest{BaseRevision: 1, ConfirmSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	state := e.Snapshot()
	state.Transactions[restore.ID].Status = "applying"
	if err := store.Save(state); err != nil {
		t.Fatal(err)
	}
	recovered := testEngine(t, store, a)
	if recovered.Snapshot().Revision != 1 || recovered.Snapshot().Active != "" ||
		!Equal(recovered.Snapshot().Desired, candidate()) {
		t.Fatal("interrupted restoration corrupted desired revision")
	}
	tx := recovered.Snapshot().Transactions[restore.ID]
	if tx.Status != "rolled_back" || tx.RestoredFrom == nil || *tx.RestoredFrom != 0 ||
		tx.SubmittedAt == nil || tx.CommittedAt != nil {
		t.Fatalf("recovered restore metadata: %+v", tx)
	}
	page, err := recovered.ListRevisions(50, nil)
	if err != nil || len(page.Revisions) != 2 {
		t.Fatalf("recovered history: %+v %v", page, err)
	}
	observed, err := recovered.View(context.Background())
	if err != nil || observed.Drift || !Equal(observed.Observed, candidate()) {
		t.Fatalf("recovered state: %+v %v", observed, err)
	}
}

func TestStoreRejectsInconsistentRevisionHistory(t *testing.T) {
	store := testStore(t)
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	tx := commitConfig(t, e, candidate())
	base := e.Snapshot()
	for name, corrupt := range map[string]func(*State){
		"missing": func(s *State) { s.Transactions = map[string]*Transaction{} },
		"future":  func(s *State) { s.Transactions[tx.ID].BaseRevision = 1 },
		"duplicate": func(s *State) {
			other := Clone(*s.Transactions[tx.ID])
			other.ID = "duplicate"
			s.Transactions[other.ID] = &other
		},
		"desired-mismatch": func(s *State) { s.Desired.Interfaces[0].MTU = 9000 },
		"false-provenance": func(s *State) { source := uint64(0); s.Transactions[tx.ID].RestoredFrom = &source },
	} {
		t.Run(name, func(t *testing.T) {
			state := Clone(base)
			corrupt(&state)
			if err := store.Save(state); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Load(); err == nil {
				t.Fatal("inconsistent revision archive accepted")
			}
		})
	}
}
