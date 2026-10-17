package control

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"
)

type RevisionMetadata struct {
	Revision      uint64     `json:"revision"`
	Current       bool       `json:"current"`
	TransactionID string     `json:"transaction_id,omitempty"`
	SubmittedAt   *time.Time `json:"submitted_at"`
	CommittedAt   *time.Time `json:"committed_at"`
	SubmittedBy   string     `json:"submitted_by,omitempty"`
	CommittedBy   string     `json:"committed_by,omitempty"`
	Description   string     `json:"description,omitempty"`
	RestoredFrom  *uint64    `json:"restored_from_revision,omitempty"`
}

type Revision struct {
	RevisionMetadata
	Config Config `json:"config"`
}

type RevisionPage struct {
	Revisions          []RevisionMetadata `json:"revisions"`
	NextBeforeRevision *uint64            `json:"next_before_revision,omitempty"`
}

type RestoreRequest struct {
	BaseRevision   uint64 `json:"base_revision"`
	ConfirmSeconds int    `json:"confirm_timeout_seconds"`
	Description    string `json:"description,omitempty"`
}

// Committed transaction snapshots are the revision archive; avoid maintaining a
// second independently mutable copy of historical configurations.
func revisionRecords(state State) (map[uint64]Revision, error) {
	records := map[uint64]Revision{}
	initial := state.Desired
	for _, t := range state.Transactions {
		if t.Status != "committed" {
			continue
		}
		if t.BaseRevision >= state.Revision {
			return nil, fmt.Errorf("committed transaction %s has invalid base revision", t.ID)
		}
		number := t.BaseRevision + 1
		if _, exists := records[number]; exists {
			return nil, fmt.Errorf("duplicate committed revision %d", number)
		}
		records[number] = Revision{RevisionMetadata: RevisionMetadata{
			Revision: number, Current: number == state.Revision, TransactionID: t.ID,
			SubmittedAt: t.SubmittedAt, CommittedAt: t.CommittedAt, SubmittedBy: t.Actor,
			CommittedBy: t.CommittedBy, Description: t.Description, RestoredFrom: t.RestoredFrom,
		}, Config: t.Candidate}
		if number == 1 {
			initial = t.Previous
		}
	}
	records[0] = Revision{RevisionMetadata: RevisionMetadata{
		Revision: 0, Current: state.Revision == 0, CommittedAt: state.InitializedAt,
		CommittedBy: "system", Description: "Initial configuration",
	}, Config: initial}
	if uint64(len(records)-1) != state.Revision {
		return nil, fmt.Errorf("revision archive is incomplete")
	}
	current, exists := records[state.Revision]
	if !exists || !Equal(current.Config, state.Desired) {
		return nil, fmt.Errorf("current desired configuration does not match revision archive")
	}
	for _, t := range state.Transactions {
		base, exists := records[t.BaseRevision]
		if !exists || !Equal(base.Config, t.Previous) {
			return nil, fmt.Errorf("transaction %s does not match its base revision", t.ID)
		}
		if t.RestoredFrom != nil {
			source, exists := records[*t.RestoredFrom]
			if !exists || *t.RestoredFrom > t.BaseRevision || !Equal(source.Config, t.Candidate) {
				return nil, fmt.Errorf("transaction %s has inconsistent restoration provenance", t.ID)
			}
		}
	}
	return records, nil
}

func (e *Engine) GetRevision(number uint64) (Revision, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	records, err := revisionRecords(e.state)
	if err != nil {
		return Revision{}, err
	}
	r, exists := records[number]
	if !exists {
		return Revision{}, fmt.Errorf("%w: %d", ErrRevisionNotFound, number)
	}
	return Clone(r), nil
}

func (e *Engine) ListRevisions(limit int, before *uint64) (RevisionPage, error) {
	if limit < 1 || limit > 100 {
		return RevisionPage{}, fmt.Errorf("%w: revision list limit must be 1..100", ErrValidation)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	records, err := revisionRecords(e.state)
	if err != nil {
		return RevisionPage{}, err
	}
	numbers := make([]uint64, 0, len(records))
	for number := range records {
		if before == nil || number < *before {
			numbers = append(numbers, number)
		}
	}
	slices.SortFunc(numbers, func(a, b uint64) int {
		if a > b {
			return -1
		}
		if a < b {
			return 1
		}
		return 0
	})
	page := RevisionPage{Revisions: []RevisionMetadata{}}
	for _, number := range numbers {
		if len(page.Revisions) == limit {
			last := page.Revisions[len(page.Revisions)-1].Revision
			page.NextBeforeRevision = &last
			break
		}
		page.Revisions = append(page.Revisions, Clone(records[number].RevisionMetadata))
	}
	return page, nil
}

func (e *Engine) Restore(ctx context.Context, actor string, number uint64, r RestoreRequest) (Transaction, error) {
	revision, err := e.GetRevision(number)
	if err != nil {
		return Transaction{}, err
	}
	description := strings.TrimSpace(r.Description)
	if description == "" {
		description = fmt.Sprintf("Restore revision %d", number)
	}
	return e.submit(ctx, actor, Request{
		BaseRevision: r.BaseRevision, ConfirmSeconds: r.ConfirmSeconds,
		Config: revision.Config, Description: description,
	}, &number)
}
