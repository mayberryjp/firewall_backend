package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netcontrol/internal/control"
)

func commitHistoryConfig(t *testing.T, e *control.Engine, config control.Config) {
	t.Helper()
	tx, err := e.Submit(context.Background(), "author", control.Request{
		BaseRevision: e.Snapshot().Revision, ConfirmSeconds: 30, Config: config, Description: "Network migration",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "reviewer"); err != nil {
		t.Fatal(err)
	}
}

func historyConfig() control.Config {
	c := control.EmptyConfig()
	c.Interfaces = []control.Interface{{Name: "wan", Kind: "dummy", Role: "wan", MTU: 1500, Up: true, Addresses: []string{"192.0.2.10/24"}}}
	c.Firewall.NAT.Masquerade = []control.MasqueradeRule{{Family: "ipv4", Source: "10.8.0.0/24", OutInterface: "wan"}}
	return c
}

func TestRevisionListAndHistoricalRetrieval(t *testing.T) {
	h, e := fixture(t)
	commitHistoryConfig(t, e, historyConfig())
	w := request(t, h, "GET", "/api/v1/revisions?limit=1", "reader-test-token", nil)
	var page control.RevisionPage
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(page.Revisions) != 1 || page.Revisions[0].Revision != 1 ||
		page.Revisions[0].CommittedAt == nil || page.Revisions[0].SubmittedAt == nil ||
		page.Revisions[0].Description != "Network migration" || page.Revisions[0].SubmittedBy != "author" ||
		page.Revisions[0].CommittedBy != "reviewer" || !page.Revisions[0].Current ||
		page.NextBeforeRevision == nil || *page.NextBeforeRevision != 1 {
		t.Fatalf("revision listing: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"config":`) {
		t.Fatal("summary endpoint returned full snapshots")
	}
	w = request(t, h, "GET", "/api/v1/revisions?limit=1&before_revision=1", "reader-test-token", nil)
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(page.Revisions) != 1 || page.Revisions[0].Revision != 0 {
		t.Fatalf("pagination: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/api/v1/revisions/1", "reader-test-token", nil)
	var revision control.Revision
	if err := json.Unmarshal(w.Body.Bytes(), &revision); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || !control.Equal(revision.Config, historyConfig()) || revision.Revision != 1 {
		t.Fatalf("snapshot: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/api/v1/revisions?before_revision=0", "reader-test-token", nil)
	if w.Code != 200 || w.Body.String() != "{\"revisions\":[]}\n" {
		t.Fatalf("empty listing: %d %s", w.Code, w.Body.String())
	}
}

func TestRevisionRestoreRESTLifecycleAndProvenance(t *testing.T) {
	h, e := fixture(t)
	commitHistoryConfig(t, e, historyConfig())
	commitHistoryConfig(t, e, control.EmptyConfig())
	body := control.RestoreRequest{BaseRevision: 2, ConfirmSeconds: 30, Description: "Recover previous WAN"}
	for _, token := range []string{"reader-test-token", "firewall-test-token", "nat-test-token"} {
		w := request(t, h, "POST", "/api/v1/revisions/1/restore", token, body)
		if w.Code != 403 {
			t.Fatalf("restricted principal restored cross-subsystem history: %d %s", w.Code, w.Body.String())
		}
	}
	w := request(t, h, "POST", "/api/v1/revisions/1/restore", "admin-test-token", body)
	if w.Code != 202 {
		t.Fatalf("restore: %d %s", w.Code, w.Body.String())
	}
	var tx control.Transaction
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	if tx.RestoredFrom == nil || *tx.RestoredFrom != 1 || tx.Actor != "admin" || tx.Description != body.Description ||
		w.Header().Get("Location") != "/api/v1/transactions/"+tx.ID {
		t.Fatalf("restore metadata: %+v", tx)
	}
	if e.Snapshot().Revision != 2 {
		t.Fatal("restore committed without confirmation")
	}
	retry := request(t, h, "POST", "/api/v1/revisions/1/restore", "admin-test-token", body)
	if retry.Code != 409 {
		t.Fatalf("active restore did not block another package: %d %s", retry.Code, retry.Body.String())
	}
	w = request(t, h, "GET", "/api/v1/revisions/3", "reader-test-token", nil)
	if w.Code != 404 {
		t.Fatal("provisional restore entered revision history")
	}
	w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "admin-test-token", nil)
	if w.Code != 200 {
		t.Fatalf("confirmation: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/api/v1/revisions/3", "reader-test-token", nil)
	var restored control.Revision
	if err := json.Unmarshal(w.Body.Bytes(), &restored); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || restored.RestoredFrom == nil || *restored.RestoredFrom != 1 || !restored.Current ||
		restored.CommittedAt == nil || restored.CommittedBy != "admin" || !control.Equal(restored.Config, historyConfig()) {
		t.Fatalf("restored revision: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/api/v1/revisions/2", "reader-test-token", nil)
	var previous control.Revision
	if err := json.Unmarshal(w.Body.Bytes(), &previous); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || previous.Current || !control.Equal(previous.Config, control.EmptyConfig()) {
		t.Fatal("restore rewrote old history")
	}
}

func TestNATOperatorCanRestoreNATOnlyChanges(t *testing.T) {
	h, e := fixture(t)
	base := historyConfig()
	base.Firewall.NAT = control.NAT{}
	commitHistoryConfig(t, e, base)
	commitHistoryConfig(t, e, historyConfig())
	w := request(t, h, "POST", "/api/v1/revisions/1/restore", "nat-test-token", control.RestoreRequest{BaseRevision: 2, ConfirmSeconds: 30})
	if w.Code != 202 {
		t.Fatalf("NAT-only restore: %d %s", w.Code, w.Body.String())
	}
	var tx control.Transaction
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "nat-test-token", nil)
	if w.Code != 200 || e.Snapshot().Revision != 3 || !control.Equal(e.Snapshot().Desired, base) {
		t.Fatalf("NAT-only confirmation: %d %s", w.Code, w.Body.String())
	}
}

func TestRevisionAPIRejectsInvalidAndStaleRequests(t *testing.T) {
	h, e := fixture(t)
	commitHistoryConfig(t, e, historyConfig())
	tests := []struct {
		name, method, path, token string
		body                      any
		status                    int
	}{
		{"anonymous", "GET", "/api/v1/revisions", "", nil, 401},
		{"no-read-list", "GET", "/api/v1/revisions", "writer-test-token", nil, 403},
		{"missing-revision", "GET", "/api/v1/revisions/99", "reader-test-token", nil, 404},
		{"bad-number", "GET", "/api/v1/revisions/nope", "reader-test-token", nil, 400},
		{"negative-number", "GET", "/api/v1/revisions/-1", "reader-test-token", nil, 400},
		{"zero-limit", "GET", "/api/v1/revisions?limit=0", "reader-test-token", nil, 400},
		{"large-limit", "GET", "/api/v1/revisions?limit=101", "reader-test-token", nil, 400},
		{"nonnumeric-limit", "GET", "/api/v1/revisions?limit=x", "reader-test-token", nil, 400},
		{"empty-limit", "GET", "/api/v1/revisions?limit=", "reader-test-token", nil, 400},
		{"duplicate-limit", "GET", "/api/v1/revisions?limit=1&limit=2", "reader-test-token", nil, 400},
		{"negative-cursor", "GET", "/api/v1/revisions?before_revision=-1", "reader-test-token", nil, 400},
		{"overflow-cursor", "GET", "/api/v1/revisions?before_revision=18446744073709551616", "reader-test-token", nil, 400},
		{"unknown-query", "GET", "/api/v1/revisions?unknown=true", "reader-test-token", nil, 400},
		{"invalid-query-escape", "GET", "/api/v1/revisions?limit=1%ZZ", "reader-test-token", nil, 400},
		{"no-read-restore", "POST", "/api/v1/revisions/0/restore", "writer-test-token", control.RestoreRequest{BaseRevision: 1, ConfirmSeconds: 30}, 403},
		{"missing-source", "POST", "/api/v1/revisions/99/restore", "admin-test-token", control.RestoreRequest{BaseRevision: 1, ConfirmSeconds: 30}, 404},
		{"stale-restore", "POST", "/api/v1/revisions/0/restore", "admin-test-token", control.RestoreRequest{BaseRevision: 0, ConfirmSeconds: 30}, 409},
		{"invalid-timeout", "POST", "/api/v1/revisions/0/restore", "admin-test-token", control.RestoreRequest{BaseRevision: 1, ConfirmSeconds: 0}, 422},
		{"invalid-description", "POST", "/api/v1/revisions/0/restore", "admin-test-token", control.RestoreRequest{BaseRevision: 1, ConfirmSeconds: 30, Description: strings.Repeat("x", 1025)}, 422},
		{"unknown-body-field", "POST", "/api/v1/revisions/0/restore", "admin-test-token", `{"base_revision":1,"confirm_timeout_seconds":30,"config":{}}`, 400},
		{"bad-restore-number", "POST", "/api/v1/revisions/nope/restore", "admin-test-token", control.RestoreRequest{}, 400},
		{"bad-restore-action", "POST", "/api/v1/revisions/0/delete", "admin-test-token", control.RestoreRequest{}, 404},
		{"immutable-revision", "PUT", "/api/v1/revisions/1", "admin-test-token", nil, 405},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := request(t, h, test.method, test.path, test.token, test.body)
			if w.Code != test.status {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
		})
	}
	r := httptest.NewRequest("POST", "/api/v1/revisions/0/restore", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer "+"admin-test-token")
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type: %d", w.Code)
	}
	if e.Snapshot().Revision != 1 || e.Snapshot().Active != "" {
		t.Fatal("rejected restore mutated state")
	}
}

func TestAuthorizationUsesTheExactRequestedBaseRevision(t *testing.T) {
	state := control.State{Revision: 2, Desired: historyConfig()}
	principal := Credential{Permissions: permissions}
	if err := authorizeAtRevision(principal, state, 3, control.EmptyConfig()); err != control.ErrConflict {
		t.Fatalf("authorization allowed a predicted future base revision: %v", err)
	}
	if err := authorizeAtRevision(principal, state, 1, control.EmptyConfig()); err != control.ErrConflict {
		t.Fatalf("authorization allowed an obsolete base revision: %v", err)
	}
	if err := authorizeAtRevision(principal, state, 2, control.EmptyConfig()); err != nil {
		t.Fatal(err)
	}
}
