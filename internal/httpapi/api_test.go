package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netcontrol/internal/control"
)

func fixture(t *testing.T) (http.Handler, *control.Engine) {
	t.Helper()
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	e, err := control.NewEngine(store, control.NewSimulator(control.EmptyConfig()), log)
	if err != nil {
		t.Fatal(err)
	}
	hash := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	handler, err := New(e, []Credential{
		{Name: "admin", TokenSHA256: hash("admin-test-token"), Permissions: permissions},
		{Name: "reader", TokenSHA256: hash("reader-test-token"), Permissions: []string{"state.read"}},
		{Name: "writeonly", TokenSHA256: hash("writer-test-token"), Permissions: []string{"transactions.write"}},
		{Name: "firewall", TokenSHA256: hash("firewall-test-token"), Permissions: []string{"state.read", "transactions.write", "firewall.write"}},
		{Name: "nat", TokenSHA256: hash("nat-test-token"), Permissions: []string{"state.read", "transactions.write", "nat.write"}},
		{Name: "softflowd", TokenSHA256: hash("softflowd-test-token"), Permissions: []string{"state.read", "transactions.write", "softflowd.write"}},
		{Name: "interfaces", TokenSHA256: hash("interfaces-test-token"), Permissions: []string{"state.read", "transactions.write", "interfaces.write"}},
		{Name: "gateways", TokenSHA256: hash("gateways-test-token"), Permissions: []string{"state.read", "transactions.write", "gateway_monitors.write"}},
		{Name: "ntp", TokenSHA256: hash("ntp-test-token"), Permissions: []string{"state.read", "transactions.write", "ntp.write"}},
		{Name: "syslog", TokenSHA256: hash("syslog-test-token"), Permissions: []string{"state.read", "transactions.write", "syslog.write"}},
		{Name: "vnstat", TokenSHA256: hash("vnstat-test-token"), Permissions: []string{"state.read", "transactions.write", "vnstat.write"}},
		{Name: "kernel-namespace", TokenSHA256: hash("kernel-namespace-test-token"), Permissions: []string{"state.read", "transactions.write", "kernel.namespace.write"}},
		{Name: "kernel-host", TokenSHA256: hash("kernel-host-test-token"), Permissions: []string{"state.read", "transactions.write", "kernel.host.write"}},
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	return handler, e
}

func request(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	var err error
	if body != nil {
		if raw, ok := body.(string); ok {
			data = []byte(raw)
		} else {
			data, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(data))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !json.Valid(w.Body.Bytes()) {
		t.Fatalf("non-JSON response: %s", w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("missing no-store")
	}
	return w
}

func TestHTTPTransactionRoundTrip(t *testing.T) {
	h, e := fixture(t)
	c := control.EmptyConfig()
	c.Interfaces = []control.Interface{{Name: "wan", Kind: "dummy", Role: "wan", MTU: 1500, Up: true, Addresses: []string{"192.0.2.10/24"}}}
	w := request(t, h, "POST", "/api/v1/transactions", "admin-test-token", control.Request{BaseRevision: 0, ConfirmSeconds: 30, Config: c})
	if w.Code != http.StatusAccepted {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var tx control.Transaction
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	if w.Header().Get("Location") != "/api/v1/transactions/"+tx.ID {
		t.Fatal("missing location")
	}
	for _, path := range []string{"/api/v1/state", "/api/v1/interfaces", "/api/v1/interfaces/wan", "/api/v1/routes", "/api/v1/policy-rules", "/api/v1/firewall/rules", "/api/v1/wireguard", "/api/v1/transactions", "/api/v1/transactions/" + tx.ID} {
		if w := request(t, h, "GET", path, "reader-test-token", nil); w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	if w := request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "admin-test-token", nil); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if e.Snapshot().Revision != 1 {
		t.Fatal("revision not committed")
	}
	w = request(t, h, "POST", "/api/v1/transactions", "admin-test-token", control.Request{BaseRevision: 0, ConfirmSeconds: 30, Config: c})
	if w.Code != http.StatusConflict {
		t.Fatalf("stale revision: %d", w.Code)
	}
}

func TestHTTPRejectsUnauthorizedAndInvalidRequests(t *testing.T) {
	h, e := fixture(t)
	tests := []struct {
		name, method, path, token string
		body                      any
		status                    int
	}{
		{"anonymous", "GET", "/api/v1/state", "", nil, 401},
		{"bad-token", "GET", "/api/v1/state", "wrong", nil, 401},
		{"read-only", "POST", "/api/v1/transactions", "reader-test-token", control.Request{}, 403},
		{"unknown-field", "POST", "/api/v1/transactions", "admin-test-token", `{"unknown":true}`, 400},
		{"trailing-json", "POST", "/api/v1/transactions", "admin-test-token", `{} {}`, 400},
		{"invalid-config", "POST", "/api/v1/transactions", "admin-test-token", control.Request{Config: control.EmptyConfig(), ConfirmSeconds: 0}, 422},
		{"oversize", "POST", "/api/v1/transactions", "admin-test-token", `{"config":{"firewall":{"policy":"` + strings.Repeat("x", 1<<20) + `"}}}`, 400},
		{"unknown-path", "GET", "/api/v1/missing", "admin-test-token", nil, 404},
		{"missing-transaction", "GET", "/api/v1/transactions/missing", "admin-test-token", nil, 404},
		{"wrong-method", "PUT", "/api/v1/interfaces/wan/addresses", "admin-test-token", nil, 405},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := request(t, h, test.method, test.path, test.token, test.body)
			if w.Code != test.status {
				t.Fatalf("%d: %s", w.Code, w.Body.String())
			}
			if test.status == http.StatusUnauthorized &&
				(!strings.Contains(w.Body.String(), `"error":"valid API key required"`) || w.Header().Get("WWW-Authenticate") != "Bearer") {
				t.Fatalf("expected API key error and Bearer challenge: %v %s", w.Header(), w.Body.String())
			}
		})
	}
	if e.Snapshot().Active != "" || e.Snapshot().Revision != 0 {
		t.Fatal("rejected requests mutated state")
	}
}

func TestSubsystemAuthorizationAlsoAppliesToConfirmationAndRollback(t *testing.T) {
	h, e := fixture(t)
	c := control.EmptyConfig()
	c.Interfaces = []control.Interface{{Name: "wan", Kind: "dummy", Role: "wan", MTU: 1500, Up: true}}
	w := request(t, h, "POST", "/api/v1/transactions", "firewall-test-token", control.Request{Config: c, ConfirmSeconds: 30})
	if w.Code != 403 {
		t.Fatalf("firewall operator modified interface: %d", w.Code)
	}
	tx, err := e.Submit(context.Background(), "admin", control.Request{Config: c, ConfirmSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"confirm", "rollback"} {
		w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/"+action, "firewall-test-token", nil)
		if w.Code != 403 {
			t.Fatalf("firewall operator could %s unrelated changes", action)
		}
	}
	w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/rollback", "admin-test-token", nil)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	c = control.EmptyConfig()
	c.Firewall.Policy = "drop"
	w = request(t, h, "POST", "/api/v1/transactions", "firewall-test-token", control.Request{Config: c, ConfirmSeconds: 30})
	if w.Code != 202 {
		t.Fatalf("firewall-only changes rejected: %d %s", w.Code, w.Body.String())
	}
}

func TestWireGuardRemovalRequiresWireGuardPermission(t *testing.T) {
	before := control.EmptyConfig()
	before.Interfaces = []control.Interface{{Name: "wg0", Kind: "wireguard", Role: "lan", MTU: 1420, WireGuard: &control.WireGuard{KeyRef: "wg0", ListenPort: 51820}}}
	limited := Credential{Permissions: []string{"interfaces.write"}}
	if err := authorize(limited, before, control.EmptyConfig()); err == nil {
		t.Fatal("WireGuard removal bypassed subsystem permission")
	}
}

func TestDocumentedMigrationOverRealHTTP(t *testing.T) {
	h, e := fixture(t)
	server := httptest.NewServer(h)
	defer server.Close()
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "migration.json"))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", server.URL+"/api/v1/transactions", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer admin-test-token")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 202 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	var tx control.Transaction
	if err := json.NewDecoder(resp.Body).Decode(&tx); err != nil {
		t.Fatal(err)
	}
	view, err := e.View(context.Background())
	if err != nil || view.Drift || len(view.Observed.Interfaces) != 2 || len(view.Observed.Routes) != 2 ||
		len(view.Observed.Firewall.NAT.Masquerade) != 1 {
		t.Fatalf("migration state: %+v %v", view, err)
	}
	req, err = http.NewRequest("POST", server.URL+"/api/v1/transactions/"+tx.ID+"/confirm", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer admin-test-token")
	confirmation, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer confirmation.Body.Close()
	if confirmation.StatusCode != 200 || e.Snapshot().Revision != 1 {
		t.Fatalf("confirmation failed: %d", confirmation.StatusCode)
	}
}
