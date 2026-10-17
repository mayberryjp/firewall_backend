package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"netcontrol/internal/control"
)

type failedObservationAdapter struct{ *control.Simulator }

func (a *failedObservationAdapter) Observe(context.Context, control.Config) (control.Config, error) {
	return control.Config{}, errors.New("injected parent observation failure")
}

func TestRuntimeRemainsReadableWhenConfigurationObservationFails(t *testing.T) {
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	e, err := control.NewEngine(store, &failedObservationAdapter{Simulator: control.NewSimulator(control.EmptyConfig())}, logger)
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte("runtime-reader-test-token")))
	h, err := New(e, []Credential{{Name: "reader", TokenSHA256: hash, Permissions: []string{"state.read"}}}, logger)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(t, h, "GET", "/api/v1/state", "runtime-reader-test-token", nil); w.Code != 503 {
		t.Fatalf("observation error hidden: %d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/api/v1/runtime", "/api/v1/parent-interfaces", "/api/v1/services/softflowd/status", "/api/v1/kernel/tunables", "/api/v1/kernel/tunables/catalog", "/api/v1/statistics", "/api/v1/statistics/interfaces", "/api/v1/statistics/protocols"} {
		if w := request(t, h, "GET", path, "runtime-reader-test-token", nil); w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
}

func TestServiceAPIAndSeparateAuthorization(t *testing.T) {
	h, e := fixture(t)
	c := control.EmptyConfig()
	c.Softflowd = []control.SoftflowdConfig{{Name: "office", Enabled: true, Interface: "uplink.100", Collector: "192.0.2.50:2055",
		ExportVersion: 10, SamplingRate: 100, MaxFlows: 65536, Snaplen: 256}}
	body := control.Request{Config: c, ConfirmSeconds: 30}
	for _, token := range []string{"reader-test-token", "writer-test-token", "firewall-test-token", "nat-test-token", "interfaces-test-token"} {
		w := request(t, h, "POST", "/api/v1/transactions", token, body)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: %d %s", token, w.Code, w.Body.String())
		}
	}
	w := request(t, h, "POST", "/api/v1/transactions", "softflowd-test-token", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var tx control.Transaction
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "GET", "/api/v1/services/softflowd", "reader-test-token", nil)
	var configs []control.SoftflowdConfig
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &configs) != nil || len(configs) != 1 || !configs[0].Enabled {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/api/v1/services/softflowd/status", "reader-test-token", nil)
	var status struct {
		Instances []control.SoftflowdStatus `json:"instances"`
		Error     string                    `json:"error"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &status) != nil || len(status.Instances) != 1 || status.Instances[0].State != "simulated" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	for _, token := range []string{"reader-test-token", "writer-test-token", "firewall-test-token", "interfaces-test-token"} {
		if w := request(t, h, "POST", "/api/v1/services/softflowd/reconcile", token, nil); w.Code != 403 {
			t.Fatalf("repair permission: %d %s", w.Code, w.Body.String())
		}
		if w := request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", token, nil); w.Code != 403 {
			t.Fatalf("confirm permission: %d %s", w.Code, w.Body.String())
		}
	}
	if w := request(t, h, "POST", "/api/v1/services/softflowd/reconcile", "softflowd-test-token", nil); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if e.Snapshot().Revision != 0 || len(e.Snapshot().Transactions) != 1 {
		t.Fatal("runtime repair changed revision")
	}
	if w := request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "softflowd-test-token", nil); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	next := control.Clone(c)
	next.Softflowd[0].Enabled = false
	w = request(t, h, "POST", "/api/v1/transactions", "softflowd-test-token", control.Request{BaseRevision: 1, ConfirmSeconds: 30, Config: next})
	if w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "GET", "/api/v1/services/softflowd/status", "reader-test-token", nil)
	if json.Unmarshal(w.Body.Bytes(), &status) != nil || status.Instances[0].State != "disabled" {
		t.Fatal(w.Body.String())
	}
	if w := request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/rollback", "softflowd-test-token", nil); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "POST", "/api/v1/revisions/0/restore", "interfaces-test-token", control.RestoreRequest{BaseRevision: 1, ConfirmSeconds: 30})
	if w.Code != 403 {
		t.Fatalf("restore bypassed service permission: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "POST", "/api/v1/revisions/0/restore", "softflowd-test-token", control.RestoreRequest{BaseRevision: 1, ConfirmSeconds: 30})
	if w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestVLANAndRuntimeResources(t *testing.T) {
	h, _ := fixture(t)
	c := control.EmptyConfig()
	c.Interfaces = []control.Interface{{Name: "uplink.100", Kind: "vlan", MTU: 1500, Up: true, VLAN: &control.VLAN{Parent: "uplink", ID: 100}}}
	body := control.Request{Config: c, ConfirmSeconds: 30}
	if w := request(t, h, "POST", "/api/v1/transactions", "softflowd-test-token", body); w.Code != 403 {
		t.Fatalf("service permission configured a VLAN: %d", w.Code)
	}
	w := request(t, h, "POST", "/api/v1/transactions", "interfaces-test-token", body)
	if w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/api/v1/vlans", "reader-test-token", nil)
	var links []control.Interface
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &links) != nil || len(links) != 1 || links[0].VLAN.ID != 100 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	for _, path := range []string{"/api/v1/runtime", "/api/v1/parent-interfaces", "/api/v1/services/softflowd/status", "/api/v1/services/softflowd"} {
		if w := request(t, h, "GET", path, "reader-test-token", nil); w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		if w := request(t, h, "GET", path, "writer-test-token", nil); w.Code != 403 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
}
