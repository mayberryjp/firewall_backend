package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"netcontrol/internal/control"
)

func TestKernelPermissionsCatalogAndLifecycle(t *testing.T) {
	h, e := fixture(t)
	for _, path := range []string{"/api/v1/kernel/tunables", "/api/v1/kernel/tunables/catalog"} {
		if w := request(t, h, "GET", path, "reader-test-token", nil); w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		if w := request(t, h, "GET", path, "writer-test-token", nil); w.Code != 403 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	w := request(t, h, "GET", "/api/v1/kernel/tunables/catalog", "reader-test-token", nil)
	var catalog []control.KernelParameter
	if err := json.Unmarshal(w.Body.Bytes(), &catalog); err != nil || len(catalog) != 22 {
		t.Fatalf("invalid catalog %s %v", w.Body.String(), err)
	}
	var bounds []struct {
		Min *int64 `json:"min"`
		Max *int64 `json:"max"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &bounds); err != nil {
		t.Fatal(err)
	}
	for _, entry := range bounds {
		if entry.Min == nil || entry.Max == nil {
			t.Fatal("catalog omitted an explicit numeric bound")
		}
	}
	c := control.EmptyConfig()
	c.Kernel.Namespace["net.core.somaxconn"] = "8192"
	body := control.Request{Config: c, ConfirmSeconds: 30}
	for _, token := range []string{"reader-test-token", "interfaces-test-token", "softflowd-test-token", "kernel-host-test-token"} {
		if w := request(t, h, "POST", "/api/v1/transactions", token, body); w.Code != 403 {
			t.Fatalf("%s: %d %s", token, w.Code, w.Body.String())
		}
	}
	w = request(t, h, "POST", "/api/v1/transactions", "kernel-namespace-test-token", body)
	if w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var tx control.Transaction
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "GET", "/api/v1/kernel/tunables", "reader-test-token", nil)
	var view control.KernelView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil || view.Drift || view.Observed.Namespace["net.core.somaxconn"] != "8192" || view.Original.Namespace["net.core.somaxconn"] != "4096" {
		t.Fatalf("%s %v", w.Body.String(), err)
	}
	for _, token := range []string{"interfaces-test-token", "kernel-host-test-token"} {
		if w := request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", token, nil); w.Code != 403 {
			t.Fatal(w.Body.String())
		}
		if w := request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/rollback", token, nil); w.Code != 403 {
			t.Fatal(w.Body.String())
		}
	}
	if w := request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "kernel-namespace-test-token", nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	next := control.Clone(c)
	next.Kernel.Host["net.core.netdev_max_backlog"] = "2000"
	body = control.Request{BaseRevision: 1, Config: next, ConfirmSeconds: 30}
	if w := request(t, h, "POST", "/api/v1/transactions", "kernel-namespace-test-token", body); w.Code != 403 {
		t.Fatal("namespace role changed host", w.Body.String())
	}
	w = request(t, h, "POST", "/api/v1/transactions", "kernel-host-test-token", body)
	if w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	if w := request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "kernel-namespace-test-token", nil); w.Code != 403 {
		t.Fatal(w.Body.String())
	}
	if w := request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "kernel-host-test-token", nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = request(t, h, "POST", "/api/v1/revisions/1/restore", "kernel-namespace-test-token", control.RestoreRequest{BaseRevision: 2, ConfirmSeconds: 30})
	if w.Code != 403 {
		t.Fatal("restore bypassed host permission", w.Body.String())
	}
	w = request(t, h, "POST", "/api/v1/revisions/1/restore", "kernel-host-test-token", control.RestoreRequest{BaseRevision: 2, ConfirmSeconds: 30})
	if w.Code != 202 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if e.Snapshot().Revision != 2 {
		t.Fatal("restore committed without confirmation")
	}
}

func TestKernelInputRejectsInvalidTypesAndScope(t *testing.T) {
	h, _ := fixture(t)
	for _, body := range []string{
		`{"confirm_timeout_seconds":30,"config":{"firewall":{"policy":"accept"},"kernel":{"namespace":{"net.core.somaxconn":8192}}}}`,
		`{"confirm_timeout_seconds":30,"config":{"firewall":{"policy":"accept"},"kernel":{"profile":"fastest"}}}`,
	} {
		if w := request(t, h, "POST", "/api/v1/transactions", "admin-test-token", body); w.Code != http.StatusBadRequest {
			t.Fatalf("%d %s", w.Code, w.Body.String())
		}
	}
	c := control.EmptyConfig()
	c.Kernel.Namespace["net.core.netdev_budget"] = "1000"
	if w := request(t, h, "POST", "/api/v1/transactions", "admin-test-token", control.Request{Config: c, ConfirmSeconds: 30}); w.Code != 422 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
