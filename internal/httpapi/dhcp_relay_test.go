package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"netcontrol/internal/control"
)

func TestDHCPRelayAPIAndPermissions(t *testing.T) {
	h, e := fixture(t)
	c := control.EmptyConfig()
	c.Interfaces = []control.Interface{{Name: "lan0", Kind: "dummy", Role: "lan", MTU: 1500, Up: true,
		Addresses: []string{"192.0.2.1/24"}}}
	commitHistoryConfig(t, e, c)
	c.Interfaces[0].DHCPRelay = control.DHCPRelayConfig{Enabled: true, Servers: []string{"198.51.100.10", "198.51.100.20"}}
	body := control.Request{BaseRevision: 1, ConfirmSeconds: 30, Config: c}
	for _, token := range []string{"reader-test-token", "writer-test-token", "firewall-test-token", "softflowd-test-token"} {
		w := request(t, h, "POST", "/api/v1/transactions", token, body)
		if w.Code != 403 {
			t.Fatalf("token %s changed relay settings: %d %s", token, w.Code, w.Body.String())
		}
	}
	w := request(t, h, "POST", "/api/v1/transactions", "interfaces-test-token", body)
	if w.Code != 202 {
		t.Fatalf("relay submit: %d %s", w.Code, w.Body.String())
	}
	var tx control.Transaction
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "GET", "/api/v1/interfaces/lan0", "reader-test-token", nil)
	var link control.Interface
	if err := json.Unmarshal(w.Body.Bytes(), &link); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || !link.DHCPRelay.Enabled || len(link.DHCPRelay.Servers) != 2 {
		t.Fatalf("relay readback: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/api/v1/services/dhcp-relay/status", "reader-test-token", nil)
	var status struct {
		Interfaces []control.DHCPRelayStatus `json:"interfaces"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(status.Interfaces) != 1 || status.Interfaces[0].State != "simulated" {
		t.Fatalf("relay status: %d %s", w.Code, w.Body.String())
	}
	for _, token := range []string{"reader-test-token", "writer-test-token", "softflowd-test-token"} {
		w = request(t, h, "POST", "/api/v1/services/dhcp-relay/reconcile", token, nil)
		if w.Code != 403 {
			t.Fatalf("relay repair permission: %d %s", w.Code, w.Body.String())
		}
	}
	w = request(t, h, "POST", "/api/v1/services/softflowd/reconcile", "softflowd-test-token", nil)
	if w.Code != 403 {
		t.Fatalf("softflowd-only token repaired an enabled relay: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "POST", "/api/v1/services/dhcp-relay/reconcile", "interfaces-test-token", nil)
	if w.Code != 200 || e.Snapshot().Revision != 1 {
		t.Fatalf("relay repair: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "interfaces-test-token", nil)
	if w.Code != 200 {
		t.Fatalf("relay confirm: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/api/v1/revisions/2", "reader-test-token", nil)
	var revision control.Revision
	if err := json.Unmarshal(w.Body.Bytes(), &revision); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(revision.Config.Interfaces) != 1 || !revision.Config.Interfaces[0].DHCPRelay.Enabled {
		t.Fatalf("relay revision: %d %s", w.Code, w.Body.String())
	}

}

func TestDHCPRelayExample(t *testing.T) {
	h, _ := fixture(t)
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "dhcp-relay.json"))
	if err != nil {
		t.Fatal(err)
	}
	w := request(t, h, "POST", "/api/v1/transactions", "admin-test-token", string(data))
	if w.Code != 202 {
		t.Fatalf("relay example: %d %s", w.Code, w.Body.String())
	}
}

func TestDHCPRelayAPIValidation(t *testing.T) {
	for _, relay := range []struct {
		json string
		code int
	}{
		{`{"enabled":true,"servers":[]}`, 422},
		{`{"enabled":true,"servers":["2001:db8::1"]}`, 422},
		{`{"enabled":"true","servers":["198.51.100.10"]}`, 400},
		{`{"enabled":true,"servers":"198.51.100.10"}`, 400},
		{`{"enabled":true,"servers":[1]}`, 400},
		{`{"enabled":true,"servers":["198.51.100.10","198.51.100.10"]}`, 422},
	} {
		h, _ := fixture(t)
		body := `{"base_revision":0,"confirm_timeout_seconds":30,"config":{"interfaces":[{"name":"lan0","role":"lan",` +
			`"kind":"dummy","mtu":1500,"up":true,"addresses":["192.0.2.1/24"],"dhcp_relay":` + relay.json +
			`}],"firewall":{"policy":"accept"}}}`
		w := request(t, h, "POST", "/api/v1/transactions", "interfaces-test-token", body)
		if w.Code != relay.code {
			t.Fatalf("relay %s: %d %s", relay.json, w.Code, w.Body.String())
		}
	}
}

func TestDHCPRelayRepairRequiresPermissionsForAllEnabledServices(t *testing.T) {
	h, e := fixture(t)
	c := control.EmptyConfig()
	c.Softflowd = []control.SoftflowdConfig{{Name: "office", Enabled: true, Interface: "uplink",
		Collector: "192.0.2.50:2055", ExportVersion: 10, SamplingRate: 1, MaxFlows: 1000, Snaplen: 256}}
	commitHistoryConfig(t, e, c)
	w := request(t, h, "POST", "/api/v1/services/dhcp-relay/reconcile", "interfaces-test-token", nil)
	if w.Code != 403 {
		t.Fatalf("interface-only token repaired softflowd: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "POST", "/api/v1/services/dhcp-relay/reconcile", "admin-test-token", nil)
	if w.Code != 200 {
		t.Fatalf("admin repair: %d %s", w.Code, w.Body.String())
	}
}
