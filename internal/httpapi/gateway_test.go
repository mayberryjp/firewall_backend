package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netcontrol/internal/control"
)

func apiGatewayConfig() control.Config {
	c := control.EmptyConfig()
	c.Interfaces = []control.Interface{{Name: "wan0", Kind: "dummy", Role: "wan", MTU: 1500, Up: true, Addresses: []string{"192.0.2.2/24"}}}
	c.Routes = []control.Route{{Destination: "198.51.100.0/24", Gateway: "192.0.2.1", Interface: "wan0", Table: 10000, Metric: 100}}
	c.Rules = []control.Rule{{Source: "192.0.2.2/32", Table: 10000, Priority: 10000}}
	c.GatewayMonitors = []control.GatewayMonitor{{Name: "wan1", Enabled: true, Interface: "wan0",
		SourceAddress: "192.0.2.2", Gateway: "192.0.2.1", Target: "198.51.100.10", RoutingTable: 10000}}
	c.Normalize()
	return c
}

func TestGatewayAPIAndPermissions(t *testing.T) {
	h, e := fixture(t)
	c := apiGatewayConfig()
	network := control.Clone(c)
	network.GatewayMonitors = nil
	commitHistoryConfig(t, e, network)
	body := control.Request{BaseRevision: 1, ConfirmSeconds: 30, Config: c}
	for _, token := range []string{"reader-test-token", "interfaces-test-token", "softflowd-test-token", "writer-test-token"} {
		if w := request(t, h, "POST", "/api/v1/transactions", token, body); w.Code != 403 {
			t.Fatalf("monitor mutation permission: %s %d %s", token, w.Code, w.Body.String())
		}
	}
	w := request(t, h, "POST", "/api/v1/transactions", "gateways-test-token", body)
	if w.Code != 202 {
		t.Fatalf("submit: %d %s", w.Code, w.Body.String())
	}
	var tx control.Transaction
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/gateway-monitors", "/api/v1/statistics/gateways",
		"/api/v1/statistics/gateways/wan1", "/api/v1/services/gateway-monitoring/status", "/api/v1/runtime"} {
		if w := request(t, h, "GET", path, "reader-test-token", nil); w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		if w := request(t, h, "GET", path, "writer-test-token", nil); w.Code != 403 {
			t.Fatalf("read permission: %s %d", path, w.Code)
		}
		if w := request(t, h, "GET", path, "", nil); w.Code != 401 {
			t.Fatalf("authentication: %s %d", path, w.Code)
		}
	}
	w = request(t, h, "GET", "/api/v1/statistics/gateways/wan1", "reader-test-token", nil)
	var sample struct {
		Monitor control.GatewayMonitorStatistics `json:"monitor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &sample); err != nil {
		t.Fatal(err)
	}
	if sample.Monitor.ProcessState != "simulated" || sample.Monitor.Health != "unknown" ||
		sample.Monitor.RTTAvgMS != nil || sample.Monitor.RTTVariationMS != nil {
		t.Fatalf("fabricated simulator measurements: %s", w.Body.String())
	}
	for path, code := range map[string]int{"/api/v1/statistics/gateways/missing": 404,
		"/api/v1/statistics/gateways?live=true": 400, "/api/v1/statistics/gateways/wan1/extra": 404,
		"/api/v1/statistics/gateways/bad%20name": 400} {
		if w := request(t, h, "GET", path, "reader-test-token", nil); w.Code != code {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	if w := request(t, h, "POST", "/api/v1/statistics/gateways", "admin-test-token", nil); w.Code != 405 {
		t.Fatal(w.Code)
	}
	for _, path := range []string{"/api/v1/services/dhcp-relay/reconcile", "/api/v1/services/softflowd/reconcile"} {
		token := "interfaces-test-token"
		if path == "/api/v1/services/softflowd/reconcile" {
			token = "softflowd-test-token"
		}
		if w := request(t, h, "POST", path, token, nil); w.Code != 403 {
			t.Fatalf("cross-service permission: %d %s", w.Code, w.Body.String())
		}
	}
	if w := request(t, h, "POST", "/api/v1/services/gateway-monitoring/reconcile", "gateways-test-token", nil); w.Code != 200 || e.Snapshot().Revision != 1 {
		t.Fatalf("monitor repair changed revision or failed: %d %s", w.Code, w.Body.String())
	}
	if w := request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "interfaces-test-token", nil); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "gateways-test-token", nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
}

func TestGatewayExampleAndJSONTypes(t *testing.T) {
	h, _ := fixture(t)
	body, err := os.ReadFile(filepath.Join("..", "..", "examples", "gateway-monitoring.json"))
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(body), `"probe_interval_ms": 1000`, `"probe_interval_ms": "1000"`, 1)
	if w := request(t, h, "POST", "/api/v1/transactions", "admin-test-token", bad); w.Code != 400 {
		t.Fatalf("invalid numeric field type accepted: %d %s", w.Code, w.Body.String())
	}
	if w := request(t, h, "POST", "/api/v1/transactions", "admin-test-token", string(body)); w.Code != 202 {
		t.Fatalf("gateway example: %d %s", w.Code, w.Body.String())
	}
}

func TestGatewayAPIValidationAndSharedRepair(t *testing.T) {
	h, e := fixture(t)
	c := apiGatewayConfig()
	commitHistoryConfig(t, e, c)
	c.GatewayMonitors[0].Target = "not-an-ip"
	if w := request(t, h, "POST", "/api/v1/transactions", "gateways-test-token", control.Request{BaseRevision: 1, ConfirmSeconds: 30, Config: c}); w.Code != 422 {
		t.Fatalf("invalid target: %d %s", w.Code, w.Body.String())
	}
	c = apiGatewayConfig()
	c.Interfaces[0].DHCPRelay = control.DHCPRelayConfig{Enabled: true, Servers: []string{"198.51.100.20"}}
	commitHistoryConfig(t, e, c)
	if w := request(t, h, "POST", "/api/v1/services/gateway-monitoring/reconcile", "gateways-test-token", nil); w.Code != 403 {
		t.Fatalf("gateway-only caller repaired DHCP: %d %s", w.Code, w.Body.String())
	}
	if w := request(t, h, "POST", "/api/v1/services/gateway-monitoring/reconcile", "admin-test-token", nil); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
}
