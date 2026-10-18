package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"netcontrol/internal/control"
)

func TestApplianceAPIAndScopedPermissions(t *testing.T) {
	for _, service := range []string{"ntp", "syslog", "vnstat"} {
		t.Run(service, func(t *testing.T) {
			h, e := fixture(t)
			c := control.EmptyConfig()
			switch service {
			case "ntp":
				c.NTP = control.NTPConfig{Enabled: true, Servers: []string{"ntp.example.invalid"}}
			case "syslog":
				c.Syslog = control.SyslogConfig{Enabled: true, Servers: []control.SyslogServer{{Host: "logs.example.invalid", Port: 6514, Transport: "tls"}}}
			case "vnstat":
				c.VNStat.Enabled = true
			}
			body := control.Request{BaseRevision: 0, ConfirmSeconds: 30, Config: c}
			for _, token := range []string{"reader-test-token", "interfaces-test-token", "softflowd-test-token", "gateways-test-token"} {
				if w := request(t, h, "POST", "/api/v1/transactions", token, body); w.Code != 403 {
					t.Fatalf("mutation permission bypass: %d %s", w.Code, w.Body.String())
				}
			}
			token := service + "-test-token"
			w := request(t, h, "POST", "/api/v1/transactions", token, body)
			if w.Code != 202 {
				t.Fatalf("service submit: %d %s", w.Code, w.Body.String())
			}
			var tx control.Transaction
			if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
				t.Fatal(err)
			}
			for _, suffix := range []string{"", "/status"} {
				path := "/api/v1/services/" + service + suffix
				if w := request(t, h, "GET", path, "reader-test-token", nil); w.Code != 200 {
					t.Fatalf("read: %d %s", w.Code, w.Body.String())
				}
				if w := request(t, h, "GET", path, "", nil); w.Code != 401 {
					t.Fatal("unauthenticated read", w.Code)
				}
				if w := request(t, h, "GET", path, "writer-test-token", nil); w.Code != 403 {
					t.Fatal("read permission bypass", w.Code)
				}
			}
			w = request(t, h, "GET", "/api/v1/services/"+service+"/status", token, nil)
			var result struct {
				Instances []control.ApplianceServiceStatus `json:"instances"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			want := 1
			if service == "vnstat" {
				want = 2
			}
			if len(result.Instances) != want {
				t.Fatalf("wrong instance count: %s", w.Body.String())
			}
			for _, status := range result.Instances {
				if status.State != "simulated" || status.PID != 0 {
					t.Fatal("fabricated process", status)
				}
			}
			for _, path := range []string{"/api/v1/services/softflowd/reconcile", "/api/v1/services/dhcp-relay/reconcile", "/api/v1/services/gateway-monitoring/reconcile"} {
				other := "softflowd-test-token"
				if path == "/api/v1/services/dhcp-relay/reconcile" {
					other = "interfaces-test-token"
				}
				if path == "/api/v1/services/gateway-monitoring/reconcile" {
					other = "gateways-test-token"
				}
				if w := request(t, h, "POST", path, other, nil); w.Code != 403 {
					t.Fatalf("shared repair bypass %s: %d", path, w.Code)
				}
			}
			if w := request(t, h, "POST", "/api/v1/services/"+service+"/reconcile", token, nil); w.Code != 200 || e.Snapshot().Revision != 0 {
				t.Fatalf("repair failed or changed revision: %d %s", w.Code, w.Body.String())
			}
			if w := request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "interfaces-test-token", nil); w.Code != 403 {
				t.Fatal("confirmation permission bypass", w.Code)
			}
			if w := request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", token, nil); w.Code != 200 {
				t.Fatal(w.Body.String())
			}
			c.NTP.Enabled, c.Syslog.Enabled, c.VNStat.Enabled = true, true, true
			c.NTP.Servers = []string{"192.0.2.123"}
			c.Syslog.Servers = []control.SyslogServer{{Host: "192.0.2.10", Port: 514, Transport: "udp"}}
			commitHistoryConfig(t, e, c)
			if w := request(t, h, "POST", "/api/v1/services/"+service+"/reconcile", token, nil); w.Code != 403 {
				t.Fatal("cross-service repair bypass", w.Code)
			}
		})
	}
}

func TestApplianceCompleteExample(t *testing.T) {
	h, _ := fixture(t)
	body, err := os.ReadFile(filepath.Join("..", "..", "examples", "appliance-services.json"))
	if err != nil {
		t.Fatal(err)
	}
	if w := request(t, h, "POST", "/api/v1/transactions", "admin-test-token", string(body)); w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestApplianceAPIValidation(t *testing.T) {
	h, _ := fixture(t)
	c := control.EmptyConfig()
	c.NTP.Enabled = true
	if w := request(t, h, "POST", "/api/v1/transactions", "ntp-test-token", control.Request{Config: c, ConfirmSeconds: 30}); w.Code != 422 {
		t.Fatal(w.Code, w.Body.String())
	}

	for _, service := range []string{"ntp", "syslog", "vnstat"} {
		if w := request(t, h, "PUT", "/api/v1/services/"+service, "admin-test-token", nil); w.Code != 405 {
			t.Fatal(w.Code)
		}
		if w := request(t, h, "POST", "/api/v1/services/"+service+"/reconcile", "reader-test-token", nil); w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	if w := request(t, h, "GET", "/api/v1/services/vnstat/extra", "admin-test-token", nil); w.Code != 404 {
		t.Fatal(w.Code)
	}
}
