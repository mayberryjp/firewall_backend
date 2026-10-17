package httpapi

import (
	"encoding/json"
	"testing"

	"netcontrol/internal/control"
)

func TestICMPSettingAPIAndPermissions(t *testing.T) {
	h, _ := fixture(t)
	read := func(want bool) {
		t.Helper()
		w := request(t, h, "GET", "/api/v1/firewall/rules", "reader-test-token", nil)
		var f control.Firewall
		if err := json.Unmarshal(w.Body.Bytes(), &f); err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || f.AllowAllICMP == nil || *f.AllowAllICMP != want {
			t.Fatalf("ICMP readback: %d %s", w.Code, w.Body.String())
		}
	}
	read(true)
	body := `{"base_revision":0,"confirm_timeout_seconds":30,"config":{"firewall":{"policy":"accept","allow_all_icmp":false}}}`
	for _, token := range []string{"reader-test-token", "writer-test-token", "nat-test-token", "interfaces-test-token"} {
		w := request(t, h, "POST", "/api/v1/transactions", token, body)
		if w.Code != 403 {
			t.Fatalf("token %s changed ICMP setting: %d %s", token, w.Code, w.Body.String())
		}
	}
	w := request(t, h, "POST", "/api/v1/transactions", "firewall-test-token", body)
	if w.Code != 202 {
		t.Fatalf("ICMP submit: %d %s", w.Code, w.Body.String())
	}
	var tx control.Transaction
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	read(false)
	w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "firewall-test-token", nil)
	if w.Code != 200 {
		t.Fatalf("ICMP confirmation: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/api/v1/revisions/1", "reader-test-token", nil)
	var revision control.Revision
	if err := json.Unmarshal(w.Body.Bytes(), &revision); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || revision.Config.Firewall.AllowAllICMP == nil || *revision.Config.Firewall.AllowAllICMP {
		t.Fatalf("revision lost ICMP setting: %d %s", w.Code, w.Body.String())
	}
	// An old client omitting the new field gets the enabled default.
	body = `{"base_revision":1,"confirm_timeout_seconds":30,"config":{"firewall":{"policy":"accept"}}}`
	w = request(t, h, "POST", "/api/v1/transactions", "firewall-test-token", body)
	if w.Code != 202 {
		t.Fatalf("omitted ICMP setting: %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	read(true)
	w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/rollback", "firewall-test-token", nil)
	if w.Code != 200 {
		t.Fatalf("ICMP rollback: %d %s", w.Code, w.Body.String())
	}
	read(false)
}

func TestICMPSettingRejectsInvalidJSONTypes(t *testing.T) {
	h, _ := fixture(t)
	for _, value := range []string{`"true"`, `1`, `{}`} {
		body := `{"base_revision":0,"confirm_timeout_seconds":30,"config":{"firewall":{"policy":"accept","allow_all_icmp":` + value + `}}}`
		w := request(t, h, "POST", "/api/v1/transactions", "firewall-test-token", body)
		if w.Code != 400 {
			t.Fatalf("invalid ICMP value %s: %d %s", value, w.Code, w.Body.String())
		}
	}
}
