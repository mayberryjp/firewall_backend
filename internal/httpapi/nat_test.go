package httpapi

import (
	"encoding/json"
	"testing"

	"netcontrol/internal/control"
)

func TestNATReadReturnsStableEmptyArray(t *testing.T) {
	h, _ := fixture(t)
	w := request(t, h, "GET", "/api/v1/firewall/nat", "reader-test-token", nil)
	if w.Code != 200 || w.Body.String() != "{\"masquerade\":[]}\n" {
		t.Fatalf("NAT response: %d %s", w.Code, w.Body.String())
	}
}

func TestNATTransactionAuthorizationAndRollback(t *testing.T) {
	h, e := fixture(t)
	base := control.EmptyConfig()
	base.Interfaces = []control.Interface{{Name: "wan", Kind: "dummy", MTU: 1500, Up: true, Addresses: []string{"192.0.2.10/24"}}}
	w := request(t, h, "POST", "/api/v1/transactions", "admin-test-token", control.Request{Config: base, ConfirmSeconds: 30})
	if w.Code != 202 {
		t.Fatalf("base: %d %s", w.Code, w.Body.String())
	}
	var tx control.Transaction
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "admin-test-token", nil)
	if w.Code != 200 {
		t.Fatalf("base confirmation: %d %s", w.Code, w.Body.String())
	}
	config := control.Clone(base)
	config.Firewall.NAT.Masquerade = []control.MasqueradeRule{{Family: "ipv4", Source: "10.8.0.0/24", OutInterface: "wan"}}
	for _, token := range []string{"reader-test-token", "firewall-test-token"} {
		w = request(t, h, "POST", "/api/v1/transactions", token, control.Request{BaseRevision: 1, Config: config, ConfirmSeconds: 30})
		if w.Code != 403 {
			t.Fatalf("%s modified NAT: %d", token, w.Code)
		}
	}
	w = request(t, h, "POST", "/api/v1/transactions", "nat-test-token", control.Request{BaseRevision: 1, Config: config, ConfirmSeconds: 30})
	if w.Code != 202 {
		t.Fatalf("NAT-only update: %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	if e.Snapshot().Revision != 1 || len(e.Snapshot().Desired.Firewall.NAT.Masquerade) != 0 {
		t.Fatal("unconfirmed NAT published as committed desired state")
	}
	w = request(t, h, "GET", "/api/v1/firewall/nat", "reader-test-token", nil)
	var nat control.NAT
	if err := json.Unmarshal(w.Body.Bytes(), &nat); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(nat.Masquerade) != 1 || nat.Masquerade[0] != config.Firewall.NAT.Masquerade[0] {
		t.Fatalf("observed NAT: %d %s", w.Code, w.Body.String())
	}
	for _, action := range []string{"confirm", "rollback"} {
		w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/"+action, "firewall-test-token", nil)
		if w.Code != 403 {
			t.Fatalf("filter operator could %s NAT", action)
		}
	}
	w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "nat-test-token", nil)
	if w.Code != 200 || e.Snapshot().Revision != 2 {
		t.Fatalf("NAT confirmation: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "POST", "/api/v1/transactions", "nat-test-token", control.Request{BaseRevision: 2, Config: base, ConfirmSeconds: 30})
	if w.Code != 202 {
		t.Fatalf("NAT removal: %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/rollback", "nat-test-token", nil)
	if w.Code != 200 {
		t.Fatalf("NAT rollback: %d %s", w.Code, w.Body.String())
	}
	if !control.Equal(e.Snapshot().Desired, config) {
		t.Fatal("rollback changed committed NAT configuration")
	}
	w = request(t, h, "GET", "/api/v1/firewall/nat", "reader-test-token", nil)
	if err := json.Unmarshal(w.Body.Bytes(), &nat); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(nat.Masquerade) != 1 || nat.Masquerade[0] != config.Firewall.NAT.Masquerade[0] {
		t.Fatalf("rollback did not restore observed NAT: %d %s", w.Code, w.Body.String())
	}
}

func TestNATPermissionDoesNotGrantFilteringOrInterfaces(t *testing.T) {
	before := control.EmptyConfig()
	c := Credential{Permissions: []string{"nat.write"}}
	after := control.Clone(before)
	after.Firewall.Policy = "drop"
	if err := authorize(c, before, after); err == nil {
		t.Fatal("NAT permission granted filter writes")
	}
	after = control.Clone(before)
	after.Interfaces = []control.Interface{{Name: "wan", Kind: "dummy", MTU: 1500}}
	if err := authorize(c, before, after); err == nil {
		t.Fatal("NAT permission granted interface writes")
	}
}
