package httpapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"netcontrol/internal/control"
)

func TestHostPolicyAPITransactionAndPermissions(t *testing.T) {
	h, e := fixture(t)
	for _, path := range []string{"/api/v1/firewall/hosts", "/api/v1/firewall/interface-policies"} {
		w := request(t, h, "GET", path, "reader-test-token", nil)
		if w.Code != 200 || w.Body.String() != "[]\n" {
			t.Fatalf("empty policy read: %d %s", w.Code, w.Body.String())
		}
	}
	c := control.EmptyConfig()
	c.Firewall.Policy = "drop"
	c.Firewall.Policies = &control.FirewallPolicies{
		Hosts: []control.FirewallHost{
			{ID: "laptop", Name: "Laptop", Addresses: []string{"192.0.2.10"}, Policy: "drop",
				Rules: []control.HostPolicyRule{{Protocol: "tcp", DestinationPorts: []int{443}, Action: "accept"}}},
		},
	}
	for _, token := range []string{"reader-test-token", "nat-test-token", "interfaces-test-token"} {
		w := request(t, h, "POST", "/api/v1/transactions", token, control.Request{Config: c, ConfirmSeconds: 30})
		if w.Code != 403 {
			t.Fatalf("token %s changed host policy: %d %s", token, w.Code, w.Body.String())
		}
	}
	w := request(t, h, "POST", "/api/v1/transactions", "firewall-test-token", control.Request{Config: c, ConfirmSeconds: 30})
	if w.Code != 202 {
		t.Fatalf("host-policy submit: %d %s", w.Code, w.Body.String())
	}
	var tx control.Transaction
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "GET", "/api/v1/firewall/hosts", "reader-test-token", nil)
	var hosts []control.FirewallHost
	if err := json.Unmarshal(w.Body.Bytes(), &hosts); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(hosts) != 1 || hosts[0].ID != "laptop" {
		t.Fatalf("host read: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "nat-test-token", nil)
	if w.Code != 403 {
		t.Fatal("NAT operator confirmed firewall policy")
	}
	w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "firewall-test-token", nil)
	if w.Code != 200 {
		t.Fatalf("confirmation: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/api/v1/revisions/1", "reader-test-token", nil)
	var revision control.Revision
	if err := json.Unmarshal(w.Body.Bytes(), &revision); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || !control.Equal(revision.Config, c) {
		t.Fatalf("revision lost policies: %d %s", w.Code, w.Body.String())
	}
	changed := control.Clone(c)
	changed.Firewall.Policies.Hosts[0].Addresses = []string{"192.0.2.11"}
	w = request(t, h, "POST", "/api/v1/transactions", "firewall-test-token", control.Request{BaseRevision: 1, Config: changed, ConfirmSeconds: 30})
	if w.Code != 202 {
		t.Fatalf("host address change: %d %s", w.Code, w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/rollback", "firewall-test-token", nil)
	if w.Code != 200 || !control.Equal(e.Snapshot().Desired, c) {
		t.Fatalf("rollback lost host policy: %d %s", w.Code, w.Body.String())
	}
}

func TestHostPolicyExampleAndInterfaceRead(t *testing.T) {
	h, _ := fixture(t)
	data, err := os.ReadFile(filepath.Join("..", "..", "examples", "host-policies.json"))
	if err != nil {
		t.Fatal(err)
	}
	w := request(t, h, "POST", "/api/v1/transactions", "admin-test-token", string(data))
	if w.Code != 202 {
		t.Fatalf("documented example: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/api/v1/firewall/interface-policies", "reader-test-token", nil)
	var policies []control.InterfacePolicy
	if err := json.Unmarshal(w.Body.Bytes(), &policies); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(policies) != 1 || policies[0].Interface != "lan" || len(policies[0].Rules) != 2 {
		t.Fatalf("interface override read: %d %s", w.Code, w.Body.String())
	}
}

func TestInterfacePolicyRequiresFirewallPermissionNotInterfaceMutationPermission(t *testing.T) {
	before := control.EmptyConfig()
	before.Interfaces = []control.Interface{{Name: "lan", Kind: "dummy", MTU: 1500}}
	after := control.Clone(before)
	after.Firewall.Policies = &control.FirewallPolicies{Interfaces: []control.InterfacePolicy{{Interface: "lan", Rules: []control.HostPolicyRule{{Action: "drop"}}}}}
	if err := authorize(Credential{Permissions: []string{"firewall.write"}}, before, after); err != nil {
		t.Fatal(err)
	}
	if err := authorize(Credential{Permissions: []string{"interfaces.write"}}, before, after); err == nil {
		t.Fatal("interface mutation permission granted firewall policy writes")
	}
}
