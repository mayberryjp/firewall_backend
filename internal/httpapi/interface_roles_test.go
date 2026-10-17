package httpapi

import (
	"encoding/json"
	"testing"

	"netcontrol/internal/control"
)

func TestInterfaceRoleAPIAndPermissions(t *testing.T) {
	h, e := fixture(t)
	c := control.EmptyConfig()
	c.Interfaces = []control.Interface{{Name: "edge0", Kind: "dummy", Role: "wan", MTU: 1500, Up: true}}
	commitHistoryConfig(t, e, c)
	c.Interfaces[0].Role = "lan"
	for _, token := range []string{"reader-test-token", "writer-test-token", "firewall-test-token", "nat-test-token"} {
		w := request(t, h, "POST", "/api/v1/transactions", token, control.Request{BaseRevision: 1, ConfirmSeconds: 30, Config: c})
		if w.Code != 403 {
			t.Fatalf("token %s changed interface role: %d %s", token, w.Code, w.Body.String())
		}
	}
	w := request(t, h, "POST", "/api/v1/transactions", "interfaces-test-token", control.Request{BaseRevision: 1, ConfirmSeconds: 30, Config: c})
	if w.Code != 202 {
		t.Fatalf("role-only submission: %d %s", w.Code, w.Body.String())
	}
	var tx control.Transaction
	if err := json.Unmarshal(w.Body.Bytes(), &tx); err != nil {
		t.Fatal(err)
	}
	if tx.Candidate.Interfaces[0].Role != "lan" || tx.Previous.Interfaces[0].Role != "wan" {
		t.Fatal("transaction lost interface roles")
	}
	w = request(t, h, "GET", "/api/v1/interfaces", "reader-test-token", nil)
	var links []control.Interface
	if err := json.Unmarshal(w.Body.Bytes(), &links); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(links) != 1 || links[0].Role != "lan" {
		t.Fatalf("observed role readback: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "POST", "/api/v1/transactions/"+tx.ID+"/confirm", "interfaces-test-token", nil)
	if w.Code != 200 {
		t.Fatalf("role confirmation: %d %s", w.Code, w.Body.String())
	}
	w = request(t, h, "GET", "/api/v1/revisions/2", "reader-test-token", nil)
	var revision control.Revision
	if err := json.Unmarshal(w.Body.Bytes(), &revision); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(revision.Config.Interfaces) != 1 || revision.Config.Interfaces[0].Role != "lan" {
		t.Fatalf("revision role readback: %d %s", w.Code, w.Body.String())
	}
}

func TestInterfaceRoleAPIRejectsMissingAndInvalidValues(t *testing.T) {
	for _, value := range []string{"", `,"role":null`, `,"role":""`, `,"role":"WAN"`, `,"role":"dmz"`, `,"role":1`, `,"role":true`} {
		t.Run(value, func(t *testing.T) {
			h, _ := fixture(t)
			body := `{"base_revision":0,"confirm_timeout_seconds":30,"config":{"interfaces":[{"name":"edge0","kind":"dummy","mtu":1500,"up":true` +
				value + `}],"firewall":{"policy":"accept"}}}`
			w := request(t, h, "POST", "/api/v1/transactions", "admin-test-token", body)
			want := 422
			if value == `,"role":1` || value == `,"role":true` {
				want = 400
			}
			if w.Code != want {
				t.Fatalf("invalid role accepted: %d %s", w.Code, w.Body.String())
			}
		})
	}
}
