package control

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

func TestMasqueradeValidation(t *testing.T) {
	for _, rule := range []MasqueradeRule{
		{Family: "ipv4", OutInterface: "wan"},
		{Family: "ipv4", Source: "0.0.0.0/0", OutInterface: "wan"},
		{Family: "ipv6", Source: "2001:db8::/32", OutInterface: "wan"},
		{Family: "ipv6", Source: "::/0", OutInterface: "wan"},
	} {
		c := candidate()
		c.Interfaces[0].Addresses = append(c.Interfaces[0].Addresses, "2001:db8::1/64")
		c.Firewall.NAT.Masquerade = []MasqueradeRule{rule}
		if err := c.Validate(); err != nil {
			t.Fatalf("valid rule %+v: %v", rule, err)
		}
	}
	for name, rule := range map[string]MasqueradeRule{
		"missing-family":           {OutInterface: "wan"},
		"unknown-family":           {Family: "inet", OutInterface: "wan"},
		"wrong-family":             {Family: "ipv4", Source: "2001:db8::/32", OutInterface: "wan"},
		"no-egress-family-address": {Family: "ipv6", OutInterface: "wan"},
		"noncanonical-source":      {Family: "ipv4", Source: "192.0.2.10/24", OutInterface: "wan"},
		"invalid-source":           {Family: "ipv4", Source: "not-a-network", OutInterface: "wan"},
		"mapped-source":            {Family: "ipv6", Source: "::ffff:192.0.2.0/120", OutInterface: "wan"},
		"missing-egress":           {Family: "ipv4"},
		"unmanaged-egress":         {Family: "ipv4", OutInterface: "external"},
		"loopback-egress":          {Family: "ipv4", OutInterface: "lo"},
		"invalid-egress":           {Family: "ipv4", OutInterface: "../wan"},
	} {
		t.Run(name, func(t *testing.T) {
			c := candidate()
			c.Firewall.NAT.Masquerade = []MasqueradeRule{rule}
			if err := c.Validate(); err == nil {
				t.Fatal("invalid masquerade rule accepted")
			}
		})
	}
}

func TestMasqueradeOrderIsPreserved(t *testing.T) {
	a := candidate()
	a.Firewall.NAT.Masquerade = append(a.Firewall.NAT.Masquerade, MasqueradeRule{Family: "ipv4", OutInterface: "wan"})
	b := Clone(a)
	b.Firewall.NAT.Masquerade[0], b.Firewall.NAT.Masquerade[1] = b.Firewall.NAT.Masquerade[1], b.Firewall.NAT.Masquerade[0]
	if Equal(a, b) {
		t.Fatal("normalization discarded masquerade rule order")
	}
}

func TestLegacyJournalWithoutNATRemainsUsable(t *testing.T) {
	store := testStore(t)
	c := candidate()
	c.Firewall.NAT = NAT{}
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	tx := submit(t, e, 0, c)
	data, err := json.Marshal(e.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	removeNAT := func(config any) {
		delete(config.(map[string]any)["firewall"].(map[string]any), "nat")
	}
	removeNAT(legacy["desired"])
	for _, value := range legacy["transactions"].(map[string]any) {
		transaction := value.(map[string]any)
		removeNAT(transaction["candidate"])
		removeNAT(transaction["previous"])
	}
	data, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Desired.Firewall.NAT.Masquerade == nil || loaded.Transactions[tx.ID].Candidate.Firewall.NAT.Masquerade == nil {
		t.Fatal("legacy NAT fields were not normalized")
	}
	restarted := testEngine(t, store, NewSimulator(c))
	if _, err := restarted.Confirm(context.Background(), tx.ID, "operator"); err != nil {
		t.Fatal(err)
	}
}
