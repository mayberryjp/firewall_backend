package control

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func applianceTestConfig() Config {
	c := EmptyConfig()
	c.NTP = NTPConfig{Enabled: true, Servers: []string{"ntp.example.invalid", "2001:db8::123"}}
	c.Syslog = SyslogConfig{Enabled: true, Servers: []SyslogServer{{Host: "logs.example.invalid", Port: 6514, Transport: "tls"}}}
	c.VNStat.Enabled = true
	c.Normalize()
	return c
}

func TestApplianceValidation(t *testing.T) {
	c := applianceTestConfig()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Config){
		"empty ntp":        func(c *Config) { c.NTP.Servers = nil },
		"empty syslog":     func(c *Config) { c.Syslog.Servers = nil },
		"duplicate ntp":    func(c *Config) { c.NTP.Servers = []string{"192.0.2.1", "192.0.2.1"} },
		"duplicate syslog": func(c *Config) { c.Syslog.Servers = append(c.Syslog.Servers, c.Syslog.Servers[0]) },
		"port zero":        func(c *Config) { c.Syslog.Servers[0].Port = 0 },
		"port overflow":    func(c *Config) { c.Syslog.Servers[0].Port = 65536 },
		"transport":        func(c *Config) { c.Syslog.Servers[0].Transport = "http" },
		"injection":        func(c *Config) { c.NTP.Servers[0] = "example.invalid\nmakestep 1 -1" },
		"syslog injection": func(c *Config) { c.Syslog.Servers[0].Host = `"); file("/tmp/injected");` },
		"disabled invalid": func(c *Config) { c.NTP.Enabled = false; c.NTP.Servers = []string{"host with spaces"} },
		"too many":         func(c *Config) { c.NTP.Enabled = false; c.NTP.Servers = make([]string, 9) },
	} {
		t.Run(name, func(t *testing.T) {
			next := Clone(c)
			change(&next)
			if err := next.Validate(); err == nil {
				t.Fatal("invalid service settings accepted")
			}
		})
	}
	for _, host := range []string{"", "UPPER.example", "-bad", "bad-", "a..b", "127.0.0.999", "::ffff:192.0.2.1",
		"fe80::1%eth0", "224.0.0.1", "0.0.0.0", "host:123", strings.Repeat("a", 64)} {
		if validServerHost(host) {
			t.Fatalf("invalid host accepted: %q", host)
		}
	}
	for _, host := range []string{"router", "pool.ntp.org", "192.0.2.1", "2001:db8::1", "::1"} {
		if !validServerHost(host) {
			t.Fatalf("valid host rejected: %q", host)
		}
	}
	c.NTP.Enabled, c.Syslog.Enabled = false, false
	if err := c.Validate(); err != nil {
		t.Fatal("disabled server lists cannot be retained", err)
	}
	empty := EmptyConfig()
	if empty.NTP.Enabled || empty.Syslog.Enabled || empty.VNStat.Enabled || empty.NTP.Servers == nil || empty.Syslog.Servers == nil {
		t.Fatal("unsafe defaults or null lists")
	}
	before := Clone(c)
	c.Normalize()
	c.Normalize()
	if !reflect.DeepEqual(before, c) {
		t.Fatal("normalization is not deterministic")
	}
}

func TestApplianceConfigurationTemplates(t *testing.T) {
	c := applianceTestConfig()
	c.Syslog.Servers = append(c.Syslog.Servers, SyslogServer{Host: "192.0.2.10", Port: 514, Transport: "udp"})
	c.Syslog.Servers = append(c.Syslog.Servers, SyslogServer{Host: "2001:db8::10", Port: 514, Transport: "tcp"})
	ntp := applianceConfigurationText("ntp", "/run/test", "/state/test", "/var/log/backend.log", "/etc/ssl/cert.pem", c)
	if strings.Contains(ntp, "makestep") || strings.Contains(ntp, "\nallow ") ||
		!strings.Contains(ntp, "\nport 0\ncmdport 0\n") || !strings.Contains(ntp, "leapsecmode slew") ||
		strings.Count(ntp, " iburst\n") != 2 {
		t.Fatalf("NTP is not slew-only client mode: %s", ntp)
	}
	syslog := applianceConfigurationText("syslog", "/run/test", "/state/test", "/var/log/backend.log", "/etc/ssl/cert.pem", c)
	for _, text := range []string{"system();", "internal();", `file("/var/log/backend.log"`, `file("/var/log/messages"`,
		"peer-verify(required-trusted)", `transport("tls") port(6514)`, `transport("udp") port(514)`, `transport("tcp") port(514) ip-protocol(6)`} {
		if !strings.Contains(syslog, text) {
			t.Fatalf("missing syslog directive %q in %s", text, syslog)
		}
	}
	vnstat := applianceConfigurationText("vnstat-managed", "/run/test", "/state/managed", "", "", c)
	for _, text := range []string{`DatabaseDir "/state/managed"`, "AlwaysAddNewInterfaces 1", "SaveInterval 1", "RescanDatabaseOnSave 1", "UseUTC 1"} {
		if !strings.Contains(vnstat, text) {
			t.Fatalf("missing vnstat setting %q", text)
		}
	}
}

func TestAppliancePersistenceRollbackRestoreAndSimulation(t *testing.T) {
	store := testStore(t)
	e := testEngine(t, store, NewSimulator(EmptyConfig()))
	c := applianceTestConfig()
	tx := submit(t, e, 0, c)
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	next := Clone(c)
	next.NTP.Servers = []string{"192.0.2.123"}
	next.Syslog.Enabled, next.VNStat.Enabled = false, false
	tx = submit(t, e, 1, next)
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	restarted := testEngine(t, store, NewSimulator(c))
	runtime, err := restarted.Runtime(context.Background())
	if err != nil || len(runtime.Appliance) != 4 {
		t.Fatalf("missing service states: %+v %v", runtime, err)
	}
	for _, status := range runtime.Appliance {
		if status.State != "simulated" || status.PID != 0 || status.DatabaseDirectory != "" {
			t.Fatalf("simulator implies real activity: %+v", status)
		}
	}
	if runtime.Appliance[2].Scope != "host" || runtime.Appliance[3].Scope != "managed" {
		t.Fatal("vnstat scopes collapsed")
	}
	tx = submit(t, restarted, 1, next)
	if _, err := restarted.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	tx, err = restarted.Restore(context.Background(), "test", 1, RestoreRequest{BaseRevision: 2, ConfirmSeconds: 30})
	if err != nil || !reflect.DeepEqual(tx.Candidate, c) {
		t.Fatalf("restore lost service settings: %+v %v", tx, err)
	}
	if _, err := restarted.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
}
