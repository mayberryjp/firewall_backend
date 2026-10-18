package control

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func TestLinuxApplianceRequiresOperatorOptIn(t *testing.T) {
	namespace := extensionNamespace(t)
	adapter, err := NewLinuxAdapter(namespace, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := adapter.Close(); err != nil {
			t.Error(err)
		}
	})
	e := testEngine(t, testStore(t), adapter)
	c := EmptyConfig()
	c.VNStat.Enabled = true
	_, err = e.Submit(context.Background(), "test", Request{Config: c, ConfirmSeconds: 30})
	if !errors.Is(err, ErrValidation) || len(e.Snapshot().Transactions) != 0 {
		t.Fatalf("operator gate bypassed: %v", err)
	}
}

func TestLinuxApplianceConfigurationSyntax(t *testing.T) {
	if os.Getenv("NETCONTROL_APPLIANCE_SYNTAX") != "1" {
		t.Skip("requires explicitly installed chronyd/syslog-ng/vnstatd syntax test dependencies")
	}
	c := applianceTestConfig()
	c.Syslog.Servers = append(c.Syslog.Servers, SyslogServer{Host: "192.0.2.20", Port: 514, Transport: "udp"}, SyslogServer{Host: "2001:db8::20", Port: 514, Transport: "tcp"})
	dir := t.TempDir()
	logFile := filepath.Join(dir, "backend.log")
	if err := os.WriteFile(logFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	m := &applianceManager{option: LinuxOptions{BackendLogFile: logFile, SyslogCAFile: "/etc/ssl/cert.pem"}}
	for _, item := range []struct{ name, env string }{{"ntp", "NETCONTROL_NTP_BINARY"}, {"syslog", "NETCONTROL_SYSLOG_BINARY"}, {"vnstat-host", "NETCONTROL_VNSTATD_BINARY"}} {
		t.Run(item.name, func(t *testing.T) {
			binary := os.Getenv(item.env)
			if binary == "" {
				t.Fatalf("missing %s", item.env)
			}
			if err := m.checkConfiguration(context.Background(), applianceSpec{name: item.name, binary: binary}, c, t.TempDir()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLinuxApplianceVNStatAllInterfacesAndLifecycle(t *testing.T) {
	namespace := extensionNamespace(t)
	binary, client := os.Getenv("NETCONTROL_VNSTATD_BINARY"), os.Getenv("NETCONTROL_VNSTAT_BINARY")
	if binary == "" || client == "" {
		t.Skip("requires installed vnstatd and vnstat")
	}
	root := t.TempDir()
	options := LinuxOptions{AllowHostServices: true, VNStatBinary: binary, VNStatClientBinary: client,
		ServicesRuntimeDirectory: filepath.Join(root, "runtime"), ServicesStateDirectory: filepath.Join(root, "state"), Logger: testLogger()}
	adapter, err := NewLinuxAdapter(namespace, "", options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if adapter != nil {
			if err := adapter.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	a := adapter.(*linuxAdapter)
	if err := a.inNamespace(context.Background(), func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		lo, err := h.LinkByName("lo")
		if err != nil {
			return err
		}
		return h.LinkSetUp(lo)
	}); err != nil {
		t.Fatal(err)
	}
	store := testStore(t)
	e := testEngine(t, store, adapter)
	c := EmptyConfig()
	c.VNStat.Enabled = true
	tx := submit(t, e, 0, c)
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	runtime, err := e.Runtime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	pids := map[string]int{}
	for _, status := range runtime.Appliance {
		if strings.HasPrefix(status.Name, "vnstat-") {
			if status.State != "running" || status.PID == 0 || status.DatabaseDirectory == "" {
				t.Fatalf("vnstat not ready: %+v", status)
			}
			paths[status.Name], pids[status.Name] = status.DatabaseDirectory, status.PID
			file := a.appliance.configPath(status.Name)
			names, err := a.appliance.vnstatOutput(context.Background(), client, file, "--dbiflist", "1")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains("\n"+names, "\nlo\n") {
				t.Fatalf("loopback was excluded: %s", names)
			}
		}
	}
	if len(paths) != 2 || paths["vnstat-host"] == paths["vnstat-managed"] {
		t.Fatal("namespace databases are not isolated", paths)
	}
	if err := a.inNamespace(context.Background(), func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		return h.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "discovered0"}})
	}); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(12 * time.Second)
	for {
		names, err := a.appliance.vnstatOutput(context.Background(), client, a.appliance.configPath("vnstat-managed"), "--dbiflist", "1")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains("\n"+names, "\ndiscovered0\n") {
			break
		}
		if time.Now().After(until) {
			t.Fatalf("new unmanaged interface not discovered: %s", names)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// Generate real loopback traffic in each namespace without touching host routes.
	sendTraffic := func() error {
		server, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			return err
		}
		defer server.Close()
		conn, err := net.Dial("udp4", server.LocalAddr().String())
		if err != nil {
			return err
		}
		defer conn.Close()
		for i := 0; i < 32; i++ {
			if _, err := conn.Write(make([]byte, 1024)); err != nil {
				return err
			}
		}
		return nil
	}
	if err := a.runInNamespace(context.Background(), a.appliance.host, false, sendTraffic); err != nil {
		t.Fatal(err)
	}
	if err := a.inNamespace(context.Background(), sendTraffic); err != nil {
		t.Fatal(err)
	}
	time.Sleep(6 * time.Second)
	// A graceful stop must save initialized histories rather than remove databases.
	next := Clone(c)
	next.VNStat.Enabled = false
	tx = submit(t, e, 1, next)
	for name, path := range paths {
		data, err := a.appliance.vnstatOutput(context.Background(), client, a.appliance.configPath(name), "--json", "s")
		if err != nil {
			t.Fatal(err)
		}
		var history struct {
			Interfaces []struct {
				Name    string `json:"name"`
				Traffic struct {
					Total struct {
						RX uint64 `json:"rx"`
						TX uint64 `json:"tx"`
					} `json:"total"`
				} `json:"traffic"`
			} `json:"interfaces"`
		}
		if err := json.Unmarshal([]byte(data), &history); err != nil {
			t.Fatal(err, data)
		}
		found := false
		for _, iface := range history.Interfaces {
			if iface.Name == "lo" {
				found = true
				if iface.Traffic.Total.RX < 32*1024 || iface.Traffic.Total.TX < 32*1024 {
					t.Fatalf("%s did not persist real loopback traffic: %+v", path, iface)
				}
			}
		}
		if !found {
			t.Fatal("loopback history missing", path)
		}
	}
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if info, err := os.Stat(filepath.Join(path, "vnstat.db")); err != nil || info.Size() == 0 {
			t.Fatalf("history removed: %s %v", path, err)
		}
	}
	status, err := e.Runtime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range status.Appliance {
		if strings.HasPrefix(item.Name, "vnstat-") && (item.State != "running" || item.PID == pids[item.Name]) {
			t.Fatalf("rollback did not restart vnstat: %+v", item)
		}
		owned := a.appliance.children["vnstat-managed"]
		if err := owned.cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-owned.done:
		case <-time.After(5 * time.Second):
			t.Fatal("owned vnstat child did not exit")
		}
		if status := a.appliance.Status(c); status[3].State != "exited" {
			t.Fatalf("failure not surfaced: %+v", status)
		}
		if _, err := e.ReconcileServices(context.Background(), "test", func(Config) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if e.Snapshot().Revision != 1 || a.appliance.children["vnstat-managed"].cmd.Process.Pid == owned.cmd.Process.Pid {
			t.Fatal("repair failed or changed configuration revision")
		}
	}
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	adapter = nil
	adapter, err = NewLinuxAdapter(namespace, "", options)
	if err != nil {
		t.Fatal(err)
	}
	restarted := testEngine(t, store, adapter)
	status, err = restarted.Runtime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range status.Appliance {
		if strings.HasPrefix(item.Name, "vnstat-") && (item.State != "running" || item.DatabaseDirectory != paths[item.Name]) {
			t.Fatalf("restart changed database scope: %+v", item)
		}
	}
}
