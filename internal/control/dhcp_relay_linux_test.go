package control

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func relayLinuxOptions(t *testing.T) LinuxOptions {
	t.Helper()
	binary := os.Getenv("NETCONTROL_DHCP_RELAY_BINARY")
	if binary == "" {
		t.Skip("requires operator-installed dnsmasq via NETCONTROL_DHCP_RELAY_BINARY and service UID/GID")
	}
	uid, err := strconv.Atoi(os.Getenv("NETCONTROL_DHCP_RELAY_UID"))
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(os.Getenv("NETCONTROL_DHCP_RELAY_GID"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, dir := range []string{filepath.Dir(root), root} {
		if err := os.Chmod(dir, 0711); err != nil {
			t.Fatal(err)
		}
	}
	return LinuxOptions{DHCPRelayBinary: binary, DHCPRelayRuntimeDirectory: root,
		DHCPRelayUID: uid, DHCPRelayGID: gid, Logger: testLogger()}
}

func TestDaemonUDPReadinessRequiresOwnedSocket(t *testing.T) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	address, ok := socket.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatal("unexpected socket address")
	}
	if err := daemonOwnsUDPPort(os.Getpid(), address.Port); err != nil {
		t.Fatal(err)
	}
	if err := daemonOwnsUDPPort(os.Getpid(), 0); err == nil {
		t.Fatal("unbound port was reported as owned")
	}
}

func TestDHCPRelayStalePIDGuard(t *testing.T) {
	root := t.TempDir()
	m := &dhcpRelayManager{root: root, uid: os.Getuid()}
	if err := os.Mkdir(m.directory(), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.pidfile(), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.cleanDirectory(); err == nil {
		t.Fatal("live PID file was removed")
	}
	if _, err := os.Stat(m.pidfile()); err != nil {
		t.Fatal("live PID file was changed")
	}
	if err := os.Remove(m.pidfile()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "not-a-pid"), m.pidfile()); err != nil {
		t.Fatal(err)
	}
	if err := m.cleanDirectory(); err == nil {
		t.Fatal("symlink PID file accepted")
	}
}

func TestLinuxDHCPRelayRequiresOperatorIntegration(t *testing.T) {
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
	_, err = e.Submit(context.Background(), "test", Request{Config: relayConfig(), ConfirmSeconds: 30})
	if !errors.Is(err, ErrValidation) || len(e.Snapshot().Transactions) != 0 {
		t.Fatalf("unavailable DHCP relay was not rejected before intent: %v", err)
	}
}

func TestLinuxDHCPRelayLifecycle(t *testing.T) {
	options := relayLinuxOptions(t)
	namespace := extensionNamespace(t)
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
	store := testStore(t)
	e := testEngine(t, store, adapter)
	c := relayConfig()
	tx := submit(t, e, 0, c)
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	adapter = nil
	adapter, err = NewLinuxAdapter(namespace, "", options)
	if err != nil {
		t.Fatal(err)
	}
	e = testEngine(t, store, adapter)
	status, err := e.Runtime(context.Background())
	if err != nil || len(status.DHCPRelay) != 1 || status.DHCPRelay[0].State != "running" || status.DHCPRelay[0].PID == 0 {
		t.Fatalf("relay not resumed for pending candidate: %+v %v", status, err)
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	child := adapter.(*linuxAdapter).relay.snapshot()
	if err := child.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	<-child.done
	view, err := e.View(context.Background())
	if err != nil || !view.Drift {
		t.Fatalf("dead relay was not observed as drift: %+v %v", view, err)
	}
	status, err = e.Runtime(context.Background())
	if err != nil || status.DHCPRelay[0].State != "exited" || status.DHCPRelay[0].Error == "" {
		t.Fatalf("relay exit not exposed: %+v %v", status, err)
	}
	status, err = e.ReconcileServices(context.Background(), "test", nil)
	if err != nil || status.DHCPRelay[0].State != "running" || status.DHCPRelay[0].PID == child.cmd.Process.Pid {
		t.Fatalf("relay recovery: %+v %v", status, err)
	}
	disabled := Clone(c)
	disabled.Interfaces[0].DHCPRelay.Enabled = false
	tx = submit(t, e, 1, disabled)
	if adapter.(*linuxAdapter).relay.snapshot() != nil {
		t.Fatal("disabled relay process still exists")
	}
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	view, err = e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, c) {
		t.Fatalf("relay rollback readback: %+v %v", view, err)
	}
	changed := Clone(c)
	changed.Interfaces[0].DHCPRelay.Servers = []string{"198.51.100.30"}
	tx = submit(t, e, 1, changed)
	view, err = e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, changed) {
		t.Fatalf("relay server change: %+v %v", view, err)
	}
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	tx = submit(t, e, 1, EmptyConfig())
	if adapter.(*linuxAdapter).relay.snapshot() != nil {
		t.Fatal("removing the interface left the relay running")
	}
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
}
