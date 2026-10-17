package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func extensionNamespace(t *testing.T) string {
	t.Helper()
	if os.Getenv("NETCONTROL_INTEGRATION") != "1" {
		t.Skip("requires explicit Linux namespace integration opt-in")
	}
	name := fmt.Sprintf("ncext-%d-%d", os.Getpid(), time.Now().UnixNano())
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	created, createErr := netns.NewNamed(name)
	restoreErr := netns.Set(original)
	original.Close()
	if restoreErr != nil {
		t.Fatalf("restore namespace: %v", restoreErr)
	}
	runtime.UnlockOSThread()
	if createErr != nil {
		t.Fatal(createErr)
	}
	created.Close()
	t.Cleanup(func() {
		if err := netns.DeleteNamed(name); err != nil {
			t.Error(err)
		}
	})
	return name
}

func TestLinuxVLANProtectedParents(t *testing.T) {
	namespace := extensionNamespace(t)
	setup, err := NewLinuxAdapter(namespace, "")
	if err != nil {
		t.Fatal(err)
	}
	err = setup.(*linuxAdapter).inNamespace(context.Background(), func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		if err := h.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "uplink", MTU: 1500}, PeerName: "uplink-peer"}); err != nil {
			return err
		}
		for _, name := range []string{"uplink", "uplink-peer"} {
			link, err := h.LinkByName(name)
			if err != nil {
				return err
			}
			if err := h.LinkSetUp(link); err != nil {
				return err
			}
		}
		link, err := h.LinkByName("uplink")
		if err != nil {
			return err
		}
		address, err := netlink.ParseAddr("198.51.100.1/24")
		if err != nil {
			return err
		}
		return h.AddrAdd(link, address)
	})
	closeErr := setup.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	adapter, err := NewLinuxAdapter(namespace, "", LinuxOptions{ParentInterfaces: []string{"uplink", "uplink-peer"}})
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
	native := adapter.(*linuxAdapter)
	e := testEngine(t, testStore(t), adapter)
	initial, err := e.Runtime(context.Background())
	if err != nil || len(initial.Parents) != 2 {
		t.Fatalf("%+v %v", initial, err)
	}
	invalid := EmptyConfig()
	invalid.Interfaces = []Interface{{Name: "uplink", Kind: "dummy", Role: "wan", MTU: 1400}}
	if _, err := e.Submit(context.Background(), "test", Request{Config: invalid, ConfirmSeconds: 30}); !errors.Is(err, ErrValidation) {
		t.Fatalf("protected parent mutation: %v", err)
	}
	if len(e.Snapshot().Transactions) != 0 {
		t.Fatal("invalid parent mutation journaled")
	}
	c := vlanConfig()
	commitConfig(t, e, c)
	view, err := e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, c) {
		t.Fatalf("%+v %v", view, err)
	}
	tx := submit(t, e, 1, EmptyConfig())
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	view, err = e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, c) {
		t.Fatalf("VLAN rollback: %+v %v", view, err)
	}
	commitConfig(t, e, EmptyConfig())
	current, err := e.Runtime(context.Background())
	if err != nil || !reflect.DeepEqual(initial.Parents, current.Parents) {
		t.Fatalf("parent changed: %+v -> %+v %v", initial.Parents, current.Parents, err)
	}
	err = native.inNamespace(context.Background(), func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		link, err := h.LinkByName("uplink")
		if err != nil {
			return err
		}
		addresses, err := h.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return err
		}
		if len(addresses) != 1 || addresses[0].IPNet.String() != "198.51.100.1/24" {
			return fmt.Errorf("protected parent address changed: %+v", addresses)
		}
		return h.LinkSetHardwareAddr(link, net.HardwareAddr{2, 0, 0, 0, 0, 42})
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.View(context.Background()); err == nil {
		t.Fatal("changed parent identity was silently adopted")
	}
	current, err = e.Runtime(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, parent := range current.Parents {
		if parent.Name == "uplink" && (parent.Available || parent.Error == "") {
			t.Fatal("lost parent identity not exposed")
		}
	}
}

func TestLinuxSoftflowdLifecycle(t *testing.T) {
	binary := os.Getenv("NETCONTROL_SOFTFLOWD_BINARY")
	if binary == "" {
		t.Skip("requires NETCONTROL_SOFTFLOWD_BINARY, NETCONTROL_SOFTFLOWD_UID and NETCONTROL_SOFTFLOWD_GID")
	}
	namespace := extensionNamespace(t)
	uid, err := strconv.Atoi(os.Getenv("NETCONTROL_SOFTFLOWD_UID"))
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(os.Getenv("NETCONTROL_SOFTFLOWD_GID"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	// Only these test-created ancestors are opened for the non-root child.
	for _, dir := range []string{filepath.Dir(root), root} {
		if err := os.Chmod(dir, 0711); err != nil {
			t.Fatal(err)
		}
	}
	options := LinuxOptions{SoftflowdBinary: binary, RuntimeDirectory: root, SoftflowdUID: uid, SoftflowdGID: gid, Logger: testLogger()}
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
	err = adapter.(*linuxAdapter).inNamespace(context.Background(), func() error {
		h, err := netlink.NewHandle()
		if err != nil {
			return err
		}
		defer h.Close()
		link, err := h.LinkByName("lo")
		if err != nil {
			return err
		}
		return h.LinkSetUp(link)
	})
	if err != nil {
		t.Fatal(err)
	}
	store := testStore(t)
	e := testEngine(t, store, adapter)
	c := EmptyConfig()
	c.Interfaces = []Interface{{Name: "capture", Kind: "dummy", Role: "lan", MTU: 1500, Up: true}}
	c.Softflowd = []SoftflowdConfig{flowConfig()}
	c.Softflowd[0].Interface = "capture"
	c.Softflowd[0].Collector = "127.0.0.1:2055"
	tx := submit(t, e, 0, c)
	// Stop only children (not the transaction), then exercise startup resumption.
	if err := adapter.Close(); err != nil {
		t.Fatal(err)
	}
	adapter = nil
	adapter, err = NewLinuxAdapter(namespace, "", options)
	if err != nil {
		t.Fatal(err)
	}
	e = testEngine(t, store, adapter)
	state, err := e.Runtime(context.Background())
	if err != nil || len(state.Softflowd) != 1 || state.Softflowd[0].State != "running" || state.Softflowd[0].PID == 0 {
		t.Fatalf("%+v %v", state, err)
	}
	if e.Snapshot().Active != tx.ID {
		t.Fatal("pending candidate was not resumed")
	}
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	manager := adapter.(*linuxAdapter).flows
	child := manager.snapshot()["office"]
	if err := child.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-child.done:
	case <-time.After(5 * time.Second):
		t.Fatal("owned child did not exit")
	}
	state, err = e.Runtime(context.Background())
	if err != nil || state.Softflowd[0].State != "exited" {
		t.Fatalf("%+v %v", state, err)
	}
	view, err := e.View(context.Background())
	if err != nil || !view.Drift {
		t.Fatalf("process loss did not cause drift: %+v %v", view, err)
	}
	state, err = e.ReconcileServices(context.Background(), "test", nil)
	if err != nil || state.Softflowd[0].State != "running" || state.Softflowd[0].PID == child.cmd.Process.Pid {
		t.Fatalf("%+v %v", state, err)
	}
	next := Clone(c)
	next.Softflowd[0].SamplingRate++
	tx = submit(t, e, 1, next)
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	view, err = e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, c) {
		t.Fatalf("%+v %v", view, err)
	}
	invalid := Clone(c)
	invalid.Softflowd[0].CaptureFilter = "tcp and ("
	failed, err := e.Submit(context.Background(), "test", Request{BaseRevision: 1, ConfirmSeconds: 30, Config: invalid})
	if err == nil || failed.Status != "rolled_back" {
		t.Fatalf("invalid BPF did not compensate: %+v %v", failed, err)
	}
	view, err = e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, c) {
		t.Fatalf("BPF rollback: %+v %v", view, err)
	}
	c.Softflowd = []SoftflowdConfig{}
	commitConfig(t, e, c)
	if len(manager.snapshot()) != 0 {
		t.Fatal("removed service still owned/running")
	}
}

func TestLinuxSoftflowdOwnershipGuards(t *testing.T) {
	for _, options := range []LinuxOptions{
		{SoftflowdBinary: "relative", RuntimeDirectory: "relative", SoftflowdUID: 1000, SoftflowdGID: 1000},
		{SoftflowdBinary: "/operator/binary", RuntimeDirectory: "/operator/runtime", SoftflowdUID: 0, SoftflowdGID: 1000},
		{SoftflowdBinary: "/operator/binary", RuntimeDirectory: "/operator/runtime", SoftflowdUID: 1000, SoftflowdGID: 0},
	} {
		if _, err := newSoftflowdManager(nil, options); err == nil {
			t.Fatal("unsafe process options accepted")
		}
	}
	output := &flowOutput{}
	data := []byte(strings.Repeat("x", 20000))
	if n, err := output.Write(data); err != nil || n != len(data) || len(output.String()) != 8192 || !output.Truncated() {
		t.Fatalf("unbounded output: %d %v", n, err)
	}
	links := []netlink.Link{
		&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "root", Index: 1}},
		&netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "outer", Index: 2, ParentIndex: 1}},
		&netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "inner", Index: 3, ParentIndex: 2}},
	}
	ordered := deletionOrder(links)
	if ordered[0].Attrs().Name != "inner" || ordered[1].Attrs().Name != "outer" || ordered[2].Attrs().Name != "root" {
		t.Fatal("incorrect child-first deletion")
	}
}
