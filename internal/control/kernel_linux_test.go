package control

import (
	"context"
	"errors"
	"strconv"
	"testing"
)

func TestLinuxKernelHostOptInGate(t *testing.T) {
	a := &linuxAdapter{}
	called := false
	if err := a.kernelScope(context.Background(), "host", func() error { called = true; return nil }); !errors.Is(err, ErrValidation) || called {
		t.Fatalf("host scope bypassed opt-in: %v", err)
	}
	if err := a.WriteKernel(context.Background(), KernelConfig{Host: map[string]string{"net.core.netdev_budget": "300"}}); !errors.Is(err, ErrValidation) {
		t.Fatalf("host write bypassed opt-in: %v", err)
	}
}

func TestLinuxKernelNamespaceLifecycle(t *testing.T) {
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
	native := adapter.(*linuxAdapter)
	ctx := context.Background()
	c := EmptyConfig()
	c.Kernel.Namespace["net.core.somaxconn"] = "4096"
	c.Kernel.Namespace["net.ipv4.tcp_sack"] = "1"
	original, err := native.ReadKernel(ctx, c.Kernel)
	if err != nil {
		t.Fatal(err)
	}
	if original.Namespace["net.ipv4.tcp_sack"] == "1" {
		c.Kernel.Namespace["net.ipv4.tcp_sack"] = "0"
	}
	n, err := strconv.Atoi(original.Namespace["net.core.somaxconn"])
	if err != nil {
		t.Fatal(err)
	}
	if n < 2147483647 {
		n++
	} else {
		n--
	}
	c.Kernel.Namespace["net.core.somaxconn"] = strconv.Itoa(n)
	store := testStore(t)
	e := testEngine(t, store, adapter)
	tx := submit(t, e, 0, c)
	if !kernelEqual(*tx.KernelBefore, original) {
		t.Fatal("native baseline differs from actual pre-write state")
	}
	e = testEngine(t, store, adapter)
	view, err := e.KernelView(ctx)
	if err != nil || view.Drift || !kernelEqual(view.Observed, c.Kernel) {
		t.Fatalf("%+v %v", view, err)
	}
	if _, err := e.Confirm(ctx, tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	remove := submit(t, e, 1, EmptyConfig())
	actual, err := native.ReadKernel(ctx, original)
	if err != nil || !kernelEqual(actual, original) {
		t.Fatalf("native omission did not restore originals: %+v %v", actual, err)
	}
	if _, err := e.Rollback(remove.ID, "test"); err != nil {
		t.Fatal(err)
	}
	actual, err = native.ReadKernel(ctx, c.Kernel)
	if err != nil || !kernelEqual(actual, c.Kernel) {
		t.Fatalf("%+v %v", actual, err)
	}
	commitConfig(t, e, EmptyConfig())
	actual, err = native.ReadKernel(ctx, original)
	if err != nil || !kernelEqual(actual, original) {
		t.Fatalf("originals not restored on release: %+v %v", actual, err)
	}
}
