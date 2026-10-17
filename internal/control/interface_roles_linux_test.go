package control

import (
	"context"
	"testing"
)

func TestLinuxInterfaceRoleRoundTrip(t *testing.T) {
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
	c := candidate()
	tx := submit(t, e, 0, c)
	if _, err := e.Confirm(context.Background(), tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	view, err := e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, c) {
		t.Fatalf("native WAN role readback: %+v %v", view, err)
	}
	changed := Clone(c)
	changed.Interfaces[0].Role = "lan"
	tx = submit(t, e, 1, changed)
	view, err = e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, changed) {
		t.Fatalf("native LAN role readback: %+v %v", view, err)
	}
	if _, err := e.Rollback(tx.ID, "test"); err != nil {
		t.Fatal(err)
	}
	view, err = e.View(context.Background())
	if err != nil || view.Drift || !Equal(view.Observed, c) {
		t.Fatalf("native role rollback: %+v %v", view, err)
	}
}
