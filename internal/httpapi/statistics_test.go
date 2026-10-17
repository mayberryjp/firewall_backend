package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"netcontrol/internal/control"
)

func TestStatisticsRoutesPermissionsAndShapes(t *testing.T) {
	h, e := fixture(t)
	c := control.EmptyConfig()
	c.Interfaces = []control.Interface{{Name: "wan.100", Kind: "dummy", Role: "wan", MTU: 1500, Up: true}}
	tx, err := e.Submit(context.Background(), "test", control.Request{Config: c, ConfirmSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	before := e.Snapshot()
	for _, path := range []string{"/api/v1/statistics", "/api/v1/statistics/interfaces", "/api/v1/statistics/interfaces/wan.100", "/api/v1/statistics/protocols"} {
		for _, item := range []struct {
			token string
			code  int
		}{{"", 401}, {"writer-test-token", 403}, {"reader-test-token", 200}} {
			w := request(t, h, "GET", path, item.token, nil)
			if w.Code != item.code {
				t.Fatalf("%s %s: %d %s", path, item.token, w.Code, w.Body.String())
			}
			if item.code == 200 {
				var payload map[string]json.RawMessage
				if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
					t.Fatal(err)
				}
				var sample control.StatisticsSample
				if err := json.Unmarshal(payload["sample"], &sample); err != nil || sample.Status != "simulated" || sample.CollectedAt.IsZero() {
					t.Fatalf("%s %v", w.Body.String(), err)
				}
				switch path {
				case "/api/v1/statistics":
					if len(payload) != 3 || payload["interfaces"] == nil || payload["protocols"] == nil {
						t.Fatal(w.Body.String())
					}
				case "/api/v1/statistics/interfaces/wan.100":
					var link control.InterfaceStatistics
					if err := json.Unmarshal(payload["interface"], &link); err != nil || link.Name != "wan.100" || link.Counters != nil {
						t.Fatalf("%s %v", w.Body.String(), err)
					}
					if len(payload) != 2 {
						t.Fatal(w.Body.String())
					}
				default:
					if len(payload) != 2 {
						t.Fatal(w.Body.String())
					}
				}
			}
		}
		for _, method := range []string{"POST", "PUT", "DELETE", "PATCH"} {
			w := request(t, h, method, path, "reader-test-token", nil)
			if w.Code != 405 || w.Header().Get("Allow") != "GET" {
				t.Fatalf("statistics not read-only: %s %d %s", method, w.Code, w.Body.String())
			}
		}
	}
	for path, code := range map[string]int{
		"/api/v1/statistics/interfaces/missing":       404,
		"/api/v1/statistics/unknown":                  404,
		"/api/v1/statistics/interfaces/":              404,
		"/api/v1/statistics/interfaces/wan.100/extra": 404,
		"/api/v1/statistics/interfaces/bad%20name":    400,
		"/api/v1/statistics?anything=1":               400,
		"/api/v1/statistics?":                         400,
	} {
		if w := request(t, h, "GET", path, "reader-test-token", nil); w.Code != code {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	if !reflect.DeepEqual(before, e.Snapshot()) || e.Snapshot().Active != tx.ID {
		t.Fatal("statistics mutated journal")
	}
}

type statisticsAPIAdapter struct {
	*control.Simulator
	result *control.NetworkStatistics
	err    error
}

func (a *statisticsAPIAdapter) Statistics(ctx context.Context, q control.StatisticsQuery, c control.Config) (control.NetworkStatistics, error) {
	if a.err != nil {
		return control.NetworkStatistics{}, a.err
	}
	if a.result != nil {
		return control.Clone(*a.result), nil
	}
	return a.Simulator.Statistics(ctx, q, c)
}

func statisticsHandler(t *testing.T, adapter control.Adapter) http.Handler {
	t.Helper()
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	e, err := control.NewEngine(store, adapter, logger)
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte("statistics-reader-test-token")))
	h, err := New(e, []Credential{{Name: "reader", TokenSHA256: hash, Permissions: []string{"state.read"}}}, logger)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestStatisticsLargeCountersAndUnavailableAreNotZeros(t *testing.T) {
	now := time.Now().UTC()
	result := control.NetworkStatistics{Sample: control.StatisticsSample{Scope: "test-scope", Status: "available", StartedAt: now, CollectedAt: now},
		Interfaces: []control.InterfaceStatistics{{Name: "wan", Index: 7, Status: "available", CounterBits: 64, Counters: &control.InterfaceCounters{RxBytes: ^uint64(0), TxBytes: 9007199254740993}}},
		Protocols:  []control.ProtocolStatistics{{Name: "snmp", Status: "available", Groups: map[string]map[string]string{"Tcp": {"MaxConn": "-1", "ActiveOpens": "9007199254740993"}}}}}
	adapter := &statisticsAPIAdapter{Simulator: control.NewSimulator(control.EmptyConfig()), result: &result}
	h := statisticsHandler(t, adapter)
	w := request(t, h, "GET", "/api/v1/statistics/interfaces/wan", "statistics-reader-test-token", nil)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var payload struct {
		Interface struct {
			Counters map[string]string `json:"counters"`
		} `json:"interface"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || payload.Interface.Counters["rx_bytes"] != "18446744073709551615" || payload.Interface.Counters["tx_bytes"] != "9007199254740993" {
		t.Fatalf("%s %v", w.Body.String(), err)
	}
	result.Sample.Status = "partial"
	result.Interfaces[0].Status = "unavailable"
	result.Interfaces[0].Counters = nil
	result.Interfaces[0].CounterBits = 0
	result.Interfaces[0].Error = "kernel supplied no interface counters"
	result.Protocols[0] = control.ProtocolStatistics{Name: "snmp6", Status: "unavailable", Error: "kernel source is not exposed"}
	w = request(t, h, "GET", "/api/v1/statistics", "statistics-reader-test-token", nil)
	var partial control.NetworkStatistics
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &partial) != nil || partial.Sample.Status != "partial" || partial.Interfaces[0].Counters != nil ||
		partial.Interfaces[0].Error == "" || partial.Protocols[0].Groups != nil || partial.Protocols[0].Error == "" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	adapter.err = errors.New("injected malformed kernel statistics")
	w = request(t, h, "GET", "/api/v1/statistics", "statistics-reader-test-token", nil)
	if w.Code != 503 {
		t.Fatalf("collection error returned success: %d %s", w.Code, w.Body.String())
	}
	adapter.err = nil
	result.Interfaces = nil
	w = request(t, h, "GET", "/api/v1/statistics/interfaces/wan", "statistics-reader-test-token", nil)
	if w.Code != 503 {
		t.Fatal("inconsistent single-interface sample returned success")
	}
}

func TestStatisticsEmptyCollectionsAreArrays(t *testing.T) {
	h, _ := fixture(t)
	w := request(t, h, "GET", "/api/v1/statistics/interfaces", "reader-test-token", nil)
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || string(payload["interfaces"]) != "[]" {
		t.Fatalf("%s %v", w.Body.String(), err)
	}
}
