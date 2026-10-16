package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netcontrol/internal/control"
	"netcontrol/internal/httpapi"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("service failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	backend := flag.String("backend", "simulator", "simulator or linux")
	namespace := flag.String("namespace", "", "exclusive pre-created Linux network namespace")
	stateFile := flag.String("state", "state.json", "durable journal path (local filesystem)")
	keyDir := flag.String("keys", "", "directory of pre-provisioned private WireGuard key files")
	authFile := flag.String("auth-file", "", "JSON credential file containing token hashes and permissions")
	listen := flag.String("listen", "127.0.0.1:8080", "management listener outside the target namespace")
	cert := flag.String("tls-cert", "", "TLS certificate; required for non-loopback listeners")
	key := flag.String("tls-key", "", "TLS private key")
	flag.Parse()
	if *authFile == "" {
		return fmt.Errorf("-auth-file is required; anonymous administration is disabled")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if (*cert == "") != (*key == "") {
		return fmt.Errorf("both -tls-cert and -tls-key are required together")
	}
	if *cert == "" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("non-loopback listeners require TLS")
	}
	data, err := os.ReadFile(*authFile)
	if err != nil {
		return err
	}
	var credentials []httpapi.Credential
	if err := json.Unmarshal(data, &credentials); err != nil {
		return fmt.Errorf("parse credentials: %w", err)
	}
	store, err := control.OpenStore(*stateFile)
	if err != nil {
		return err
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Error("state unlock failed", "error", err)
		}
	}()
	var adapter control.Adapter
	switch *backend {
	case "simulator":
		state, err := store.Load()
		if err != nil {
			return err
		}
		initial := state.Desired
		if state.Active != "" {
			t, ok := state.Transactions[state.Active]
			if !ok {
				return fmt.Errorf("journal references missing transaction")
			}
			initial = t.Candidate
		}
		adapter = control.NewSimulator(initial)
	case "linux":
		adapter, err = control.NewLinuxAdapter(*namespace, *keyDir)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown backend %q", *backend)
	}
	defer func() {
		if err := adapter.Close(); err != nil {
			logger.Error("adapter close failed", "error", err)
		}
	}()
	engine, err := control.NewEngine(store, adapter, logger)
	if err != nil {
		return err
	}
	handler, err := httpapi.New(engine, credentials, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		engine.Watch(ctx)
	}()
	defer func() { stop(); <-watchDone }()
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 75 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		logger.Info("management API listening", "address", listener.Addr().String(), "backend", *backend, "scope", adapter.Scope())
		if *cert != "" {
			done <- server.ServeTLS(listener, *cert, *key)
		} else {
			done <- server.Serve(listener)
		}
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
		defer cancel()
		shutdownErr := server.Shutdown(shutdownCtx)
		if shutdownErr != nil {
			shutdownErr = errors.Join(shutdownErr, server.Close())
		}
		if active := engine.Snapshot().Active; active != "" {
			_, err = engine.Rollback(active, "service shutdown")
		}
		return errors.Join(shutdownErr, err)
	}
}
