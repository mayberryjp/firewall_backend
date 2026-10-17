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
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"netcontrol/internal/control"
	"netcontrol/internal/httpapi"
	"netcontrol/internal/identity"
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
	parents := flag.String("adopt-parents", "", "comma-separated pre-provisioned read-only VLAN/capture parent links")
	flowBinary := flag.String("softflowd-binary", "", "absolute path to operator-installed softflowd (integration disabled when empty)")
	flowRuntime := flag.String("softflowd-runtime-dir", "/run/netcontrol-softflowd", "dedicated root-owned mode-0711 process runtime directory")
	flowUID := flag.Int("softflowd-uid", -1, "non-root numeric UID for managed softflowd children")
	flowGID := flag.Int("softflowd-gid", -1, "non-root numeric GID for managed softflowd children")
	relayBinary := flag.String("dhcp-relay-binary", "", "absolute path to operator-installed dnsmasq (relay integration disabled when empty)")
	relayRuntime := flag.String("dhcp-relay-runtime-dir", "/run/netcontrol-dhcp-relay", "dedicated root-owned mode-0711 DHCP relay runtime directory")
	relayUID := flag.Int("dhcp-relay-uid", -1, "non-root numeric UID of an existing account for the DHCP relay child")
	relayGID := flag.Int("dhcp-relay-gid", -1, "non-root numeric GID of an existing group for the DHCP relay child")
	hostTunables := flag.Bool("allow-host-tunables", false, "explicitly allow allowlisted host-global network sysctls; takes an exclusive host tuning lock")
	authFile := flag.String("auth-file", "", "JSON credential file containing token hashes and permissions")
	credentialDB := flag.String("credential-db", "", "device credential database (default: <state>.credentials.db); mutually exclusive with -auth-file")
	listen := flag.String("listen", "127.0.0.1:8080", "management listener outside the target namespace")
	cert := flag.String("tls-cert", "", "TLS certificate; required for non-loopback listeners")
	key := flag.String("tls-key", "", "TLS private key")
	flag.Parse()
	if *authFile != "" && *credentialDB != "" {
		return fmt.Errorf("-auth-file and -credential-db are mutually exclusive")
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
	var credentials []httpapi.Credential
	var identities *identity.Store
	if *authFile != "" {
		data, err := os.ReadFile(*authFile)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &credentials); err != nil {
			return fmt.Errorf("parse credentials: %w", err)
		}
	} else {
		if *credentialDB == "" {
			*credentialDB = *stateFile + ".credentials.db"
		}
		dbPath, err := filepath.Abs(*credentialDB)
		if err != nil {
			return err
		}
		statePath, err := filepath.Abs(*stateFile)
		if err != nil {
			return err
		}
		if strings.EqualFold(dbPath, statePath) {
			return fmt.Errorf("credential database must be separate from the network state journal")
		}
		identities, err = identity.Open(*credentialDB)
		if err != nil {
			return err
		}
		defer func() {
			if err := identities.Close(); err != nil {
				logger.Error("credential database close failed", "error", err)
			}
		}()
		status, err := identities.Status()
		if err != nil {
			return err
		}
		if !status.AccountExists {
			logger.Warn("device is unclaimed; first visitor can create the device account; restrict management network access until configured")
		}
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
		var parentNames []string
		if *parents != "" {
			parentNames = strings.Split(*parents, ",")
		}
		adapter, err = control.NewLinuxAdapter(*namespace, *keyDir, control.LinuxOptions{
			ParentInterfaces: parentNames, SoftflowdBinary: *flowBinary, RuntimeDirectory: *flowRuntime,
			SoftflowdUID: *flowUID, SoftflowdGID: *flowGID, Logger: logger,
			AllowHostTunables: *hostTunables,
			DHCPRelayBinary:   *relayBinary, DHCPRelayRuntimeDirectory: *relayRuntime,
			DHCPRelayUID: *relayUID, DHCPRelayGID: *relayGID,
		})
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
	var handler http.Handler
	if identities != nil {
		handler = httpapi.NewDevice(engine, identities, logger)
	} else {
		handler, err = httpapi.New(engine, credentials, logger)
		if err != nil {
			return err
		}
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
