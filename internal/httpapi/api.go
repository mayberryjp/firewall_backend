package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"netcontrol/internal/control"
)

type Credential struct {
	Name        string   `json:"name"`
	TokenSHA256 string   `json:"token_sha256"`
	Permissions []string `json:"permissions"`
}

var permissions = []string{"state.read", "transactions.write", "interfaces.write", "routes.write", "policy.write", "firewall.write", "nat.write", "wireguard.write"}

type API struct {
	engine      *control.Engine
	credentials []Credential
	logger      *slog.Logger
}

func New(engine *control.Engine, credentials []Credential, logger *slog.Logger) (http.Handler, error) {
	if len(credentials) == 0 {
		return nil, fmt.Errorf("at least one credential is required")
	}
	names, hashes := map[string]bool{}, map[string]bool{}
	for _, c := range credentials {
		hash, err := hex.DecodeString(c.TokenSHA256)
		if err != nil || len(hash) != sha256.Size || strings.TrimSpace(c.Name) == "" || names[c.Name] || hashes[strings.ToLower(c.TokenSHA256)] {
			return nil, fmt.Errorf("credential names and SHA-256 token hashes must be valid and unique")
		}
		names[c.Name], hashes[strings.ToLower(c.TokenSHA256)] = true, true
		for _, p := range c.Permissions {
			if !slices.Contains(permissions, p) {
				return nil, fmt.Errorf("unknown permission %q", p)
			}
		}
	}
	return &API{engine: engine, credentials: control.Clone(credentials), logger: logger}, nil
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := http.StatusOK
	actor := "unauthenticated"
	defer func() {
		a.logger.Info("http audit", "actor", actor, "method", r.Method, "path", r.URL.Path, "status", status, "remote", r.RemoteAddr, "duration", time.Since(start))
	}()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	fail := func(code int, err error, t *control.Transaction) {
		status = code
		w.WriteHeader(code)
		a.encode(w, map[string]any{"error": err.Error(), "transaction": t})
	}
	var credential *Credential
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		hash := sha256.Sum256([]byte(strings.TrimPrefix(header, "Bearer ")))
		for i := range a.credentials {
			expected, _ := hex.DecodeString(a.credentials[i].TokenSHA256)
			if subtle.ConstantTimeCompare(hash[:], expected) == 1 {
				credential = &a.credentials[i]
			}
		}
	}
	if credential == nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		fail(http.StatusUnauthorized, fmt.Errorf("valid bearer credential required"), nil)
		return
	}
	actor = credential.Name
	has := func(p string) bool { return slices.Contains(credential.Permissions, p) }
	if r.Method == http.MethodGet {
		if !has("state.read") {
			fail(http.StatusForbidden, fmt.Errorf("state.read permission required"), nil)
			return
		}
		if r.URL.Path == "/api/v1/transactions" {
			a.encode(w, a.engine.Snapshot().Transactions)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/transactions/") {
			id := strings.TrimPrefix(r.URL.Path, "/api/v1/transactions/")
			t, ok := a.engine.Snapshot().Transactions[id]
			if !ok {
				fail(http.StatusNotFound, control.ErrNotFound, nil)
				return
			}
			a.encode(w, t)
			return
		}
		known := []string{"/api/v1/state", "/api/v1/interfaces", "/api/v1/routes", "/api/v1/policy-rules", "/api/v1/firewall/rules", "/api/v1/firewall/nat", "/api/v1/wireguard"}
		isInterface := strings.HasPrefix(r.URL.Path, "/api/v1/interfaces/")
		if !slices.Contains(known, r.URL.Path) && !isInterface {
			fail(http.StatusNotFound, fmt.Errorf("endpoint not found"), nil)
			return
		}
		view, err := a.engine.View(r.Context())
		if err != nil {
			fail(http.StatusServiceUnavailable, fmt.Errorf("observation failed: %w", err), nil)
			return
		}
		switch r.URL.Path {
		case "/api/v1/state":
			a.encode(w, view)
		case "/api/v1/interfaces":
			a.encode(w, view.Observed.Interfaces)
		case "/api/v1/routes":
			a.encode(w, view.Observed.Routes)
		case "/api/v1/policy-rules":
			a.encode(w, view.Observed.Rules)
		case "/api/v1/firewall/rules":
			a.encode(w, view.Observed.Firewall)
		case "/api/v1/firewall/nat":
			a.encode(w, view.Observed.Firewall.NAT)
		case "/api/v1/wireguard":
			links := []control.Interface{}
			for _, link := range view.Observed.Interfaces {
				if link.WireGuard != nil {
					links = append(links, link)
				}
			}
			a.encode(w, links)
		default:
			name := strings.TrimPrefix(r.URL.Path, "/api/v1/interfaces/")
			for _, link := range view.Observed.Interfaces {
				if link.Name == name {
					a.encode(w, link)
					return
				}
			}
			fail(http.StatusNotFound, fmt.Errorf("interface not found"), nil)
		}
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		fail(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"), nil)
		return
	}
	if !has("transactions.write") {
		fail(http.StatusForbidden, fmt.Errorf("transactions.write permission required"), nil)
		return
	}
	if r.URL.Path == "/api/v1/transactions" {
		if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
			fail(http.StatusUnsupportedMediaType, fmt.Errorf("application/json required"), nil)
			return
		}
		var request control.Request
		if err := decode(w, r, &request); err != nil {
			fail(http.StatusBadRequest, err, nil)
			return
		}
		if err := authorize(*credential, a.engine.Snapshot().Desired, request.Config); err != nil {
			fail(http.StatusForbidden, err, nil)
			return
		}
		t, err := a.engine.Submit(r.Context(), actor, request)
		if err != nil {
			fail(errorStatus(err), err, transactionPointer(t))
			return
		}
		status = http.StatusAccepted
		w.Header().Set("Location", "/api/v1/transactions/"+t.ID)
		w.WriteHeader(status)
		a.encode(w, t)
		return
	}
	path := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/transactions/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/api/v1/transactions/") || len(path) != 2 || (path[1] != "confirm" && path[1] != "rollback") {
		fail(http.StatusNotFound, fmt.Errorf("endpoint not found"), nil)
		return
	}
	id := path[0]
	t, ok := a.engine.Snapshot().Transactions[id]
	if !ok {
		fail(http.StatusNotFound, control.ErrNotFound, nil)
		return
	}
	if err := authorize(*credential, t.Previous, t.Candidate); err != nil {
		fail(http.StatusForbidden, err, nil)
		return
	}
	var result control.Transaction
	var err error
	if path[1] == "confirm" {
		result, err = a.engine.Confirm(r.Context(), id, actor)
	} else {
		result, err = a.engine.Rollback(id, actor)
	}
	if err != nil {
		fail(errorStatus(err), err, transactionPointer(result))
		return
	}
	a.encode(w, result)
}

func transactionPointer(t control.Transaction) *control.Transaction {
	if t.ID == "" {
		return nil
	}
	return &t
}

func errorStatus(err error) int {
	switch {
	case errors.Is(err, control.ErrValidation):
		return http.StatusUnprocessableEntity
	case errors.Is(err, control.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, control.ErrNotFound):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

func decode(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("request must contain exactly one JSON value")
	}
	return nil
}

func (a *API) encode(w http.ResponseWriter, value any) {
	if err := json.NewEncoder(w).Encode(value); err != nil {
		a.logger.Error("HTTP response write failed", "error", err)
	}
}

func authorize(c Credential, before, after control.Config) error {
	before, after = control.Clone(before), control.Clone(after)
	before.Normalize()
	after.Normalize()
	need := func(permission string, different bool) error {
		if different && !slices.Contains(c.Permissions, permission) {
			return fmt.Errorf("%s permission required", permission)
		}
		return nil
	}
	equal := func(a, b any) bool {
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		return string(x) == string(y)
	}
	if err := need("routes.write", !equal(before.Routes, after.Routes)); err != nil {
		return err
	}
	if err := need("policy.write", !equal(before.Rules, after.Rules)); err != nil {
		return err
	}
	if err := need("nat.write", !equal(before.Firewall.NAT, after.Firewall.NAT)); err != nil {
		return err
	}
	before.Firewall.NAT, after.Firewall.NAT = control.NAT{}, control.NAT{}
	if err := need("firewall.write", !equal(before.Firewall, after.Firewall)); err != nil {
		return err
	}
	wgBefore, wgAfter := map[string]*control.WireGuard{}, map[string]*control.WireGuard{}
	for i := range before.Interfaces {
		link := &before.Interfaces[i]
		if link.WireGuard != nil {
			wgBefore[link.Name] = link.WireGuard
		}
		link.WireGuard = nil
	}
	for i := range after.Interfaces {
		link := &after.Interfaces[i]
		if link.WireGuard != nil {
			wgAfter[link.Name] = link.WireGuard
		}
		link.WireGuard = nil
	}
	if err := need("wireguard.write", !equal(wgBefore, wgAfter)); err != nil {
		return err
	}
	return need("interfaces.write", !equal(before.Interfaces, after.Interfaces))
}
