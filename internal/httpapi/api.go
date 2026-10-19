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
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"netcontrol/internal/control"
)

type Credential struct {
	Name        string   `json:"name"`
	TokenSHA256 string   `json:"token_sha256"`
	Permissions []string `json:"permissions"`
}

var permissions = []string{"state.read", "transactions.write", "interfaces.write", "routes.write", "policy.write", "firewall.write", "nat.write", "wireguard.write", "softflowd.write", "gateway_monitors.write", "ntp.write", "syslog.write", "vnstat.write", "kernel.namespace.write", "kernel.host.write"}

type API struct {
	engine       *control.Engine
	credentials  []Credential
	logger       *slog.Logger
	authenticate func(string) (Credential, bool, error)
}

func New(engine *control.Engine, credentials []Credential, logger *slog.Logger) (http.Handler, error) {
	if len(credentials) == 0 {
		return nil, fmt.Errorf("at least one credential is required")
	}
	names, hashes := map[string]bool{}, map[string]bool{}
	for _, c := range credentials {
		hash, err := hex.DecodeString(c.TokenSHA256)
		if err != nil || len(hash) != sha256.Size || strings.TrimSpace(c.Name) == "" || names[c.Name] || hashes[strings.ToLower(c.TokenSHA256)] {
			return nil, fmt.Errorf("credential names and SHA-256 API key hashes must be valid and unique")
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
	if strings.HasPrefix(r.URL.Path, "/api/v1/") {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Expose-Headers", "Location, WWW-Authenticate, Retry-After")
		if r.Method == http.MethodOptions && r.Header.Get("Origin") != "" && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			if method := r.Header.Get("Access-Control-Request-Method"); method != http.MethodGet && method != http.MethodPost {
				fail(http.StatusMethodNotAllowed, fmt.Errorf("cross-origin method must be GET or POST"), nil)
				return
			}
			for _, header := range strings.Split(r.Header.Get("Access-Control-Request-Headers"), ",") {
				header = strings.TrimSpace(header)
				if header != "" && !strings.EqualFold(header, "Authorization") && !strings.EqualFold(header, "Content-Type") {
					fail(http.StatusBadRequest, fmt.Errorf("unsupported cross-origin request header %q", header), nil)
					return
				}
			}
			status = http.StatusNoContent
			w.WriteHeader(status)
			return
		}
	}
	var credential *Credential
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		token := strings.TrimPrefix(header, "Bearer ")
		if a.authenticate != nil {
			value, ok, err := a.authenticate(token)
			if err != nil {
				a.logger.Error("credential lookup failed", "error", err)
				fail(http.StatusServiceUnavailable, fmt.Errorf("credential store unavailable"), nil)
				return
			}
			if ok {
				credential = &value
			}
		} else {
			hash := sha256.Sum256([]byte(token))
			for i := range a.credentials {
				expected, _ := hex.DecodeString(a.credentials[i].TokenSHA256)
				if subtle.ConstantTimeCompare(hash[:], expected) == 1 {
					credential = &a.credentials[i]
				}
			}
		}
	}
	if credential == nil {
		w.Header().Set("WWW-Authenticate", "Bearer")
		fail(http.StatusUnauthorized, fmt.Errorf("valid API key required"), nil)
		return
	}
	actor = credential.Name
	has := func(p string) bool { return slices.Contains(credential.Permissions, p) }
	if r.Method == http.MethodGet {
		if !has("state.read") {
			fail(http.StatusForbidden, fmt.Errorf("state.read permission required"), nil)
			return
		}
		if isStatisticsPath(r.URL.Path) {
			query, err := statisticsQuery(r)
			if err != nil {
				code := http.StatusBadRequest
				if errors.Is(err, errStatisticsEndpointNotFound) {
					code = http.StatusNotFound
				}
				fail(code, err, nil)
				return
			}
			snapshot, err := a.engine.Statistics(r.Context(), query)
			if err != nil {
				code := http.StatusServiceUnavailable
				if errors.Is(err, control.ErrStatisticsInterfaceNotFound) || errors.Is(err, control.ErrGatewayMonitorNotFound) {
					code = http.StatusNotFound
				}
				fail(code, err, nil)
				return
			}
			switch {
			case query.Monitor != "":
				if len(snapshot.Gateways) != 1 || snapshot.Gateways[0].Name != query.Monitor {
					fail(http.StatusServiceUnavailable, fmt.Errorf("adapter returned an inconsistent gateway sample"), nil)
					return
				}
				a.encode(w, map[string]any{"sample": snapshot.Sample, "monitor": snapshot.Gateways[0]})
			case query.Section == control.StatisticsGateways:
				a.encode(w, map[string]any{"sample": snapshot.Sample, "monitors": snapshot.Gateways})
			case query.Interface != "":
				if len(snapshot.Interfaces) != 1 || snapshot.Interfaces[0].Name != query.Interface {
					fail(http.StatusServiceUnavailable, fmt.Errorf("adapter returned an inconsistent interface sample"), nil)
					return
				}
				a.encode(w, map[string]any{"sample": snapshot.Sample, "interface": snapshot.Interfaces[0]})
			case query.Section == control.StatisticsInterfaces:
				a.encode(w, map[string]any{"sample": snapshot.Sample, "interfaces": snapshot.Interfaces})
			case query.Section == control.StatisticsProtocols:
				a.encode(w, map[string]any{"sample": snapshot.Sample, "protocols": snapshot.Protocols})
			default:
				a.encode(w, snapshot)
			}
			return
		}
		if r.URL.Path == "/api/v1/kernel/tunables/catalog" {
			a.encode(w, control.KernelCatalog())
			return
		}
		if r.URL.Path == "/api/v1/kernel/tunables" {
			view, err := a.engine.KernelView(r.Context())
			if err != nil {
				fail(http.StatusServiceUnavailable, err, nil)
				return
			}
			a.encode(w, view)
			return
		}
		if r.URL.Path == "/api/v1/runtime" || r.URL.Path == "/api/v1/parent-interfaces" ||
			r.URL.Path == "/api/v1/services/softflowd/status" || r.URL.Path == "/api/v1/services/dhcp-relay/status" ||
			r.URL.Path == "/api/v1/services/gateway-monitoring/status" || applianceServicePath(r.URL.Path, "status") != "" {
			runtime, err := a.engine.Runtime(r.Context())
			if err != nil {
				fail(http.StatusServiceUnavailable, err, nil)
				return
			}
			switch r.URL.Path {
			case "/api/v1/services/ntp/status", "/api/v1/services/syslog/status", "/api/v1/services/vnstat/status":
				name := applianceServicePath(r.URL.Path, "status")
				instances := []control.ApplianceServiceStatus{}
				for _, instance := range runtime.Appliance {
					if instance.Name == name || name == "vnstat" && strings.HasPrefix(instance.Name, "vnstat-") {
						instances = append(instances, instance)
					}
				}
				a.encode(w, map[string]any{"instances": instances, "error": runtime.Error})
			case "/api/v1/services/gateway-monitoring/status":
				a.encode(w, map[string]any{"monitors": runtime.Gateways, "error": runtime.Error})
			case "/api/v1/parent-interfaces":
				a.encode(w, runtime.Parents)
			case "/api/v1/services/softflowd/status":
				a.encode(w, map[string]any{"instances": runtime.Softflowd, "error": runtime.Error})
			case "/api/v1/services/dhcp-relay/status":
				a.encode(w, map[string]any{"interfaces": runtime.DHCPRelay, "error": runtime.Error})
			default:
				a.encode(w, runtime)
			}
			return
		}
		if r.URL.Path == "/api/v1/revisions" {
			limit, before, err := revisionListOptions(r)
			if err != nil {
				fail(http.StatusBadRequest, err, nil)
				return
			}
			page, err := a.engine.ListRevisions(limit, before)
			if err != nil {
				fail(errorStatus(err), err, nil)
				return
			}
			a.encode(w, page)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/v1/revisions/") {
			value := strings.TrimPrefix(r.URL.Path, "/api/v1/revisions/")
			if strings.Contains(value, "/") {
				fail(http.StatusNotFound, fmt.Errorf("endpoint not found"), nil)
				return
			}
			number, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				fail(http.StatusBadRequest, fmt.Errorf("revision must be an unsigned 64-bit integer"), nil)
				return
			}
			revision, err := a.engine.GetRevision(number)
			if err != nil {
				fail(errorStatus(err), err, nil)
				return
			}
			a.encode(w, revision)
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
		known := []string{"/api/v1/state", "/api/v1/interfaces", "/api/v1/vlans", "/api/v1/gateway-monitors", "/api/v1/services/softflowd", "/api/v1/routes", "/api/v1/policy-rules", "/api/v1/firewall/rules", "/api/v1/firewall/hosts", "/api/v1/firewall/interface-policies", "/api/v1/firewall/nat", "/api/v1/wireguard"}
		isInterface := strings.HasPrefix(r.URL.Path, "/api/v1/interfaces/")
		if !slices.Contains(known, r.URL.Path) && !isInterface && applianceServicePath(r.URL.Path, "") == "" {
			fail(http.StatusNotFound, fmt.Errorf("endpoint not found"), nil)
			return
		}
		view, err := a.engine.View(r.Context())
		if err != nil {
			fail(http.StatusServiceUnavailable, fmt.Errorf("observation failed: %w", err), nil)
			return
		}
		switch r.URL.Path {
		case "/api/v1/services/ntp":
			a.encode(w, view.Observed.NTP)
		case "/api/v1/services/syslog":
			a.encode(w, view.Observed.Syslog)
		case "/api/v1/services/vnstat":
			a.encode(w, view.Observed.VNStat)
		case "/api/v1/gateway-monitors":
			a.encode(w, view.Observed.GatewayMonitors)
		case "/api/v1/state":
			a.encode(w, view)
		case "/api/v1/interfaces":
			a.encode(w, view.Observed.Interfaces)
		case "/api/v1/vlans":
			links := []control.Interface{}
			for _, link := range view.Observed.Interfaces {
				if link.VLAN != nil {
					links = append(links, link)
				}
			}
			a.encode(w, links)
		case "/api/v1/services/softflowd":
			a.encode(w, view.Observed.Softflowd)
		case "/api/v1/routes":
			a.encode(w, view.Observed.Routes)
		case "/api/v1/policy-rules":
			a.encode(w, view.Observed.Rules)
		case "/api/v1/firewall/rules":
			a.encode(w, view.Observed.Firewall)
		case "/api/v1/firewall/hosts":
			hosts := []control.FirewallHost{}
			if view.Observed.Firewall.Policies != nil {
				hosts = view.Observed.Firewall.Policies.Hosts
			}
			a.encode(w, hosts)
		case "/api/v1/firewall/interface-policies":
			policies := []control.InterfacePolicy{}
			if view.Observed.Firewall.Policies != nil {
				policies = view.Observed.Firewall.Policies.Interfaces
			}
			a.encode(w, policies)
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
	if isStatisticsPath(r.URL.Path) {
		w.Header().Set("Allow", "GET")
		fail(http.StatusMethodNotAllowed, fmt.Errorf("statistics endpoints are read-only"), nil)
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
	if r.URL.Path == "/api/v1/services/softflowd/reconcile" || r.URL.Path == "/api/v1/services/dhcp-relay/reconcile" ||
		r.URL.Path == "/api/v1/services/gateway-monitoring/reconcile" || applianceServicePath(r.URL.Path, "reconcile") != "" {
		permission := "softflowd.write"
		if r.URL.Path == "/api/v1/services/dhcp-relay/reconcile" {
			permission = "interfaces.write"
		}
		if r.URL.Path == "/api/v1/services/gateway-monitoring/reconcile" {
			permission = "gateway_monitors.write"
		}
		if service := applianceServicePath(r.URL.Path, "reconcile"); service != "" {
			permission = service + ".write"
		}
		if !has("state.read") || !has(permission) {
			fail(http.StatusForbidden, fmt.Errorf("state.read and %s permissions required", permission), nil)
			return
		}
		var denied error
		runtime, err := a.engine.ReconcileServices(r.Context(), actor, func(expected control.Config) error {
			denied = authorizeServiceReconcile(*credential, expected)
			return denied
		})
		if err != nil {
			status := errorStatus(err)
			if denied != nil {
				status = http.StatusForbidden
			}
			fail(status, err, nil)
			return
		}
		a.encode(w, runtime)
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
		if err := authorizeAtRevision(*credential, a.engine.Snapshot(), request.BaseRevision, request.Config); err != nil {
			code := http.StatusForbidden
			if errors.Is(err, control.ErrConflict) {
				code = http.StatusConflict
			}
			fail(code, err, nil)
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
	if strings.HasPrefix(r.URL.Path, "/api/v1/revisions/") {
		path := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/revisions/"), "/")
		if len(path) != 2 || path[1] != "restore" {
			fail(http.StatusNotFound, fmt.Errorf("endpoint not found"), nil)
			return
		}
		if !has("state.read") {
			fail(http.StatusForbidden, fmt.Errorf("state.read permission required for historical restore"), nil)
			return
		}
		number, err := strconv.ParseUint(path[0], 10, 64)
		if err != nil {
			fail(http.StatusBadRequest, fmt.Errorf("revision must be an unsigned 64-bit integer"), nil)
			return
		}
		if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
			fail(http.StatusUnsupportedMediaType, fmt.Errorf("application/json required"), nil)
			return
		}
		var request control.RestoreRequest
		if err := decode(w, r, &request); err != nil {
			fail(http.StatusBadRequest, err, nil)
			return
		}
		revision, err := a.engine.GetRevision(number)
		if err != nil {
			fail(errorStatus(err), err, nil)
			return
		}
		if err := authorizeAtRevision(*credential, a.engine.Snapshot(), request.BaseRevision, revision.Config); err != nil {
			code := http.StatusForbidden
			if errors.Is(err, control.ErrConflict) {
				code = http.StatusConflict
			}
			fail(code, err, nil)
			return
		}
		t, err := a.engine.Restore(r.Context(), actor, number, request)
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
	case errors.Is(err, control.ErrNotFound), errors.Is(err, control.ErrRevisionNotFound):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}

func revisionListOptions(r *http.Request) (int, *uint64, error) {
	limit := 50
	var before *uint64
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, nil, fmt.Errorf("invalid revision list query: %w", err)
	}
	for name, values := range query {
		if len(values) != 1 || values[0] == "" {
			return 0, nil, fmt.Errorf("revision list parameters must have exactly one nonempty value")
		}
		switch name {
		case "limit":
			n, err := strconv.Atoi(values[0])
			if err != nil || n < 1 || n > 100 {
				return 0, nil, fmt.Errorf("limit must be 1..100")
			}
			limit = n
		case "before_revision":
			n, err := strconv.ParseUint(values[0], 10, 64)
			if err != nil {
				return 0, nil, fmt.Errorf("before_revision must be an unsigned 64-bit integer")
			}
			before = &n
		default:
			return 0, nil, fmt.Errorf("unknown revision list parameter %q", name)
		}
	}
	return limit, before, nil
}

func authorizeAtRevision(c Credential, state control.State, base uint64, target control.Config) error {
	if state.Revision != base {
		return control.ErrConflict
	}
	return authorize(c, state.Desired, target)
}

func authorizeServiceReconcile(c Credential, expected control.Config) error {
	for _, service := range []struct {
		name    string
		enabled bool
	}{{"ntp", expected.NTP.Enabled}, {"syslog", expected.Syslog.Enabled}, {"vnstat", expected.VNStat.Enabled}} {
		if service.enabled && !slices.Contains(c.Permissions, service.name+".write") {
			return fmt.Errorf("%s.write permission required to reconcile enabled host services", service.name)
		}
	}
	for _, monitor := range expected.GatewayMonitors {
		if monitor.Enabled && !slices.Contains(c.Permissions, "gateway_monitors.write") {
			return fmt.Errorf("gateway_monitors.write permission required to reconcile enabled monitors")
		}
	}
	for _, service := range expected.Softflowd {
		if service.Enabled && !slices.Contains(c.Permissions, "softflowd.write") {
			return fmt.Errorf("softflowd.write permission required to reconcile enabled services")
		}
	}
	for _, link := range expected.Interfaces {
		if link.DHCPRelay.Enabled && !slices.Contains(c.Permissions, "interfaces.write") {
			return fmt.Errorf("interfaces.write permission required to reconcile enabled DHCP relays")
		}
	}
	return nil
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
	if err := need("softflowd.write", !equal(before.Softflowd, after.Softflowd)); err != nil {
		return err
	}
	if err := need("gateway_monitors.write", !equal(before.GatewayMonitors, after.GatewayMonitors)); err != nil {
		return err
	}
	for _, service := range []struct {
		name          string
		before, after any
	}{{"ntp", before.NTP, after.NTP}, {"syslog", before.Syslog, after.Syslog}, {"vnstat", before.VNStat, after.VNStat}} {
		if err := need(service.name+".write", !equal(service.before, service.after)); err != nil {
			return err
		}
	}
	if err := need("kernel.namespace.write", !equal(before.Kernel.Namespace, after.Kernel.Namespace)); err != nil {
		return err
	}
	if err := need("kernel.host.write", !equal(before.Kernel.Host, after.Kernel.Host)); err != nil {
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
