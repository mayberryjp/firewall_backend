package httpapi

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"netcontrol/internal/control"
	"netcontrol/internal/identity"
)

//go:embed web/*
var deviceFiles embed.FS

const sessionCookie = "netcontrol_session"

type device struct {
	store *identity.Store
	api *API
	logger *slog.Logger
	mu sync.Mutex
	window time.Time
	attempts int
}

func NewDevice(engine *control.Engine, store *identity.Store, logger *slog.Logger) http.Handler {
	api := &API{engine: engine, logger: logger}
	api.authenticate = func(token string) (Credential, bool, error) {
		key, ok, err := store.Authenticate(token)
		return Credential{Name: key.Name, Permissions: permissions}, ok, err
	}
	return &device{store: store, api: api, logger: logger}
}

func (d *device) allowAttempt() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if now.Sub(d.window) >= time.Minute {
		d.window, d.attempts = now, 0
	}
	d.attempts++
	return d.attempts <= 10
}

func (d *device) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	if r.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		d.api.ServeHTTP(w, r)
		return
	}
	if r.URL.Path == "/" || r.URL.Path == "/app.js" || r.URL.Path == "/style.css" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			d.fail(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			return
		}
		name, contentType := "index.html", "text/html; charset=utf-8"
		if r.URL.Path == "/app.js" {
			name, contentType = "app.js", "text/javascript; charset=utf-8"
		} else if r.URL.Path == "/style.css" {
			name, contentType = "style.css", "text/css; charset=utf-8"
		}
		data, err := deviceFiles.ReadFile("web/" + name)
		if err != nil {
			d.fail(w, 500, err)
			return
		}
		w.Header().Set("Content-Type", contentType)
		if r.Method != http.MethodHead {
			if _, err := w.Write(data); err != nil {
				d.logger.Error("website response write failed", "error", err)
			}
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if !strings.HasPrefix(r.URL.Path, "/auth/") {
		d.fail(w, 404, fmt.Errorf("endpoint not found"))
		return
	}
	token := ""
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		token = cookie.Value
	}
	if r.Method != http.MethodGet {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if r.Header.Get("Origin") != scheme+"://"+r.Host {
			d.fail(w, 403, fmt.Errorf("same-origin request required"))
			return
		}
		contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || contentType != "application/json" {
			d.fail(w, 415, fmt.Errorf("application/json required"))
			return
		}
	}
	if r.URL.Path == "/auth/status" && r.Method == http.MethodGet {
		status, err := d.store.Status()
		if err != nil {
			d.fail(w, 500, err)
			return
		}
		authenticated := false
		if token != "" {
			err := d.store.Session(token)
			if err != nil && !errors.Is(err, identity.ErrDenied) {
				d.fail(w, 500, err)
				return
			}
			authenticated = err == nil
		}
		stage, username := "login", ""
		if !status.AccountExists {
			stage = "account"
		} else if authenticated {
			username = status.Username
			stage = "keys"
			if status.Complete {
				stage = "ready"
			}
		}
		d.write(w, 200, map[string]any{"stage": stage, "authenticated": authenticated, "configured": status.Complete, "username": username})
		return
	}
	if (r.URL.Path == "/auth/setup" || r.URL.Path == "/auth/login") && r.Method == http.MethodPost {
		if !d.allowAttempt() {
			w.Header().Set("Retry-After", "60")
			d.fail(w, 429, fmt.Errorf("too many sign-in/setup attempts; retry in one minute"))
			return
		}
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := decode(w, r, &input); err != nil {
			d.fail(w, 400, err)
			return
		}
		var value string
		var err error
		if r.URL.Path == "/auth/setup" {
			value, err = d.store.Setup(input.Username, input.Password)
		} else {
			value, err = d.store.Login(input.Username, input.Password)
		}
		if err != nil {
			d.storeError(w, err)
			d.logger.Warn("device sign-in/setup rejected", "path", r.URL.Path, "remote", r.RemoteAddr)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: value, Path: "/auth/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: int(identity.SessionLifetime.Seconds())})
		d.logger.Info("device sign-in/setup succeeded", "path", r.URL.Path, "remote", r.RemoteAddr)
		d.write(w, 200, map[string]bool{"ok": true})
		return
	}
	if err := d.store.Session(token); err != nil {
		d.storeError(w, err)
		return
	}
	switch {
	case r.URL.Path == "/auth/logout" && r.Method == http.MethodPost:
		if err := d.store.Logout(token); err != nil {
			d.storeError(w, err)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/auth/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		d.write(w, 200, map[string]bool{"ok": true})
	case r.URL.Path == "/auth/complete" && r.Method == http.MethodPost:
		var input struct { Saved bool `json:"saved"` }
		if err := decode(w, r, &input); err != nil || !input.Saved {
			d.fail(w, 400, fmt.Errorf("confirm that you saved your API key"))
			return
		}
		if err := d.store.Complete(token); err != nil {
			d.storeError(w, err)
			return
		}
		d.logger.Info("device setup completed", "remote", r.RemoteAddr)
		d.write(w, 200, map[string]bool{"ok": true})
	case r.URL.Path == "/auth/keys" && r.Method == http.MethodGet:
		list, err := d.store.Keys(token)
		if err != nil {
			d.storeError(w, err)
			return
		}
		d.write(w, 200, map[string]any{"keys": list})
	case r.URL.Path == "/auth/keys" && r.Method == http.MethodPost:
		var input struct { Name string `json:"name"` }
		if err := decode(w, r, &input); err != nil {
			d.fail(w, 400, err)
			return
		}
		key, value, err := d.store.CreateKey(token, input.Name)
		if err != nil {
			d.storeError(w, err)
			return
		}
		d.logger.Info("API key created", "key_id", key.ID, "remote", r.RemoteAddr)
		d.write(w, 201, map[string]any{"key": key, "token": value})
	case strings.HasPrefix(r.URL.Path, "/auth/keys/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(r.URL.Path, "/auth/keys/")
		if err := d.store.DeleteKey(token, id); err != nil {
			d.storeError(w, err)
			return
		}
		d.logger.Info("API key revoked", "key_id", id, "remote", r.RemoteAddr)
		d.write(w, 200, map[string]bool{"ok": true})
	default:
		d.fail(w, 404, fmt.Errorf("endpoint or method not found"))
	}
}

func (d *device) write(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		d.logger.Error("device response write failed", "error", err)
	}
}

func (d *device) fail(w http.ResponseWriter, status int, err error) {
	if status >= 500 {
		d.logger.Error("device request failed", "error", err)
		err = fmt.Errorf("credential service unavailable")
	}
	d.write(w, status, map[string]string{"error": err.Error()})
}

func (d *device) storeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, identity.ErrDenied):
		status = 401
	case errors.Is(err, identity.ErrConflict), errors.Is(err, identity.ErrNoKey):
		status = 409
	case errors.Is(err, identity.ErrInvalid):
		status = 400
	case errors.Is(err, identity.ErrNotFound):
		status = 404
	}
	d.fail(w, status, err)
}
