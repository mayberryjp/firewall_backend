package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"netcontrol/internal/identity"
)

func deviceFixture(t *testing.T) http.Handler {
	t.Helper()
	_, engine := fixture(t)
	store, err := identity.Open(filepath.Join(t.TempDir(), "credentials.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return NewDevice(engine, store, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func deviceRequest(h http.Handler, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://device.test"+path, strings.NewReader(body))
	r.Header.Set("Origin", "https://device.test")
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestDeviceSetupAndKeyManagement(t *testing.T) {
	h := deviceFixture(t)
	check := func(w *httptest.ResponseRecorder, code int) {
		t.Helper()
		if w.Code != code {
			t.Fatalf("expected %d, got %d: %s", code, w.Code, w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing no-store")
		}
	}
	w := deviceRequest(h, "GET", "/auth/status", "", nil)
	check(w, 200)
	if !strings.Contains(w.Body.String(), `"stage":"account"`) {
		t.Fatal(w.Body.String())
	}
	check(deviceRequest(h, "GET", "/auth/keys", "", nil), 401)
	check(request(t, h, "GET", "/api/v1/state", "", nil), 401)
	w = deviceRequest(h, "POST", "/auth/setup", `{"username":"admin","password":"a unique test password"}`, nil)
	check(w, 200)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].Path != "/auth/" {
		t.Fatalf("unsafe cookie: %+v", cookies)
	}
	cookie := cookies[0]
	check(deviceRequest(h, "POST", "/auth/setup", `{"username":"other","password":"a unique test password"}`, nil), 409)
	check(deviceRequest(h, "POST", "/auth/complete", `{"saved":true}`, cookie), 409)
	w = deviceRequest(h, "POST", "/auth/keys", `{"name":"dashboard"}`, cookie)
	check(w, 201)
	var created struct {
		Key   identity.Key `json:"key"`
		Token string       `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Token) != 67 {
		t.Fatal("missing generated token")
	}
	check(request(t, h, "GET", "/api/v1/state", created.Token, nil), 401)
	check(deviceRequest(h, "POST", "/auth/complete", `{"saved":false}`, cookie), 400)
	check(deviceRequest(h, "POST", "/auth/complete", `{"saved":true}`, cookie), 200)
	check(request(t, h, "GET", "/api/v1/state", created.Token, nil), 200)
	check(deviceRequest(h, "GET", "/api/v1/state", "", cookie), 401)
	check(request(t, h, "GET", "/auth/keys", created.Token, nil), 401)
	w = deviceRequest(h, "GET", "/auth/keys", "", cookie)
	check(w, 200)
	if bytes.Contains(w.Body.Bytes(), []byte(created.Token)) || strings.Contains(w.Body.String(), `"hash"`) || !strings.Contains(w.Body.String(), created.Key.Masked) {
		t.Fatalf("unsafe masked response: %s", w.Body.String())
	}
	// A second key can be added without invalidating the first.
	check(deviceRequest(h, "POST", "/auth/keys", `{"name":"automation"}`, cookie), 201)
	check(deviceRequest(h, "DELETE", "/auth/keys/"+created.Key.ID, "", cookie), 200)
	check(request(t, h, "GET", "/api/v1/state", created.Token, nil), 401)
	check(deviceRequest(h, "DELETE", "/auth/keys/"+created.Key.ID, "", cookie), 404)
	check(deviceRequest(h, "POST", "/auth/logout", `{}`, cookie), 200)
	check(deviceRequest(h, "GET", "/auth/keys", "", cookie), 401)
	check(deviceRequest(h, "POST", "/auth/login", `{"username":"admin","password":"wrong"}`, nil), 401)
	w = deviceRequest(h, "POST", "/auth/login", `{"username":"admin","password":"a unique test password"}`, nil)
	check(w, 200)
	w = deviceRequest(h, "GET", "/auth/status", "", w.Result().Cookies()[0])
	check(w, 200)
	if !strings.Contains(w.Body.String(), `"stage":"ready"`) {
		t.Fatal(w.Body.String())
	}
}

func TestDeviceRequestProtection(t *testing.T) {
	h := deviceFixture(t)
	for _, origin := range []string{"", "https://evil.test", "http://device.test"} {
		r := httptest.NewRequest("POST", "https://device.test/auth/setup", strings.NewReader(`{}`))
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("origin %q accepted: %d", origin, w.Code)
		}
	}
	for _, body := range []string{`{"unexpected":true}`, `{} {}`, strings.Repeat("x", 5000)} {
		if w := deviceRequest(h, "POST", "/auth/setup", body, nil); w.Code != 400 {
			t.Fatalf("bad input: %d %s", w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest("POST", "https://device.test/auth/setup", strings.NewReader(`{}`))
	r.Header.Set("Origin", "https://device.test")
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 415 {
		t.Fatal(w.Code)
	}
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		w := deviceRequest(h, "GET", path, "", nil)
		if w.Code != 200 || w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("asset %s: %d", path, w.Code)
		}
	}
}

func TestDeviceLoginRateLimit(t *testing.T) {
	h := deviceFixture(t)
	for range 10 {
		w := deviceRequest(h, "POST", "/auth/login", `{"username":"unknown","password":"incorrect"}`, nil)
		if w.Code != 401 {
			t.Fatalf("login response: %d", w.Code)
		}
	}
	w := deviceRequest(h, "POST", "/auth/login", `{"username":"unknown","password":"incorrect"}`, nil)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("missing rate limit: %d", w.Code)
	}
}
