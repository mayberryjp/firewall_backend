package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"netcontrol/internal/control"
	"netcontrol/internal/identity"
)

func TestAPICORSPreflight(t *testing.T) {
	for _, mode := range []string{"static", "device"} {
		t.Run(mode, func(t *testing.T) {
			h, engine := fixture(t)
			if mode == "device" {
				h = deviceFixture(t)
				engine = h.(*device).api.engine
			}
			for _, test := range []struct {
				name, origin, method, headers string
				status                        int
			}{
				{"read", "https://dashboard.test", "GET", "authorization", 204},
				{"write", "https://other.test", "POST", "authorization, content-type", 204},
				{"mixed-case", "https://dashboard.test", "POST", " Authorization , CONTENT-TYPE ", 204},
				{"no-headers", "https://dashboard.test", "GET", "", 204},
				{"unsupported-method", "https://dashboard.test", "DELETE", "authorization", 405},
				{"unsupported-header", "https://dashboard.test", "POST", "X-Custom", 400},
				{"missing-origin", "", "GET", "authorization", 401},
				{"missing-method", "https://dashboard.test", "", "authorization", 401},
			} {
				t.Run(test.name, func(t *testing.T) {
					r := httptest.NewRequest("OPTIONS", "/api/v1/transactions", nil)
					r.Header.Set("Origin", test.origin)
					r.Header.Set("Access-Control-Request-Method", test.method)
					r.Header.Set("Access-Control-Request-Headers", test.headers)
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					if w.Code != test.status {
						t.Fatalf("status %d: %s", w.Code, w.Body.String())
					}
					checkAPICORS(t, w)
					if test.status == 204 {
						if w.Body.Len() != 0 || w.Header().Get("Access-Control-Allow-Methods") != "GET, POST" ||
							w.Header().Get("Access-Control-Allow-Headers") != "Authorization, Content-Type" {
							t.Fatalf("invalid preflight: headers=%v body=%s", w.Header(), w.Body.String())
						}
					}
				})
			}
			if engine.Snapshot().Revision != 0 || engine.Snapshot().Active != "" {
				t.Fatal("preflight mutated configuration")
			}
		})
	}
}

func checkAPICORS(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Header().Get("Access-Control-Allow-Origin") != "*" ||
		w.Header().Get("Access-Control-Allow-Credentials") != "" ||
		w.Header().Get("Access-Control-Expose-Headers") != "Location, WWW-Authenticate, Retry-After" ||
		w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("invalid CORS headers: %v", w.Header())
	}
}

func TestAPICORSResponses(t *testing.T) {
	h, _ := fixture(t)
	for _, test := range []struct {
		name, path, token string
		status            int
	}{
		{"success", "/api/v1/state", "reader-test-token", 200},
		{"anonymous", "/api/v1/state", "", 401},
		{"bad-token", "/api/v1/state", "wrong", 401},
		{"permission", "/api/v1/state", "writer-test-token", 403},
		{"not-found", "/api/v1/missing", "reader-test-token", 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", test.path, nil)
			r.Header.Set("Origin", "https://dashboard.test")
			if test.token != "" {
				r.Header.Set("Authorization", "Bearer "+test.token)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			checkAPICORS(t, w)
		})
	}
	data, err := json.Marshal(control.Request{BaseRevision: 0, ConfirmSeconds: 30, Config: control.EmptyConfig()})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/v1/transactions", strings.NewReader(string(data)))
	r.Header.Set("Origin", "https://dashboard.test")
	r.Header.Set("Authorization", "Bearer admin-test-token")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 202 || w.Header().Get("Location") == "" {
		t.Fatalf("cross-origin transaction: %d %s", w.Code, w.Body.String())
	}
	checkAPICORS(t, w)
}

func TestDeviceCORSCredentialIsolation(t *testing.T) {
	h := deviceFixture(t)
	w := deviceRequest(h, "POST", "/auth/setup", `{"username":"admin","password":"a unique test password"}`, nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	w = deviceRequest(h, "POST", "/auth/keys", `{"name":"dashboard"}`, cookie)
	var created struct {
		Key   identity.Key `json:"key"`
		Token string       `json:"token"`
	}
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	crossOriginRead := func(token string, status int) {
		t.Helper()
		r := httptest.NewRequest("GET", "https://device.test/api/v1/state", nil)
		r.Header.Set("Origin", "https://dashboard.test")
		r.AddCookie(cookie)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		checkAPICORS(t, w)
	}
	crossOriginRead(created.Token, 401)
	if w := deviceRequest(h, "POST", "/auth/complete", `{"saved":true}`, cookie); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	crossOriginRead(created.Token, 200)
	crossOriginRead("", 401)
	if w := deviceRequest(h, "DELETE", "/auth/keys/"+created.Key.ID, "", cookie); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	crossOriginRead(created.Token, 401)
	for _, path := range []string{"/", "/auth/status", "/auth/setup", "/auth/login", "/auth/keys", "/auth/complete"} {
		for _, method := range []string{"GET", "POST", "OPTIONS"} {
			r := httptest.NewRequest(method, "https://device.test"+path, strings.NewReader(`{}`))
			r.Header.Set("Origin", "https://dashboard.test")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Access-Control-Request-Method", "POST")
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatalf("CORS exposed %s %s", method, path)
			}
			if strings.HasPrefix(path, "/auth/") && method != "GET" && w.Code != 403 {
				t.Fatalf("cross-origin auth mutation accepted: %s %s: %d", method, path, w.Code)
			}
		}
	}
}
