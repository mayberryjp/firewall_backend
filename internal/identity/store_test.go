package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestCredentialLifecycleAndPersistence(t *testing.T) {
	s, path := openTest(t)
	password := "a unique test password"
	token, err := s.Setup("admin", password)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(token); !errors.Is(err, ErrNoKey) {
		t.Fatalf("completed without key: %v", err)
	}
	first, raw, err := s.CreateKey(token, "dashboard")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 67 || first.Masked != "nc_..."+raw[len(raw)-4:] {
		t.Fatalf("wrong generated key shape: %+v", first)
	}
	if _, ok, err := s.Authenticate(raw); err != nil || ok {
		t.Fatalf("key works before setup completion: %v %v", ok, err)
	}
	if _, _, err := s.CreateKey(token, "dashboard"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate name: %v", err)
	}
	if err := s.Complete(token); err != nil {
		t.Fatal(err)
	}
	if key, ok, err := s.Authenticate(raw); err != nil || !ok || key.ID != first.ID {
		t.Fatalf("authentication: %+v %v %v", key, ok, err)
	}
	if _, ok, err := s.Authenticate(raw[:len(raw)-1] + "z"); err != nil || ok {
		t.Fatalf("invalid key accepted: %v %v", ok, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, ok, err := s.Authenticate(raw); err != nil || !ok {
		t.Fatalf("key not persistent: %v %v", ok, err)
	}
	status, err := s.Status()
	if err != nil || !status.Complete || status.Username != "admin" {
		t.Fatalf("status: %+v %v", status, err)
	}
	if _, err := s.Login("admin", "wrong password"); !errors.Is(err, ErrDenied) {
		t.Fatalf("bad password accepted: %v", err)
	}
	if _, err := s.Login("wrong", password); !errors.Is(err, ErrDenied) {
		t.Fatalf("bad username accepted: %v", err)
	}
	login, err := s.Login("admin", password)
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.Keys(login)
	if err != nil || len(list) != 1 || list[0].ID != first.ID {
		t.Fatalf("list: %+v %v", list, err)
	}
	data, err := json.Marshal(list)
	if err != nil || bytes.Contains(data, []byte(raw)) || bytes.Contains(data, []byte("hash")) {
		t.Fatalf("key list leaked secrets: %s %v", data, err)
	}
	if err := s.DeleteKey(login, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.Authenticate(raw); err != nil || ok {
		t.Fatalf("revoked key accepted: %v %v", ok, err)
	}
	if _, _, err := s.CreateKey(login, "replacement"); err != nil {
		t.Fatalf("cannot replace last revoked key: %v", err)
	}
	if err := s.Logout(login); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Keys(login); !errors.Is(err, ErrDenied) {
		t.Fatalf("logged-out session accepted: %v", err)
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{raw, password, token, login} {
		if bytes.Contains(disk, []byte(secret)) {
			t.Fatal("plaintext secret persisted in database")
		}
	}
}

func TestPendingSetupResumesAndConcurrentClaimIsAtomic(t *testing.T) {
	s, path := openTest(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Setup("admin", "a unique test password")
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrConflict):
			conflict++
		default:
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("claims: %d successes, %d conflicts", success, conflict)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	login, err := s.Login("admin", "a unique test password")
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.Status()
	if err != nil || !status.AccountExists || status.Complete {
		t.Fatalf("pending account lost: %+v %v", status, err)
	}
	if _, _, err := s.CreateKey(login, "resumed"); err != nil {
		t.Fatal(err)
	}
}

func TestValidationAndExpiredSession(t *testing.T) {
	s, _ := openTest(t)
	for _, input := range [][2]string{{"", "long enough password"}, {" admin", "long enough password"}, {"admin", "short"}, {"admin", strings.Repeat("x", 73)}} {
		if _, err := s.Setup(input[0], input[1]); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid input accepted: %v", err)
		}

	}
	token, err := s.Setup("admin", "long enough password")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		a, _, err := readAccount(b)
		if err != nil {
			return err
		}
		cost, err := bcrypt.Cost(a.Password)
		if err != nil || cost != 12 {
			t.Fatalf("password hash cost: %d %v", cost, err)
		}
		return put(b, "session:"+digest(token), session{Expires: time.Now().Add(-time.Minute)})
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateKey(token, "new"); !errors.Is(err, ErrDenied) {
		t.Fatalf("expired session created key: %v", err)
	}
	if err := s.Complete(token); !errors.Is(err, ErrDenied) {
		t.Fatalf("expired session completed setup: %v", err)
	}
	if _, err := s.Keys(""); !errors.Is(err, ErrDenied) {
		t.Fatalf("anonymous key access: %v", err)
	}
	if _, _, err := s.CreateKey(token, " "); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid key name: %v", err)
	}
}

func TestRejectsEmptyOrCorruptDatabase(t *testing.T) {
	for _, data := range [][]byte{{}, []byte("not a credential database")} {
		path := filepath.Join(t.TempDir(), "credentials.db")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if s, err := Open(path); err == nil {
			s.Close()
			t.Fatal("invalid existing database became an unclaimed device")
		}
	}
}

func TestCredentialStoreErrorsFailClosed(t *testing.T) {
	s, _ := openTest(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Status(); err == nil {
		t.Fatal("closed database returned a valid status")
	}
	if _, ok, err := s.Authenticate("nc_" + strings.Repeat("a", 64)); err == nil || ok {
		t.Fatalf("closed database authentication: %v %v", ok, err)
	}
}
