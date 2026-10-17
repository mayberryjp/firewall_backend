package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrConflict = errors.New("device account already exists")
	ErrInvalid = errors.New("invalid username, password, or key name")
	ErrDenied = errors.New("invalid credentials or expired session")
	ErrNotFound = errors.New("API key not found")
	ErrNoKey = errors.New("create and save an API key before finishing setup")
)

var bucket = []byte("identity-v1")

const SessionLifetime = 30 * time.Minute

type Store struct{ db *bolt.DB }

type account struct {
	Username string `json:"username"`
	Password []byte `json:"password_hash"`
	Complete bool `json:"complete"`
}

type Key struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Masked string `json:"masked"`
	CreatedAt time.Time `json:"created_at"`
}

type storedKey struct {
	Key
	Hash string `json:"hash"`
}

type session struct {
	Expires time.Time `json:"expires"`
}

type Status struct {
	AccountExists bool
	Complete bool
	Username string
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
			return nil, fmt.Errorf("credential database must be a regular owner-only file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open credential database: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucket)
		return err
	}); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func readAccount(b *bolt.Bucket) (account, bool, error) {
	value := b.Get([]byte("account"))
	if value == nil {
		return account{}, false, nil
	}
	var a account
	err := json.Unmarshal(value, &a)
	if err == nil && (a.Username == "" || len(a.Password) == 0) {
		err = errors.New("invalid stored account")
	}
	return a, true, err
}

func put(b *bolt.Bucket, key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), data)
}

func (s *Store) Status() (Status, error) {
	var status Status
	err := s.db.View(func(tx *bolt.Tx) error {
		a, exists, err := readAccount(tx.Bucket(bucket))
		status = Status{AccountExists: exists, Complete: a.Complete, Username: a.Username}
		return err
	})
	return status, err
}

func validName(value string, max int) bool {
	return value != "" && len(value) <= max && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func secret(prefix string) (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func newSession(b *bolt.Bucket, token string) error {
	c := b.Cursor()
	count := 0
	for k, v := c.Seek([]byte("session:")); k != nil && strings.HasPrefix(string(k), "session:"); k, v = c.Next() {
		var stored session
		if err := json.Unmarshal(v, &stored); err != nil {
			return err
		}
		if !time.Now().Before(stored.Expires) {
			if err := c.Delete(); err != nil {
				return err
			}
		} else {
			count++
		}
	}
	if count >= 32 {
		return errors.New("too many active sessions; log out or wait for sessions to expire")
	}
	return put(b, "session:"+digest(token), session{Expires: time.Now().Add(SessionLifetime)})
}

func (s *Store) Setup(username, password string) (string, error) {
	if !validName(username, 64) || len(password) < 12 || len(password) > 72 {
		return "", ErrInvalid
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	token, err := secret("session_")
	if err != nil {
		return "", err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		_, exists, err := readAccount(b)
		if err != nil {
			return err
		}
		if exists {
			return ErrConflict
		}
		if err := put(b, "account", account{Username: username, Password: hash}); err != nil {
			return err
		}
		return newSession(b, token)
	})
	return token, err
}

func (s *Store) Login(username, password string) (string, error) {
	var a account
	err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		a, _, err = readAccount(tx.Bucket(bucket))
		return err
	})
	if err != nil {
		return "", err
	}
	if len(password) > 72 || bcrypt.CompareHashAndPassword(a.Password, []byte(password)) != nil || a.Username != username {
		return "", ErrDenied
	}
	token, err := secret("session_")
	if err != nil {
		return "", err
	}
	err = s.db.Update(func(tx *bolt.Tx) error { return newSession(tx.Bucket(bucket), token) })
	return token, err
}

func checkSession(b *bolt.Bucket, token string) error {
	value := b.Get([]byte("session:" + digest(token)))
	if value == nil || token == "" {
		return ErrDenied
	}
	var stored session
	if err := json.Unmarshal(value, &stored); err != nil {
		return err
	}
	if !time.Now().Before(stored.Expires) {
		return ErrDenied
	}
	return nil
}

func (s *Store) Session(token string) error {
	return s.db.View(func(tx *bolt.Tx) error { return checkSession(tx.Bucket(bucket), token) })
}

func (s *Store) Logout(token string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Delete([]byte("session:" + digest(token)))
	})
}

func keys(b *bolt.Bucket) ([]Key, error) {
	result := []Key{}
	c := b.Cursor()
	for k, v := c.Seek([]byte("key:")); k != nil && strings.HasPrefix(string(k), "key:"); k, v = c.Next() {
		var stored storedKey
		if err := json.Unmarshal(v, &stored); err != nil {
			return nil, err
		}
		result = append(result, stored.Key)
	}
	return result, nil
}

func (s *Store) Keys(token string) ([]Key, error) {
	var result []Key
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if err := checkSession(b, token); err != nil {
			return err
		}
		var err error
		result, err = keys(b)
		return err
	})
	return result, err
}

func (s *Store) CreateKey(token, name string) (Key, string, error) {
	if !validName(name, 80) {
		return Key{}, "", ErrInvalid
	}
	value, err := secret("nc_")
	if err != nil {
		return Key{}, "", err
	}
	id, err := secret("")
	if err != nil {
		return Key{}, "", err
	}
	key := Key{ID: id, Name: name, Masked: "nc_..." + value[len(value)-4:], CreatedAt: time.Now().UTC()}
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if err := checkSession(b, token); err != nil {
			return err
		}
		list, err := keys(b)
		if err != nil {
			return err
		}
		if len(list) >= 100 {
			return fmt.Errorf("%w: maximum of 100 API keys", ErrInvalid)
		}
		for _, existing := range list {
			if existing.Name == name {
				return fmt.Errorf("%w: key names must be unique", ErrInvalid)
			}
		}
		return put(b, "key:"+id, storedKey{Key: key, Hash: digest(value)})
	})
	return key, value, err
}

func (s *Store) DeleteKey(token, id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if err := checkSession(b, token); err != nil {
			return err
		}
		key := []byte("key:" + id)
		if b.Get(key) == nil {
			return ErrNotFound
		}
		return b.Delete(key)
	})
}

func (s *Store) Complete(token string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if err := checkSession(b, token); err != nil {
			return err
		}
		list, err := keys(b)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			return ErrNoKey
		}
		a, _, err := readAccount(b)
		if err != nil {
			return err
		}
		a.Complete = true
		return put(b, "account", a)
	})
}

func (s *Store) Authenticate(token string) (Key, bool, error) {
	var result Key
	found := false
	if len(token) != 67 || !strings.HasPrefix(token, "nc_") {
		return result, false, nil
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		a, _, err := readAccount(b)
		if err != nil || !a.Complete {
			return err
		}
		c := b.Cursor()
		hash := digest(token)
		for k, v := c.Seek([]byte("key:")); k != nil && strings.HasPrefix(string(k), "key:"); k, v = c.Next() {
			var stored storedKey
			if err := json.Unmarshal(v, &stored); err != nil {
				return err
			}
			if subtle.ConstantTimeCompare([]byte(stored.Hash), []byte(hash)) == 1 {
				result, found = stored.Key, true
			}
		}
		return nil
	})
	return result, found, err
}
