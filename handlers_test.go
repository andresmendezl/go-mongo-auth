package main

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

// memStore is an in-memory Store for handler tests.
type memStore struct {
	mu       sync.Mutex
	users    map[string]User // by username
	sessions map[string]string
}

func newMemStore() *memStore {
	return &memStore{users: map[string]User{}, sessions: map[string]string{}}
}

func (m *memStore) CreateUser(_ context.Context, username string, hash []byte) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[username]; ok {
		return User{}, ErrUserExists
	}
	u := User{ID: rand.Text(), Username: username, PasswordHash: hash, CreatedAt: time.Now()}
	m.users[username] = u
	return u, nil
}

func (m *memStore) GetUserByUsername(_ context.Context, username string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[username]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (m *memStore) CreateSession(_ context.Context, userID string, _ time.Duration) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	token := rand.Text()
	m.sessions[hashToken(token)] = userID
	return token, nil
}

func (m *memStore) SessionUser(_ context.Context, token string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.sessions[hashToken(token)]
	if !ok {
		return User{}, ErrNotFound
	}
	for _, u := range m.users {
		if u.ID == id {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

func (m *memStore) DeleteSession(_ context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, hashToken(token))
	return nil
}

func (m *memStore) Ping(context.Context) error { return nil }

func newTestServer(t *testing.T, limit rate.Limit, burst int) (*httptest.Server, *http.Client) {
	t.Helper()
	s := &Server{
		store:   newMemStore(),
		cfg:     Config{SessionTTL: time.Hour},
		limiter: NewRateLimiter(t.Context(), limit, burst, false),
	}
	ts := httptest.NewServer(s.routes())
	t.Cleanup(ts.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return ts, &http.Client{Jar: jar}
}

func do(t *testing.T, c *http.Client, method, url, body string) int {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestAuthFlow(t *testing.T) {
	ts, c := newTestServer(t, rate.Inf, 0)
	creds := `{"username":"Andres","password":"supersecret"}`

	steps := []struct {
		name, method, path, body string
		want                     int
	}{
		{"me before login", "GET", "/me", "", 401},
		{"register", "POST", "/register", creds, 201},
		{"register duplicate (case-insensitive)", "POST", "/register", `{"username":"andres","password":"supersecret"}`, 409},
		{"wrong password", "POST", "/login", `{"username":"andres","password":"wrongpass1"}`, 401},
		{"unknown user", "POST", "/login", `{"username":"nobody","password":"wrongpass1"}`, 401},
		{"login", "POST", "/login", creds, 200},
		{"me after login", "GET", "/me", "", 200},
		{"logout", "POST", "/logout", "", 204},
		{"me after logout", "GET", "/me", "", 401},
	}
	for _, s := range steps {
		if got := do(t, c, s.method, ts.URL+s.path, s.body); got != s.want {
			t.Fatalf("%s: got %d, want %d", s.name, got, s.want)
		}
	}
}

func TestRegisterValidation(t *testing.T) {
	ts, c := newTestServer(t, rate.Inf, 0)
	cases := map[string]string{
		"short password": `{"username":"valid","password":"short"}`,
		"long password":  `{"username":"valid","password":"` + strings.Repeat("a", 73) + `"}`,
		"short username": `{"username":"ab","password":"supersecret"}`,
		"bad username":   `{"username":"no spaces","password":"supersecret"}`,
		"unknown field":  `{"username":"valid","password":"supersecret","admin":true}`,
		"malformed JSON": `{"username":`,
		"empty body":     ``,
	}
	for name, body := range cases {
		if got := do(t, c, "POST", ts.URL+"/register", body); got != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, got)
		}
	}
}

func TestLoginRateLimit(t *testing.T) {
	ts, c := newTestServer(t, rate.Every(time.Hour), 3)
	body := `{"username":"nobody","password":"wrongpass1"}`
	for i := range 3 {
		if got := do(t, c, "POST", ts.URL+"/login", body); got != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d, want 401", i+1, got)
		}
	}
	if got := do(t, c, "POST", ts.URL+"/login", body); got != http.StatusTooManyRequests {
		t.Fatalf("got %d, want 429", got)
	}
}

func TestCrossOriginRejected(t *testing.T) {
	ts, c := newTestServer(t, rate.Inf, 0)
	req, _ := http.NewRequest("POST", ts.URL+"/logout", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403", resp.StatusCode)
	}
}
