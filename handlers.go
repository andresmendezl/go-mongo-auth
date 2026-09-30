package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookie = "session"
	bcryptCost    = 12
	minPassword   = 8
	maxPassword   = 72 // bcrypt rejects passwords longer than 72 bytes
	maxBodyBytes  = 1 << 16
)

var usernameRE = regexp.MustCompile(`^[a-z0-9_.-]{3,32}$`)

// dummyHash is compared against when a user doesn't exist, so login takes
// the same time either way and doesn't leak which usernames are registered.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcryptCost)

type Server struct {
	store   Store
	cfg     Config
	limiter *RateLimiter
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /readyz", s.handleReady)
	mux.Handle("POST /register", s.limiter.Middleware(http.HandlerFunc(s.handleRegister)))
	mux.Handle("POST /login", s.limiter.Middleware(http.HandlerFunc(s.handleLogin)))
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.Handle("GET /me", s.requireAuth(http.HandlerFunc(s.handleMe)))

	// Outermost middleware runs first.
	var h http.Handler = mux
	h = http.NewCrossOriginProtection().Handler(h) // CSRF: rejects cross-site browser requests
	h = securityHeaders(h)
	h = logRequests(h)
	h = recoverPanics(h)
	return h
}

type credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type userResponse struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"createdAt"`
}

func toResponse(u User) userResponse {
	return userResponse{ID: u.ID, Username: u.Username, CreatedAt: u.CreatedAt}
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if err := decodeJSON(w, r, &c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	c.Username = normalizeUsername(c.Username)
	if !usernameRE.MatchString(c.Username) {
		writeError(w, http.StatusBadRequest, "username must be 3-32 characters: a-z, 0-9, '_', '.', '-'")
		return
	}
	if len(c.Password) < minPassword || len(c.Password) > maxPassword {
		writeError(w, http.StatusBadRequest, "password must be 8-72 characters")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(c.Password), bcryptCost)
	if err != nil {
		s.internalError(w, r, "hash password", err)
		return
	}

	u, err := s.store.CreateUser(r.Context(), c.Username, hash)
	if errors.Is(err, ErrUserExists) {
		writeError(w, http.StatusConflict, "username is taken")
		return
	}
	if err != nil {
		s.internalError(w, r, "create user", err)
		return
	}

	slog.InfoContext(r.Context(), "user registered", "user_id", u.ID)
	writeJSON(w, http.StatusCreated, toResponse(u))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if err := decodeJSON(w, r, &c); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	u, err := s.store.GetUserByUsername(r.Context(), normalizeUsername(c.Username))
	if err != nil && !errors.Is(err, ErrNotFound) {
		s.internalError(w, r, "get user", err)
		return
	}
	hash := dummyHash
	if err == nil {
		hash = u.PasswordHash
	}
	// Always run bcrypt, and check both conditions, so failures look identical.
	if bcrypt.CompareHashAndPassword(hash, []byte(c.Password)) != nil || err != nil {
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	token, err := s.store.CreateSession(r.Context(), u.ID, s.cfg.SessionTTL)
	if err != nil {
		s.internalError(w, r, "create session", err)
		return
	}

	s.setSessionCookie(w, token, int(s.cfg.SessionTTL.Seconds()))
	writeJSON(w, http.StatusOK, toResponse(u))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := s.store.DeleteSession(r.Context(), c.Value); err != nil {
			s.internalError(w, r, "delete session", err)
			return
		}
	}
	s.setSessionCookie(w, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, toResponse(currentUser(r)))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		slog.WarnContext(r.Context(), "readiness check failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, op string, err error) {
	slog.ErrorContext(r.Context(), op, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func normalizeUsername(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("encode response", "err", err)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
