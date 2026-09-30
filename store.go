package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrUserExists = errors.New("user already exists")
	ErrNotFound   = errors.New("not found")
)

type User struct {
	ID           string
	Username     string
	PasswordHash []byte
	CreatedAt    time.Time
}

// Store is the persistence layer. Handlers depend on this interface, not on
// MongoDB directly, so the database can be swapped or faked in tests.
type Store interface {
	CreateUser(ctx context.Context, username string, passwordHash []byte) (User, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	// CreateSession returns the raw token to hand to the client. Only its
	// hash is persisted.
	CreateSession(ctx context.Context, userID string, ttl time.Duration) (string, error)
	// SessionUser returns the owner of a valid, unexpired session.
	SessionUser(ctx context.Context, token string) (User, error)
	DeleteSession(ctx context.Context, token string) error
	Ping(ctx context.Context) error
}

// hashToken lets us store session IDs without storing the tokens themselves,
// so a database leak can't be used to hijack sessions.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
