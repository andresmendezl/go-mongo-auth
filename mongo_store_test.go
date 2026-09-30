package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Integration test. Runs only when TEST_MONGODB_URI is set, against a
// throwaway database that is dropped afterwards.
func newTestMongoStore(t *testing.T) *MongoStore {
	t.Helper()
	uri := os.Getenv("TEST_MONGODB_URI")
	if uri == "" {
		t.Skip("TEST_MONGODB_URI not set")
	}
	dbName := "authtest_" + strings.ToLower(bson.NewObjectID().Hex())
	s, err := NewMongoStore(t.Context(), uri, dbName)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.client.Database(dbName).Drop(ctx)
		_ = s.Close(ctx)
	})
	return s
}

func TestMongoStore(t *testing.T) {
	s := newTestMongoStore(t)
	ctx := t.Context()

	u, err := s.CreateUser(ctx, "andres", []byte("hash"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateUser(ctx, "andres", []byte("hash")); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate: got %v, want ErrUserExists", err)
	}
	if _, err := s.GetUserByUsername(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user: got %v, want ErrNotFound", err)
	}

	token, err := s.CreateSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.SessionUser(ctx, token)
	if err != nil || got.ID != u.ID {
		t.Fatalf("SessionUser: got %v, %v", got, err)
	}

	// The raw token must never be stored.
	n, err := s.sessions.CountDocuments(ctx, bson.D{{Key: "_id", Value: token}})
	if err != nil || n != 0 {
		t.Fatalf("raw token found in database (n=%d, err=%v)", n, err)
	}

	if err := s.DeleteSession(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionUser(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: got %v, want ErrNotFound", err)
	}

	expired, err := s.CreateSession(ctx, u.ID, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionUser(ctx, expired); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session: got %v, want ErrNotFound", err)
	}
}
