package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Addr         string
	MongoURI     string
	MongoDB      string
	SessionTTL   time.Duration
	CookieSecure bool // must be true in production (HTTPS)
	TrustProxy   bool // read client IP from X-Forwarded-For; only enable behind a trusted proxy
}

func LoadConfig() (Config, error) {
	cfg := Config{
		Addr:         getenv("ADDR", ":8080"),
		MongoURI:     os.Getenv("MONGODB_URI"),
		MongoDB:      getenv("MONGODB_DB", "auth"),
		SessionTTL:   24 * time.Hour,
		CookieSecure: true,
	}
	if cfg.MongoURI == "" {
		return cfg, errors.New("MONGODB_URI is required")
	}

	var err error
	if v := os.Getenv("SESSION_TTL"); v != "" {
		if cfg.SessionTTL, err = time.ParseDuration(v); err != nil {
			return cfg, fmt.Errorf("SESSION_TTL: %w", err)
		}
	}
	if cfg.CookieSecure, err = getbool("COOKIE_SECURE", true); err != nil {
		return cfg, err
	}
	if cfg.TrustProxy, err = getbool("TRUST_PROXY", false); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getbool(key string, fallback bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return b, nil
}
