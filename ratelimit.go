package main

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter is a per-IP token bucket. State is in memory, so each instance
// limits independently; use a shared store (e.g. Redis) when running several.
type RateLimiter struct {
	mu         sync.Mutex
	clients    map[string]*clientLimiter
	limit      rate.Limit
	burst      int
	trustProxy bool
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func NewRateLimiter(ctx context.Context, limit rate.Limit, burst int, trustProxy bool) *RateLimiter {
	rl := &RateLimiter{
		clients:    make(map[string]*clientLimiter),
		limit:      limit,
		burst:      burst,
		trustProxy: trustProxy,
	}
	go rl.cleanup(ctx)
	return rl
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	c, ok := rl.clients[key]
	if !ok {
		c = &clientLimiter{limiter: rate.NewLimiter(rl.limit, rl.burst)}
		rl.clients[key] = c
	}
	c.lastSeen = time.Now()
	return c.limiter.Allow()
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(clientIP(r, rl.trustProxy)) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cleanup evicts idle clients so the map doesn't grow without bound.
func (rl *RateLimiter) cleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.mu.Lock()
			for key, c := range rl.clients {
				if time.Since(c.lastSeen) > 5*time.Minute {
					delete(rl.clients, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}

func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		// The last entry is the one appended by our own proxy; earlier
		// entries are client-controlled and can be spoofed.
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
