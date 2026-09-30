# go-mongo-auth

Session-based authentication service in Go, backed by MongoDB. Standard library HTTP server, no framework.

## Features

- Register, login, logout, and a protected `/me` endpoint
- Passwords hashed with bcrypt (cost 12); constant-time login failures that don't reveal whether a username exists
- Opaque session tokens in `HttpOnly`, `SameSite=Lax` cookies; only a SHA-256 hash of each token is stored
- Session expiry enforced on lookup and cleaned up by a MongoDB TTL index
- Per-IP rate limiting on login and register
- CSRF protection via Go's `http.CrossOriginProtection`
- Strict JSON input (size cap, unknown fields rejected, username validation)
- Structured JSON logging, panic recovery, security headers
- Liveness (`/healthz`) and readiness (`/readyz`, pings MongoDB) probes
- Graceful shutdown on `SIGINT`/`SIGTERM`

## API

| Method | Path        | Body                                  | Success                |
|--------|-------------|---------------------------------------|------------------------|
| POST   | `/register` | `{"username": "...", "password": "..."}` | `201` user             |
| POST   | `/login`    | `{"username": "...", "password": "..."}` | `200` user + cookie    |
| POST   | `/logout`   | —                                     | `204`                  |
| GET    | `/me`       | — (session cookie)                    | `200` user             |
| GET    | `/healthz`  | —                                     | `200`                  |
| GET    | `/readyz`   | —                                     | `200` / `503`          |

Errors are returned as `{"error": "message"}`.

Usernames are case-insensitive, 3–32 characters of `a-z 0-9 _ . -`. Passwords are 8–72 characters.

## Running locally

Requires Go 1.27+ and a MongoDB instance.

```sh
MONGODB_URI=mongodb://localhost:27017 COOKIE_SECURE=false go run .
```

```sh
curl -X POST localhost:8080/register -d '{"username":"alice","password":"supersecret"}'
curl -c cookies.txt -X POST localhost:8080/login -d '{"username":"alice","password":"supersecret"}'
curl -b cookies.txt localhost:8080/me
```

### Docker

```sh
docker build -t go-mongo-auth .
docker run -p 8080:8080 -e MONGODB_URI=mongodb://host.docker.internal:27017 go-mongo-auth
```

## Configuration

| Variable        | Default  | Description                                                              |
|-----------------|----------|--------------------------------------------------------------------------|
| `MONGODB_URI`   | —        | **Required.** MongoDB connection string                                  |
| `MONGODB_DB`    | `auth`   | Database name                                                            |
| `ADDR`          | `:8080`  | Listen address                                                           |
| `SESSION_TTL`   | `24h`    | Session lifetime (Go duration)                                           |
| `COOKIE_SECURE` | `true`   | Set the cookie `Secure` flag. Only disable for local HTTP development    |
| `TRUST_PROXY`   | `false`  | Use `X-Forwarded-For` for client IPs. Only enable behind a trusted proxy |

## Testing

```sh
go test ./...                                                  # unit tests
TEST_MONGODB_URI=mongodb://localhost:27017 go test -race ./... # + MongoDB integration tests
```

Integration tests use a randomly named database and drop it afterwards.

## Project layout

| File              | Purpose                                         |
|-------------------|-------------------------------------------------|
| `main.go`         | Startup, HTTP server, graceful shutdown         |
| `config.go`       | Environment configuration                       |
| `store.go`        | `Store` interface and shared types              |
| `mongo_store.go`  | MongoDB implementation and indexes              |
| `handlers.go`     | Routes and HTTP handlers                        |
| `middleware.go`   | Auth, logging, panic recovery, security headers |
| `ratelimit.go`    | Per-IP rate limiter                             |

## Limitations

- Rate limiting is in-memory, so limits are per instance. Use a shared store such as Redis when running multiple replicas.
- No email verification, password reset, or account lockout yet.
