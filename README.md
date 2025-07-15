# jwtguard ⚡

![GitHub Release](https://img.shields.io/github/v/release/pooulad/jwtguard)

<img src="./assets/logo.png" alt="jwtguard_logo" width="150" />

<br />

`jwtguard` is a lightweight JWT-based authentication and session management package in Go that supports:

- Access & Refresh Token generation

- Token decoding & validation

- Session-limited access token management

- Refresh token revocation & IP/device binding

- Redis-based session storage

## Features

- 🔐 Access/Refresh token separation

- 📦 Redis-backed session store

- 🧠 Max concurrent session control per user

- 🧹 Fine-grained session/token revocation

- ⚡ Stateless access tokens

- 🛡️ IP/User-Agent checks on refresh

---

## Installation

```bash
go get github.com/pooulad/jwtguard@latest
```

## Redis Dependency

This package uses Redis for storing refresh tokens and access session tracking. Ensure Redis is running and accessible.

### Getting Started

```go
package main

import (
"context"
"log"
"time"
"jwtguard"
"github.com/redis/go-redis/v9"
)

func main() {
    redisClient := redis.NewClient(&redis.Options{
    Addr: "localhost:6379",
    DB:   0,
    })

    jwtGuard := jwtguard.New(redisClient, jwtguard.JwtGuardOptions{
    SecretKey:          "your-very-secure-secret-key-from-env",
    MaxSessionsPerUser: 5,
    RefreshTokenTTL:    30 * 24 * time.Hour, // default is 720h
    IssuerName:         "your-app-name",
    })

    // Generate a refresh token for a user
    refreshToken, err := jwtGuard.GenerateRefreshToken(context.Background(), &jwtguard.RefreshTokenPayload{
        IP:        "192.168.11.11",
        Sub:       "userid",   // Subject/user ID
        UserAgent: "Mozilla",  // User agent for security context
        IssuedAt:  time.Now(), // Token issue time
    }, time.Hour) // Custom expiration
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("refresh token generated: %s", refreshToken)
}
```

See full [example](/example/main.go).

## Documentation 📋

[![Go Reference](https://pkg.go.dev/badge/github.com/pooulad/jwtguard.svg)](https://pkg.go.dev/github.com/pooulad/jwtguard)

Check latest version please.

## Security Notes

Ensure your SecretKey is long and unpredictable.

Always pass correct IP and User-Agent for secure refreshes.

Rotate secrets periodically if needed.

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for more information.

## Author

Built with ❤️ by [Pooulad](https://github.com/pooulad)
