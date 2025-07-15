package jwtguard

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

// TokenEncodingAlgorithm defines the algorithm used to sign JWT tokens.
// In this case, it uses HMAC with SHA-512 (HS512) for stronger security.
// This algorithm is symmetric, meaning the same secret is used for both signing and verification.
var TokenEncodingAlgorithm = jwt.SigningMethodHS512

// TokenType represents the type of token: Access or Refresh.
type TokenType int

const (
	// DefaultRefreshTokenTTL defines the default time-to-live for refresh tokens (30 days).
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour

	// DefaultMaxSessions specifies the default maximum number of active sessions per user.
	// -1 means unlimited sessions are allowed.
	DefaultMaxSessions = -1

	// RefreshTokenByteLength defines the length (in bytes) of generated refresh token strings.
	RefreshTokenByteLength = 32

	// AccessToken represents an access token used for short-term API access.
	AccessToken TokenType = iota

	// RefreshToken represents a refresh token used to obtain new access tokens after expiration.
	RefreshToken
)

// JwtGuarder defines the interface for JWT authentication management.
// It supports generating, decoding, and revoking access and refresh tokens,
// as well as managing active sessions per user.
type JwtGuarder interface {
	GenerateAccessToken(ctx context.Context, sub string, expiresAt time.Duration) (string, error)
	DecodeAccessToken(ctx context.Context, token string) (*AccessTokenClaims, error)
	GetActiveAccessTokens(ctx context.Context, sub string) ([]string, error)
	TerminateAccessToken(ctx context.Context, sub string, jti string) error
	TerminateAllAccessTokens(ctx context.Context, sub string) error
	GenerateRefreshToken(ctx context.Context, payload *RefreshTokenPayload, expiresAt time.Duration) (string, error)
	DecodeRefreshToken(ctx context.Context, sub string, refreshToken string) (*RefreshTokenPayload, error)
	RefreshAccessToken(ctx context.Context, sub string, refreshToken string, accessToken string, ip string) (string, error)
	TerminateRefreshToken(ctx context.Context, sub string, refreshToken string) error
}

// jwtGuard represents the JwtGuarder interface.
type jwtGuard struct {
	redisClient *redis.Client
	options     JwtGuardOptions
}

// JwtGuardOptions defines jwtGuard initial settings.
type JwtGuardOptions struct {
	SecretKey          string
	MaxSessionsPerUser int
	RefreshTokenTTL    time.Duration
	IssuerName         string
}

// New creates new jwtGuard interface based on redisClient and JwtGuardOptions in params.
func New(redisClient *redis.Client, options JwtGuardOptions) JwtGuarder {
	if options.MaxSessionsPerUser == 0 {
		options.MaxSessionsPerUser = DefaultMaxSessions
	}
	if options.RefreshTokenTTL == 0 {
		options.RefreshTokenTTL = DefaultRefreshTokenTTL
	}
	if options.IssuerName == "" {
		options.IssuerName = "jwtguard"
	}
	return &jwtGuard{
		redisClient: redisClient,
		options:     options,
	}
}
