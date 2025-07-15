package jwtguard

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AccessTokenPayload represents custom fields of access token payload like Sub,CreatedAt and TokenType.
type AccessTokenPayload struct {
	Sub       string    `json:"sub"`
	CreatedAt time.Time `json:"createdAt"`
	TokenType TokenType `json:"tokenType"`
}

// AccessTokenClaims represents all fields of claims in JWT include AccessTokenPayload.
type AccessTokenClaims struct {
	Payload AccessTokenPayload
	jwt.RegisteredClaims
}

// GenerateAccessToken makes a new access token for use in api or resources
func (j *jwtGuard) GenerateAccessToken(ctx context.Context, sub string, expiresAt time.Duration) (string, error) {
	if j.options.MaxSessionsPerUser > 0 {
		activeSessions, err := j.GetActiveAccessTokens(ctx, sub)
		if err != nil {
			return "", ErrGenerateAccessToken
		}
		if len(activeSessions) >= j.options.MaxSessionsPerUser {
			return "", ErrMaxSessionsPerUser
		}
	}

	now := time.Now()
	jti := uuid.NewString()

	claims := AccessTokenClaims{
		Payload: AccessTokenPayload{
			Sub:       sub,
			TokenType: AccessToken,
			CreatedAt: time.Now(),
		},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiresAt)),
			Issuer:    j.options.IssuerName,
			Subject:   sub,
		},
	}

	value := "1"
	err := j.redisClient.Set(ctx, generateAccessTokenKey(sub, jti), value, expiresAt).Err()
	if err != nil {
		return "", ErrGenerateAccessToken
	}

	token, err := jwt.NewWithClaims(TokenEncodingAlgorithm, claims).SignedString([]byte(j.options.SecretKey))
	if err != nil {
		return "", err
	}
	return token, nil
}

// DecodeAccessToken parses access token and returns AccessTokenClaims data.
func (j *jwtGuard) DecodeAccessToken(ctx context.Context, token string) (*AccessTokenClaims, error) {
	claims := &AccessTokenClaims{}
	jwtToken, err := jwt.ParseWithClaims(token, claims,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, ErrUnexpectedSigningMethod
			}

			return []byte(j.options.SecretKey), nil
		},
	)
	if err != nil {
		return nil, ErrDecodeAccessToken
	}

	expiration, err := jwtToken.Claims.GetExpirationTime()
	if err != nil || expiration == nil {
		return nil, ErrNoExpirationAccessToken
	}
	now := time.Now()
	if expiration.Time.Before(now) {
		return nil, ErrExpiredAccessToken
	}

	if jwtToken.Valid {
		if claims.Payload.TokenType != AccessToken {
			return nil, ErrInvalidTokenType
		}

		return claims, nil
	}

	return nil, ErrInvalidToken
}

// TerminateAccessToken deletes access token from redis.
func (j *jwtGuard) TerminateAccessToken(ctx context.Context, sub string, jti string) error {
	_, err := j.redisClient.Del(ctx, generateAccessTokenKey(sub, jti)).Result()
	if err != nil {
		return err
	}
	return nil
}

// TerminateAccessToken deletes all access token from redis based on sub(UUID or user id or any key).
func (j *jwtGuard) TerminateAllAccessTokens(ctx context.Context, sub string) error {
	var cursor uint64 = 0
	var batchSize int64 = 100
	pattern := fmt.Sprintf("session:%s:*", sub)

	for {
		keys, nextCursor, err := j.redisClient.Scan(ctx, cursor, pattern, batchSize).Result()
		if err != nil {
			return err
		}

		if len(keys) > 0 {
			if err := j.redisClient.Del(ctx, keys...).Err(); err != nil {
				return err
			}
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
	return nil
}

// GetActiveAccessTokens returns all active sessions in redis based on sub(UUID or user id or any key).
func (j *jwtGuard) GetActiveAccessTokens(ctx context.Context, sub string) ([]string, error) {
	var cursor uint64
	var batchSize int64 = 100
	var sessions []string

	pattern := fmt.Sprintf("session:%s:*", sub)

	for {
		keys, newCursor, err := j.redisClient.Scan(ctx, cursor, pattern, batchSize).Result()
		if err != nil {
			return nil, err
		}

		for _, key := range keys {
			parts := strings.Split(key, ":")
			if len(parts) == 3 {
				sessions = append(sessions, parts[2])
			}
		}
		cursor = newCursor
		if cursor == 0 {
			break
		}
	}

	return sessions, nil
}

// generateAccessTokenKey makes access token key for use in functions
func generateAccessTokenKey(sub, jti string) string {
	return fmt.Sprintf("session:%s:%s", sub, jti)
}
