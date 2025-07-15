package jwtguard

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// RefreshTokenPayload represents fields of refresh token payload like IP,Sub,etc...
type RefreshTokenPayload struct {
	IP        string    `json:"IP"`
	Sub       string    `json:"sub"`
	UserAgent string    `json:"userAgent"`
	IssuedAt  time.Time `json:"issuedAt"`
	TokenType TokenType `json:"tokenType"`
}

// GenerateRefreshToken makes a new refresh token.
func (j *jwtGuard) GenerateRefreshToken(ctx context.Context, payload *RefreshTokenPayload, expiresAt time.Duration) (string, error) {
	refreshToken, err := generateRandomString(RefreshTokenByteLength)
	if err != nil {
		return "", err
	}

	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return "", ErrEncodingMarshal
	}

	err = j.redisClient.HSet(ctx, generateRefreshTokenHashKey(payload.Sub), []string{
		refreshToken, string(payloadJson),
	}).Err()
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}

// DecodeRefreshToken decodes refresh token and returns RefreshTokenPayload data.
func (j *jwtGuard) DecodeRefreshToken(ctx context.Context, sub string, refreshToken string) (*RefreshTokenPayload, error) {
	payloadStr, err := j.redisClient.HGet(ctx, generateRefreshTokenHashKey(sub), refreshToken).Result()
	if err != nil {
		return nil, ErrInvalidToken
	}

	var payload *RefreshTokenPayload

	err = json.Unmarshal([]byte(payloadStr), &payload)
	if err != nil {
		return nil, ErrInvalidToken
	}

	return payload, nil
}

// TerminateRefreshToken deletes refresh token from redis.
func (j *jwtGuard) TerminateRefreshToken(ctx context.Context, sub string, refreshToken string) error {
	_, err := j.redisClient.HDel(ctx, generateRefreshTokenHashKey(sub), refreshToken).Result()
	if err != nil {
		return err
	}
	return nil
}

// RefreshAccessToken deletes old access token and makes new one for use in api and other resources.
func (j *jwtGuard) RefreshAccessToken(ctx context.Context, sub string, refreshToken string, accessToken string, ip string) (string, error) {
	payload, err := j.DecodeRefreshToken(ctx, sub, refreshToken)
	if err != nil {
		return "", err
	}

	if payload.IP != ip {
		return "", ErrInvalidIP
	}

	expiredAt := payload.IssuedAt.Add(j.options.RefreshTokenTTL)
	if time.Now().After(expiredAt) {
		return "", ErrExpiredRefreshToken
	}

	claims, err := j.DecodeAccessToken(ctx, accessToken)
	if err != nil {
		return "", err
	}

	err = j.TerminateAccessToken(ctx, sub, claims.ID)
	if err != nil {
		return "", err
	}

	token, err := j.GenerateAccessToken(ctx, sub, time.Hour)
	if err != nil {
		return "", err
	}
	return token, nil
}

// generateRefreshTokenHashKey makes refresh token key for use in functions
func generateRefreshTokenHashKey(sub string) string {
	return fmt.Sprintf("refresh:%s", sub)
}
