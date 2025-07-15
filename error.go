package jwtguard

import "errors"

// Custom errors of jwtGuard package
var (
	ErrDecodeAccessToken       = errors.New("failed to decode the jwt token")
	ErrNoExpirationAccessToken = errors.New("expirtion not set for access token")
	ErrExpiredAccessToken      = errors.New("access token expired")
	ErrUnexpectedSigningMethod = errors.New("unexpected token signing method")
	ErrInvalidTokenType        = errors.New("invalid token type")
	ErrInvalidToken            = errors.New("invalid token")
	ErrGenerateAccessToken     = errors.New("failed to generate new token")
	ErrMaxSessionsPerUser      = errors.New("too many active sessions")
	ErrEncodingMarshal         = errors.New("failed to encode target payload")
	ErrInvalidIP               = errors.New("invalid IP address")
	ErrExpiredRefreshToken     = errors.New("refresh token expired")
)
