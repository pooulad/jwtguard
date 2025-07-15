// Sample usage of the jwtguard package.
//
// This example demonstrates how to use the jwtguard package to:
// - Generate and decode refresh tokens
// - Generate and decode access tokens
// - Enforce session limits per user
// - Refresh an access token using a valid refresh token
// - Retrieve active access tokens for a user
// - Terminate individual and all access tokens
// - Terminate a specific refresh token
//
// It uses Redis as the backing store for managing session state and token metadata.

package main

import (
	"context"
	"github.com/pooulad/jwtguard"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

func main() {
	// Initialize Redis client
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   0,
	})

	// Initialize the jwtguard package with custom configuration
	jwtGuard := jwtguard.New(redisClient, jwtguard.JwtGuardOptions{
		SecretKey:          "secretkey_from_env_file_t1'Oh~)XEMb[c0@vfCm{wtmK-Vz9fbQMDeKGf,H}q;88dKVq~$", // Load from env file in production
		MaxSessionsPerUser: 5,                                                                            // Limit number of active sessions per user
		RefreshTokenTTL:    30 * 24 * time.Hour,                                                          // Time-to-live for refresh tokens
		IssuerName:         "testpackage",                                                                // Name of issuer included in access token claims
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

	// Decode the refresh token to inspect payload
	payload, err := jwtGuard.DecodeRefreshToken(context.Background(), "userid", refreshToken)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("refresh token decoded: %+v", payload)

	// Generate a new access token for the same user
	accessToken, err := jwtGuard.GenerateAccessToken(context.Background(), "userid", time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("access token generated: %s", accessToken)

	// Decode access token and inspect claims
	accessTokenClaims, err := jwtGuard.DecodeAccessToken(context.Background(), accessToken)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("access token decoded: %+v", accessTokenClaims)

	// Retrieve all active access token session IDs for the user
	sessions, err := jwtGuard.GetActiveAccessTokens(context.Background(), "userid")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("all access tokens: %s", sessions)

	// Use refresh token and old access token to generate a new access token
	newAccessToken, err := jwtGuard.RefreshAccessToken(context.Background(), "userid", refreshToken, accessToken, "192.168.11.11")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("new access token generated: %s", newAccessToken)

	// Terminate a specific access token (by session ID/JTI)
	err = jwtGuard.TerminateAccessToken(context.Background(), "userid", newAccessToken)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("access token terminated")

	// Terminate a specific refresh token
	err = jwtGuard.TerminateRefreshToken(context.Background(), "userid", refreshToken)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("refresh token terminated")

	// Terminate all access tokens associated with a user
	err = jwtGuard.TerminateAllAccessTokens(context.Background(), "userid")
	if err != nil {
		log.Fatal(err)
	}
	log.Print("all access tokens terminated")
}
