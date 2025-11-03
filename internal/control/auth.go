// Package control implements the control plane for Tunnelor connections.
// It handles PSK-based authentication, session management, and control message framing.
package control

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// PSKCache holds a decoded PSK to avoid repeated base64 decoding
// This optimization is particularly important for high-throughput scenarios
// where HMAC computation happens frequently
type PSKCache struct {
	keyBytes []byte
}

// NewPSKCache creates a new PSK cache from a base64-encoded PSK
func NewPSKCache(pskBase64 string) (*PSKCache, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(pskBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PSK: %w", err)
	}
	return &PSKCache{keyBytes: keyBytes}, nil
}

// ComputeHMAC computes HMAC-SHA256 using the cached key bytes
func (c *PSKCache) ComputeHMAC(message string) string {
	h := hmac.New(sha256.New, c.keyBytes)
	h.Write([]byte(message))
	mac := h.Sum(nil)
	return hex.EncodeToString(mac)
}

// VerifyHMAC verifies that the HMAC matches the expected value using the cached key
func (c *PSKCache) VerifyHMAC(message, expectedHMAC string) bool {
	computedHMAC := c.ComputeHMAC(message)
	// Use constant-time comparison to prevent timing attacks
	return hmac.Equal([]byte(computedHMAC), []byte(expectedHMAC))
}

// ComputeAuthHMAC computes the HMAC for authentication using the cached key
func (c *PSKCache) ComputeAuthHMAC(clientID, nonce string) string {
	payload := CreateAuthPayload(clientID, nonce)
	return c.ComputeHMAC(payload)
}

// VerifyAuthHMAC verifies the authentication HMAC using the cached key
func (c *PSKCache) VerifyAuthHMAC(clientID, nonce, hmacValue string) bool {
	payload := CreateAuthPayload(clientID, nonce)
	return c.VerifyHMAC(payload, hmacValue)
}

// GenerateNonce generates a random nonce for authentication
func GenerateNonce() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	return hex.EncodeToString(nonce), nil
}

// ComputeHMAC computes HMAC-SHA256 of the message using the given key
func ComputeHMAC(key, message string) (string, error) {
	// Decode base64 PSK
	keyBytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("failed to decode PSK: %w", err)
	}

	// Compute HMAC
	h := hmac.New(sha256.New, keyBytes)
	h.Write([]byte(message))
	mac := h.Sum(nil)

	return hex.EncodeToString(mac), nil
}

// VerifyHMAC verifies that the HMAC matches the expected value
func VerifyHMAC(key, message, expectedHMAC string) (bool, error) {
	// Compute HMAC
	computedHMAC, err := ComputeHMAC(key, message)
	if err != nil {
		return false, err
	}

	// Use constant-time comparison to prevent timing attacks
	return hmac.Equal([]byte(computedHMAC), []byte(expectedHMAC)), nil
}

// CreateAuthPayload creates the payload for HMAC computation
func CreateAuthPayload(clientID, nonce string) string {
	return clientID + "|" + nonce
}

// ComputeAuthHMAC computes the HMAC for authentication
func ComputeAuthHMAC(psk, clientID, nonce string) (string, error) {
	payload := CreateAuthPayload(clientID, nonce)
	return ComputeHMAC(psk, payload)
}

// VerifyAuthHMAC verifies the authentication HMAC
func VerifyAuthHMAC(psk, clientID, nonce, hmacValue string) (bool, error) {
	payload := CreateAuthPayload(clientID, nonce)
	return VerifyHMAC(psk, payload, hmacValue)
}
