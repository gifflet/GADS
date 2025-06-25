package clientcredentials

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// CryptoService handles cryptographic operations for client credentials
type CryptoService struct {
	// Configurações podem ser adicionadas aqui se necessário no futuro
}

// NewCryptoService creates a new crypto service
func NewCryptoService() *CryptoService {
	return &CryptoService{}
}

// GenerateClientID generates a unique client ID
func (cs *CryptoService) GenerateClientID() (string, error) {
	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes for client ID: %w", err)
	}
	return "gads_" + base64.URLEncoding.EncodeToString(bytes)[:22], nil
}

// GenerateClientSecret generates a cryptographically secure client secret
func (cs *CryptoService) GenerateClientSecret() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes for client secret: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// HashSecret hashes a client secret for secure storage
func (cs *CryptoService) HashSecret(secret string) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("secret cannot be empty")
	}

	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash secret: %w", err)
	}
	return string(hashedBytes), nil
}

// ValidateSecret validates a secret against its hash using constant-time comparison
func (cs *CryptoService) ValidateSecret(secret, hash string) bool {
	if secret == "" || hash == "" {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret))
	return err == nil
}

// GenerateSecureToken generates a secure token of specified length
func (cs *CryptoService) GenerateSecureToken(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("token length must be positive")
	}

	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// SecureCompare performs constant-time comparison of two strings
func (cs *CryptoService) SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
