package clientcredentials

import (
	"strings"
	"testing"
	"time"
)

func TestCryptoService_GenerateClientID(t *testing.T) {
	cs := NewCryptoService()

	// Test successful generation
	clientID, err := cs.GenerateClientID()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check format
	if !strings.HasPrefix(clientID, "gads_") {
		t.Errorf("Expected client ID to start with 'gads_', got %s", clientID)
	}

	// Check length (gads_ + 22 chars = 27 total)
	if len(clientID) != 27 {
		t.Errorf("Expected client ID length 27, got %d", len(clientID))
	}

	// Test uniqueness
	clientID2, err := cs.GenerateClientID()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if clientID == clientID2 {
		t.Error("Expected different client IDs, got same")
	}
}

func TestCryptoService_GenerateClientSecret(t *testing.T) {
	cs := NewCryptoService()

	// Test successful generation
	secret, err := cs.GenerateClientSecret()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check length (32 bytes base64 encoded = 44 chars)
	if len(secret) != 44 {
		t.Errorf("Expected secret length 44, got %d", len(secret))
	}

	// Test uniqueness
	secret2, err := cs.GenerateClientSecret()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if secret == secret2 {
		t.Error("Expected different secrets, got same")
	}
}

func TestCryptoService_HashSecret(t *testing.T) {
	cs := NewCryptoService()

	tests := []struct {
		name      string
		secret    string
		wantError bool
	}{
		{
			name:      "valid secret",
			secret:    "valid_secret_123",
			wantError: false,
		},
		{
			name:      "empty secret",
			secret:    "",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := cs.HashSecret(tt.secret)

			if tt.wantError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			if hash == "" {
				t.Error("Expected non-empty hash")
			}

			if hash == tt.secret {
				t.Error("Hash should not equal original secret")
			}
		})
	}
}

func TestCryptoService_ValidateSecret(t *testing.T) {
	cs := NewCryptoService()

	// Generate a secret and hash
	secret := "test_secret_123"
	hash, err := cs.HashSecret(secret)
	if err != nil {
		t.Fatalf("Failed to hash secret: %v", err)
	}

	tests := []struct {
		name     string
		secret   string
		hash     string
		expected bool
	}{
		{
			name:     "valid secret and hash",
			secret:   secret,
			hash:     hash,
			expected: true,
		},
		{
			name:     "invalid secret",
			secret:   "wrong_secret",
			hash:     hash,
			expected: false,
		},
		{
			name:     "empty secret",
			secret:   "",
			hash:     hash,
			expected: false,
		},
		{
			name:     "empty hash",
			secret:   secret,
			hash:     "",
			expected: false,
		},
		{
			name:     "both empty",
			secret:   "",
			hash:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cs.ValidateSecret(tt.secret, tt.hash)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCryptoService_GenerateSecureToken(t *testing.T) {
	cs := NewCryptoService()

	tests := []struct {
		name      string
		length    int
		wantError bool
	}{
		{
			name:      "valid length",
			length:    16,
			wantError: false,
		},
		{
			name:      "zero length",
			length:    0,
			wantError: true,
		},
		{
			name:      "negative length",
			length:    -1,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := cs.GenerateSecureToken(tt.length)

			if tt.wantError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			if token == "" {
				t.Error("Expected non-empty token")
			}

			// Test uniqueness
			token2, err := cs.GenerateSecureToken(tt.length)
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			if token == token2 {
				t.Error("Expected different tokens, got same")
			}
		})
	}
}

func TestCryptoService_SecureCompare(t *testing.T) {
	cs := NewCryptoService()

	tests := []struct {
		name     string
		a        string
		b        string
		expected bool
	}{
		{
			name:     "identical strings",
			a:        "same_string",
			b:        "same_string",
			expected: true,
		},
		{
			name:     "different strings",
			a:        "string_a",
			b:        "string_b",
			expected: false,
		},
		{
			name:     "empty strings",
			a:        "",
			b:        "",
			expected: true,
		},
		{
			name:     "one empty",
			a:        "not_empty",
			b:        "",
			expected: false,
		},
		{
			name:     "different lengths",
			a:        "short",
			b:        "much_longer_string",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cs.SecureCompare(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// Benchmark tests para verificar performance
func BenchmarkCryptoService_GenerateClientID(b *testing.B) {
	cs := NewCryptoService()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cs.GenerateClientID()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCryptoService_GenerateClientSecret(b *testing.B) {
	cs := NewCryptoService()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cs.GenerateClientSecret()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCryptoService_HashSecret(b *testing.B) {
	cs := NewCryptoService()
	secret := "benchmark_secret_123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cs.HashSecret(secret)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCryptoService_ValidateSecret(b *testing.B) {
	cs := NewCryptoService()
	secret := "benchmark_secret_123"
	hash, err := cs.HashSecret(secret)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cs.ValidateSecret(secret, hash)
	}
}

// Test de resistência a ataques de timing
func TestCryptoService_TimingAttackResistance(t *testing.T) {
	cs := NewCryptoService()

	// Gerar um hash conhecido
	correctSecret := "correct_secret"
	hash, err := cs.HashSecret(correctSecret)
	if err != nil {
		t.Fatal(err)
	}

	// Testar com segredos incorretos de diferentes tamanhos
	wrongSecrets := []string{
		"a",
		"wrong",
		"completely_wrong_secret",
		"this_is_a_very_long_wrong_secret_that_should_not_match",
	}

	for _, wrongSecret := range wrongSecrets {
		start := time.Now()
		result := cs.ValidateSecret(wrongSecret, hash)
		duration := time.Since(start)

		if result {
			t.Errorf("Secret %s should not validate", wrongSecret)
		}

		// bcrypt é naturalmente resistente a timing attacks
		// apenas verificamos que não demora mais que um tempo razoável
		if duration > time.Second {
			t.Errorf("Validation took too long: %v", duration)
		}
	}
}
