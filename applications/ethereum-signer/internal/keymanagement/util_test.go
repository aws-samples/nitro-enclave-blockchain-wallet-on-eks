package keymanagement

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"os"
	"testing"
)

func TestProvideRSAKey(t *testing.T) {
	// Clean up environment variable after tests
	defer os.Unsetenv("RSA_PRIVATE_KEY")

	t.Run("ephemeral key generation", func(t *testing.T) {
		key, err := ProvideRSAKey(true)
		if err != nil {
			t.Errorf("Failed to generate ephemeral key: %v", err)
		}

		// Verify it's a valid RSA key by checking basic properties
		if key.Size() < 256 {
			t.Error("Generated key size is too small")
		}
	})

	t.Run("non-ephemeral key with empty env", func(t *testing.T) {
		os.Unsetenv("RSA_PRIVATE_KEY")

		key, err := ProvideRSAKey(false)
		if err != nil {
			t.Errorf("Failed to handle empty environment: %v", err)
		}
		if key == nil {
			t.Error("Expected non-nil key when environment variable is not set")
		}

		retrievedKey, err := ProvideRSAKey(false)
		if err != nil {
			t.Errorf("Failed to retrieve key from environment: %v", err)
		}
		if retrievedKey == nil {
			t.Error("Expected non-nil key from environment")
		}

		// Verify the retrieved key matches the original
		if !compareRSAPrivateKeys(key, retrievedKey) {
			t.Error("Retrieved key does not match original key")
		}

	})

	t.Run("non-ephemeral key with existing env", func(t *testing.T) {

		// Generate and store a test key in environment
		testKey, err := generateEphemeralRSAKey()
		if err != nil {
			t.Fatalf("Failed to generate test key: %v", err)
		}

		// Convert to DER and base64 encode
		derBytes := x509.MarshalPKCS1PrivateKey(testKey)
		encodedKey := base64.StdEncoding.EncodeToString(derBytes)

		// Set environment variable
		os.Setenv("RSA_PRIVATE_KEY", encodedKey)

		// Test key retrieval
		retrievedKey, err := ProvideRSAKey(false)
		if err != nil {
			t.Errorf("Failed to retrieve key from environment: %v", err)
		}
		if retrievedKey == nil {
			t.Error("Expected non-nil key from environment")
		}

		// Verify the retrieved key matches the original
		if !compareRSAPrivateKeys(testKey, retrievedKey) {
			t.Error("Retrieved key does not match original key")
		}
	})

	t.Run("non-ephemeral key with invalid env value", func(t *testing.T) {
		os.Setenv("RSA_PRIVATE_KEY", "invalid-key-data")

		_, err := ProvideRSAKey(false)
		if err == nil {
			t.Error("Expected error with invalid environment variable data")
		}
	})
}

// Helper function to compare two RSA private keys
func compareRSAPrivateKeys(key1, key2 *rsa.PrivateKey) bool {
	// Compare modulus and private exponent
	return key1.N.Cmp(key2.N) == 0 && key1.D.Cmp(key2.D) == 0
}
