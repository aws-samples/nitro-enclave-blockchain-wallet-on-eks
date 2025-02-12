package keymanagement

import (
	"aws/ethereum-signer/internal/types"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"os"
	"reflect"
	"strings"
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

func TestParsePlaintext(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		want        types.PlainKey
		wantErr     bool
		errContains string
	}{
		{
			name:  "valid plaintext",
			input: base64.StdEncoding.EncodeToString([]byte(`{"secret": "secret", "eth_key": "eth_key"}`)),
			want: types.PlainKey{Secret: "secret",
				EthKey: "eth_key"},
			wantErr: false,
		},
		{
			name:        "invalid base64",
			input:       "invalid-base64!@#$",
			want:        types.PlainKey{},
			wantErr:     true,
			errContains: "failed to decode kmsResultB64",
		},
		{
			name:        "invalid json",
			input:       base64.StdEncoding.EncodeToString([]byte(`{invalid-json}`)),
			want:        types.PlainKey{},
			wantErr:     true,
			errContains: "failed to unmarshal kmsResult",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePlaintext(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParsePlaintext() error = nil, wantErr %v", tt.wantErr)
					return
				}
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ParsePlaintext() error = %v, want error containing %v", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ParsePlaintext() unexpected error = %v", err)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePlaintext() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function to compare two RSA private keys
func compareRSAPrivateKeys(key1, key2 *rsa.PrivateKey) bool {
	// Compare modulus and private exponent
	return key1.N.Cmp(key2.N) == 0 && key1.D.Cmp(key2.D) == 0
}
