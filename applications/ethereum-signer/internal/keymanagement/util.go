package keymanagement

import (
	"aws/ethereum-signer/internal/types"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
)

func ProvideRSAKey(ephemeral bool) (*rsa.PrivateKey, error) {
	var privateKey *rsa.PrivateKey
	var err error
	if !ephemeral {
		// check if key stored in env, if yes - load, unmarshal
		// if not set, run key creation script write to env and return key
		privateKey, err = loadPrivateKeyFromEnv()
		if err != nil {
			return nil, fmt.Errorf("failed to load private key from environment: %w", err)
		}

	} else {
		privateKey, err = generateEphemeralRSAKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral RSA key: %w", err)
		}
	}

	return privateKey, nil
}

func DeriveDEREncodedPublicKey(privateKey *rsa.PrivateKey) ([]byte, error) {
	publicKey := privateKey.PublicKey

	publicKeyDER, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return nil, err
	}

	return publicKeyDER, nil
}

func loadPrivateKeyFromEnv() (*rsa.PrivateKey, error) {
	// get the base64-encoded DER private key from environment variable
	privateKeyBase64 := os.Getenv("RSA_PRIVATE_KEY")

	// if privateKey is empty, run RSA key generation - serialize the key and store in env, return private key
	if privateKeyBase64 == "" {
		log.Infof("RSA_PRIVATE_KEY environment variable is not set. Generating ephemeral RSA key...")
		privateKey, err := generateEphemeralRSAKey()
		if err != nil {
			return nil, err
		}

		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyBase64 = base64.StdEncoding.EncodeToString(privateKeyBytes)
		err = os.Setenv("RSA_PRIVATE_KEY", privateKeyBase64)
		if err != nil {
			return nil, err
		}
	}

	// decode the base64 string to get DER bytes
	derBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return nil, errors.New("failed to decode base64 private key")
	}

	// parse the private key from DER format
	privateKey, err := x509.ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func generateEphemeralRSAKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func ParsePlaintext(kmsResultB64 string) (types.PlainKey, error) {
	log.Debugf("raw kmsResultB64: %v", kmsResultB64)

	kmsResult, err := base64.StdEncoding.DecodeString(kmsResultB64)
	if err != nil {
		return types.PlainKey{}, fmt.Errorf("failed to decode kmsResultB64: %v", err)
	}

	var userKey types.PlainKey

	err = json.Unmarshal(kmsResult, &userKey)
	if err != nil {
		return types.PlainKey{}, fmt.Errorf("failed to unmarshal kmsResult: %v", err)
	}

	return userKey, nil
}
