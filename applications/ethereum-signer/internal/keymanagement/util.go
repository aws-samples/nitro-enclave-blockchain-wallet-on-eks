package keymanagement

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
)

func GenerateEphemeralRSAKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
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
