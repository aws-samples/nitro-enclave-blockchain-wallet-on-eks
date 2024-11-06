package keymanagement

import (
	"aws/ethereum-signer/internal/attestation"
	aws2 "aws/ethereum-signer/internal/aws"
	"aws/ethereum-signer/internal/types"
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/pkcs7"
	"golang.org/x/net/context"
	"time"
)

// todo move type definition to outside
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type keyTransRecipientInfo struct {
	Version                int
	Rid                    asn1.RawValue `asn1:"choice"`
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

// parse the EnvelopedData structure
type envelopedDataStruct struct {
	Version              int
	RecipientInfos       []keyTransRecipientInfo `asn1:"set"`
	EncryptedContentInfo struct {
		ContentType                asn1.ObjectIdentifier
		ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
		EncryptedContent           []byte `asn1:"explicit,tag:0"`
	}
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

func DecryptCiphertextWithAttestation(credentials types.AWSCredentials, ciphertextB64 string, vsockBasePort uint32, region string, encryptionContext map[string]string) (string, error) {

	// create ephemeral private/public key for communication with KMS
	keyGenerationStart := time.Now()
	ephemeralKey, err := GenerateEphemeralRSAKey()
	if err != nil {
		return "", err
	}
	derPublicKey, err := DeriveDEREncodedPublicKey(ephemeralKey)
	if err != nil {
		return "", err
	}
	keyGenerationEnd := time.Since(keyGenerationStart).Milliseconds()
	log.Debugf("ephemeral key generation took %v ms", keyGenerationEnd)

	// include ephemeral public key in attestation doc and thus provide key to KMS for CMS encryption (RFC5652 section 6)
	// nonce and userData is not required/processed by KMS
	attestationStart := time.Now()
	attestationDocument, err := attestation.GetAttestationDoc(nil, nil, derPublicKey)
	if err != nil {
		log.Errorf("failed to get attestation document: %v", err)
		return "", err
	}
	attestationEnd := time.Since(attestationStart).Milliseconds()
	log.Debugf("attestation document generation took %v ms", attestationEnd)

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		log.Errorf("failed to decode ciphertext: %v", err)
		return "", err
	}

	configGenerationStart := time.Now()
	config, err := aws2.EnclaveSDKConfig(credentials, region, aws2.NewConnectionConfig(aws2.VSOCK, 3, vsockBasePort))
	if err != nil {
		return "", err
	}
	configGenerationEnd := time.Since(configGenerationStart).Milliseconds()
	log.Debugf("aws config generation took %v ms", configGenerationEnd)

	// send decrypt request to KMS including the attestation doc
	kmsRequestStart := time.Now()
	ciphertextForRecipient, err := decryptCiphertextWithAttestation(config, ciphertext, attestationDocument, encryptionContext)
	if err != nil {
		return "", err
	}
	kmsRequestEnd := time.Since(kmsRequestStart).Milliseconds()
	log.Debugf("kms request took %v ms", kmsRequestEnd)

	// any value in providing openssl based solution here?
	decryptRecipientCiphertext := time.Now()
	resultPlaintext, err := decryptCiphertextForRecipient(ciphertextForRecipient, ephemeralKey)
	if err != nil {
		return "", err
	}
	resultPlaintextB64 := base64.StdEncoding.EncodeToString(resultPlaintext)
	decryptRecipientCiphertextEnd := time.Since(decryptRecipientCiphertext).Milliseconds()
	log.Debugf("decrypt recipient ciphertext took %v ms", decryptRecipientCiphertextEnd)
	log.Debugf("plaintext result b64: %v", resultPlaintextB64)

	return resultPlaintextB64, nil
}

func decryptCiphertextWithAttestation(cfg aws.Config, ciphertext []byte, attestation []byte, encryptionContext map[string]string) ([]byte, error) {

	kmsClient := kms.NewFromConfig(cfg)

	kmsResponse, err := kmsClient.Decrypt(context.TODO(), &kms.DecryptInput{
		CiphertextBlob:    ciphertext,
		EncryptionContext: encryptionContext,
		Recipient: &kmstypes.RecipientInfo{
			AttestationDocument:    attestation,
			KeyEncryptionAlgorithm: "RSAES_OAEP_SHA_256",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("exception happened decrypting payload via KMS: %s", err)
	}

	return kmsResponse.CiphertextForRecipient, nil
}

func decryptRecipientInfo(encryptedKey []byte, privateKey *rsa.PrivateKey) ([]byte, error) {

	hash := crypto.SHA256

	// decrypt the encrypted key using RSAES-OAEP
	decryptedKey, err := rsa.DecryptOAEP(
		hash.New(),
		rand.Reader,
		privateKey,
		encryptedKey,
		[]byte{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %v", err)
	}

	return decryptedKey, nil
}

func decryptCiphertextForRecipient(envelopedData []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	// parse the CMS structure
	der, err := pkcs7.Ber2der(envelopedData)
	if err != nil {
		return nil, err
	}
	var info contentInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("failed to parse CMS: %v", err)
	}

	var ed envelopedDataStruct
	if _, err := asn1.Unmarshal(info.Content.Bytes, &ed); err != nil {
		return nil, fmt.Errorf("failed to parse EnvelopedData: %v", err)
	}
	log.Debugf("encrypted key: %v", hex.EncodeToString(ed.RecipientInfos[0].EncryptedKey))

	// decrypt the content encryption key
	contentEncryptionKey, err := decryptRecipientInfo(
		ed.RecipientInfos[0].EncryptedKey,
		privateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt content encryption key: %v", err)
	}
	log.Debugf("content encryption key: %v", hex.EncodeToString(contentEncryptionKey))

	block, err := aes.NewCipher(contentEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cipher block: %v", err)
	}
	mode := cipher.NewCBCDecrypter(block, ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.Bytes) //#nosec G407 passing fixed IV token from envelope

	plaintext := make([]byte, len(ed.EncryptedContentInfo.EncryptedContent))
	mode.CryptBlocks(plaintext, ed.EncryptedContentInfo.EncryptedContent)

	length := len(plaintext)

	if length%block.BlockSize() != 0 {
		log.Printf("pkcs7: Data is not block-aligned")
	}
	padLen := int(plaintext[length-1])
	ref := bytes.Repeat([]byte{byte(padLen)}, padLen)
	if padLen > block.BlockSize() || padLen == 0 || !bytes.HasSuffix(plaintext, ref) {
		log.Printf("pkcs7: Invalid padding")
	}

	return plaintext[:length-padLen], nil
}
