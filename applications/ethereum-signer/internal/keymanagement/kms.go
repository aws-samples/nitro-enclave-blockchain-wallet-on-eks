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
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/pkcs7"
	"golang.org/x/net/context"
	"time"
)

// AdvancedDecOpts config struct for advanced decryption options
type AdvancedDecOpts struct {
	EncryptionContext   map[string]string
	KeyId               string
	EncryptionAlgorithm kmstypes.EncryptionAlgorithmSpec
	EphemeralRSAKey     bool // set to FALSE to use env based key persistence
}

// Interfaces for dependencies

type KMSProvider interface {
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
}

type AWSKMSProvider struct {
	client *kms.Client
}

func NewAWSKMSProvider(credentials types.AWSCredentials, region string, connectionType aws2.ConnectionType, contextId uint32, port uint32) (*AWSKMSProvider, error) {
	cfg, err := aws2.EnclaveSDKConfig(credentials, region, aws2.NewConnectionConfig(connectionType, contextId, port))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %v", err)
	}

	return &AWSKMSProvider{
		client: kms.NewFromConfig(cfg),
	}, nil
}

func (p *AWSKMSProvider) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	return p.client.Decrypt(ctx, params, optFns...)
}

func (p *AWSKMSProvider) Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	return p.client.Encrypt(ctx, params, optFns...)
}

func DecryptCiphertextWithAttestation(ciphertextB64 string, opts *AdvancedDecOpts, attestationProvider attestation.AttestationProvider, kmsProvider KMSProvider) (string, error) {

	if opts == nil {
		opts = &AdvancedDecOpts{}
	}

	// create ephemeral private/public key for communication with KMS
	keyGenerationStart := time.Now()
	ephemeralKey, err := ProvideRSAKey(opts.EphemeralRSAKey)
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

	attestationDocument, err := attestationProvider.GetAttestationDoc(nil, nil, derPublicKey)
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

	// send decrypt request to KMS including the attestation doc
	kmsRequestStart := time.Now()
	ciphertextForRecipient, err := decryptCiphertextWithAttestationViaKMS(ciphertext, attestationDocument, opts, kmsProvider)
	if err != nil {
		return "", err
	}
	kmsRequestEnd := time.Since(kmsRequestStart).Milliseconds()
	log.Debugf("kms request took %v ms", kmsRequestEnd)

	// any value in providing openssl based solution here?
	decryptRecipientCiphertext := time.Now()
	log.Debugf("ciphertext for recipient: %v", base64.StdEncoding.EncodeToString(ciphertextForRecipient))
	log.Debugf("ephemeral private key: %v", base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(ephemeralKey)))
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

func decryptCiphertextWithAttestationViaKMS(ciphertext []byte, attestation []byte, opts *AdvancedDecOpts, kmsProvider KMSProvider) ([]byte, error) {

	// attestation doc including the public key
	recipientInfo := &kmstypes.RecipientInfo{
		AttestationDocument:    attestation,
		KeyEncryptionAlgorithm: "RSAES_OAEP_SHA_256",
	}

	decryptInput := &kms.DecryptInput{
		CiphertextBlob: ciphertext,
		Recipient:      recipientInfo}

	// process optional decrypt options and include in request
	if opts.EncryptionContext != nil {
		decryptInput.EncryptionContext = opts.EncryptionContext
	}
	if opts.KeyId != "" && opts.EncryptionAlgorithm != "" {
		decryptInput.KeyId = &opts.KeyId
		decryptInput.EncryptionAlgorithm = opts.EncryptionAlgorithm
	}

	kmsResponse, err := kmsProvider.Decrypt(context.TODO(), decryptInput)
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
	var info types.ContentInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("failed to parse CMS: %v", err)
	}

	var ed types.EnvelopedDataStruct
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
