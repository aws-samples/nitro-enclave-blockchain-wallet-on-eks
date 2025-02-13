/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package main

import (
	"aws/ethereum-signer/internal/metrics"
	"aws/ethereum-signer/internal/pod"
	signerTypes "aws/ethereum-signer/internal/types"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mdlayher/vsock"
	log "github.com/sirupsen/logrus"
	"net"
	"net/http"
	"os"
)

type TxSigner struct {
	config      *aws.Config
	enclaveCID  uint32
	enclavePort uint32
	validator   *validator.Validate
}

func NewSignerInstance(config *aws.Config, enclaveCID, enclavePort uint64) *TxSigner {
	return &TxSigner{
		config:      config,
		enclaveCID:  uint32(enclaveCID),
		enclavePort: uint32(enclavePort),
		validator:   validator.New(),
	}
}

func setupLogging(logLevel string) error {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		return fmt.Errorf("invalid LOG_LEVEL value (%s): %w", logLevel, err)
	}
	log.SetLevel(level)
	log.Infof("LOG_LEVEL=%s", level)
	return nil
}

func setupMetricsServer(enclavePort uint64) error {
	listenerPort := uint32(enclavePort + metrics.PortOffset)
	metricsServer := metrics.NewMetricsServer(3, listenerPort)
	if err := metricsServer.Start(); err != nil {
		return fmt.Errorf("failed to start metrics server on CID: %v, port: %v: %w", 3, listenerPort, err)
	}
	return nil
}

func setupRouter(config *aws.Config, enclaveID, enclavePort uint64) *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())
	signer := NewSignerInstance(config, enclaveID, enclavePort)
	router.POST("/", signer.SignTransaction)

	return router
}

type EnvVars struct {
	SecretsTable string
}

func (txs *TxSigner) getEnvironmentVariables() (*EnvVars, error) {
	secretsTable := os.Getenv("SECRETS_TABLE")

	if secretsTable == "" {
		return nil, fmt.Errorf("SECRETS_TABLE environment variable cannot be empty")
	}

	return &EnvVars{
		SecretsTable: secretsTable,
	}, nil
}

func (txs *TxSigner) getEncryptedKey(keyID string) (signerTypes.Ciphertext, error) {

	dynamoDBClient := dynamodb.NewFromConfig(*txs.config)

	keyIDValue, err := attributevalue.Marshal(keyID)
	if err != nil {
		return signerTypes.Ciphertext{}, fmt.Errorf("exception happened marshalling keyID into DynamoDB compatible query attribute:%s", err)
	}

	envVars, err := txs.getEnvironmentVariables()
	if err != nil {
		return signerTypes.Ciphertext{}, fmt.Errorf("exception happened getting environment variables:%s", err)
	}

	result, err := dynamoDBClient.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: &envVars.SecretsTable,
		Key:       map[string]dbTypes.AttributeValue{"key_id": keyIDValue},
	},
	)
	if err != nil {
		return signerTypes.Ciphertext{}, fmt.Errorf("exception happened sending GetItem request to DynamoDB:%s", err)
	}

	if len(result.Item) == 0 {
		return signerTypes.Ciphertext{}, &signerTypes.SecretNotFoundError{
			Err: fmt.Errorf("KeyID (%s) was not found", keyID),
		}
	}

	var encryptedKey signerTypes.Ciphertext
	err = attributevalue.UnmarshalMap(result.Item, &encryptedKey)
	if err != nil {
		return signerTypes.Ciphertext{}, fmt.Errorf("exception happened unmarshalling DynamoDB result into type singerTypes.Ciphertext:%s", err)
	}

	return encryptedKey, nil
}

func (txs *TxSigner) communicateWithEnclave(payload []byte) (*signerTypes.EnclaveResult, error) {
	conn, err := vsock.Dial(txs.enclaveCID, txs.enclavePort, nil) //#nosec G115
	if err != nil {
		return nil, fmt.Errorf("failed to connect to enclave: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			log.Errorf("failed to close connection: %v", err)
		}
	}()

	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("failed to write to enclave: %w", err)
	}

	response, err := txs.readEnclaveResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read enclave response: %w", err)
	}

	return response, nil
}

func (txs *TxSigner) readEnclaveResponse(conn net.Conn) (*signerTypes.EnclaveResult, error) {
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read from connection: %w", err)
	}
	log.Debugf("raw enclave key generation result: %s", buf[:n])

	var result signerTypes.EnclaveResult
	if err := json.Unmarshal(buf[:n], &result); err != nil {
		return nil, fmt.Errorf("failed to parse enclave response: %w", err)
	}
	log.Debugf("unmarshaled enclave result: %v", result)

	return &result, nil
}

func (txs *TxSigner) handleError(c *gin.Context, status int, message string, err error) {
	log.Errorf("%s: %v", message, err)
	c.IndentedJSON(status, gin.H{"error": err.Error()})
}

func (txs *TxSigner) generatePayload(signingRequest signerTypes.SigningRequest, encryptedKey signerTypes.Ciphertext, creds *types.Credentials) ([]byte, error) {

	// assemble enclave payload
	payload := signerTypes.EnclaveSigningPayload{
		Credential: signerTypes.AWSCredentials{
			AccessKeyID:     *creds.AccessKeyId,
			SecretAccessKey: *creds.SecretAccessKey,
			Token:           *creds.SessionToken,
		},
		TransactionPayload: signingRequest.TransactionPayload,
		EncryptedKey:       encryptedKey.Ciphertext,
		Timestamp:          signingRequest.Timestamp,
		HMAC:               signingRequest.HMAC,
	}
	log.Debugf("assembled signing payload: %v", payload)

	serialized, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize payload: %w", err)
	}
	log.Debugf("serialized key generation payload: %q", serialized)
	return serialized, nil

}

func (txs *TxSigner) SignTransaction(c *gin.Context) {
	var newSigningRequest signerTypes.SigningRequest

	if err := c.BindJSON(&newSigningRequest); err != nil {
		return
	}
	log.Debugf("incomming request: %v", newSigningRequest)

	//validate = validator.New()
	err := txs.validator.Struct(newSigningRequest)
	if err != nil {
		validationErrors := err.(validator.ValidationErrors)
		txs.handleError(c, http.StatusBadRequest, "incoming request could not be verified", validationErrors)
		return
	}

	stsCredentials, err := pod.GetAWSWebIdentityCredentials(txs.config, "ethereum-signer_session")
	if err != nil {
		txs.handleError(c, http.StatusInternalServerError, "exception happened gathering sts pod", err)
		return
	}
	log.Debugf("gathered sts pod: %v", stsCredentials)

	encryptedKey, err := txs.getEncryptedKey(newSigningRequest.KeyID)
	if err != nil {
		re, ok := err.(*signerTypes.SecretNotFoundError)
		if ok {
			txs.handleError(c, http.StatusNotFound, "Requested secret could not be found in DynamoDB", re.Err)
			return
		}
		txs.handleError(c, http.StatusInternalServerError, "exception happened downloading encrypted key from DynamoDB", err)
		return
	}
	log.Debugf("encrypted key: %v", encryptedKey)

	payload, err := txs.generatePayload(newSigningRequest, encryptedKey, stsCredentials)
	if err != nil {
		txs.handleError(c, http.StatusInternalServerError, "exception happened generating payload", err)
		return
	}

	result, err := txs.communicateWithEnclave(payload)
	if err != nil {
		txs.handleError(c, http.StatusInternalServerError, "exception happened communicating with enclave", err)
		return
	}
	c.IndentedJSON(result.Status, result.Body)
}
