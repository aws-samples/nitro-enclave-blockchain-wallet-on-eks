/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package main

import (
	"aws/ethereum-signer/internal/metrics"
	"aws/ethereum-signer/internal/pod"
	signerTypes "aws/ethereum-signer/internal/types"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mdlayher/vsock"
	log "github.com/sirupsen/logrus"
	"net"
	"net/http"
	"os"
)

type KeyGenerator struct {
	config      *aws.Config
	enclaveCID  uint32
	enclavePort uint32
	validator   *validator.Validate
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

	keyGen := NewKeyGenerator(config, enclaveID, enclavePort)
	router.POST("/", keyGen.GenerateKey)

	return router
}

func NewKeyGenerator(config *aws.Config, enclaveID, enclavePort uint64) *KeyGenerator {
	return &KeyGenerator{
		config:      config,
		enclaveCID:  uint32(enclaveID),
		enclavePort: uint32(enclavePort),
		validator:   validator.New(),
	}
}

type EnvVars struct {
	KeyARN       string
	SecretsTable string
}

func (kg *KeyGenerator) GenerateKey(c *gin.Context) {
	request, err := kg.validateRequest(c)
	if err != nil {
		kg.handleError(c, http.StatusBadRequest, "invalid request", err)
		return
	}

	envVars, err := kg.getEnvironmentVariables()
	if err != nil {
		kg.handleError(c, http.StatusInternalServerError, "environment configuration error", err)
		return
	}

	result, err := kg.processKeyGeneration(request, envVars)
	if err != nil {
		kg.handleError(c, http.StatusInternalServerError, "key generation failed", err)
		return
	}

	c.IndentedJSON(result.Status, result.Body)
}

func (kg *KeyGenerator) validateRequest(c *gin.Context) (*signerTypes.PlainKey, error) {
	var request signerTypes.PlainKey
	if err := c.BindJSON(&request); err != nil {
		return nil, fmt.Errorf("failed to parse request: %w", err)
	}
	log.Debugf("incoming request: %v", request)

	if err := kg.validator.Struct(request); err != nil {
		validationErrors := err.(validator.ValidationErrors)
		log.Warnf("request validation failed: %s", validationErrors)
		return nil, validationErrors
	}
	return &request, nil
}

func (kg *KeyGenerator) getEnvironmentVariables() (*EnvVars, error) {
	keyARN := os.Getenv("KEY_ARN")
	secretsTable := os.Getenv("SECRETS_TABLE")

	if keyARN == "" {
		return nil, fmt.Errorf("KEY_ARN environment variable cannot be empty")
	}
	if secretsTable == "" {
		return nil, fmt.Errorf("SECRETS_TABLE environment variable cannot be empty")
	}

	return &EnvVars{
		KeyARN:       keyARN,
		SecretsTable: secretsTable,
	}, nil
}

func (kg *KeyGenerator) processKeyGeneration(request *signerTypes.PlainKey, env *EnvVars) (*signerTypes.EnclaveResult, error) {
	credentials, err := kg.getAWSCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS credentials: %w", err)
	}

	payload, err := kg.createPayload(request, credentials, env)
	if err != nil {
		return nil, fmt.Errorf("failed to create payload: %w", err)
	}

	return kg.communicateWithEnclave(payload)
}

func (kg *KeyGenerator) getAWSCredentials() (*types.Credentials, error) {
	credentials, err := pod.GetAWSWebIdentityCredentials(kg.config, "key-generator_session")
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS credentials: %w", err)
	}
	log.Debugf("gathered AWS credentials: %v", credentials)
	return credentials, nil
}

func (kg *KeyGenerator) createPayload(request *signerTypes.PlainKey, creds *types.Credentials, env *EnvVars) ([]byte, error) {
	payload := signerTypes.EnclaveKeyGenerationPayload{
		Credential: signerTypes.AWSCredentials{
			AccessKeyID:     *creds.AccessKeyId,
			SecretAccessKey: *creds.SecretAccessKey,
			Token:           *creds.SessionToken,
		},
		KeyARN:       env.KeyARN,
		Secret:       request.Secret,
		SecretsTable: env.SecretsTable,
	}
	log.Debugf("assembled signing payload: %v", payload)

	serialized, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize payload: %w", err)
	}
	log.Debugf("serialized key generation payload: %q", serialized)
	return serialized, nil
}

func (kg *KeyGenerator) communicateWithEnclave(payload []byte) (*signerTypes.EnclaveResult, error) {
	conn, err := vsock.Dial(kg.enclaveCID, kg.enclavePort, nil) //#nosec G115
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

	response, err := kg.readEnclaveResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read enclave response: %w", err)
	}

	return response, nil
}

func (kg *KeyGenerator) readEnclaveResponse(conn net.Conn) (*signerTypes.EnclaveResult, error) {
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

func (kg *KeyGenerator) handleError(c *gin.Context, status int, message string, err error) {
	log.Errorf("%s: %v", message, err)
	c.IndentedJSON(status, gin.H{"error": err.Error()})
}
