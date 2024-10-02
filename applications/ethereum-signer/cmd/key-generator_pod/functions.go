/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package main

import (
	"aws/ethereum-signer/internal/pod"
	signerTypes "aws/ethereum-signer/internal/types"
	"encoding/json"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mdlayher/vsock"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
)

type Env struct {
	Config      *aws.Config
	EnclaveID   uint64
	EnclavePort uint64
}

var validate *validator.Validate

// todo generateKeyViaEnclave
func (e *Env) generateKey(c *gin.Context) {
	var keyGenerationRequest signerTypes.PlainKey

	if err := c.BindJSON(&keyGenerationRequest); err != nil {
		return
	}
	log.Debugf("incomming request: %v", keyGenerationRequest)

	validate = validator.New()
	err := validate.Struct(keyGenerationRequest)
	if err != nil {
		validationErrors := err.(validator.ValidationErrors)
		log.Warnf("incoming request could not be verified: %s", validationErrors)
		// todo GeneratedKey response
		c.IndentedJSON(http.StatusBadRequest, signerTypes.SignedTransaction{Error: validationErrors.Error()})
		return
	}

	stsCredentials, err := pod.GetAWSWebIdentityCredentials(e.Config, "key-generator_session")
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Debugf("gathered sts pod: %v", stsCredentials)

	keyARN := os.Getenv("KEY_ARN")
	if len(keyARN) == 0 {
		// todo return type to enclave response
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": "KEY_ARN environment variable cannot be empty"})
		return
	}

	secretsTable := os.Getenv("SECRETS_TABLE")
	if len(secretsTable) == 0 {
		// todo return type to enclave response
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": "SECRETS_TABLE environment variable cannot be empty"})
		return
	}

	// assemble enclave payload
	payload := signerTypes.EnclaveKeyGenerationPayload{
		Credential: signerTypes.AWSCredentials{
			AccessKeyID:     *stsCredentials.AccessKeyId,
			SecretAccessKey: *stsCredentials.SecretAccessKey,
			Token:           *stsCredentials.SessionToken,
		},
		KeyARN:       keyARN,
		Secret:       keyGenerationRequest.Secret,
		SecretsTable: secretsTable,
	}
	log.Debugf("assembled signing payload: %v", payload)

	payloadSerialized, err := json.Marshal(payload)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Debugf("serialized key generation payload: %q", payloadSerialized)

	conn, err := vsock.Dial(uint32(e.EnclaveID), uint32(e.EnclavePort), nil) //#nosec G115
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	_, err = conn.Write(payloadSerialized)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	buf := make([]byte, 512)

	n, err := conn.Read(buf)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	err = conn.Close()
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Debugf("raw enclave key generation result: %s", buf)

	var signingResult signerTypes.EnclaveResult

	// status not enclosed in enclave result
	err = json.Unmarshal(buf[:n], &signingResult)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Debugf("unmarshaled enclave result: %v", signingResult)

	c.IndentedJSON(signingResult.Status, signingResult.Body)
}
