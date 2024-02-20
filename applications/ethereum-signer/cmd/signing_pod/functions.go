/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package main

import (
	"aws/ethereum-signer/internal/pod"
	signerTypes "aws/ethereum-signer/internal/types"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	dbTypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/mdlayher/vsock"
	log "github.com/sirupsen/logrus"
	"net/http"
)

var validate *validator.Validate

type Env struct {
	config       *aws.Config
	secretsTable string
	enclaveCID   int64
	enclavePort  int64
}

func (e *Env) getEncryptedKey(keyID string) (signerTypes.Ciphertext, error) {

	dynamoDBClient := dynamodb.NewFromConfig(*e.config)

	keyIDValue, err := attributevalue.Marshal(keyID)
	if err != nil {
		return signerTypes.Ciphertext{}, fmt.Errorf("exception happened marshalling keyID into DynamoDB compatible query attribute:%s", err)
	}

	result, err := dynamoDBClient.GetItem(context.TODO(), &dynamodb.GetItemInput{
		TableName: &e.secretsTable,
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

func (e *Env) signTransaction(c *gin.Context) {
	var newSigningRequest signerTypes.SigningRequest

	if err := c.BindJSON(&newSigningRequest); err != nil {
		return
	}
	log.Debugf("incomming request: %v", newSigningRequest)

	validate = validator.New()
	err := validate.Struct(newSigningRequest)
	if err != nil {
		validationErrors := err.(validator.ValidationErrors)
		log.Warnf("incoming request could not be verified: %s", validationErrors)
		c.IndentedJSON(http.StatusBadRequest, signerTypes.SignedTransaction{Error: validationErrors.Error()})
		return
	}

	stsCredentials, err := pod.GetAWSWebIdentityCredentials(e.config, "ethereum-signer_session")
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Debugf("gathered sts pod: %v", stsCredentials)

	encryptedKey, err := e.getEncryptedKey(newSigningRequest.KeyID)
	if err != nil {
		re, ok := err.(*signerTypes.SecretNotFoundError)
		if ok {
			c.IndentedJSON(http.StatusNotFound, gin.H{"error": re.Error()})
			return
		}
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("exception happened downloading encrypted key from DynamoDB: %s", err)})
		return
	}
	log.Debugf("encrypted key: %v", encryptedKey)

	// assemble enclave payload
	payload := signerTypes.EnclaveSigningPayload{
		Credential: signerTypes.AWSCredentials{
			AccessKeyID:     *stsCredentials.AccessKeyId,
			SecretAccessKey: *stsCredentials.SecretAccessKey,
			Token:           *stsCredentials.SessionToken,
		},
		TransactionPayload: newSigningRequest.TransactionPayload,
		EncryptedKey:       encryptedKey.Ciphertext,
		Timestamp:          newSigningRequest.Timestamp,
		HMAC:               newSigningRequest.HMAC,
	}
	log.Debugf("assembled signing payload: %v", payload)

	conn, err := vsock.Dial(uint32(e.enclaveCID), uint32(e.enclavePort), nil)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	payloadSerialized, err := json.Marshal(payload)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Debugf("serialized signing payload: %q", payloadSerialized)

	_, err = conn.Write(payloadSerialized)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	buf := make([]byte, 4096)

	n, err := conn.Read(buf)
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Debugf("read %v bytes into buffer", n)
	err = conn.Close()
	if err != nil {
		c.IndentedJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	log.Debugf("raw enclave result: %s", buf)

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
