/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package keymanagement

import (
	aws2 "aws/ethereum-signer/internal/aws"
	signerTypes "aws/ethereum-signer/internal/types"
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	ddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/google/uuid"
	"time"
)

// dynamodb interface
type DDBProvider interface {
	PutItem(ctx context.Context, params *ddb.PutItemInput, optFns ...func(*ddb.Options)) (*ddb.PutItemOutput, error)
}

type AWSDDBProvider struct {
	client *ddb.Client
}

func NewAWSDDBProvider(credentials signerTypes.AWSCredentials, region string, connectionType aws2.ConnectionType, contextId uint32, port uint32) (*AWSDDBProvider, error) {
	cfg, err := aws2.EnclaveSDKConfig(credentials, region, aws2.NewConnectionConfig(connectionType, contextId, port))
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %v", err)
	}

	return &AWSDDBProvider{
		client: ddb.NewFromConfig(cfg),
	}, nil
}

func (p *AWSDDBProvider) PutItem(ctx context.Context, params *ddb.PutItemInput, optFns ...func(options *ddb.Options)) (*ddb.PutItemOutput, error) {
	return p.client.PutItem(ctx, params, optFns...)
}

func EncryptAndSaveKey(kmsProvider KMSProvider, ddbProvider DDBProvider, keyARN, secretTable string, plainKeyPayload signerTypes.PlainKey, address string) (string, error) {

	// Generate UUID early to fail fast if there's an issue
	secretID := uuid.New().String()

	// Use a timeout context instead of context.TODO()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Marshal the payload
	plainKeyPayloadBytes, err := json.Marshal(plainKeyPayload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal key payload: %w", err)
	}

	// Encrypt the payload
	result, err := kmsProvider.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     &keyARN,
		Plaintext: plainKeyPayloadBytes,
	})
	if err != nil {
		return "", fmt.Errorf("failed to encrypt payload via KMS: %w", err)
	}

	// Prepare DynamoDB item
	itemRaw := signerTypes.Ciphertext{
		KeyID:      secretID,
		Ciphertext: b64.StdEncoding.EncodeToString(result.CiphertextBlob),
		Address:    address,
	}

	itemDD, err := attributevalue.MarshalMap(itemRaw)
	if err != nil {
		return "", fmt.Errorf("failed to marshal DynamoDB item: %w", err)
	}

	// Configure retry options for DynamoDB
	retry := retry.AddWithMaxAttempts(retry.NewStandard(), 3)
	putItemInput := &ddb.PutItemInput{
		Item:      itemDD,
		TableName: &secretTable,
	}

	// Store with retry logic
	_, err = ddbProvider.PutItem(ctx, putItemInput, func(o *ddb.Options) {
		o.Retryer = retry
	})
	if err != nil {
		return "", fmt.Errorf("failed to store item in DynamoDB: %w", err)
	}

	return secretID, nil
}
