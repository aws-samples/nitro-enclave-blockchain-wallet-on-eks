/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package keyFunctions

import (
	signerTypes "aws/ethereum-signer/internal/types"
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/google/uuid"
)

func EncryptAndSaveKey(cfg aws.Config, keyARN, secretTable string, plainKeyPayload signerTypes.PlainKey, address string) (string, error) {

	kmsClient := kms.NewFromConfig(cfg)

	plainKeyPayloadBytes, err := json.Marshal(plainKeyPayload)
	if err != nil {
		return "", fmt.Errorf("exception happened marshalling painKeyPayload: %s", err)
	}

	input := &kms.EncryptInput{
		KeyId:     &keyARN,
		Plaintext: plainKeyPayloadBytes,
	}

	result, err := kmsClient.Encrypt(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf("exception happened encrypting payload via KMS: %s", err)
	}

	ciphertext := b64.StdEncoding.EncodeToString(result.CiphertextBlob)

	ddClient := dynamodb.NewFromConfig(cfg)

	secretID := uuid.New().String()

	itemRaw := signerTypes.Ciphertext{
		KeyID:      secretID,
		Ciphertext: ciphertext,
		Address:    address,
	}

	itemDD, err := attributevalue.MarshalMap(itemRaw)
	if err != nil {
		return "", fmt.Errorf("exception happened converting ciphertext into DynamoDB compatible format: %s", err)
	}

	// outgoing connections limited by outbound vsock proxy concurrent connections - increase retry etc. to increase resiliency if required
	// https://github.com/aws/aws-sdk-go/blob/main/aws/config_test.go#L19
	_, err = ddClient.PutItem(context.TODO(), &dynamodb.PutItemInput{
		Item:      itemDD,
		TableName: &secretTable,
	})
	if err != nil {
		return "", fmt.Errorf("exception happened storing ciphertext in DynamoDB: %s", err)
	}

	return secretID, nil
}
