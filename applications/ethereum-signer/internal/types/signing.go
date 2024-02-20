/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package types

type SecretNotFoundError struct {
	Err error
}

func (e *SecretNotFoundError) Error() string {
	return e.Err.Error()
}

type TransactionPayload struct {
	Value                float32 `json:"value,omitempty"`
	To                   string  `json:"to" validate:"required"`
	Nonce                int     `json:"nonce" validate:"gte=0"`
	Type                 int     `json:"type" validate:"required"`
	ChainID              int     `json:"chainId" validate:"required"`
	Gas                  int     `json:"gas" validate:"required"`
	MaxFeePerGas         int     `json:"maxFeePerGas" validate:"required"`
	MaxPriorityFeePerGas int     `json:"maxPriorityFeePerGas" validate:"required"`
	Data                 string  `json:"data,omitempty"`
}

type UserOpPayload struct {
	UserOpHash string `json:"userOpHash" validate:"len=66"`
}

type SigningRequest struct {
	TransactionPayload map[string]interface{} `json:"transaction_payload" validate:"required"`
	KeyID              string                 `json:"key_id" validate:"len=36"`
	Timestamp          int                    `json:"timestamp" validate:"required"`
	HMAC               string                 `json:"hmac" validate:"required"`
}

// https://stackoverflow.com/a/68806602
type PlainKey struct {
	Secret string `json:"secret" validate:"min=36"`
	EthKey string `json:"eth_key" validate:"omitempty,len=64"`
}

type AWSCredentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Token           string `json:"token"`
}

type EnclaveSigningPayload struct {
	Credential         AWSCredentials         `json:"credential" validate:"required"`
	TransactionPayload map[string]interface{} `json:"transaction_payload" validate:"required"`
	EncryptedKey       string                 `json:"encrypted_key" validate:"required"`
	Timestamp          int                    `json:"timestamp" validate:"required"`
	HMAC               string                 `json:"hmac" validate:"required"`
}

type EnclaveKeyGenerationPayload struct {
	Credential   AWSCredentials `json:"credential" validate:"required"`
	Secret       string         `json:"secret" validate:"min=36"`
	SecretsTable string         `json:"secrets_table" validate:"required"`
	KeyARN       string         `json:"key_arn" validate:"required"`
}

type SignedTransaction struct {
	TxHash    string `json:"tx_hash,omitempty"`
	SignedTX  string `json:"tx_signed,omitempty"`
	Signature string `json:"signature,omitempty"`
	Error     string `json:"error,omitempty"`
}

type EnclaveResult struct {
	Status int         `json:"status"`
	Body   interface{} `json:"body"`
}

type Ciphertext struct {
	KeyID      string `dynamodbav:"key_id" json:"key_id"`
	Ciphertext string `dynamodbav:"ciphertext" json:"ciphertext,omitempty"`
	Address    string `dynamodbav:"address" json:"address,omitempty"`
}

type UserRequest struct {
	Operation string      `json:"operation" validate:"required"`
	Payload   interface{} `json:"payload" validate:"required"`
}

type UserResponse struct {
	EnclaveStatus int         `json:"enclave_status"`
	EnclaveResult interface{} `json:"enclave_result"`
}

type UserSigningRequest struct {
	TransactionPayload map[string]interface{} `json:"transaction_payload" validate:"required"`
	KeyID              string                 `json:"key_id" validate:"len=36"`
	Secret             string                 `json:"secret" validate:"min=36"`
}
