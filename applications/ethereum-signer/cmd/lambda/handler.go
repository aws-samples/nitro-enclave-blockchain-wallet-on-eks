/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package main

import (
	signerHMAC "aws/ethereum-signer/internal/hmac"
	signerTypes "aws/ethereum-signer/internal/types"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"time"
)

var validate *validator.Validate

func handleSigningRequest(nitroInstancePrivateDNS string, userRequestPayload signerTypes.UserSigningRequest) (signerTypes.UserResponse, error) {

	timestamp := int(time.Now().Unix())

	transactionPayloadSerialized, err := json.Marshal(userRequestPayload.TransactionPayload)
	if err != nil {
		return signerTypes.UserResponse{}, err
	}

	// user password (secret) -> sha256 -> + salt -> rehash
	// user passes tx payload along with sha256 hash of secret - deterministic private key
	hmacHex := signerHMAC.CalculateHMAC(transactionPayloadSerialized, userRequestPayload.Secret, timestamp)
	if err != nil {
		return signerTypes.UserResponse{}, fmt.Errorf("exception happened calculating HMAC: %s", err)
	}
	log.Debugf("calculated HMAC: %s", hmacHex)

	transactionSigningRequest := signerTypes.SigningRequest{
		TransactionPayload: userRequestPayload.TransactionPayload,
		KeyID:              userRequestPayload.KeyID,
		Timestamp:          timestamp,
		HMAC:               hmacHex,
	}

	transactionSigningRequestSerialized, err := json.Marshal(transactionSigningRequest)
	if err != nil {
		return signerTypes.UserResponse{}, err
	}

	hostName := fmt.Sprintf("%s.%s", "ethereum-signer", nitroInstancePrivateDNS)
	enclaveResponseRaw, statusCode, err := handleEnclaveRequest(hostName, transactionSigningRequestSerialized)
	if err != nil {
		return signerTypes.UserResponse{}, nil
	}

	enclaveResponse := signerTypes.SignedTransaction{}
	err = json.Unmarshal(enclaveResponseRaw, &enclaveResponse)
	if err != nil {
		return signerTypes.UserResponse{}, err
	}

	userResponse := signerTypes.UserResponse{
		EnclaveStatus: statusCode,
		EnclaveResult: enclaveResponse,
	}
	return userResponse, nil
}

func handleGenerateKeyRequest(nitroInstancePrivateDNS string, userRequestPayload signerTypes.PlainKey) (signerTypes.UserResponse, error) {

	userRequestPayloadSerialized, err := json.Marshal(userRequestPayload)
	if err != nil {
		return signerTypes.UserResponse{}, err
	}
	hostName := fmt.Sprintf("%s.%s", "ethereum-key-generator", nitroInstancePrivateDNS)
	enclaveRespnseRaw, statusCode, err := handleEnclaveRequest(hostName, userRequestPayloadSerialized)
	if err != nil {
		return signerTypes.UserResponse{}, err
	}

	enclaveResponse := signerTypes.Ciphertext{}
	err = json.Unmarshal(enclaveRespnseRaw, &enclaveResponse)
	if err != nil {
		return signerTypes.UserResponse{}, err
	}

	userResponse := signerTypes.UserResponse{
		EnclaveStatus: statusCode,
		EnclaveResult: enclaveResponse,
	}
	return userResponse, nil
}

func handleEnclaveRequest(hostName string, enclavePayload []byte) ([]byte, int, error) {

	tlsTransport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, // #nosec G402
			// todo to enable TLS certificate validation even with self-signed cert pass custom x509 cert
			//RootCAs:
		},
	}

	tlsClient := &http.Client{Transport: tlsTransport}

	res, err := tlsClient.Post(fmt.Sprintf("https://%s:%d", hostName, 8080), "application/json", bytes.NewBuffer(enclavePayload))
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		err := res.Body.Close()
		if err != nil {
			log.Errorf("error happened closing response body: %s", err)
		}
	}()

	enclaveResponseRaw, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, err
	}

	return enclaveResponseRaw, res.StatusCode, nil
}

func isValidUUID(u string) bool {
	_, err := uuid.Parse(u)
	return err == nil
}
