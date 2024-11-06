/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package main

import (
	"aws/ethereum-signer/internal/enclave"
	"aws/ethereum-signer/internal/keymanagement"
	"aws/ethereum-signer/internal/metrics"
	signerTypes "aws/ethereum-signer/internal/types"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-playground/validator/v10"
	"github.com/mdlayher/vsock"
	log "github.com/sirupsen/logrus"
	"os"
	"strconv"
	"time"
)

var validate *validator.Validate
var version = "undefined"

func main() {
	log.Printf("starting key generation enclave (%s)", version)

	logLevel, err := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		log.Fatalf("LOG_LEVEL value (%s) could not be parsed: %s", os.Getenv("LOG_LEVEL"), err)
	}

	region := os.Getenv("REGION")
	if region == "" {
		log.Fatalf("REGION cannot be empty")
	}

	// base port is being passed via port variable during docker build
	// enclave itself listens on port for inbound connections
	// port is being incremented for outbound ports
	// vsock_1: port (runs.sh)
	// vsock_2: port + 1 (run.sh)
	// metrics: port + PortOffset(10 const)
	port := os.Getenv("PORT")
	if port == "" {
		log.Fatalf("PORT cannot be empty")
	}

	portInt, err := strconv.ParseUint(port, 10, 32)
	if err != nil {
		log.Fatalf("exception happened parsing provided port (%v) to int: %s", port, err)
	}
	listenerPort := uint32(portInt) //#nosec G115
	contextID, err := vsock.ContextID()
	if err != nil {
		log.Fatalf("exception happened getting enclave contextID: %s", err)
	}
	listener, err := vsock.ListenContextID(contextID, listenerPort, nil)
	if err != nil {
		log.Fatalf("exception happened openening vsock listener on port %v and contextID %v: %s", listenerPort, contextID, err)
	}

	log.SetLevel(logLevel)

	metricsClient := metrics.NewMetricsClient(3, listenerPort+metrics.PortOffset, 10*time.Second)
	metricsClient.Start()
	log.Infof("metrics client started with target cid: 3, port: %d", listenerPort+metrics.PortOffset)
	log.Infof("starting listener for key generation requests")
	for {

		conn, err := listener.Accept()
		if err != nil {
			enclave.HandleError(conn, fmt.Sprintf("exception happened accepting incoming connection: %s", err), 500)
			continue
		}
		log.Debugf("accepted incoming connection from: %s", conn.RemoteAddr())

		// todo conn mock
		go func() {
			buf := make([]byte, 4096)

			n, err := conn.Read(buf)
			if err != nil {
				enclave.HandleError(conn, fmt.Sprintf("exception happened reading from incoming connection: %s", err), 500)
				return
			}
			log.Debugf(fmt.Sprintf("read buffer length: %v", n))

			log.Debugf("raw enclave request: %s", buf)

			var enclavePayload signerTypes.EnclaveKeyGenerationPayload

			// status not enclosed in enclave result
			err = json.Unmarshal(buf[:n], &enclavePayload)
			if err != nil {
				enclave.HandleError(conn, fmt.Sprintf("exception happened unmarshalling payload: %s", err), 500)
				return
			}
			log.Debugf("unmarshaled enclave payload: %v", enclavePayload)

			validate = validator.New()
			err = validate.Struct(enclavePayload)
			if err != nil {
				validationErrors := err.(validator.ValidationErrors)
				enclave.HandleError(conn, fmt.Sprintf("incoming request could not be verified: %s", validationErrors), 400)
				return
			}

			ethPrivateKey, err := crypto.GenerateKey()
			if err != nil {
				enclave.HandleError(conn, fmt.Sprintf("exception happened generating new Ethereum private key: %s", err), 500)
				return
			}

			ethPublicKey := ethPrivateKey.Public()
			publicKeyECDSA, ok := ethPublicKey.(*ecdsa.PublicKey)
			if !ok {
				enclave.HandleError(conn, "cannot assert type: publicKey is not of type *ecdsa.PublicKey", 500)
				return
			}

			if publicKeyECDSA == nil {
				enclave.HandleError(conn, "public key is nil", 500)
				return
			}
			address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()

			// todo - memguard
			plainKey := signerTypes.PlainKey{
				EthKey: hex.EncodeToString(ethPrivateKey.D.Bytes()),
				Secret: enclavePayload.Secret,
			}

			cfg, err := config.LoadDefaultConfig(context.TODO(),
				config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(enclavePayload.Credential.AccessKeyID, enclavePayload.Credential.SecretAccessKey, enclavePayload.Credential.Token)))
			if err != nil {
				enclave.HandleError(conn, fmt.Sprintf("configuration error: %s", err), 500)
				return
			}
			cfg.Region = region

			// leveraging AWS SDK for service integration, retry and exponential backoff come for free
			keyID, err := keymanagement.EncryptAndSaveKey(cfg, enclavePayload.KeyARN, enclavePayload.SecretsTable, plainKey, address)
			if err != nil {
				enclave.HandleError(conn, fmt.Sprintf("exception happened encrypting and saving Ethereum key to DynamoDB: %s", err), 500)
				return
			}

			enclaveResult := signerTypes.EnclaveResult{
				Status: 200,
				Body: signerTypes.Ciphertext{KeyID: keyID,
					Address: address},
			}

			enclaveResultSerialized, err := json.Marshal(enclaveResult)
			if err != nil {
				enclave.HandleError(conn, fmt.Sprintf("error happend serializing the enclave result: %s", err), 500)
				return
			}

			_, err = conn.Write(enclaveResultSerialized)
			if err != nil {
				log.Errorf("error happened writing back result via vsock connect: %s", err)
			}
			err = conn.Close()
			if err != nil {
				log.Errorf("error happened closing vsock connection: %s", err)
			}
		}()
	}

}
