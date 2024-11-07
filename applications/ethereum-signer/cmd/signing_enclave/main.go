/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package main

import (
	"aws/ethereum-signer/internal/enclave"
	"aws/ethereum-signer/internal/ethereum"
	signerHMAC "aws/ethereum-signer/internal/hmac"
	"aws/ethereum-signer/internal/keymanagement"
	"aws/ethereum-signer/internal/metrics"
	signerTypes "aws/ethereum-signer/internal/types"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/go-playground/validator/v10"
	"github.com/mdlayher/vsock"
	log "github.com/sirupsen/logrus"
	"os"
	"strconv"
	"time"
)

var version = "undefined"
var validate *validator.Validate

func main() {
	log.Printf("starting signing enclave (%s)", version)

	logLevel, err := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		log.Fatalf("LOG_LEVEL value (%s) could not be parsed: %s", os.Getenv("LOG_LEVEL"), err)
	}

	region := os.Getenv("REGION")
	if region == "" {
		log.Fatalf("region cannot be empty")
	}

	port := os.Getenv("PORT")
	if port == "" {
		log.Fatalf("PORT cannot be empty")
	}

	portInt, err := strconv.Atoi(port)
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
	log.Infof("metrics client started with target cid: 3, port: %v", listenerPort+1)
	log.Infof("start listening for signing requests")
	for {
		conn, err := listener.Accept()
		if err != nil {
			enclave.HandleError(conn, fmt.Sprintf("exception happened accepting incoming connection: %s", err), 500)
			continue
		}
		log.Debugf("accepted incoming connection from: %s", conn.RemoteAddr())

		go func() {
			timestamp := int(time.Now().Unix())
			buf := make([]byte, 4096)

			n, err := conn.Read(buf)
			if err != nil {
				enclave.HandleError(conn, fmt.Sprintf("exception happened reading from incoming connection: %s", err), 500)
				return
			}
			log.Debugf("read buffer length: %v", n)
			log.Debugf("raw enclave request: %s", buf)

			var enclavePayload signerTypes.EnclaveSigningPayload

			// status not enclosed in enclave result
			err = json.Unmarshal(buf[:n], &enclavePayload)
			if err != nil {
				enclave.HandleError(conn, fmt.Sprintf("exception happened unmarshalling payload: %s", err), 500)
				return
			}
			log.Debugf("unmarshaled enclave payload: %v", enclavePayload)

			// validate high level payload struct (pod
			validate = validator.New()
			err = validate.Struct(enclavePayload)
			if err != nil {
				validationErrors := err.(validator.ValidationErrors)
				enclave.HandleError(conn, fmt.Sprintf("incoming request could not be verified: %s", validationErrors), 400)
				return
			}

			// todo memguard
			// go sdk + openssl decrypt
			attestationStart := time.Now()
			plaintextSDKB64, err := keymanagement.DecryptCiphertextWithAttestation(enclavePayload.Credential, enclavePayload.EncryptedKey, listenerPort, region, &keymanagement.AdvancedDecOpts{})
			if err != nil {
				//
				log.Errorf("exception happened decrypting passed cyphertext (attestation): %s", err)
			}
			attestationEnd := time.Since(attestationStart).Milliseconds()
			log.Printf("attestation SDK duration (milliseconds): %v", attestationEnd)
			log.Debugf("plaintext (sdk): %v", plaintextSDKB64)

			//log.Printf("response equal: %v", plaintextKMSToolB64 == plaintextKMSToolB64)

			userKey, err := keymanagement.ParsePlaintext(plaintextSDKB64)
			if err != nil {
				enclave.HandleError(conn, fmt.Sprintf("exception happened parsing b64 encoded KMS result : %s", err), 500)
				return
			}

			enclavePayloadSerialized, err := json.Marshal(enclavePayload.TransactionPayload)
			if err != nil {
				enclave.HandleError(conn, fmt.Sprintf("exception happened serializing the enclave payload: %s", err), 500)
				return
			}

			hmacHex := signerHMAC.CalculateHMAC(enclavePayloadSerialized, userKey.Secret, enclavePayload.Timestamp)
			if err != nil {
				enclave.HandleError(conn, fmt.Sprintf("exception happened calculating HMAC: %s", err), 500)
				return
			}
			log.Debugf("calculated HMAC: %s", hmacHex)

			if !hmac.Equal([]byte(hmacHex), []byte(enclavePayload.HMAC)) {
				enclave.HandleError(conn, "calculated and provided HMAC are different", 403)
				return
			}
			// validate the timestamp enclosed in the enclave payload. Timestamp cannot be older than 60 seconds, otherwise
			// request is considered expired
			if !signerHMAC.TimestampInRange(enclavePayload.Timestamp, timestamp, 60) {
				enclave.HandleError(conn, "request has expired", 403)
				return
			}

			var enclaveResult signerTypes.EnclaveResult

			// todo quick workaround - to be fixed
			payloadBytes, err := json.Marshal(enclavePayload.TransactionPayload)
			if err != nil {
				enclave.HandleError(conn, "exception happened determining the type of payload", 500)
				return
			}
			if _, ok := enclavePayload.TransactionPayload["userOpHash"]; ok {
				var userOpPayload signerTypes.UserOpPayload
				err = json.Unmarshal(payloadBytes, &userOpPayload)
				if err != nil {
					enclave.HandleError(conn, "exception happened determining the type of payload", 500)
					return
				}

				err = validate.Struct(userOpPayload)
				if err != nil {
					validationErrors := err.(validator.ValidationErrors)
					enclave.HandleError(conn, fmt.Sprintf("incoming userOp signing request could not be verified: %s", validationErrors), 400)
					return
				}

				// requires string to start with 0x
				bytes, err := hexutil.Decode(userOpPayload.UserOpHash)
				if err != nil {
					enclave.HandleError(conn, fmt.Sprintf("error happened converting provided UserOp hash to bytes: %s", err), 500)
				}

				userOpSignature, err := ethereum.SignUserOps(bytes, userKey.EthKey)
				if err != nil {
					enclave.HandleError(conn, fmt.Sprintf("error happened signing UserOp hash: %s", err), 500)
					return
				}
				log.Debugf("user ops raw signature: %v", userOpSignature)

				enclaveResult = signerTypes.EnclaveResult{
					Status: 200,
					Body: signerTypes.SignedTransaction{
						Signature: userOpSignature,
					},
				}
			} else if _, ok := enclavePayload.TransactionPayload["to"]; ok {
				var transactionPayload signerTypes.TransactionPayload
				err = json.Unmarshal(payloadBytes, &transactionPayload)
				if err != nil {
					enclave.HandleError(conn, fmt.Sprintf("incoming EIP1559 transacation signing request could not be unmarshalld: %s", err), 400)
					return
				}
				assembledTx := ethereum.AssembleTransaction(transactionPayload)

				err = validate.Struct(transactionPayload)
				if err != nil {
					validationErrors := err.(validator.ValidationErrors)
					enclave.HandleError(conn, fmt.Sprintf("incoming EIP1559 transacation signing request faild verification: %s", validationErrors), 400)
					return
				}

				signedTx, err := ethereum.SignEthereumTransaction(assembledTx, userKey.EthKey)
				if err != nil {
					enclave.HandleError(conn, fmt.Sprintf("error happened signing Ethereum transaction: %s", err), 500)
					return
				}

				v, r, s := signedTx.RawSignatureValues()
				log.Debugf("signedTx raw signature values: \n v: %v\n r: %v\ns: %v", v, r, s)

				signedTxSerialized, err := signedTx.MarshalBinary()
				if err != nil {
					enclave.HandleError(conn, fmt.Sprintf("error happened serializing signed Ethereum transaction: %s", err), 500)
					return
				}
				signedTxHex := hex.EncodeToString(signedTxSerialized)

				enclaveResult = signerTypes.EnclaveResult{
					Status: 200,
					Body: signerTypes.SignedTransaction{
						TxHash:   signedTx.Hash().Hex(),
						SignedTX: signedTxHex,
					},
				}
			} else {
				enclaveResult = signerTypes.EnclaveResult{
					Status: 400,
					Body: signerTypes.SignedTransaction{
						Error: fmt.Sprintf("passed transaction payload could not be processed: %v", enclavePayload.TransactionPayload),
					},
				}
			}

			enclaveResultSerialized, err := json.Marshal(enclaveResult)
			if err != nil {
				enclave.HandleError(conn, fmt.Sprintf("error happened serializing the enclave result: %s", err), 500)
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
