/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/
package main

import (
	"aws/ethereum-signer/internal/attestation"
	aws2 "aws/ethereum-signer/internal/aws"
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
	"net"
	"sync"
	"time"
)

const (
	bufferSize      = 4096
	maxWorkers      = 10
	metricsCID      = 3
	metricsInterval = 10 * time.Second
	requestTimeout  = 60 * time.Second
)

type SigningServer struct {
	config        *enclave.Config
	validate      *validator.Validate
	listener      *vsock.Listener
	metricsClient *metrics.Client
	connPool      chan struct{}
	bufferPool    *sync.Pool
}

func NewSigningServer(config *enclave.Config) *SigningServer {
	return &SigningServer{
		config:   config,
		validate: validator.New(),
		connPool: make(chan struct{}, maxWorkers),
		bufferPool: &sync.Pool{
			New: func() interface{} {
				b := make([]byte, bufferSize)
				return &b
			},
		},
	}
}

func (s *SigningServer) Initialize() error {
	if err := s.setupLogging(); err != nil {
		return fmt.Errorf("logging setup failed: %w", err)
	}

	if err := s.setupVsockListener(); err != nil {
		return fmt.Errorf("vsock listener setup failed: %w", err)
	}

	s.setupMetrics()
	return nil
}

func (s *SigningServer) setupLogging() error {
	logLevel, err := log.ParseLevel(s.config.LogLevel)
	if err != nil {
		return fmt.Errorf("invalid log level %s: %w", s.config.LogLevel, err)
	}
	log.SetLevel(logLevel)
	log.Infof("LOG_LEVEL=%s", logLevel)
	return nil
}

func (s *SigningServer) setupVsockListener() error {
	contextID, err := vsock.ContextID()
	if err != nil {
		return fmt.Errorf("failed to get contextID: %w", err)
	}

	listener, err := vsock.ListenContextID(contextID, s.config.Port, nil)
	if err != nil {
		return fmt.Errorf("failed to create listener on port %v: %w", s.config.Port, err)
	}
	s.listener = listener
	return nil
}

func (s *SigningServer) setupMetrics() {
	s.metricsClient = metrics.NewMetricsClient(metricsCID,
		s.config.Port+metrics.PortOffset, metricsInterval)
	s.metricsClient.Start()
	log.Infof("metrics client started with target cid: %d, port: %d",
		metricsCID, s.config.Port+metrics.PortOffset)
}

func (s *SigningServer) Run() {
	log.Infof("starting signing enclave (%s)", version)
	log.Info("start listening for signing requests")

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Errorf("connection accept failed: %v", err)
			continue
		}

		s.connPool <- struct{}{} // acquire connection slot
		go s.handleConnection(conn)
	}
}

func (s *SigningServer) handleConnection(conn net.Conn) {
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Errorf("failed to close connection: %v", err)
			return
		}
		<-s.connPool // release connection slot
	}()

	payload, err := s.readAndValidatePayload(conn)
	if err != nil {
		enclave.HandleError(conn, err.Error(), 400)
		return
	}

	userKey, err := s.decryptAndVerifyKey(payload)
	if err != nil {
		enclave.HandleError(conn, err.Error(), 500)
		return
	}

	if err := s.verifyHMAC(payload, userKey); err != nil {
		enclave.HandleError(conn, err.Error(), 403)
		return
	}

	if err := s.processAndSignTransaction(conn, payload, userKey); err != nil {
		enclave.HandleError(conn, err.Error(), 500)
		return
	}
}

func (s *SigningServer) readAndValidatePayload(conn net.Conn) (*signerTypes.EnclaveSigningPayload, error) {
	buf := *(s.bufferPool.Get().(*[]byte))
	defer s.bufferPool.Put(&buf)

	if err := conn.SetReadDeadline(time.Now().Add(requestTimeout)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed reading from connection: %w", err)
	}

	var payload signerTypes.EnclaveSigningPayload
	if err := json.Unmarshal(buf[:n], &payload); err != nil {
		return nil, fmt.Errorf("failed unmarshalling payload: %w", err)
	}

	if err := s.validate.Struct(payload); err != nil {
		return nil, fmt.Errorf("payload validation failed: %w", err)
	}

	return &payload, nil
}

func (s *SigningServer) decryptAndVerifyKey(payload *signerTypes.EnclaveSigningPayload) (*signerTypes.PlainKey, error) {
	kmsProvider, err := keymanagement.NewAWSKMSProvider(
		payload.Credential,
		s.config.Region,
		aws2.VSOCK,
		metricsCID,
		s.config.Port,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS provider: %w", err)
	}

	attestationStart := time.Now()
	plaintextSDKB64, err := keymanagement.DecryptCiphertextWithAttestation(
		payload.EncryptedKey,
		&keymanagement.AdvancedDecOpts{EphemeralRSAKey: false},
		&attestation.NitroAttestationProvider{},
		kmsProvider,
	)
	if err != nil {
		return nil, fmt.Errorf("attestation decryption failed: %w", err)
	}

	log.Infof("attestation duration: %dms", time.Since(attestationStart).Milliseconds())

	plaintext, err := keymanagement.ParsePlaintext(plaintextSDKB64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse plaintext: %w", err)
	}

	return &plaintext, err
}

func (s *SigningServer) verifyHMAC(payload *signerTypes.EnclaveSigningPayload, userKey *signerTypes.PlainKey) error {
	payloadSerialized, err := json.Marshal(payload.TransactionPayload)
	if err != nil {
		return fmt.Errorf("failed to serialize payload: %w", err)
	}

	calculatedHMAC := signerHMAC.CalculateHMAC(payloadSerialized, userKey.Secret, payload.Timestamp)
	if !hmac.Equal([]byte(calculatedHMAC), []byte(payload.HMAC)) {
		return fmt.Errorf("HMAC verification failed")
	}

	if !signerHMAC.TimestampInRange(payload.Timestamp, int(time.Now().Unix()), 60) {
		return fmt.Errorf("request has expired")
	}

	return nil
}

func (s *SigningServer) processAndSignTransaction(conn net.Conn, payload *signerTypes.EnclaveSigningPayload, userKey *signerTypes.PlainKey) error {

	payloadBytes, err := json.Marshal(payload.TransactionPayload)
	if err != nil {
		return fmt.Errorf("exception happened marshaling payload: %s", err)
	}

	var signedTx *signerTypes.SignedTransaction
	// todo add explicit type definition for tx type
	if _, ok := payload.TransactionPayload["userOpHash"]; ok {
		signedTx, err = s.processUserOperationTx(payloadBytes, userKey)
		if err != nil {
			//enclave.HandleError(conn, "failed to process user operation transaction", 500)
			return err
		}
	} else if _, ok := payload.TransactionPayload["to"]; ok {
		signedTx, err = s.processDynamicFeeTx(payloadBytes, userKey)
		if err != nil {
			//enclave.HandleError(conn, "failed to process user operation transaction", 500)
			return err
		}
	} else {
		return fmt.Errorf("unsupported transaction type")
	}

	// todo Process the transaction based on its type
	//var signedTx interface{}
	//switch payload.TransactionPayload.Type {
	//case "1559":
	//	signedTx, err = s.processDynamicFeeTx(payload.TransactionPayload, privateKeyECDSA)
	//case "2930":
	//	signedTx, err = s.processAccessListTx(payload.TransactionPayload, privateKeyECDSA)
	//case "legacy":
	//	signedTx, err = s.processLegacyTx(payload.TransactionPayload, privateKeyECDSA)
	//default:
	//	return fmt.Errorf("unsupported transaction type: %s", payload.TransactionPayload.Type)
	//}

	if err != nil {
		return fmt.Errorf("failed to process transaction: %w", err)
	}

	return s.sendSignedTransaction(conn, signedTx)
}

func (s *SigningServer) processUserOperationTx(payload []byte, privateKey *signerTypes.PlainKey) (*signerTypes.SignedTransaction, error) {

	var userOpPayload signerTypes.UserOpPayload
	err := json.Unmarshal(payload, &userOpPayload)
	if err != nil {
		return nil, fmt.Errorf("exception happened determining the type of UserOpPayload: %s", err)
	}

	err = validate.Struct(userOpPayload)
	if err != nil {
		validationErrors := err.(validator.ValidationErrors)
		return nil, fmt.Errorf("userOp payload validation failed: %v", validationErrors)
	}

	// requires string to start with 0x
	bytes, err := hexutil.Decode(userOpPayload.UserOpHash)
	if err != nil {
		//enclave.HandleError(conn, fmt.Sprintf("error happened converting provided UserOp hash to bytes: %s", err), 500)
	}

	userOpSignature, err := ethereum.SignUserOps(bytes, privateKey.EthKey)
	if err != nil {
		return nil, fmt.Errorf("error happened signing UserOp hash: %s", err)

	}
	log.Debugf("user ops raw signature: %v", userOpSignature)

	return &signerTypes.SignedTransaction{
		Signature: userOpSignature,
	}, nil
}

// todo interface for dynamic signature type
func (s *SigningServer) sendSignedTransaction(conn net.Conn, signedTx *signerTypes.SignedTransaction) error {
	response := signerTypes.EnclaveResult{
		Status: 200,
		Body:   signedTx,
	}

	responseData, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	if err := conn.SetWriteDeadline(time.Now().Add(requestTimeout)); err != nil {
		return fmt.Errorf("failed to set write deadline: %w", err)
	}

	if _, err := conn.Write(responseData); err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}

	return nil
}

func (s *SigningServer) processDynamicFeeTx(payload []byte, privateKey *signerTypes.PlainKey) (*signerTypes.SignedTransaction, error) {
	var transactionPayload signerTypes.TransactionPayload
	err := json.Unmarshal(payload, &transactionPayload)
	if err != nil {
		//enclave.HandleError(conn, fmt.Sprintf("incoming EIP1559 transacation signing request could not be unmarshalld: %s", err), 400)
		return nil, fmt.Errorf("incoming EIP1559 transacation signing request could not be unmarshalld: %s", err)
	}
	assembledTx := ethereum.AssembleTransaction(transactionPayload)

	err = validate.Struct(transactionPayload)
	if err != nil {
		validationErrors := err.(validator.ValidationErrors)
		//enclave.HandleError(conn, fmt.Sprintf("incoming EIP1559 transacation signing request faild verification: %s", validationErrors), 400)
		return nil, fmt.Errorf("incoming EIP1559 transacation signing request faild verification: %s", validationErrors)
	}

	signedTx, err := ethereum.SignEthereumTransaction(assembledTx, privateKey.EthKey)
	if err != nil {
		//enclave.HandleError(conn, fmt.Sprintf("error happened signing Ethereum transaction: %s", err), 500)
		return nil, fmt.Errorf("error happened signing Ethereum transaction: %s", err)
	}

	v, r, sVal := signedTx.RawSignatureValues()
	log.Debugf("signedTx raw signature values: \n v: %v\n r: %v\ns: %v", v, r, sVal)

	signedTxSerialized, err := signedTx.MarshalBinary()
	if err != nil {
		//enclave.HandleError(conn, fmt.Sprintf("error happened serializing signed Ethereum transaction: %s", err), 500)
		return nil, fmt.Errorf("error happened serializing signed Ethereum transaction: %s", err)

	}
	signedTxHex := hex.EncodeToString(signedTxSerialized)

	return &signerTypes.SignedTransaction{
		TxHash:   signedTx.Hash().Hex(),
		SignedTX: signedTxHex,
	}, nil
}
