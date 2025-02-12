/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/
package main

import (
	aws2 "aws/ethereum-signer/internal/aws"
	"aws/ethereum-signer/internal/enclave"
	"aws/ethereum-signer/internal/keymanagement"
	"aws/ethereum-signer/internal/metrics"
	signerTypes "aws/ethereum-signer/internal/types"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-playground/validator/v10"
	"github.com/mdlayher/vsock"
	log "github.com/sirupsen/logrus"
	"net"
	"sync"
	"time"
)

const (
	bufferSize  = 4096
	maxWorkers  = 10
	metricsCID  = 3
	metricsFreq = 10 * time.Second
)

type Server struct {
	config        *enclave.Config
	validate      *validator.Validate
	listener      *vsock.Listener
	metricsClient *metrics.Client
	connPool      chan struct{}
	bufferPool    *sync.Pool
}

func NewServer(config *enclave.Config) *Server {
	return &Server{
		config:   config,
		validate: validator.New(),
		connPool: make(chan struct{}, maxWorkers),
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, bufferSize)
			},
		},
	}
}

func (s *Server) Initialize() error {
	if err := s.setupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	if err := s.setupVsockListener(); err != nil {
		return fmt.Errorf("failed to setup vsock listener: %w", err)
	}

	s.setupMetrics()
	return nil
}

func (s *Server) setupLogging() error {
	logLevel, err := log.ParseLevel(s.config.LogLevel)
	if err != nil {
		return fmt.Errorf("invalid log level %s: %w", s.config.LogLevel, err)
	}
	log.SetLevel(logLevel)
	log.Infof("LOG_LEVEL=%s", logLevel)
	return nil
}

func (s *Server) setupVsockListener() error {
	contextID, err := vsock.ContextID()
	if err != nil {
		return fmt.Errorf("failed to get contextID: %w", err)
	}

	listener, err := vsock.ListenContextID(contextID, s.config.Port, nil)
	if err != nil {
		return fmt.Errorf("failed to create listener on port %v and contextID %v: %w",
			s.config.Port, contextID, err)
	}
	s.listener = listener
	return nil
}

func (s *Server) setupMetrics() {
	s.metricsClient = metrics.NewMetricsClient(metricsCID,
		s.config.Port+metrics.PortOffset, metricsFreq)
	s.metricsClient.Start()
	log.Infof("metrics client started with target cid: %d, port: %d",
		metricsCID, s.config.Port+metrics.PortOffset)
}

func (s *Server) Run() {
	log.Info("starting listener for key generation requests")
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Errorf("failed accepting connection: %v", err)
			continue
		}

		s.connPool <- struct{}{} // acquire connection slot
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		<-s.connPool // release connection slot
	}()

	payload, err := s.readAndValidatePayload(conn)
	if err != nil {
		enclave.HandleError(conn, err.Error(), 400)
		return
	}

	keyData, err := s.generateKeyPair()
	if err != nil {
		enclave.HandleError(conn, err.Error(), 500)
		return
	}

	if err := s.processAndStoreKey(conn, keyData, payload); err != nil {
		enclave.HandleError(conn, err.Error(), 500)
		return
	}
}

func (s *Server) readAndValidatePayload(conn net.Conn) (*signerTypes.EnclaveKeyGenerationPayload, error) {
	// todo https://staticcheck.dev/docs/checks/#SA6002
	buf := s.bufferPool.Get().([]byte)
	defer s.bufferPool.Put(buf)

	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed reading from connection: %w", err)
	}

	var payload signerTypes.EnclaveKeyGenerationPayload
	if err := json.Unmarshal(buf[:n], &payload); err != nil {
		return nil, fmt.Errorf("failed unmarshalling payload: %w", err)
	}

	if err := s.validate.Struct(payload); err != nil {
		return nil, fmt.Errorf("payload validation failed: %w", err)
	}

	return &payload, nil
}

func (s *Server) generateKeyPair() (*keyData, error) {
	ethPrivateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed generating Ethereum private key: %w", err)
	}

	publicKey, ok := ethPrivateKey.Public().(*ecdsa.PublicKey)
	if !ok || publicKey == nil {
		return nil, fmt.Errorf("invalid public key generated")
	}

	return &keyData{
		privateKey: ethPrivateKey,
		address:    crypto.PubkeyToAddress(*publicKey).Hex(),
	}, nil
}

type keyData struct {
	privateKey *ecdsa.PrivateKey
	address    string
}

func (s *Server) processAndStoreKey(conn net.Conn, kd *keyData, payload *signerTypes.EnclaveKeyGenerationPayload) error {
	plainKey := signerTypes.PlainKey{
		EthKey: hex.EncodeToString(kd.privateKey.D.Bytes()),
		Secret: payload.Secret,
	}

	kmsProvider, err := keymanagement.NewAWSKMSProvider(payload.Credential, s.config.Region, aws2.TCP, 0, 0)
	if err != nil {
		return fmt.Errorf("failed creating KMS provider: %w", err)
	}

	ddbProvider, err := keymanagement.NewAWSDDBProvider(payload.Credential, s.config.Region, aws2.TCP, 0, 0)
	if err != nil {
		return fmt.Errorf("failed creating DDB provider: %w", err)
	}

	keyID, err := keymanagement.EncryptAndSaveKey(kmsProvider, ddbProvider,
		payload.KeyARN, payload.SecretsTable, plainKey, kd.address)
	if err != nil {
		return fmt.Errorf("failed encrypting and saving key: %w", err)
	}

	return s.sendResponse(conn, keyID, kd.address)
}

func (s *Server) sendResponse(conn net.Conn, keyID, address string) error {
	response := signerTypes.EnclaveResult{
		Status: 200,
		Body: signerTypes.Ciphertext{
			KeyID:   keyID,
			Address: address,
		},
	}

	responseData, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed serializing response: %w", err)
	}

	if _, err := conn.Write(responseData); err != nil {
		return fmt.Errorf("failed writing response: %w", err)
	}

	return nil
}
