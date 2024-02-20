/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package main

import (
	"aws/ethereum-signer/internal/metrics"
	"context"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"os"
	"strconv"
)

func main() {
	logLevel, err := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		log.Fatalf("LOG_LEVEL value (%s) could not be parsed: %s", os.Getenv("LOG_LEVEL"), err)
	}

	certFile := os.Getenv("CERT_FILE")
	if certFile == "" {
		log.Fatalf("CERT_FILE cannot be empty")
	}

	keyFile := os.Getenv("KEY_FILE")
	if keyFile == "" {
		log.Fatalf("KEY_FILE cannot be empty")
	}

	listenAddress := os.Getenv("LISTEN_ADDRESS")
	if listenAddress == "" {
		log.Fatalf("LISTEN_ADDRESS cannot be empty")
	}

	secretsTable := os.Getenv("SECRETS_TABLE")
	if len(secretsTable) == 0 {
		log.Fatalf("SECRETS_TABLE cannot be empty")
	}

	enclaveCID := os.Getenv("ENCLAVE_CID")
	if enclaveCID == "" {
		log.Fatalf("ENCLAVE_CID cannot be empty")
	}
	enclaveCIDInt, err := strconv.ParseInt(enclaveCID, 10, 64)
	if err != nil {
		log.Fatalf("exception happened converting ENCLAVE_PORT string (%v) to int: %s", enclaveCID, err)
	}
	enclavePort := os.Getenv("VSOCK_BASE_PORT")
	if enclavePort == "" {
		log.Fatalf("ENCLAVE_PORT cannot be empty")
	}
	enclavePortInt, err := strconv.ParseInt(enclavePort, 10, 64)
	if err != nil {
		log.Fatalf("exception happened converting ENCLAVE_PORT string (%v) to int: %s", enclavePort, err)
	}

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("failed to load SDK configuration, %v", err)
	}

	env := &Env{
		config:       &cfg,
		secretsTable: secretsTable,
		enclavePort:  enclavePortInt,
		enclaveCID:   enclaveCIDInt}

	log.SetLevel(logLevel)

	log.Infof("starting enclave metrics agent")
	listenerPort := uint32(enclavePortInt + 1)
	metricsServer := metrics.NewMetricsServer(3, listenerPort)
	err = metricsServer.Start()
	if err != nil {
		log.Fatalf("failed to start metrics server on CID: %v, port: %v", 3, listenerPort)
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.POST("/", env.signTransaction)

	log.Infof("starting server on %s", listenAddress)
	err = router.RunTLS(listenAddress, certFile, keyFile)
	if err != nil {
		log.Fatalf("exception happend starting server on %s", listenAddress)
	}
}
