/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package main

import (
	"aws/ethereum-signer/internal/pod"
	"context"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	log "github.com/sirupsen/logrus"
)

// todo add build time and version tag
var version = "undefined"

func main() {
	log.Infof("starting signing pod (%s)", version)

	// Load configuration
	config, err := pod.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Setup logging
	if err := setupLogging(config.LogLevel); err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}

	// Load AWS configuration
	awsCfg, err := awsConfig.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("Failed to load SDK configuration: %v", err)
	}

	router := setupRouter(&awsCfg, config.EnclaveCID, config.EnclavePort)

	// Setup metrics server
	log.Infof("starting enclave metrics agent")
	if err := setupMetricsServer(config.EnclavePort); err != nil {
		log.Fatalf("Failed to setup metrics server: %v", err)
	}

	// Start TLS server
	log.Infof("starting server on %s", config.ListenAddress)
	if err := router.RunTLS(config.ListenAddress, config.CertFile, config.KeyFile); err != nil {
		log.Fatalf("Failed to start server on %s: %v", config.ListenAddress, err)
	}
}
