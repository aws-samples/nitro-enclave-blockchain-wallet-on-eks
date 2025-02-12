/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package main

import (
	"aws/ethereum-signer/internal/enclave"
	log "github.com/sirupsen/logrus"
)

var version = "undefined"

func main() {
	log.Infof("starting key generation enclave (%s)", version)

	config, err := enclave.LoadConfig()
	if err != nil {
		log.Fatalf("failed loading config: %s", err)
	}

	server := NewServer(config)
	if err := server.Initialize(); err != nil {
		log.Fatalf("failed initializing server: %s", err)
	}

	server.Run()
}
