/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package main

import (
	"aws/ethereum-signer/internal/enclave"
	"github.com/go-playground/validator/v10"
	log "github.com/sirupsen/logrus"
)

var version = "undefined"
var validate = validator.New()

func main() {
	config, err := enclave.LoadConfig()
	if err != nil {
		log.Fatalf("failed loading config: %v", err)
	}

	server := NewSigningServer(config)
	if err := server.Initialize(); err != nil {
		log.Fatalf("server initialization failed: %v", err)
	}

	server.Run()
}
