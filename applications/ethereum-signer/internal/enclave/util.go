/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package enclave

import (
	signerTypes "aws/ethereum-signer/internal/types"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"net"
)

func HandleError(conn net.Conn, msg string, status int) {
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Errorf("error happened closing vsock connection: %s", err)
		}
	}(conn)
	switch status {
	case 500:
		log.Errorf(msg)
	case 403:
		log.Warnf(msg)
	}

	response, _ := json.Marshal(signerTypes.EnclaveResult{
		Status: status,
		Body: signerTypes.SignedTransaction{
			Error: msg,
		},
	})
	_, err := conn.Write(response)
	if err != nil {
		log.Errorf("error happened writing back result via vsock connect: %s", err)
	}
}
