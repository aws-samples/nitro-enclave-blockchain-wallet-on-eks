/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	log "github.com/sirupsen/logrus"
	"strconv"
)

func CalculateHMAC(transactionPayloadSerialized []byte, secret string, timestamp int) string {
	log.Debugf("raw payload to sign: %s", transactionPayloadSerialized)

	transactionPayloadSerializedToSign := string(transactionPayloadSerialized) + strconv.Itoa(timestamp)
	log.Debugf("payload to sign: %s", transactionPayloadSerializedToSign)

	hmacFunc := hmac.New(sha256.New, []byte(secret))
	hmacFunc.Write([]byte(transactionPayloadSerializedToSign))
	hmacHex := hex.EncodeToString(hmacFunc.Sum(nil))

	return hmacHex
}

func TimestampInRange(providedTimestamp, ownTimestamp, maxDelta int) bool {
	return ownTimestamp <= providedTimestamp+maxDelta
}
