/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/

package main

import (
	signerTypes "aws/ethereum-signer/internal/types"
	"bytes"
	"crypto/ecdsa"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/go-playground/validator/v10"
	log "github.com/sirupsen/logrus"
	"math/big"
	"os/exec"
	"strconv"
	"strings"
)

var validate *validator.Validate

// todo wrap in known Nitro SDK errors
func filterNitroSDKError(error string) string {
	nitroSDKError := "Got non-200 answer from KMS"

	errorIdx := strings.Index(error, nitroSDKError)
	if errorIdx != -1 {
		return error[errorIdx:]
	} else {
		return error
	}
}

// todo make outbound proxy port configurable
func decryptCiphertext(credentials signerTypes.AWSCredentials, ciphertext string, vsockBasePort uint64, region string) (string, error) {
	cmd := []string{
		"decrypt",
		"--region",
		region,
		"--proxy-port",
		strconv.FormatUint(vsockBasePort, 10),
		"--aws-access-key-id",
		credentials.AccessKeyID,
		"--aws-secret-access-key",
		credentials.SecretAccessKey,
		"--aws-session-token",
		credentials.Token,
		"--ciphertext",
		ciphertext,
	}
	kmsDecryptCmd := exec.Command("/app/kmstool_enclave_cli", cmd...) // #nosec G204

	var resultOut, errOut bytes.Buffer
	kmsDecryptCmd.Stdout = &resultOut
	kmsDecryptCmd.Stderr = &errOut

	err := kmsDecryptCmd.Run()
	if err != nil {
		// todo filter error
		return "", fmt.Errorf("kmstool_enclave_cli exited with status different from 0: %s\nerror output: %s", err, filterNitroSDKError(errOut.String()))
	}

	// todo fix
	//log.Debugf("kmstool_enclave_cli raw output: %s", resultOut.String())

	resultComponents := strings.Split(resultOut.String(), ":")
	if len(resultComponents) != 2 {
		return "", errors.New("kmstool_enclave_cli result should have structure 'PLAINTEXT: <base64 encoded plaintext>'")
	}
	resultPlaintextB64 := strings.TrimSpace(resultComponents[1])

	return resultPlaintextB64, nil
}

func parsePlaintext(kmsResultB64 string) (signerTypes.PlainKey, error) {
	//log.Debugf("raw kmsResultB64: %v", kmsResultB64)

	kmsResult, err := b64.StdEncoding.DecodeString(kmsResultB64)
	if err != nil {
		return signerTypes.PlainKey{}, err
	}

	var userKey signerTypes.PlainKey

	err = json.Unmarshal(kmsResult, &userKey)
	if err != nil {
		return signerTypes.PlainKey{}, err
	}

	return userKey, nil
}

func timestampInRange(providedTimestamp, ownTimestamp, maxDelta int) bool {
	return ownTimestamp <= providedTimestamp+maxDelta
}

// https://github.com/ethereum/go-ethereum/issues/21221#issuecomment-802092592
func etherToWei(eth *big.Float) *big.Int {
	truncInt, _ := eth.Int(nil)
	truncInt = new(big.Int).Mul(truncInt, big.NewInt(params.Ether))
	fracStr := strings.Split(fmt.Sprintf("%.18f", eth), ".")[1]
	fracStr += strings.Repeat("0", 18-len(fracStr))
	fracInt, _ := new(big.Int).SetString(fracStr, 10)
	wei := new(big.Int).Add(truncInt, fracInt)
	return wei
}

func assembleEthereumTransaction(transactionPayload signerTypes.TransactionPayload) *ethTypes.Transaction {
	//log.Debugf("raw transaction payload: %v", transactionPayload)

	// todo edge cases here? error?
	chainID := big.NewInt(int64(transactionPayload.ChainID))
	to := common.HexToAddress(transactionPayload.To)
	maxFeePerGas := big.NewInt(int64(transactionPayload.MaxFeePerGas))
	maxPriorityFeePerGas := big.NewInt(int64(transactionPayload.MaxPriorityFeePerGas))
	var data []byte
	var value *big.Int

	if transactionPayload.Value != 0 {
		value = etherToWei(big.NewFloat(float64(transactionPayload.Value)))
	}

	if transactionPayload.Data != "" {
		data = []byte(transactionPayload.Data)
	}

	tx := ethTypes.NewTx(&ethTypes.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     uint64(transactionPayload.Nonce), //#nosec G115
		GasTipCap: maxPriorityFeePerGas,
		GasFeeCap: maxFeePerGas,
		Gas:       uint64(transactionPayload.Gas), //#nosec G115
		To:        &to,
		Value:     value,
		Data:      data,
	})

	return tx
}

// func signUserOps(userOpsHash *common.Hash, ethKey string) (string, error) {
func signUserOps(userOpsHash []byte, ethKey string) (string, error) {
	//log.Debugf("userOpsHashRaw: %v / ethKey %v", userOpsHash, ethKey)
	privateKey, err := crypto.HexToECDSA(ethKey)
	if err != nil {
		return "", err
	}
	// (signature.recoveryParam ? "0x1c": "0x1b")
	//https://developer.cargox.digital/examples/signing_with_go.html
	signature, err := crypto.Sign(userOpsHash[:], privateKey)
	if err != nil {
		return "", err
	}
	// ethers implementation to determine v (legacy recovery parameter) for signed messages
	log.Debugf("signature (orgiginal) v: %v", signature[64])
	signature[64] += byte(27)

	log.Debugf("signature (legacy) v: %v", signature[64])
	signatureEncoded := hexutil.Encode(signature)

	return signatureEncoded, nil
}

func signEthereumTransaction(assembledTx *ethTypes.Transaction, ethKey string) (*ethTypes.Transaction, error) {
	log.Debugf("assembledTxHash: %v / ethKey: %v", assembledTx.Hash(), ethKey)
	privateKey, err := crypto.HexToECDSA(ethKey)
	if err != nil {
		return &ethTypes.Transaction{}, err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return &ethTypes.Transaction{}, errors.New("error happened casting public key to ECDSA")
	}
	if publicKeyECDSA == nil {
		return &ethTypes.Transaction{}, errors.New("error happened casting public key to ECDSA")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	log.Debugf("assembling transaction for sender: %s", fromAddress.Hex())

	londonSigner := ethTypes.NewLondonSigner(assembledTx.ChainId())

	signedTx, err := ethTypes.SignTx(assembledTx, londonSigner, privateKey)
	if err != nil {
		return &ethTypes.Transaction{}, err
	}

	return signedTx, nil
}
