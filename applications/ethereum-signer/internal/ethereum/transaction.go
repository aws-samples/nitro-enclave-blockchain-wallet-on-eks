package ethereum

import (
	signerTypes "aws/ethereum-signer/internal/types"
	"crypto/ecdsa"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"
	"math/big"

	ethTypes "github.com/ethereum/go-ethereum/core/types"
)

func SignEthereumTransaction(assembledTx *ethTypes.Transaction, ethKey string) (*ethTypes.Transaction, error) {
	logrus.Debugf("assembledTxHash: %v / ethKey: %v", assembledTx.Hash(), ethKey)
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
	logrus.Debugf("assembling transaction for sender: %s", fromAddress.Hex())

	londonSigner := ethTypes.NewLondonSigner(assembledTx.ChainId())

	signedTx, err := ethTypes.SignTx(assembledTx, londonSigner, privateKey)
	if err != nil {
		return &ethTypes.Transaction{}, err
	}

	return signedTx, nil
}

func AssembleTransaction(transactionPayload signerTypes.TransactionPayload) *ethTypes.Transaction {
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
