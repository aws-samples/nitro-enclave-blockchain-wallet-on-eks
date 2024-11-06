package ethereum

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"
)

// func signUserOps(userOpsHash *common.Hash, ethKey string) (string, error) {
func SignUserOps(userOpsHash []byte, ethKey string) (string, error) {
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
	logrus.Debugf("signature (orgiginal) v: %v", signature[64])
	signature[64] += byte(27)

	logrus.Debugf("signature (legacy) v: %v", signature[64])
	signatureEncoded := hexutil.Encode(signature)

	return signatureEncoded, nil
}
