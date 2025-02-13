package ethereum

import (
	"fmt"
	"github.com/ethereum/go-ethereum/params"
	"math/big"
	"strings"
)

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
