package ethereum

import (
	"aws/ethereum-signer/internal/types"
	"github.com/ethereum/go-ethereum/common/hexutil"
	types2 "github.com/ethereum/go-ethereum/core/types"
	"math/big"
	"reflect"
	"testing"
)

func Test_assembleEthereumTransaction(t *testing.T) {
	type args struct {
		transactionPayload types.TransactionPayload
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "ok",
			args: args{
				transactionPayload: types.TransactionPayload{
					Value:                0.01,
					To:                   "0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
					Nonce:                0,
					Type:                 2,
					ChainID:              5,
					Gas:                  100000,
					MaxFeePerGas:         100000000000,
					MaxPriorityFeePerGas: 3000000000,
					Data:                 "",
				}},
			want: "0xd7e35d4a5f46548a2469cebf6d5a9c4749829b7477b8f9355a1e40f329575ba6",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AssembleTransaction(tt.args.transactionPayload)
			if !reflect.DeepEqual(got.Hash().Hex(), tt.want) {
				t.Errorf("assembleEthereumTransaction() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_etherToWei(t *testing.T) {
	type args struct {
		eth *big.Float
	}
	tests := []struct {
		name string
		args args
		want *big.Int
	}{
		{name: "ok",
			args: args{eth: big.NewFloat(0.001)},
			want: big.NewInt(1000000000000000),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := etherToWei(tt.args.eth); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("etherToWei() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_signEthereumTransaction(t *testing.T) {
	r, _ := new(big.Int).SetString("52797251190525160680904325891953736147891461127620022141963968447794245047899", 10)
	s, _ := new(big.Int).SetString("39479225745237986495600255552539419729722647530016349795492341493095878075154", 10)
	type args struct {
		assembledTx *types2.Transaction
		ethKey      string
	}
	tests := []struct {
		name    string
		args    args
		want    []*big.Int
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				assembledTx: AssembleTransaction(types.TransactionPayload{
					Value:                0.01,
					To:                   "0xa5D3241A1591061F2a4bB69CA0215F66520E67cf",
					Nonce:                0,
					Type:                 2,
					ChainID:              5,
					Gas:                  100000,
					MaxFeePerGas:         100000000000,
					MaxPriorityFeePerGas: 3000000000,
					Data:                 "",
				}),
				ethKey: "372369f374c68952bcb2ba2e3f3802d41d51cb255446c27def96cc848605d679",
			},
			want: []*big.Int{
				big.NewInt(1),
				r,
				s,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignEthereumTransaction(tt.args.assembledTx, tt.args.ethKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("signEthereumTransaction() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			v, r, s := got.RawSignatureValues()
			gotSignature := []*big.Int{
				v,
				r,
				s,
			}
			if !reflect.DeepEqual(gotSignature, tt.want) {
				t.Errorf("signEthereumTransaction() got = %v, want %v", gotSignature, tt.want)
			}
		})
	}
}

func Test_signUserOps(t *testing.T) {
	bytes, _ := hexutil.Decode("0xf3df4bcb3b24437160ba86a88f41d522662ed994dddd11ac477cfc16e9a71869")

	type args struct {
		userOpsHash []byte
		ethKey      string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				userOpsHash: bytes,
				ethKey:      "4ed3992ca0c7dda74dd9e77adec683afce86605866f1020c063b5ae1b67159c4",
			},
			want:    "0xd154b7efa02c822051d61899bbeb1ee9887b8bcc30f4f549a3d49950f13ee02d2140ced835ef716a4648082c762a161e1764950523f3716e0d0a51672b30205d1c",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignUserOps(tt.args.userOpsHash, tt.args.ethKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("signUserOps() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("signUserOps() got = %v, want %v", got, tt.want)
			}
		})
	}
}
