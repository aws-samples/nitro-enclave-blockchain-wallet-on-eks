package hmac

import "testing"

func TestCalculateHMAC(t *testing.T) {
	type args struct {
		transactionPayloadSerialized []byte
		secret                       string
		timestamp                    int
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{name: "userop_hash_ok",
			args: args{
				transactionPayloadSerialized: []byte("{\"userOpHash\":\"0xf3df4bcb3b24437160ba86a88f41d522662ed994dddd11ac477cfc16e9a71869\"}"),
				secret:                       "9779d2b8f0bc495b1691ce1a2baf800453e18a58d4eea8bf1fe996a0ab291dba",
				timestamp:                    1702632823,
			},
			want: "b9ccfaf082645190ceb443de71b5b534ffc176e78471b0eaec4ed492610d3def",
		},
		{name: "eth_tx_hash_ok",
			args: args{
				transactionPayloadSerialized: []byte("{\"chainId\":5,\"gas\":100000,\"maxFeePerGas\":100000000000,\"maxPriorityFeePerGas\":3000000000,\"nonce\":0,\"to\":\"0xa5D3241A1591061F2a4bB69CA0215F66520E67cf\",\"type\":2,\"value\":0.01}"),
				secret:                       "9779d2b8f0bc495b1691ce1a2baf800453e18a58d4eea8bf1fe996a0ab291dba",
				timestamp:                    1702632821,
			},
			want: "ec6aabbc51be4c5a09938dc1fc6d3ccd677c9c804ee0813f127f810b44699641",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CalculateHMAC(tt.args.transactionPayloadSerialized, tt.args.secret, tt.args.timestamp)
			if got != tt.want {
				t.Errorf("CalculateHMAC() got = %v, want %v", got, tt.want)
			}
		})
	}
}
