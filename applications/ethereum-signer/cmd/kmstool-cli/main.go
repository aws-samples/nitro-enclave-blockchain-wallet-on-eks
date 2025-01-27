package main

import (
	"aws/ethereum-signer/cmd/kmstool-cli/cmd"
	"os"
)

func main() {
	if err := cmd.NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
