# kmstool-cli

`kmstool-cli` is a cli tool written in Go(lang) that supports sending decrypt
requests from inside AWS Nitro Enclaves leveraging cryptographic attestation.

## Build

Change with your terminal into this folder and execute the `go build` command:

```shell
cd applications/ethereum-signer/cmd/kmstool-cli
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.Version=v0.0.1 -X main.BuildTime=$(date -u +'%Y-%m-%d_%H:%M:%S')" -o kmstool-cli
```

## Usage

**decrypt request**

```shell
./kmstool-cli decrypt \
    --region us-west-2 \
    --proxy-port 8000 \
    --aws-access-key-id ACCESS_KEY \
    --aws-secret-access-key SECRET_KEY \
    --aws-session-token SESSION_TOKEN \
    --ciphertext BASE64_ENCODED_TEXT \
    --encryption-context key1=value1,key2=value2 \
    --key-id KEY_ID \
    --encryption-algorithm ALGORITHM
````

If `decryption` worked successfully, the base64 encoded plaintext will be printed on `stdoout` without any
leading or trailing characters, thus the based64 encoded string can directly be processed.

**show version information that has been specified during build time**

```shell
./kmstool-cli --version
```

**use verbose mode with decrypt command**

```shell
./kmstool-cli decrypt --region us-west-2 --ciphertext BASE64_TEXT -v
```

If `-v/--verbose` mode has been selected, all input parameters will be printed to `stdout` on the terminal in additon
to the base64 encoded plaintext.

**deactivate ephemeral key for decrypt command**
```shell
./kmstool-cli decrypt --region us-west-2 --ciphertext BASE64_TEXT -v --ephemeral-key false
```

Key will be generated the first time the cli is run and stored in env var. Subsequent calls will
load the RSA private key from env instead of regenerating it for every run. 

Using the [aws-nitro-enclave-blockchain-wallet](https://github.com/aws-samples/aws-nitro-enclave-blockchain-wallet?tab=readme-ov-file) as
a standard testing harness, setting the `--ephemeral-key` flag to `false`, on average saves avg. `~50/60ms` on the RSA key generation step.

**get help**

```shell
./kmstool-cli --help
```
