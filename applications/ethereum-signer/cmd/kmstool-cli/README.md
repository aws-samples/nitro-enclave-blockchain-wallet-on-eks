# kmstool-cli

`kmstool-cli` is a cli tool written in Go(lang) that supports sending decrypt
requests from inside AWS Nitro Enclaves leveraging cryptographic attestation.

## Build

Change with your terminal into this folder and execute the `go build` command:

```shell
cd applications/ethere um-signer/cmd/kmstool-cli
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

If `-v/--verbose` mode has been selected, all input paramters will be printed to `stdout` on the terminal in additon
to the base64 encoded plaintext.

**get help**

```shell
./kmstool-cli --help
```
