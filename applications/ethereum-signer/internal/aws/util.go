package aws

import (
	signerTypes "aws/ethereum-signer/internal/types"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/mdlayher/vsock"
	"golang.org/x/net/context"
	"net"
	"net/http"
	"time"
)

type ConnectionType int

const (
	VSOCK ConnectionType = iota
	TCP
)

type ConnectionConfig struct {
	connectionType ConnectionType
	contextID      uint32
	port           uint32
}

func NewConnectionConfig(connectionType ConnectionType, contextID uint32, port uint32) ConnectionConfig {
	if connectionType != VSOCK {
		return ConnectionConfig{
			connectionType: connectionType,
		}
	}

	return ConnectionConfig{
		connectionType: connectionType,
		contextID:      contextID,
		port:           port,
	}
}

func EnclaveSDKConfig(ephemeralCredentials signerTypes.AWSCredentials, region string, connectionConfig ConnectionConfig) (aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(ephemeralCredentials.AccessKeyID, ephemeralCredentials.SecretAccessKey, ephemeralCredentials.Token)))
	if err != nil {
		//enclave.HandleError(conn, fmt.Sprintf("configuration error: %s", err), 500)
		return aws.Config{}, err
	}
	cfg.Region = region
	cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	// replace dialer with vsock based approach if required, else rely on standard http dial out
	if connectionConfig.connectionType == VSOCK {
		cfg.HTTPClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network string, address string) (conn net.Conn, e error) {
					return vsock.Dial(connectionConfig.contextID, connectionConfig.port, nil)
				},
			},
		}
	}

	return cfg, nil
}
