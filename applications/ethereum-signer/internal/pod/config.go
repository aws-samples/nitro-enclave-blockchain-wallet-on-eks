package pod

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	LogLevel      string
	CertFile      string
	KeyFile       string
	ListenAddress string
	EnclaveCID    uint64
	EnclavePort   uint64
}

func LoadConfig() (*Config, error) {
	config := &Config{
		LogLevel:      os.Getenv("LOG_LEVEL"),
		CertFile:      os.Getenv("CERT_FILE"),
		KeyFile:       os.Getenv("KEY_FILE"),
		ListenAddress: os.Getenv("LISTEN_ADDRESS"),
	}

	// Validate required fields
	requiredEnvs := map[string]string{
		"CERT_FILE":      config.CertFile,
		"KEY_FILE":       config.KeyFile,
		"LISTEN_ADDRESS": config.ListenAddress,
	}

	for env, value := range requiredEnvs {
		if value == "" {
			return nil, fmt.Errorf("%s cannot be empty", env)
		}
	}

	// Parse Enclave CID
	enclaveCID := os.Getenv("ENCLAVE_CID")
	if enclaveCID == "" {
		return nil, fmt.Errorf("ENCLAVE_CID cannot be empty")
	}
	cid, err := strconv.ParseUint(enclaveCID, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ENCLAVE_CID: %w", err)
	}
	config.EnclaveCID = cid

	// Parse Enclave Port
	enclavePort := os.Getenv("VSOCK_BASE_PORT")
	if enclavePort == "" {
		return nil, fmt.Errorf("VSOCK_BASE_PORT cannot be empty")
	}
	port, err := strconv.ParseUint(enclavePort, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VSOCK_BASE_PORT: %w", err)
	}
	config.EnclavePort = port

	return config, nil
}
