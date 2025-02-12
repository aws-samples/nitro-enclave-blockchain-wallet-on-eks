package enclave

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	LogLevel string
	Region   string
	Port     uint32
}

func LoadConfig() (*Config, error) {
	port := os.Getenv("PORT")
	if port == "" {
		return nil, fmt.Errorf("PORT cannot be empty")
	}

	portInt, err := strconv.ParseUint(port, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid port number: %v", err)
	}

	region := os.Getenv("REGION")
	if region == "" {
		return nil, fmt.Errorf("REGION cannot be empty")
	}

	return &Config{
		LogLevel: os.Getenv("LOG_LEVEL"),
		Region:   region,
		Port:     uint32(portInt),
	}, nil
}
