/*
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

SPDX-License-Identifier: MIT-0
*/
package main

import (
	aws2 "aws/ethereum-signer/internal/aws"
	"aws/ethereum-signer/internal/enclave"
	"aws/ethereum-signer/internal/keymanagement"
	"aws/ethereum-signer/internal/metrics"
	signerTypes "aws/ethereum-signer/internal/types"
	"bufio"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-playground/validator/v10"
	"github.com/mdlayher/vsock"
	log "github.com/sirupsen/logrus"
)

const (
	bufferSize  = 4096
	maxWorkers  = 10
	metricsCID  = 3
	metricsFreq = 10 * time.Second
)

type Server struct {
	config        *enclave.Config
	validate      *validator.Validate
	listener      *vsock.Listener
	metricsClient *metrics.Client
	connPool      chan struct{}
	bufferPool    *sync.Pool
}

func NewServer(config *enclave.Config) *Server {
	return &Server{
		config:   config,
		validate: validator.New(),
		connPool: make(chan struct{}, maxWorkers),
		bufferPool: &sync.Pool{
			New: func() interface{} {
				b := make([]byte, bufferSize)
				return &b
			},
		},
	}
}

func (s *Server) Initialize() error {
	if err := s.setupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	if err := s.setupVsockListener(); err != nil {
		return fmt.Errorf("failed to setup vsock listener: %w", err)
	}

	s.setupMetrics()
	// Demo code to produce sin shaped CPU load pattern - uncomment below to enable
	// s.startCPULoad()

	// Demo code to log hardware environment - uncomment below to enable
	// s.LogHardwareEnvironment()
	return nil
}

func (s *Server) setupLogging() error {
	logLevel, err := log.ParseLevel(s.config.LogLevel)
	if err != nil {
		return fmt.Errorf("invalid log level %s: %w", s.config.LogLevel, err)
	}
	log.SetLevel(logLevel)
	log.Infof("LOG_LEVEL=%s", logLevel)
	return nil
}

func (s *Server) setupVsockListener() error {
	contextID, err := vsock.ContextID()
	if err != nil {
		return fmt.Errorf("failed to get contextID: %w", err)
	}

	listener, err := vsock.ListenContextID(contextID, s.config.Port, nil)
	if err != nil {
		return fmt.Errorf("failed to create listener on port %v and contextID %v: %w",
			s.config.Port, contextID, err)
	}
	s.listener = listener
	return nil
}

func (s *Server) setupMetrics() {
	s.metricsClient = metrics.NewMetricsClient(metricsCID,
		s.config.Port+metrics.PortOffset, metricsFreq)
	s.metricsClient.Start()
	log.Infof("metrics client started with target cid: %d, port: %d",
		metricsCID, s.config.Port+metrics.PortOffset)
}

// startCPULoad generates CPU load following a sine wave pattern (10%-90%) on both vCPUs
func (s *Server) startCPULoad() {
	numCPUs := 2
	cycleDuration := 600 * time.Second // Full sine wave cycle (10 minutes)

	for i := 0; i < numCPUs; i++ {
		go func() {
			startTime := time.Now()
			for {
				// Calculate current position in sine wave (0 to 2π)
				elapsed := time.Since(startTime).Seconds()
				phase := (elapsed / cycleDuration.Seconds()) * 2 * 3.14159265359

				// Sine wave oscillates -1 to 1, scale to 0.10 to 0.90
				sineValue := (math.Sin(phase) + 1) / 2
				loadPercent := 0.10 + 0.80*sineValue

				// 100ms cycle: spin for loadPercent, sleep for rest
				cyclePeriod := 100 * time.Millisecond
				spinDuration := time.Duration(float64(cyclePeriod) * loadPercent)
				sleepDuration := cyclePeriod - spinDuration

				// Spin phase
				spinStart := time.Now()
				for time.Since(spinStart) < spinDuration {
					_ = 1 + 1
				}
				// Sleep phase
				time.Sleep(sleepDuration)
			}
		}()
	}
	log.Info("CPU load generator started (sine wave 10%-90% on 2 vCPUs, 10min cycle)")
}

func (s *Server) Run() {
	log.Info("starting listener for key generation requests")
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Errorf("failed accepting connection: %v", err)
			continue
		}

		s.connPool <- struct{}{} // acquire connection slot
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		err := conn.Close()
		if err != nil {
			log.Errorf("failed closing connection: %v", err)
			return
		}
		<-s.connPool // release connection slot
	}()

	payload, err := s.readAndValidatePayload(conn)
	if err != nil {
		enclave.HandleError(conn, err.Error(), 400)
		return
	}

	keyData, err := s.generateKeyPair()
	if err != nil {
		enclave.HandleError(conn, err.Error(), 500)
		return
	}

	if err := s.processAndStoreKey(conn, keyData, payload); err != nil {
		enclave.HandleError(conn, err.Error(), 500)
		return
	}
}

func (s *Server) readAndValidatePayload(conn net.Conn) (*signerTypes.EnclaveKeyGenerationPayload, error) {
	buf := *(s.bufferPool.Get().(*[]byte))
	defer s.bufferPool.Put(&buf)

	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed reading from connection: %w", err)
	}

	var payload signerTypes.EnclaveKeyGenerationPayload
	if err := json.Unmarshal(buf[:n], &payload); err != nil {
		return nil, fmt.Errorf("failed unmarshalling payload: %w", err)
	}

	if err := s.validate.Struct(payload); err != nil {
		return nil, fmt.Errorf("payload validation failed: %w", err)
	}

	return &payload, nil
}

func (s *Server) generateKeyPair() (*keyData, error) {
	ethPrivateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed generating Ethereum private key: %w", err)
	}

	publicKey, ok := ethPrivateKey.Public().(*ecdsa.PublicKey)
	if !ok || publicKey == nil {
		return nil, fmt.Errorf("invalid public key generated")
	}

	return &keyData{
		privateKey: ethPrivateKey,
		address:    crypto.PubkeyToAddress(*publicKey).Hex(),
	}, nil
}

type keyData struct {
	privateKey *ecdsa.PrivateKey
	address    string
}

func (s *Server) processAndStoreKey(conn net.Conn, kd *keyData, payload *signerTypes.EnclaveKeyGenerationPayload) error {
	plainKey := signerTypes.PlainKey{
		EthKey: hex.EncodeToString(kd.privateKey.D.Bytes()),
		Secret: payload.Secret,
	}

	kmsProvider, err := keymanagement.NewAWSKMSProvider(payload.Credential, s.config.Region, aws2.TCP, 0, 0)
	if err != nil {
		return fmt.Errorf("failed creating KMS provider: %w", err)
	}

	ddbProvider, err := keymanagement.NewAWSDDBProvider(payload.Credential, s.config.Region, aws2.TCP, 0, 0)
	if err != nil {
		return fmt.Errorf("failed creating DDB provider: %w", err)
	}

	keyID, err := keymanagement.EncryptAndSaveKey(kmsProvider, ddbProvider,
		payload.KeyARN, payload.SecretsTable, plainKey, kd.address)
	if err != nil {
		return fmt.Errorf("failed encrypting and saving key: %w", err)
	}

	return s.sendResponse(conn, keyID, kd.address)
}

func (s *Server) sendResponse(conn net.Conn, keyID, address string) error {
	response := signerTypes.EnclaveResult{
		Status: 200,
		Body: signerTypes.Ciphertext{
			KeyID:   keyID,
			Address: address,
		},
	}

	responseData, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed serializing response: %w", err)
	}

	if _, err := conn.Write(responseData); err != nil {
		return fmt.Errorf("failed writing response: %w", err)
	}

	return nil
}

// LogHardwareEnvironment logs detailed hardware environment information including
// CPU cores, memory, network interfaces, and disk configuration.
func (s *Server) LogHardwareEnvironment() {
	log.Debug("=== Hardware Environment Information ===")

	// CPU Information
	s.logCPUInfo()

	// Memory Information
	s.logMemoryInfo()

	// Network Information
	s.logNetworkInfo()

	// Disk Information
	s.logDiskInfo()

	log.Debug("=== End Hardware Environment Information ===")
}

func (s *Server) logCPUInfo() {
	log.Debugf("CPU Cores (logical): %d", runtime.NumCPU())
	log.Debugf("GOMAXPROCS: %d", runtime.GOMAXPROCS(0))
	log.Debugf("Go Version: %s", runtime.Version())
	log.Debugf("Architecture: %s", runtime.GOARCH)
	log.Debugf("OS: %s", runtime.GOOS)

	// Read /proc/cpuinfo for detailed CPU info (Linux-specific)
	if cpuInfo, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		lines := strings.Split(string(cpuInfo), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "model name") ||
				strings.HasPrefix(line, "cpu MHz") ||
				strings.HasPrefix(line, "cache size") {
				log.Debugf("CPU: %s", strings.TrimSpace(line))
			}
		}

		// Log raw /proc/cpuinfo content
		log.Debug("--- Raw /proc/cpuinfo ---")
		log.Debug(string(cpuInfo))
		log.Debug("--- End /proc/cpuinfo ---")
	} else {
		log.Debugf("CPU: unable to read /proc/cpuinfo: %v", err)
	}
}

func (s *Server) logMemoryInfo() {
	// Read /proc/meminfo for memory details (Linux-specific)
	if memInfo, err := os.ReadFile("/proc/meminfo"); err == nil {
		lines := strings.Split(string(memInfo), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "MemTotal") ||
				strings.HasPrefix(line, "MemFree") ||
				strings.HasPrefix(line, "MemAvailable") ||
				strings.HasPrefix(line, "Buffers") ||
				strings.HasPrefix(line, "Cached") ||
				strings.HasPrefix(line, "SwapTotal") ||
				strings.HasPrefix(line, "SwapFree") {
				log.Debugf("Memory: %s", strings.TrimSpace(line))
			}
		}
	} else {
		log.Debugf("Memory: unable to read /proc/meminfo: %v", err)
	}

	// Go runtime memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	log.Debugf("Go Heap Alloc: %d MB", memStats.HeapAlloc/1024/1024)
	log.Debugf("Go Heap Sys: %d MB", memStats.HeapSys/1024/1024)
	log.Debugf("Go Total Alloc: %d MB", memStats.TotalAlloc/1024/1024)
}

func (s *Server) logNetworkInfo() {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Debugf("Network: unable to get interfaces: %v", err)
		return
	}

	for _, iface := range interfaces {
		log.Debugf("Network Interface: %s (Index: %d, MTU: %d, Flags: %s)",
			iface.Name, iface.Index, iface.MTU, iface.Flags.String())

		if iface.HardwareAddr != nil {
			log.Debugf("  Hardware Address: %s", iface.HardwareAddr.String())
		}

		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				log.Debugf("  Address: %s", addr.String())
			}
		}
	}

	// Log vsock context ID if available
	if contextID, err := vsock.ContextID(); err == nil {
		log.Debugf("Vsock Context ID: %d", contextID)
	}
}

func (s *Server) logDiskInfo() {
	// Read /proc/mounts for mounted filesystems
	file, err := os.Open("/proc/mounts")
	if err != nil {
		log.Debugf("Disk: unable to read /proc/mounts: %v", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 {
			device := fields[0]
			mountPoint := fields[1]
			fsType := fields[2]
			options := fields[3]

			// Skip pseudo filesystems for cleaner output
			if strings.HasPrefix(device, "/dev/") || mountPoint == "/" {
				log.Debugf("Disk: %s mounted at %s (type: %s, options: %s)",
					device, mountPoint, fsType, options)
			}
		}
	}

	// Log disk usage for key directories
	for _, path := range []string{"/", "/tmp", "/var"} {
		if usage, err := getDiskUsage(path); err == nil {
			log.Debugf("Disk Usage [%s]: Total: %d MB, Free: %d MB, Used: %.1f%%",
				path, usage.total/1024/1024, usage.free/1024/1024, usage.usedPercent)
		}
	}
}

type diskUsage struct {
	total       uint64
	free        uint64
	usedPercent float64
}

func getDiskUsage(path string) (*diskUsage, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return nil, err
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	used := total - free
	usedPercent := float64(0)
	if total > 0 {
		usedPercent = float64(used) / float64(total) * 100
	}

	return &diskUsage{
		total:       total,
		free:        free,
		usedPercent: usedPercent,
	}, nil
}
