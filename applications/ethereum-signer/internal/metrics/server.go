package metrics

import (
	metricTypes "aws/ethereum-signer/internal/types"
	"encoding/json"
	"fmt"
	"github.com/mdlayher/vsock"
	"github.com/prozz/aws-embedded-metrics-golang/emf"
	log "github.com/sirupsen/logrus"
	"net"
	"os"
	"strings"
)

const (
	PortOffset = 10
)

type Server struct {
	cid            uint32
	port           uint32
	podName        string
	nodeName       string
	deploymentName string
}

func NewMetricsServer(cid uint32, port uint32) *Server {

	return &Server{
		cid:            cid,
		port:           port,
		podName:        os.Getenv("POD_NAME"),
		nodeName:       os.Getenv("NODE_NAME"),
		deploymentName: strings.Join(strings.Split(os.Getenv("POD_NAME"), "-")[0:3], "-"),
	}
}

func (ms *Server) listen() (net.Listener, error) {
	var ln net.Listener
	var err error

	ln, err = vsock.ListenContextID(ms.cid, ms.port, nil)
	if err != nil {
		return nil, err
	}

	return ln, nil
}

func (ms *Server) handleIncomingMetrics() error {
	ln, err := ms.listen()
	if err != nil {
		return err
	}

	log.Infof("Listening for incoming metrics on %v:%v", ms.cid, ms.port)

	// todo spawn go routine in go routine or just have for in main thread?
	go func() {
		for {
			inMetrics, err := ln.Accept()
			if err != nil {
				log.Errorf("error happened accepted incoming metrics push request: %s", err)
				continue
			}

			buf := make([]byte, 512)

			n, err := inMetrics.Read(buf)
			if err != nil {
				log.Errorf("exception happened reading from incoming connection: %s", err)
			}
			log.Infof(fmt.Sprintf("read buffer length: %v", n))
			log.Debugf("raw enclave metrics: %s", buf)

			enclaveSystemMetrics := metricTypes.EnclaveSystemMetrics{}

			err = json.Unmarshal(buf[:n], &enclaveSystemMetrics)
			if err != nil {
				log.Errorf("exception happened unmarshalling metrics payload: %s", err)
				continue
			}
			log.Debugf("unmarshaled enclave metrics payload: %v", enclaveSystemMetrics)

			ms.createEMFLogs(
				enclaveSystemMetrics.CPUConsumptionUser,
				enclaveSystemMetrics.CPUConsumptionSystem,
				enclaveSystemMetrics.MemoryUsed,
				enclaveSystemMetrics.MemoryCached,
			)

			err = inMetrics.Close()
			if err != nil {
				log.Errorf("error happened closing incoming metrics push request: %s", err)
			}
		}
	}()
	return nil
}

func (ms *Server) Start() error {
	err := ms.handleIncomingMetrics()

	return err
}

func (ms *Server) createEMFLogs(enclaveCPUUser int, enclaveCPUSystem int, enclaveMemoryUsed int, enclaveMemoryCached int) {
	emf.New(emf.WithoutDimensions()).Namespace("NitroEnclave").DimensionSet(
		emf.NewDimension("NodeName", ms.nodeName),
		emf.NewDimension("Deployment", ms.deploymentName),
		emf.NewDimension("Pod", ms.podName)).
		MetricsAs(map[string]int{
			"enclave_memory_utilization_used":   enclaveMemoryUsed,
			"enclave_memory_utilization_cached": enclaveMemoryCached,
			"enclave_cpu_utilization_user":      enclaveCPUUser,
			"enclave_cpu_utilization_system":    enclaveCPUSystem}, emf.Percent).Log()
}
