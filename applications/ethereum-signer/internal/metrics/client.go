package metrics

import (
	"aws/ethereum-signer/internal/types"
	"encoding/json"
	"github.com/mackerelio/go-osstat/cpu"
	"github.com/mackerelio/go-osstat/memory"
	"github.com/mdlayher/vsock"
	log "github.com/sirupsen/logrus"
	"math"
	"time"
)

type Client struct {
	cid       uint32
	port      uint32
	frequency time.Duration
}

func NewMetricsClient(cid uint32, port uint32, frequency time.Duration) *Client {
	return &Client{
		cid:       cid,
		port:      port,
		frequency: frequency,
	}
}

func (mc *Client) Start() {
	go mc.logSystemStats()
}

func (mc *Client) monitorSystemCPU() (int, int, error) {
	before, err := cpu.Get()
	if err != nil {
		return 0.0, 0.0, err
	}
	time.Sleep(time.Duration(1) * time.Second)
	after, err := cpu.Get()
	if err != nil {
		return 0.0, 0.0, err
	}
	total := float64(after.Total - before.Total)
	cpuUser := int(math.Round(float64(after.User-before.User) / total * 100))
	cpuSystem := int(math.Round(float64(after.System-before.System) / total * 100))
	log.Infof("cpuUser: %v, cpuSystem: %v", cpuUser, cpuSystem)

	return cpuUser, cpuSystem, nil
}

func (mc *Client) monitorSystemMemory() (int, int, error) {
	memory, err := memory.Get()
	if err != nil {
		return 0.0, 0.0, err
	}
	memoryUsed := int(math.Round(float64(memory.Used) / float64(memory.Total) * 100))
	memoryCached := int(math.Round(float64(memory.Cached) / float64(memory.Total) * 100))
	log.Infof("memoryUsed: %v, memoryCached: %v", memoryUsed, memoryCached)

	return memoryUsed, memoryCached, nil
}

func (mc *Client) pushToMetricsServer(enclaveMetrics types.EnclaveSystemMetrics) error {
	metricsSerialized, err := json.Marshal(enclaveMetrics)
	if err != nil {
		return err
	}
	log.Debugf("serialized metrics payload: %q", metricsSerialized)

	conn, err := vsock.Dial(mc.cid, mc.port, nil)
	if err != nil {
		return err
	}

	_, err = conn.Write(metricsSerialized)
	if err != nil {
		return err
	}

	err = conn.Close()
	if err != nil {
		return err
	}
	return nil
}

func (mc *Client) logSystemStats() {
	for range time.Tick(mc.frequency) {
		cpuUser, cpuSystem, err := mc.monitorSystemCPU()
		if err != nil {
			log.Errorf("error happened gathering cpu metrics: %s", err)
		}

		memoryUsed, memoryCached, err := mc.monitorSystemMemory()
		if err != nil {
			log.Errorf("error happened gethering memory metrics: %s", err)
		}

		// convert to int, no float precession required for CW metrics/alarms
		metrics := types.EnclaveSystemMetrics{
			Timestamp:            0,
			CPUConsumptionUser:   cpuUser,
			CPUConsumptionSystem: cpuSystem,
			MemoryUsed:           memoryUsed,
			MemoryCached:         memoryCached,
		}

		err = mc.pushToMetricsServer(metrics)
		if err != nil {
			log.Errorf("error happened pushing out metrics: %s\npayload: %v", err, metrics)
		}
	}
}
