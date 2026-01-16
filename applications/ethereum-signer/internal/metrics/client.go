package metrics

import (
	"aws/ethereum-signer/internal/types"
	"encoding/json"
	"math"
	"time"

	"github.com/mackerelio/go-osstat/cpu"
	"github.com/mackerelio/go-osstat/memory"
	"github.com/mdlayher/vsock"
	log "github.com/sirupsen/logrus"
)

type Client struct {
	cid          uint32
	port         uint32
	emitInterval time.Duration
	sampleRate   time.Duration
}

func NewMetricsClient(cid uint32, port uint32, emitInterval time.Duration) *Client {
	return &Client{
		cid:          cid,
		port:         port,
		emitInterval: emitInterval,
		sampleRate:   1 * time.Second, // Sample every 1s for spike detection
	}
}

func (mc *Client) Start() {
	go mc.collectAndEmitMetrics()
}

func (mc *Client) monitorSystemCPU() (int, int, error) {
	before, err := cpu.Get()
	if err != nil {
		return 0, 0, err
	}
	time.Sleep(time.Duration(1) * time.Second)
	after, err := cpu.Get()
	if err != nil {
		return 0, 0, err
	}
	total := float64(after.Total - before.Total)
	cpuUser := int(math.Round(float64(after.User-before.User) / total * 100))
	cpuSystem := int(math.Round(float64(after.System-before.System) / total * 100))

	return cpuUser, cpuSystem, nil
}

func (mc *Client) monitorSystemMemory() (int, int, error) {
	mem, err := memory.Get()
	if err != nil {
		return 0, 0, err
	}
	memoryUsed := int(math.Round(float64(mem.Used) / float64(mem.Total) * 100))
	memoryCached := int(math.Round(float64(mem.Cached) / float64(mem.Total) * 100))

	return memoryUsed, memoryCached, nil
}

func (mc *Client) pushToMetricsServer(enclaveMetrics types.EnclaveSystemMetrics) error {
	metricsSerialized, err := json.Marshal(enclaveMetrics)
	if err != nil {
		return err
	}

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

func (mc *Client) collectAndEmitMetrics() {
	// Aggregation state
	var cpuUserSamples, cpuSystemSamples []int
	var memUsedSamples, memCachedSamples []int

	sampleTicker := time.NewTicker(mc.sampleRate)
	emitTicker := time.NewTicker(mc.emitInterval)

	for {
		select {
		case <-sampleTicker.C:
			// Collect sample
			cpuUser, cpuSystem, err := mc.monitorSystemCPU()
			if err != nil {
				log.Errorf("error gathering cpu metrics: %s", err)
				continue
			}
			memUsed, memCached, err := mc.monitorSystemMemory()
			if err != nil {
				log.Errorf("error gathering memory metrics: %s", err)
				continue
			}

			cpuUserSamples = append(cpuUserSamples, cpuUser)
			cpuSystemSamples = append(cpuSystemSamples, cpuSystem)
			memUsedSamples = append(memUsedSamples, memUsed)
			memCachedSamples = append(memCachedSamples, memCached)

		case <-emitTicker.C:
			if len(cpuUserSamples) == 0 {
				continue
			}

			// Calculate aggregates
			metrics := types.EnclaveSystemMetrics{
				Timestamp:            time.Now().Unix(),
				CPUConsumptionUser:   avg(cpuUserSamples),
				CPUConsumptionSystem: avg(cpuSystemSamples),
				MemoryUsed:           avg(memUsedSamples),
				MemoryCached:         avg(memCachedSamples),
				CPUUserMin:           min(cpuUserSamples),
				CPUUserMax:           max(cpuUserSamples),
				CPUSystemMin:         min(cpuSystemSamples),
				CPUSystemMax:         max(cpuSystemSamples),
				MemoryUsedMin:        min(memUsedSamples),
				MemoryUsedMax:        max(memUsedSamples),
			}

			err := mc.pushToMetricsServer(metrics)
			if err != nil {
				log.Errorf("error pushing metrics: %s\npayload: %v", err, metrics)
			}

			// Reset samples
			cpuUserSamples = cpuUserSamples[:0]
			cpuSystemSamples = cpuSystemSamples[:0]
			memUsedSamples = memUsedSamples[:0]
			memCachedSamples = memCachedSamples[:0]
		}
	}
}

func min(values []int) int {
	if len(values) == 0 {
		return 0
	}
	m := values[0]
	for _, v := range values[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func max(values []int) int {
	if len(values) == 0 {
		return 0
	}
	m := values[0]
	for _, v := range values[1:] {
		if v > m {
			m = v
		}
	}
	return m
}

func avg(values []int) int {
	if len(values) == 0 {
		return 0
	}
	sum := 0
	for _, v := range values {
		sum += v
	}
	return sum / len(values)
}
