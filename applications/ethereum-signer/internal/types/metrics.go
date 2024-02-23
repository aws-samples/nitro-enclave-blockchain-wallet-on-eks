package types

type EnclaveSystemMetrics struct {
	Timestamp            int `json:"Timestamp"`
	CPUConsumptionUser   int `json:"CPUConsumptionUser"`
	CPUConsumptionSystem int `json:"CPUConsumptionSystem"`
	MemoryUsed           int `json:"MemoryUsed"`
	MemoryCached         int `json:"MemoryCached"`
}
